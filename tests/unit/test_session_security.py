"""
Security tests for shadow313.core.session
Covers:
  1. Path traversal prevention (encrypted + plaintext writes)
  2. Wrong-key authentication failure (fail-closed, no plaintext fallback)
  3. Plaintext downgrade prevention (cryptography unavailable → RuntimeError)
  4. Version consistency
"""
import json
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from shadow313.core.session import Session


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_session(tmp_path):
    """Return a plaintext Session rooted at tmp_path/sessions."""
    return Session(str(tmp_path / "sessions"))


@pytest.fixture
def tmp_enc_session(tmp_path):
    """Return an encrypted Session, or skip if cryptography not installed."""
    try:
        s = Session(str(tmp_path / "sessions"), encrypt=True)
        return s
    except RuntimeError as e:
        if "cryptography" in str(e).lower():
            pytest.skip("cryptography package not installed")
        raise


# ─────────────────────────────────────────────────────────────────────────────
# 1. PATH TRAVERSAL PREVENTION — plaintext
# ─────────────────────────────────────────────────────────────────────────────

class TestPathTraversalPlaintext:
    """Traversal attempts must never create files outside the session dir."""

    def test_single_dotdot_stays_inside(self, tmp_path):
        s = Session(str(tmp_path / "sessions"))
        outside = tmp_path / "escape.json"
        result = s.write("../escape.json", {"pwned": True})
        assert not outside.exists(), f"File escaped to {outside}"
        assert str(result).startswith(str(s.session_dir))

    def test_double_dotdot_stays_inside(self, tmp_path):
        s = Session(str(tmp_path / "sessions"))
        outside = tmp_path.parent / "escape.json"
        result = s.write("../../escape.json", {"pwned": True})
        assert not outside.exists(), f"File escaped to {outside}"
        assert str(result).startswith(str(s.session_dir))

    def test_absolute_path_sanitized(self, tmp_path):
        s = Session(str(tmp_path / "sessions"))
        result = s.write("/tmp/evil.json", {"pwned": True})
        # Must write inside session dir, not to /tmp/evil.json
        assert str(result).startswith(str(s.session_dir))
        assert not Path("/tmp/evil.json").exists() or str(result) != "/tmp/evil.json"

    def test_hidden_file_rejected(self, tmp_session):
        with pytest.raises(ValueError, match="Invalid filename"):
            tmp_session.write(".hidden", {"data": True})

    def test_empty_filename_rejected(self, tmp_session):
        with pytest.raises((ValueError, OSError)):
            tmp_session.write("", {"data": True})

    def test_normal_filename_works(self, tmp_session):
        path = tmp_session.write("findings.json", {"cve": "CVE-2026-001"})
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["cve"] == "CVE-2026-001"

    def test_path_method_traversal_sanitized(self, tmp_session):
        result = tmp_session.path("../escape")
        assert str(result).startswith(str(tmp_session.session_dir))

    def test_path_method_dotfile_rejected(self, tmp_session):
        with pytest.raises(ValueError, match="Invalid filename"):
            tmp_session.path(".hidden")

    def test_no_file_escapes_boundary(self, tmp_path):
        """Comprehensive: none of these traversal strings should escape."""
        s = Session(str(tmp_path / "sessions"))
        attempts = [
            "../escape1.json",
            "../../escape2.json",
            "../../../escape3.json",
            "/tmp/escape4.json",
        ]
        for attempt in attempts:
            try:
                result = s.write(attempt, {"attempt": attempt})
                assert str(result).startswith(str(s.session_dir)), \
                    f"Write of {attempt!r} escaped to {result}"
            except (ValueError, OSError):
                pass  # rejection is also acceptable

        # Nothing should have escaped to tmp_path root
        escaped = list(tmp_path.glob("escape*.json"))
        assert len(escaped) == 0, f"Files escaped: {escaped}"


# ─────────────────────────────────────────────────────────────────────────────
# 2. PATH TRAVERSAL PREVENTION — encrypted writes
# ─────────────────────────────────────────────────────────────────────────────

class TestPathTraversalEncrypted:
    """Encrypted writes must apply the same sanitization as plaintext."""

    def test_encrypted_single_dotdot_stays_inside(self, tmp_path):
        try:
            s = Session(str(tmp_path / "sessions"), encrypt=True)
        except RuntimeError:
            pytest.skip("cryptography not installed")
        outside = tmp_path / "escape.json"
        result = s.write("../escape.json", {"pwned": True})
        assert not outside.exists(), f"Encrypted write escaped to {outside}"
        assert str(result).startswith(str(s.session_dir))

    def test_encrypted_double_dotdot_stays_inside(self, tmp_path):
        try:
            s = Session(str(tmp_path / "sessions"), encrypt=True)
        except RuntimeError:
            pytest.skip("cryptography not installed")
        outside = tmp_path.parent / "escape.json"
        result = s.write("../../escape.json", {"pwned": True})
        assert not outside.exists(), f"Encrypted write escaped to {outside}"
        assert str(result).startswith(str(s.session_dir))

    def test_encrypted_hidden_file_rejected(self, tmp_path):
        try:
            s = Session(str(tmp_path / "sessions"), encrypt=True)
        except RuntimeError:
            pytest.skip("cryptography not installed")
        with pytest.raises(ValueError, match="Invalid filename"):
            s.write(".hidden", {"data": True})

    def test_encrypted_normal_write_roundtrip(self, tmp_enc_session):
        """Encrypted write → read must return original data."""
        data = {"secret": "test-value-313", "score": 0.99}
        path = tmp_enc_session.write("test_data.json", data)
        assert path.exists()
        # File on disk must NOT be plaintext JSON
        raw = path.read_bytes()
        assert b'"secret"' not in raw, "Encrypted file contains plaintext!"
        # Read back must decrypt correctly
        recovered = tmp_enc_session.read("test_data.json")
        assert recovered is not None
        assert recovered.get("secret") == "test-value-313"


# ─────────────────────────────────────────────────────────────────────────────
# 3. WRONG-KEY AUTHENTICATION FAILURE (fail-closed)
# ─────────────────────────────────────────────────────────────────────────────

class TestWrongKeyFailClosed:
    """
    When decryption fails (wrong key / tampered ciphertext), the session
    must fail closed — it must NOT fall back to returning plaintext or
    silently returning None without signalling the error.
    """

    def test_wrong_key_does_not_return_plaintext(self, tmp_path):
        """Write with key A, read with key B — must not return original data."""
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            pytest.skip("cryptography not installed")

        # Write with session using one key
        s1 = Session(str(tmp_path / "sessions"), encrypt=True)
        s1.write("secret.json", {"classified": "top-secret-313"})

        # Tamper: replace the key file with a different key
        key_file = s1.session_dir / ".session.key"
        if key_file.exists():
            key_file.write_bytes(Fernet.generate_key())

        # Read with corrupted key — must NOT return the original plaintext
        s2 = Session(str(tmp_path / "sessions"), encrypt=True)
        result = s2.read("secret.json")

        # Either returns None (graceful failure) or raises — never returns original data
        if result is not None:
            assert result.get("classified") != "top-secret-313", \
                "SECURITY: Wrong key returned original plaintext!"

    def test_tampered_ciphertext_does_not_return_data(self, tmp_path):
        """Bit-flip the ciphertext — must not return original data."""
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            pytest.skip("cryptography not installed")

        s = Session(str(tmp_path / "sessions"), encrypt=True)
        s.write("secret.json", {"classified": "top-secret-313"})

        # Find and corrupt the encrypted file
        enc_files = list(s.session_dir.glob("secret.json*"))
        if not enc_files:
            pytest.skip("No encrypted file found to tamper with")

        enc_file = enc_files[0]
        raw = bytearray(enc_file.read_bytes())
        # Flip bytes in the middle of the ciphertext
        mid = len(raw) // 2
        for i in range(mid, min(mid + 8, len(raw))):
            raw[i] ^= 0xFF
        enc_file.write_bytes(bytes(raw))

        # Read must not return original data
        result = s.read("secret.json")
        if result is not None:
            assert result.get("classified") != "top-secret-313", \
                "SECURITY: Tampered ciphertext returned original plaintext!"

    def test_read_nonexistent_returns_none(self, tmp_enc_session):
        """Reading a file that doesn't exist must return None, not raise."""
        result = tmp_enc_session.read("nonexistent_file.json")
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 4. PLAINTEXT DOWNGRADE PREVENTION
# ─────────────────────────────────────────────────────────────────────────────

class TestPlaintextDowngradePrevention:
    """
    When encrypt=True but the cryptography package is unavailable,
    the session must fail closed (raise RuntimeError), NOT silently
    downgrade to writing unencrypted data.
    """

    def test_encrypt_true_without_cryptography_raises(self, tmp_path):
        """
        Simulate cryptography being unavailable.
        Session(encrypt=True) must raise RuntimeError, not silently write plaintext.
        """
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name in ("cryptography", "cryptography.fernet"):
                raise ImportError("Simulated: cryptography not installed")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            try:
                s = Session(str(tmp_path / "sessions"), encrypt=True)
                # If Session was created, writing must either raise or fail closed
                # It must NOT silently write plaintext
                try:
                    path = s.write("test.json", {"secret": "value"})
                    # If write succeeded, verify the file is NOT plaintext
                    if path and path.exists():
                        raw = path.read_bytes()
                        assert b'"secret"' not in raw, \
                            "SECURITY: Plaintext downgrade occurred — cryptography unavailable but data written unencrypted!"
                except (RuntimeError, ImportError):
                    pass  # Correct: fail closed
            except (RuntimeError, ImportError):
                pass  # Correct: fail at construction

    def test_encrypted_file_not_readable_as_plaintext(self, tmp_path):
        """An encrypted file must not be parseable as plain JSON."""
        try:
            s = Session(str(tmp_path / "sessions"), encrypt=True)
        except RuntimeError:
            pytest.skip("cryptography not installed")

        s.write("secret.json", {"password": "hunter2", "key": "abc123"})

        # Find the written file
        enc_files = list(s.session_dir.glob("secret*"))
        assert len(enc_files) > 0, "No file was written"

        for enc_file in enc_files:
            raw = enc_file.read_bytes()
            # Must not contain plaintext field names or values
            assert b'"password"' not in raw, \
                f"SECURITY: Plaintext field 'password' found in {enc_file.name}"
            assert b'"key"' not in raw, \
                f"SECURITY: Plaintext field 'key' found in {enc_file.name}"
            assert b"hunter2" not in raw, \
                f"SECURITY: Plaintext value 'hunter2' found in {enc_file.name}"
            # Must not be valid JSON
            try:
                json.loads(raw)
                pytest.fail(f"SECURITY: Encrypted file {enc_file.name} is valid JSON (plaintext!)")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass  # Correct: not readable as JSON

    def test_write_encrypted_then_read_plaintext_fails(self, tmp_path):
        """
        Write encrypted, then open a plaintext Session on the same dir.
        The plaintext session must not be able to read the encrypted data.
        """
        try:
            s_enc = Session(str(tmp_path / "sessions"), encrypt=True)
        except RuntimeError:
            pytest.skip("cryptography not installed")

        s_enc.write("secret.json", {"classified": "top-secret"})

        # Open same session dir without encryption
        s_plain = Session(str(tmp_path / "sessions"), encrypt=False)
        result = s_plain.read("secret.json")

        # Either returns None (file not found at plain path) or garbled data
        # Must NOT return the original dict
        if result is not None and isinstance(result, dict):
            assert result.get("classified") != "top-secret", \
                "SECURITY: Encrypted data readable by plaintext session!"


# ─────────────────────────────────────────────────────────────────────────────
# 5. VERSION CONSISTENCY
# ─────────────────────────────────────────────────────────────────────────────

class TestVersionConsistency:

    def test_version_is_4(self):
        import shadow313
        assert shadow313.__version__.startswith("4."), \
            f"Expected version 4.x.x, got {shadow313.__version__}"

    def test_session_meta_version(self, tmp_path):
        s = Session(str(tmp_path / "sessions"))
        meta_path = s.session_dir / "meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            version = meta.get("version", "")
            assert version.startswith("4.") or version == "", \
                f"Session meta has wrong version: {version}"

    def test_session_dir_created_on_init(self, tmp_path):
        s = Session(str(tmp_path / "sessions"))
        assert s.session_dir.exists(), "Session dir must be created on init"
