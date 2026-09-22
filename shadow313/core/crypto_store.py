"""
shadow313.core.crypto_store  — v4
AES-256-GCM encrypted session store with 4-tier key resolution.

Cipher spec:
  Algorithm:  AES-256-GCM (authenticated encryption)
  Key size:   256 bits (32 bytes)
  Nonce size: 96 bits (12 bytes) — random per operation
  Wire format: nonce(12) || ciphertext+tag (variable)
  PBKDF2:     480,000 iterations, SHA-256 (NIST SP 800-132)

Key resolution hierarchy:
  1. OS Keychain (keyring library)
  2. Key file (~/.shadow313/session.key)
  3. PBKDF2 from passphrase
  4. Auto-generated key (stored in keychain if available)
"""
from __future__ import annotations
import os
import json
from pathlib import Path
from typing import Optional


_KEY_FILE = Path("~/.shadow313/session.key").expanduser()
_KEYRING_SERVICE = "shadow313"
_KEYRING_USERNAME = "session_key"
_PBKDF2_ITERATIONS = 480_000


class KeyManager:
    """4-tier key resolution for AES-256-GCM session encryption."""

    def __init__(self, key_file: Path = _KEY_FILE) -> None:
        self._key_file = key_file
        self._cached_key: Optional[bytes] = None

    def get_key(self, passphrase: str | None = None) -> bytes:
        if self._cached_key:
            return self._cached_key

        # Tier 1: OS Keychain
        key = self._from_keychain()
        if key:
            self._cached_key = key
            return key

        # Tier 2: Key file
        key = self._from_key_file()
        if key:
            self._cached_key = key
            return key

        # Tier 3: PBKDF2 from passphrase
        if passphrase:
            key = self._from_passphrase(passphrase)
            self._cached_key = key
            return key

        # Tier 4: Auto-generate
        key = os.urandom(32)
        self._store_key(key)
        self._cached_key = key
        return key

    def _from_keychain(self) -> Optional[bytes]:
        try:
            import keyring
            val = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
            if val:
                return bytes.fromhex(val)
        except Exception as _e:
            import logging
            logging.getLogger("shadow313.crypto").debug(f"Keychain unavailable: {_e}")
        return None

    def _from_key_file(self) -> Optional[bytes]:
        if self._key_file.exists():
            try:
                data = self._key_file.read_bytes()
                if len(data) == 32:
                    return data
            except OSError:
                pass
        return None

    def _from_passphrase(self, passphrase: str) -> bytes:
        """
        CRQC-007 fix: Argon2id replaces PBKDF2-SHA256.
        Argon2id is memory-hard — Grover's algorithm provides at most √2 speedup
        against the key search, but the memory cost makes quantum brute-force
        infeasible even with a CRQC. Falls back to PBKDF2-SHA256 if argon2-cffi
        is not installed (e.g., air-gapped environments without the package).
        """
        salt_file = self._key_file.parent / "session.salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = os.urandom(32)
            salt_file.parent.mkdir(parents=True, exist_ok=True)
            salt_file.write_bytes(salt)
            salt_file.chmod(0o600)

        try:
            from argon2.low_level import hash_secret_raw, Type
            # Argon2id parameters: time_cost=3, memory_cost=65536 (64MB), parallelism=4
            # 64MB memory cost makes quantum brute-force infeasible (CRQC-007 fix)
            key = hash_secret_raw(
                secret=passphrase.encode(),
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID,
            )
        except ImportError:
            import hashlib
            import logging
            logging.getLogger("shadow313.crypto").warning(
                "argon2-cffi not installed — falling back to PBKDF2-SHA256 (CRQC-007 unmitigated). "
                "Install with: pip install argon2-cffi"
            )
            key = hashlib.pbkdf2_hmac(
                "sha256",
                passphrase.encode(),
                salt,
                _PBKDF2_ITERATIONS,
                dklen=32,
            )
        return key

    def _store_key(self, key: bytes) -> None:
        # Try keychain first
        try:
            import keyring
            keyring.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, key.hex())
            return
        except Exception as _e:
            import logging
            logging.getLogger("shadow313.crypto").debug(f"Keychain store failed: {_e}")
        # Fall back to key file
        try:
            self._key_file.parent.mkdir(parents=True, exist_ok=True)
            self._key_file.write_bytes(key)
            self._key_file.chmod(0o600)
        except OSError:
            pass

    def rotate_key(self) -> bytes:
        """Generate and store a new key, invalidating the old one."""
        self._cached_key = None
        new_key = os.urandom(32)
        self._store_key(new_key)
        self._cached_key = new_key
        return new_key


class AESGCMCipher:
    """Low-level AES-256-GCM encrypt/decrypt."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self._key = key

    def encrypt(self, plaintext: str | bytes) -> bytes:
        """Returns nonce(12) || ciphertext+tag."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, ciphertext: bytes) -> str:
        """Expects nonce(12) || ciphertext+tag. Returns plaintext string."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if len(ciphertext) < 13:
            raise ValueError("Ciphertext too short")
        nonce = ciphertext[:12]
        ct    = ciphertext[12:]
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return plaintext.decode()


class EncryptedSessionStore:
    """
    Drop-in replacement for plain file I/O.
    Transparently encrypts writes and decrypts reads.
    Falls back to plain I/O if cryptography library is unavailable.
    """

    def __init__(
        self,
        session_dir: Path,
        passphrase: str | None = None,
    ) -> None:
        self._dir = session_dir
        self._cipher: Optional[AESGCMCipher] = None
        try:
            km  = KeyManager()
            key = km.get_key(passphrase)
            self._cipher = AESGCMCipher(key)
        except ImportError:
            pass  # cryptography not installed — plain I/O fallback

    def write_encrypted(self, filename: str, content: str) -> None:
        path = self._dir / filename
        if self._cipher:
            path.write_bytes(self._cipher.encrypt(content))
        else:
            path.write_text(content)

    def read_encrypted(self, filename: str) -> Optional[str]:
        path = self._dir / filename
        if not path.exists():
            return None
        if self._cipher:
            try:
                return self._cipher.decrypt(path.read_bytes())
            except Exception:
                # Fallback: try plain read (file may not be encrypted)
                try:
                    return path.read_text()
                except Exception:
                    return None
        return path.read_text()

    @property
    def is_encrypted(self) -> bool:
        return self._cipher is not None