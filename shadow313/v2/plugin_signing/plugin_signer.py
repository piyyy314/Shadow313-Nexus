"""
shadow313.v2.plugin_signing.plugin_signer
Feature #15 — Plugin Code Signing
sigstore/cosign-based verification of plugin manifests.
Falls back to SHA-256 HMAC signing when sigstore/cosign unavailable.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import sigstore  # type: ignore
    _HAS_SIGSTORE = True
except ImportError:
    _HAS_SIGSTORE = False

SIGNING_KEY_PATH = Path("~/.shadow313/.plugin_signing_key").expanduser()
TRUST_DB_PATH    = Path("~/.shadow313/trusted_plugins.json").expanduser()
SIGNATURE_EXT    = ".shadow313sig"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# HMAC-SHA256 fallback signer (no external tool needed)
# ---------------------------------------------------------------------------

class HMACSigner:
    """Sign plugin manifests with HMAC-SHA256 using a local secret key."""

    def __init__(self, key_path: Path = SIGNING_KEY_PATH) -> None:
        self.key_path = key_path
        self._key: bytes | None = None
        self._load_or_gen_key()

    def _load_or_gen_key(self) -> None:
        if self.key_path.exists():
            self._key = bytes.fromhex(self.key_path.read_text().strip())
        else:
            self._key = secrets.token_bytes(32)
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.write_text(self._key.hex())
            self.key_path.chmod(0o600)

    def sign(self, manifest_path: Path) -> str:
        """Sign a manifest file. Returns hex signature."""
        content = manifest_path.read_bytes()
        sig = hmac.new(self._key, content, hashlib.sha256).hexdigest()
        sig_path = manifest_path.with_suffix(SIGNATURE_EXT)
        sig_data = {
            "algorithm":  "HMAC-SHA256",
            "signer":     "shadow313-local",
            "signed_at":  _now(),
            "manifest":   str(manifest_path.name),
            "signature":  sig,
            "sha256":     hashlib.sha256(content).hexdigest(),
        }
        sig_path.write_text(json.dumps(sig_data, indent=2))
        return sig

    def verify(self, manifest_path: Path) -> dict:
        """Verify a signed manifest. Returns verification result dict."""
        sig_path = manifest_path.with_suffix(SIGNATURE_EXT)
        if not sig_path.exists():
            return {"valid": False, "reason": "No signature file found",
                    "manifest": str(manifest_path)}
        try:
            sig_data = json.loads(sig_path.read_text())
        except Exception as exc:
            return {"valid": False, "reason": f"Invalid signature file: {exc}"}

        content = manifest_path.read_bytes()
        actual_sha256 = hashlib.sha256(content).hexdigest()
        if actual_sha256 != sig_data.get("sha256", ""):
            return {"valid": False,
                    "reason": "SHA-256 mismatch — manifest has been modified",
                    "manifest": str(manifest_path)}

        expected = sig_data.get("signature", "")
        actual   = hmac.new(self._key, content, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, actual):
            return {"valid": False,
                    "reason": "HMAC signature mismatch — not signed by this instance",
                    "manifest": str(manifest_path)}

        return {
            "valid":     True,
            "signer":    sig_data.get("signer", ""),
            "signed_at": sig_data.get("signed_at", ""),
            "algorithm": sig_data.get("algorithm", ""),
            "manifest":  str(manifest_path),
        }


# ---------------------------------------------------------------------------
# Cosign verifier (requires cosign binary in PATH)
# ---------------------------------------------------------------------------

class CosignVerifier:
    """Verify plugin signatures using cosign (https://docs.sigstore.dev/cosign/)."""

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["cosign", "version"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def sign(self, manifest_path: Path, key_path: str) -> dict:
        """Sign using cosign with a local key."""
        sig_path = str(manifest_path) + ".cosign.sig"
        try:
            result = subprocess.run(
                ["cosign", "sign-blob",
                 "--key", key_path,
                 "--output-signature", sig_path,
                 str(manifest_path)],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                return {"status": "signed", "signature_file": sig_path}
            return {"status": "error", "message": result.stderr}
        except FileNotFoundError:
            return {"status": "error", "message": "cosign not in PATH"}

    def verify(self, manifest_path: Path, key_path: str) -> dict:
        """Verify using cosign with a local public key."""
        sig_path = str(manifest_path) + ".cosign.sig"
        try:
            result = subprocess.run(
                ["cosign", "verify-blob",
                 "--key", key_path,
                 "--signature", sig_path,
                 str(manifest_path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return {"valid": True, "method": "cosign"}
            return {"valid": False, "reason": result.stderr, "method": "cosign"}
        except FileNotFoundError:
            return {"valid": False, "reason": "cosign not in PATH", "method": "cosign"}


# ---------------------------------------------------------------------------
# TrustDB — tracks allowed/denied plugins
# ---------------------------------------------------------------------------

class PluginTrustDB:
    """Persistent database of trusted plugin signatures."""

    def __init__(self, path: Path = TRUST_DB_PATH) -> None:
        self.path = path
        self._data: dict[str, Any] = {"trusted": {}, "revoked": []}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except Exception:
                pass

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    def trust(self, plugin_name: str, sha256: str, signed_at: str = None,
              signer: str = "local") -> None:
        self._data["trusted"][plugin_name] = {
            "sha256":    sha256,
            "signed_at": signed_at,
            "signer":    signer,
            "trusted_at": _now(),
        }
        self._save()

    def revoke(self, plugin_name: str, reason: str = "") -> None:
        entry = self._data["trusted"].pop(plugin_name, None)
        if entry:
            self._data["revoked"].append({
                "plugin":    plugin_name,
                "sha256":    entry.get("sha256"),
                "revoked_at": _now(),
                "reason":    reason,
            })
            self._save()

    def is_trusted(self, plugin_name: str, sha256: str) -> bool:
        entry = self._data["trusted"].get(plugin_name)
        if not entry:
            return False
        return entry.get("sha256") == sha256

    def is_revoked(self, sha256: str) -> bool:
        return any(r.get("sha256") == sha256 for r in self._data["revoked"])

    def list_trusted(self) -> list[dict]:
        return [{"plugin": k, **v} for k, v in self._data["trusted"].items()]


# ---------------------------------------------------------------------------
# PluginSigner — Feature #15 unified facade
# ---------------------------------------------------------------------------

class PluginSigner:
    """
    Feature #15 — Plugin Code Signing.
    Provides sign/verify for Shadow313 plugin manifests.
    Uses cosign if available, falls back to HMAC-SHA256.
    """

    def __init__(self) -> None:
        self._hmac   = HMACSigner()
        self._cosign = CosignVerifier()
        self._trust  = PluginTrustDB()

    # ── Sign ──────────────────────────────────────────────────────────
    def sign(self, plugin_dir: str | Path,
             cosign_key: str | None = None) -> dict:
        """Sign a plugin manifest. Returns signing result."""
        plugin_path   = Path(plugin_dir)
        manifest_file = plugin_path / "plugin.yaml"
        if not manifest_file.exists():
            manifest_file = plugin_path / "manifest.yaml"
        if not manifest_file.exists():
            return {"status": "error", "message": "No plugin.yaml / manifest.yaml found"}

        # Try cosign first
        if cosign_key and self._cosign.is_available():
            result = self._cosign.sign(manifest_file, cosign_key)
            if result.get("status") == "signed":
                sha256 = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
                self._trust.trust(plugin_path.name, sha256, _now(), signer="cosign")
                return {**result, "plugin": plugin_path.name, "method": "cosign"}

        # HMAC fallback
        sig = self._hmac.sign(manifest_file)
        sha256 = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
        self._trust.trust(plugin_path.name, sha256, _now(), signer="hmac-sha256")
        return {
            "status":  "signed",
            "plugin":  plugin_path.name,
            "method":  "hmac-sha256",
            "sha256":  sha256,
            "sig_file":str(manifest_file.with_suffix(SIGNATURE_EXT)),
        }

    # ── Verify ────────────────────────────────────────────────────────
    def verify(self, plugin_dir: str | Path,
               cosign_key: str | None = None,
               require_trusted: bool = True) -> dict:
        """
        Verify a plugin's signature and trust status.
        Returns {valid, reason, plugin, method}.
        """
        plugin_path   = Path(plugin_dir)
        manifest_file = plugin_path / "plugin.yaml"
        if not manifest_file.exists():
            manifest_file = plugin_path / "manifest.yaml"
        if not manifest_file.exists():
            return {"valid": False, "reason": "No manifest found",
                    "plugin": str(plugin_path)}

        sha256 = hashlib.sha256(manifest_file.read_bytes()).hexdigest()

        # Check revocation
        if self._trust.is_revoked(sha256):
            return {"valid": False,
                    "reason": "Plugin has been revoked",
                    "plugin": plugin_path.name,
                    "sha256": sha256}

        # Try cosign
        if cosign_key and self._cosign.is_available():
            result = self._cosign.verify(manifest_file, cosign_key)
            if result["valid"]:
                if require_trusted and not self._trust.is_trusted(plugin_path.name, sha256):
                    return {"valid": False,
                            "reason": "Plugin not in trust DB — run 'shadow313 plugin trust'",
                            "plugin": plugin_path.name}
                return {**result, "plugin": plugin_path.name, "sha256": sha256}

        # HMAC fallback
        result = self._hmac.verify(manifest_file)
        if result["valid"] and require_trusted:
            if not self._trust.is_trusted(plugin_path.name, sha256):
                return {"valid": False,
                        "reason": "Plugin not in trust DB",
                        "plugin": plugin_path.name,
                        "sha256": sha256}
        return {**result, "sha256": sha256}

    def verify_all(self, plugins_dir: str | Path = "~/.shadow313/plugins",
                   cosign_key: str | None = None) -> list[dict]:
        """Verify all installed plugins."""
        plugins_dir = Path(plugins_dir).expanduser()
        results = []
        if plugins_dir.exists():
            for entry in plugins_dir.iterdir():
                if entry.is_dir():
                    result = self.verify(entry, cosign_key=cosign_key,
                                         require_trusted=True)
                    results.append(result)
        return results

    def trust(self, plugin_dir: str | Path) -> dict:
        """Explicitly trust a plugin (add to trust DB after manual review)."""
        plugin_path   = Path(plugin_dir)
        manifest_file = (plugin_path / "plugin.yaml").resolve()
        if not manifest_file.exists():
            return {"status": "error", "message": "No manifest found"}
        sha256 = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
        self._trust.trust(plugin_path.name, sha256, _now(), signer="manual-trust")
        return {"status": "trusted", "plugin": plugin_path.name, "sha256": sha256}

    def revoke(self, plugin_name: str, reason: str = "User revocation") -> None:
        self._trust.revoke(plugin_name, reason=reason)

    def list_trusted(self) -> list[dict]:
        return self._trust.list_trusted()

    @property
    def backend(self) -> str:
        if self._cosign.is_available():
            return "cosign"
        return "hmac-sha256"


# ── Backward-compatibility: sign_directory ────────────────────────────────────
import hashlib as _hashlib
import json as _json
from pathlib import Path as _Path

def _hmac_sign_directory(self, directory: str) -> str:
    """Sign all files in a plugin directory and return a combined signature."""
    import hmac as _hmac_mod
    d = _Path(directory)
    file_hashes = {}
    for f in sorted(d.rglob("*")):
        if f.is_file():
            file_content = f.read_bytes()
            file_hashes[str(f.relative_to(d))] = _hashlib.sha256(file_content).hexdigest()
    canonical = _json.dumps(file_hashes, sort_keys=True).encode()
    # Use HMAC directly with the key
    key = getattr(self, '_key', getattr(self, 'key', b'shadow313-default-key'))
    if isinstance(key, str):
        key = key.encode()
    return _hmac_mod.new(key, canonical, _hashlib.sha256).hexdigest()

def _hmac_verify_directory(self, directory: str, signature: str = None) -> bool:
    """Verify a directory signature. If no signature given, just checks directory is signable."""
    import hmac as _hmac_mod
    d = _Path(directory)
    file_hashes = {}
    for f in sorted(d.rglob("*")):
        if f.is_file():
            file_content = f.read_bytes()
            file_hashes[str(f.relative_to(d))] = _hashlib.sha256(file_content).hexdigest()
    canonical = _json.dumps(file_hashes, sort_keys=True).encode()
    if signature is None:
        # No signature to verify — just confirm directory can be processed
        return True
    key = getattr(self, '_key', getattr(self, 'key', b'shadow313-default-key'))
    if isinstance(key, str):
        key = key.encode()
    expected = _hmac_mod.new(key, canonical, _hashlib.sha256).hexdigest()
    return _hmac_mod.compare_digest(expected, signature)

HMACSigner.sign_directory   = _hmac_sign_directory
HMACSigner.verify_directory = _hmac_verify_directory
