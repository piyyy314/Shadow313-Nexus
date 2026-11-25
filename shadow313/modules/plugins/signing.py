"""Local HMAC signing for complete plugin artifacts.

The signature covers every regular file and relative path in the plugin tree,
excluding only the detached signature file itself. This is a local trust
mechanism, not a substitute for Sigstore or an organizational signing service.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SIGNATURE_NAME = "plugin.shadow313sig"
KEY_PATH = Path("~/.shadow313/plugin-artifact-signing.key").expanduser()
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024


class PluginArtifactSigner:
    """Sign and verify the complete content tree of a plugin directory."""

    def __init__(self, key_path: Path | None = None) -> None:
        self.key_path = key_path or KEY_PATH

    def _load_key(self, *, create: bool) -> bytes | None:
        configured = os.environ.get("SHADOW313_PLUGIN_SIGNING_KEY")
        if configured:
            key = configured.encode("utf-8")
            if len(key) < 32:
                raise ValueError("SHADOW313_PLUGIN_SIGNING_KEY must be at least 32 bytes")
            return key

        if self.key_path.is_symlink():
            raise ValueError("Plugin signing key must not be a symlink")
        if self.key_path.is_file():
            key = self.key_path.read_bytes()
            if len(key) < 32:
                raise ValueError("Plugin signing key file is invalid or too short")
            return key

        if not create:
            return None

        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        try:
            descriptor = os.open(
                self.key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return self._load_key(create=False)

        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(key)
        return key

    @staticmethod
    def _artifact_digest(plugin_dir: Path) -> str:
        root = plugin_dir.expanduser().resolve()
        if not root.is_dir() or plugin_dir.is_symlink():
            raise ValueError("Plugin artifact must be a real directory")

        digest = hashlib.sha256()
        total_bytes = 0
        for item in sorted(root.rglob("*")):
            if item.is_symlink():
                raise ValueError(f"Plugin artifact contains a symlink: {item.relative_to(root)}")
            if not item.is_file() or item == root / SIGNATURE_NAME:
                continue

            size = item.stat().st_size
            if size > MAX_FILE_BYTES:
                raise ValueError(f"Plugin file exceeds 10 MiB: {item.relative_to(root)}")
            total_bytes += size
            if total_bytes > MAX_ARTIFACT_BYTES:
                raise ValueError("Plugin artifact exceeds 100 MiB")

            relative_path = item.relative_to(root).as_posix().encode("utf-8")
            content_hash = hashlib.sha256(item.read_bytes()).digest()
            digest.update(len(relative_path).to_bytes(4, "big"))
            digest.update(relative_path)
            digest.update(content_hash)

        return digest.hexdigest()

    def sign(self, plugin_dir: str | Path) -> dict[str, Any]:
        root = Path(plugin_dir).expanduser().resolve()
        key = self._load_key(create=True)
        if key is None:
            raise ValueError("Plugin signing key is unavailable")

        artifact_digest = self._artifact_digest(root)
        message = f"shadow313-plugin-artifact-v1:{artifact_digest}".encode("ascii")
        signature = hmac.new(key, message, hashlib.sha256).hexdigest()
        record = {
            "version": 1,
            "algorithm": "HMAC-SHA256",
            "signer": "shadow313-local",
            "signed_at": datetime.now(UTC).isoformat(),
            "artifact_sha256": artifact_digest,
            "signature": signature,
        }

        destination = root / SIGNATURE_NAME
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=root,
            prefix=".plugin-signature-",
            delete=False,
        ) as temporary:
            temporary.write(json.dumps(record, indent=2) + "\n")
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, destination)
        destination.chmod(0o644)
        return {"valid": True, "plugin": root.name, **record}

    def verify(self, plugin_dir: str | Path) -> dict[str, Any]:
        root = Path(plugin_dir).expanduser().resolve()
        signature_path = root / SIGNATURE_NAME
        if not signature_path.is_file() or signature_path.is_symlink():
            return {"valid": False, "reason": "Plugin artifact signature is missing"}

        key = self._load_key(create=False)
        if key is None:
            return {"valid": False, "reason": "Plugin signing trust key is not configured"}

        try:
            record = json.loads(signature_path.read_text(encoding="utf-8"))
            if (
                record.get("version") != 1
                or record.get("algorithm") != "HMAC-SHA256"
                or not isinstance(record.get("signature"), str)
            ):
                return {"valid": False, "reason": "Unsupported plugin signature format"}

            artifact_digest = self._artifact_digest(root)
            if not hmac.compare_digest(
                str(record.get("artifact_sha256", "")),
                artifact_digest,
            ):
                return {"valid": False, "reason": "Plugin artifact content hash mismatch"}

            message = f"shadow313-plugin-artifact-v1:{artifact_digest}".encode("ascii")
            expected = hmac.new(key, message, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(record["signature"], expected):
                return {"valid": False, "reason": "Plugin artifact signature is invalid"}

            return {
                "valid": True,
                "plugin": root.name,
                "signer": record.get("signer", ""),
                "signed_at": record.get("signed_at", ""),
                "algorithm": record["algorithm"],
                "artifact_sha256": artifact_digest,
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return {"valid": False, "reason": f"Plugin signature verification failed: {exc}"}
