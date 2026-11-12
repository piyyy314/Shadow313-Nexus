from __future__ import annotations

"""Legacy HMAC-signed plugin loader with explicit signing-key configuration."""

import hashlib
import hmac
import importlib
import json
import os
import re
from pathlib import Path
from typing import Any, Callable

PLUGIN_HOOKS = [
    "recon.post",
    "vuln.post",
    "exploit.pre",
    "network.post",
    "defense.post",
    "quantum.post",
    "alert.fire",
    "session.close",
]
_PLUGIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class PluginManager:
    """Load plugins only when their manifest has a valid HMAC signature.

    Supply a unique signing key of at least 32 characters, or set
    SHADOW313_PLUGIN_SIGNING_KEY. There is intentionally no built-in key.
    """

    def __init__(
        self,
        plugin_dir: str = "shadow313/plugins",
        secret: str | None = None,
    ) -> None:
        configured_secret = secret or os.environ.get("SHADOW313_PLUGIN_SIGNING_KEY", "")
        if len(configured_secret) < 32:
            raise ValueError(
                "Set SHADOW313_PLUGIN_SIGNING_KEY to a unique secret of at least 32 characters"
            )
        self.plugin_dir = Path(plugin_dir).expanduser().resolve()
        self.secret = configured_secret.encode("utf-8")
        self._plugins: dict[str, Any] = {}
        self._hooks: dict[str, list[Callable]] = {hook: [] for hook in PLUGIN_HOOKS}

    def _plugin_path(self, plugin_name: str) -> Path | None:
        if not _PLUGIN_NAME.fullmatch(plugin_name):
            return None
        candidate = (self.plugin_dir / plugin_name).resolve()
        if candidate.parent != self.plugin_dir:
            return None
        return candidate

    def load_all(self) -> int:
        if not self.plugin_dir.is_dir():
            return 0
        count = 0
        for directory in self.plugin_dir.iterdir():
            if directory.is_dir() and (directory / "plugin.json").is_file():
                if self.load(directory.name):
                    count += 1
        return count

    def load(self, plugin_name: str) -> bool:
        plugin_path = self._plugin_path(plugin_name)
        if plugin_path is None:
            return False
        manifest_path = plugin_path / "plugin.json"
        sig_path = plugin_path / "plugin.shadow313sig"
        if not manifest_path.is_file() or not sig_path.is_file():
            return False
        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            signature = sig_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False

        expected = hmac.new(self.secret, manifest_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False

        for hook in manifest.get("hooks", []):
            if hook in self._hooks:
                self._hooks[hook].append(
                    lambda data, name=plugin_name, selected_hook=hook:
                    self._dispatch(name, selected_hook, data)
                )
        self._plugins[plugin_name] = manifest
        return True

    def fire(self, hook: str, data: dict[str, Any]) -> list[Any]:
        """Dispatch each registered hook exactly once and retain falsey results."""
        results = []
        for callback in self._hooks.get(hook, []):
            result = callback(data)
            if result is not None:
                results.append(result)
        return results

    def _dispatch(self, plugin_name: str, hook: str, data: dict) -> dict | None:
        try:
            module = importlib.import_module(
                f"shadow313.plugins.{plugin_name}.analyzer"
            )
            handler = getattr(module, "handle", None)
            if callable(handler):
                return handler(hook, data)
        except Exception:
            # Plugin failures are isolated from the host application.
            return None
        return None

    def sign_plugin(self, plugin_name: str) -> str:
        plugin_path = self._plugin_path(plugin_name)
        if plugin_path is None:
            raise ValueError("Invalid plugin name")
        manifest_path = plugin_path / "plugin.json"
        if not manifest_path.is_file():
            raise FileNotFoundError(manifest_path)
        signature = hmac.new(
            self.secret, manifest_path.read_bytes(), hashlib.sha256
        ).hexdigest()
        (plugin_path / "plugin.shadow313sig").write_text(
            signature, encoding="utf-8"
        )
        return signature

    def list_plugins(self) -> list[dict[str, Any]]:
        return [
            {"name": name, "manifest": manifest}
            for name, manifest in self._plugins.items()
        ]
