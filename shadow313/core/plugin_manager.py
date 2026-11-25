"""Legacy plugin metadata loader with execution disabled.

Use shadow313.modules.plugins.PluginManager for sandboxed plugin execution.
This compatibility loader only discovers and verifies signed metadata.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shadow313.modules.plugins.signing import PluginArtifactSigner

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
    """Discover signed legacy plugin metadata without importing plugin code."""

    def __init__(
        self,
        plugin_dir: str = "shadow313/plugins",
        signer: PluginArtifactSigner | None = None,
    ) -> None:
        self.plugin_dir = Path(plugin_dir).expanduser()
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        self.plugin_dir = self.plugin_dir.resolve()
        self.signer = signer or PluginArtifactSigner()
        self._plugins: dict[str, Any] = {}
        self._hooks: dict[str, list[str]] = {hook: [] for hook in PLUGIN_HOOKS}

    def _plugin_path(self, plugin_name: str) -> Path | None:
        if not _PLUGIN_NAME.fullmatch(plugin_name):
            return None
        candidate = self.plugin_dir / plugin_name
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve()
        if resolved.parent != self.plugin_dir:
            return None
        return resolved

    def load_all(self) -> int:
        """Load metadata only for signed, valid plugin directories."""
        count = 0
        for directory in self.plugin_dir.iterdir():
            if directory.is_symlink() or not directory.is_dir():
                continue
            if self.load(directory.name):
                count += 1
        return count

    def load(self, plugin_name: str) -> bool:
        """Verify the complete artifact and load its metadata; never import code."""
        if plugin_name in self._plugins:
            return True
        plugin_path = self._plugin_path(plugin_name)
        if plugin_path is None:
            return False
        manifest_path = plugin_path / "plugin.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            return False

        verification = self.signer.verify(plugin_path)
        if not verification.get("valid"):
            return False

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False
        if not isinstance(manifest, dict):
            return False

        hooks = manifest.get("hooks", [])
        if not isinstance(hooks, list) or any(
            not isinstance(hook, str) or hook not in self._hooks
            for hook in hooks
        ):
            return False

        for hook in hooks:
            if plugin_name not in self._hooks[hook]:
                self._hooks[hook].append(plugin_name)
        self._plugins[plugin_name] = manifest
        return True

    def fire(self, hook: str, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Return explicit disabled statuses; never import legacy plugin code."""
        if hook not in self._hooks:
            return []
        return [
            self._dispatch(plugin_name, hook, data)
            for plugin_name in self._hooks[hook]
        ]

    def _dispatch(
        self,
        plugin_name: str,
        hook: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "plugin": plugin_name,
            "hook": hook,
            "status": "sandbox_unavailable",
            "reason": (
                "Legacy in-process plugin execution is disabled. "
                "Use the canonical sandboxed plugin runner."
            ),
        }

    def sign_plugin(self, plugin_name: str) -> str:
        """Sign the complete plugin artifact, not only plugin.json."""
        plugin_path = self._plugin_path(plugin_name)
        if plugin_path is None:
            raise ValueError("Invalid plugin name")
        manifest_path = plugin_path / "plugin.json"
        if not manifest_path.is_file():
            raise FileNotFoundError(manifest_path)
        return str(self.signer.sign(plugin_path)["signature"])

    def list_plugins(self) -> list[dict[str, Any]]:
        return [
            {"name": name, "manifest": manifest}
            for name, manifest in self._plugins.items()
        ]
