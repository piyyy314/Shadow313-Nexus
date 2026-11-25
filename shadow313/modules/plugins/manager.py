"""Canonical plugin registry and lifecycle manager with path-safe installation."""
from __future__ import annotations

import json
import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .manifest import (
    MANIFEST_TEMPLATE,
    PLUGIN_ENTRY_TEMPLATE,
    PLUGIN_NAME_RE,
    VALID_HOOKS,
    PluginManifest,
)
from .signing import PluginArtifactSigner

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_name(name: str) -> bool:
    return bool(PLUGIN_NAME_RE.fullmatch(name)) and name not in {".", ".."}


class PluginRegistry:
    """Manage plugin directories without allowing manifest-controlled path escapes."""

    def __init__(
        self,
        plugins_dir: str = "~/.shadow313/plugins",
        require_signed: bool = True,
        signer: PluginArtifactSigner | None = None,
    ) -> None:
        configured = Path(plugins_dir).expanduser()
        configured.mkdir(parents=True, exist_ok=True)
        self.plugins_dir = configured.resolve()
        self._loaded: dict[str, PluginManifest] = {}
        self._enabled: set[str] = set()
        self.require_signed = require_signed
        self.signer = signer or PluginArtifactSigner()

    def _plugin_dir(self, name: str) -> Path | None:
        if not _safe_name(name):
            return None
        candidate = self.plugins_dir / name
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve()
        if resolved.parent != self.plugins_dir:
            return None
        return resolved

    def discover(self) -> list[PluginManifest]:
        manifests: list[PluginManifest] = []
        for entry in self.plugins_dir.iterdir():
            if entry.is_symlink() or not entry.is_dir():
                continue
            try:
                manifest = PluginManifest(entry)
                if self.require_signed and not self.signer.verify(entry).get("valid"):
                    logger.warning(
                        "Ignoring unsigned or modified plugin %s", entry.name
                    )
                    continue
                errors = manifest.validate()
                if errors:
                    logger.warning(
                        "Ignoring invalid plugin %s: %s",
                        entry.name,
                        "; ".join(errors),
                    )
                    continue
                manifests.append(manifest)
                self._loaded[manifest.name] = manifest
            except (OSError, ValueError, TypeError) as exc:
                logger.warning("Ignoring plugin %s: %s", entry.name, exc)
        return manifests

    def enable(self, name: str) -> bool:
        if name in self._loaded:
            self._enabled.add(name)
            return True
        return False

    def disable(self, name: str) -> bool:
        self._enabled.discard(name)
        return True

    def get_enabled(self) -> list[PluginManifest]:
        return [self._loaded[name] for name in self._enabled if name in self._loaded]

    def get_hooks(self, hook: str) -> list[PluginManifest]:
        return [plugin for plugin in self.get_enabled() if hook in plugin.hooks]

    def install(self, plugin_path: str) -> tuple[bool, str]:
        """Install a validated local plugin without replacing an existing plugin."""
        source = Path(plugin_path).expanduser()
        if not source.is_dir() or source.is_symlink():
            return False, "Plugin source must be an existing, non-symlink directory"
        source = source.resolve()

        try:
            manifest = PluginManifest(source)
        except (OSError, ValueError, TypeError) as exc:
            return False, f"Invalid plugin manifest: {exc}"

        errors = manifest.validate()
        if errors:
            return False, f"Validation errors: {'; '.join(errors)}"

        if self.require_signed and not self.signer.verify(source).get("valid"):
            return False, "Plugin signature is missing or invalid; signing is required"

        for item in source.rglob("*"):
            if item.is_symlink():
                relative_path = item.relative_to(source)
                return False, (
                    "Plugin contains a symlink and cannot be installed: "
                    f"{relative_path}"
                )

        destination = self._plugin_dir(manifest.name)
        if destination is None:
            return False, (
                "Plugin name does not resolve to a safe plugin-local directory"
            )
        if destination.exists():
            return False, (
                f"Plugin '{manifest.name}' already exists; "
                "remove it explicitly before reinstalling"
            )

        try:
            shutil.copytree(source, destination, symlinks=True)
            if any(item.is_symlink() for item in destination.rglob("*")):
                shutil.rmtree(destination)
                return False, (
                    "Plugin copy contains a symlink; installation was rolled back"
                )
            installed = PluginManifest(destination)
            installed_errors = installed.validate()
            if self.require_signed and not self.signer.verify(destination).get("valid"):
                shutil.rmtree(destination)
                return False, "Installed plugin signature verification failed"
            if installed_errors:
                shutil.rmtree(destination)
                return False, (
                    "Installed plugin failed validation: "
                    f"{'; '.join(installed_errors)}"
                )
        except Exception as exc:
            if destination.exists() and destination.parent == self.plugins_dir:
                shutil.rmtree(destination, ignore_errors=True)
            return False, f"Plugin installation failed: {type(exc).__name__}: {exc}"

        self._loaded[installed.name] = installed
        return True, f"Plugin '{installed.name}' installed → {destination}"

    def sign(self, plugin_path: str) -> tuple[bool, str]:
        """Sign the complete validated plugin artifact."""
        source = Path(plugin_path).expanduser()
        try:
            manifest = PluginManifest(source)
        except (OSError, ValueError, TypeError) as exc:
            return False, f"Invalid plugin manifest: {exc}"
        errors = manifest.validate()
        if errors:
            return False, f"Validation errors: {'; '.join(errors)}"
        try:
            result = self.signer.sign(source)
        except (OSError, ValueError, TypeError) as exc:
            return False, f"Plugin signing failed: {exc}"
        return True, f"Plugin '{manifest.name}' signed ({result['algorithm']})"

    def verify(self, plugin_path: str) -> dict[str, Any]:
        """Verify the complete plugin artifact signature."""
        return self.signer.verify(Path(plugin_path).expanduser())

    def is_trusted(self, plugin_path: Path) -> bool:
        """Re-verify signed artifacts immediately before dispatch when required."""
        return not self.require_signed or bool(
            self.signer.verify(plugin_path).get("valid")
        )

    def verify_all(self) -> list[dict[str, Any]]:
        """Verify each installed plugin directory without enabling or executing it."""
        results = []
        for entry in sorted(self.plugins_dir.iterdir()):
            if entry.is_symlink() or not entry.is_dir():
                continue
            results.append(self.signer.verify(entry))
        return results

    def remove(self, name: str) -> tuple[bool, str]:
        """Remove only a validated, direct child directory of the plugin root."""
        self._enabled.discard(name)
        plugin_dir = self._plugin_dir(name)
        if plugin_dir is None:
            return False, "Invalid plugin name or unsafe plugin path"
        if not plugin_dir.is_dir():
            return False, f"Plugin '{name}' not found"
        if plugin_dir.parent != self.plugins_dir:
            return False, "Refusing to remove a path outside the plugin directory"

        shutil.rmtree(plugin_dir)
        self._loaded.pop(name, None)
        return True, f"Plugin '{name}' removed"

    def list_all(self) -> list[dict[str, Any]]:
        self.discover()
        return [
            {**manifest.to_dict(), "enabled": manifest.name in self._enabled}
            for manifest in self._loaded.values()
        ]


class HookDispatcher:
    """Dispatch approved hooks through the sandbox-aware PluginRunner."""

    def __init__(self, registry: PluginRegistry, session_id: str) -> None:
        self.registry = registry
        self.session_id = session_id

    def fire(
        self,
        hook: str,
        module: str,
        module_output: Any = None,
        target: str = "",
    ) -> list[dict]:
        from .runner import PluginRunner

        context = {
            "session_id": self.session_id,
            "hook": hook,
            "module": module,
            "target": target,
            "module_output": module_output,
            "timestamp": _now(),
        }
        results = []
        for plugin in self.registry.get_hooks(hook):
            if not self.registry.is_trusted(plugin.path):
                results.append(
                    {
                        "plugin": plugin.name,
                        "status": "signature_invalid",
                        "reason": (
                            "Plugin artifact signature is missing or no longer valid"
                        ),
                    }
                )
                continue
            results.append(
                PluginRunner(
                    plugin,
                    require_signed=self.registry.require_signed,
                    signer=self.registry.signer,
                ).execute(context)
            )
        return results


class PluginScaffolder:
    """Create new plugin scaffolds without overwriting existing paths."""

    def __init__(self, plugins_dir: str = "~/.shadow313/plugins") -> None:
        self.plugins_dir = Path(plugins_dir).expanduser().resolve()

    def create(self, name: str, hook: str = "recon.post", author: str = "") -> Path:
        if not _safe_name(name):
            raise ValueError("Plugin name must be a simple 1-64 character identifier")
        if hook not in VALID_HOOKS:
            raise ValueError(f"Unsupported plugin hook: {hook}")
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        destination = (self.plugins_dir / name).resolve()
        if destination.parent != self.plugins_dir:
            raise ValueError("Plugin scaffold path escapes the plugin directory")
        if destination.exists():
            raise FileExistsError(f"Plugin scaffold already exists: {destination}")

        destination.mkdir()
        manifest = MANIFEST_TEMPLATE.replace("my-plugin", name)
        if author:
            if len(author) > 128 or any(ord(character) < 32 for character in author):
                raise ValueError(
                    "Plugin author must be at most 128 printable characters"
                )
            manifest = manifest.replace(
                "author: handle",
                f"author: {json.dumps(author)}",
            )
        (destination / "plugin.yaml").write_text(manifest, encoding="utf-8")
        (destination / "plugin.py").write_text(
            PLUGIN_ENTRY_TEMPLATE.format(name=name, hook=hook),
            encoding="utf-8",
        )
        (destination / "README.md").write_text(
            f"# {name}\n\nA Shadow313 plugin.\n\n"
            f"## Hook\n`{hook}`\n\n"
            "## Usage\n```bash\n"
            f"shadow313 plugin --install ./{name}/\n"
            f"shadow313 plugin --enable {name}\n"
            "```\n",
            encoding="utf-8",
        )
        return destination
