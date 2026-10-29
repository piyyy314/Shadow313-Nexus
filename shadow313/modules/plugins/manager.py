"""shadow313.modules.plugins.manager — Plugin registry and lifecycle manager."""
from __future__ import annotations
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .manifest import PluginManifest, MANIFEST_TEMPLATE, PLUGIN_ENTRY_TEMPLATE


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PluginRegistry:
    def __init__(self, plugins_dir: str = "~/.shadow313/plugins") -> None:
        self.plugins_dir = Path(plugins_dir).expanduser()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self._loaded: dict[str, PluginManifest] = {}
        self._enabled: set[str] = set()

    def discover(self) -> list[PluginManifest]:
        manifests = []
        for entry in self.plugins_dir.iterdir():
            if entry.is_dir():
                try:
                    m = PluginManifest(entry)
                    manifests.append(m)
                    self._loaded[m.name] = m
                except Exception:
                    pass
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
        return [self._loaded[n] for n in self._enabled if n in self._loaded]

    def get_hooks(self, hook: str) -> list[PluginManifest]:
        return [p for p in self.get_enabled() if hook in p.hooks]

    def install(self, plugin_path: str) -> tuple[bool, str]:
        src = Path(plugin_path).expanduser()
        if not src.is_dir():
            return False, f"Plugin directory not found: {src}"
        try:
            m = PluginManifest(src)
        except Exception as exc:
            return False, f"Invalid plugin manifest: {exc}"
        errors = m.validate()
        if errors:
            return False, f"Validation errors: {'; '.join(errors)}"
        dest = self.plugins_dir / m.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(str(src), str(dest))
        m2 = PluginManifest(dest)
        self._loaded[m2.name] = m2
        return True, f"Plugin '{m2.name}' installed → {dest}"

    def remove(self, name: str) -> tuple[bool, str]:
        self._enabled.discard(name)
        plugin_dir = self.plugins_dir / name
        if plugin_dir.exists():
            shutil.rmtree(plugin_dir)
            self._loaded.pop(name, None)
            return True, f"Plugin '{name}' removed"
        return False, f"Plugin '{name}' not found"

    def list_all(self) -> list[dict]:
        self.discover()
        return [{**m.to_dict(), "enabled": m.name in self._enabled}
                for m in self._loaded.values()]


class HookDispatcher:
    def __init__(self, registry: PluginRegistry, session_id: str) -> None:
        self.registry   = registry
        self.session_id = session_id

    def fire(self, hook: str, module: str,
             module_output: Any = None, target: str = "") -> list[dict]:
        from .runner import PluginRunner
        plugins = self.registry.get_hooks(hook)
        if not plugins:
            return []
        results = []
        ctx = {
            "session_id":    self.session_id,
            "hook":          hook,
            "module":        module,
            "target":        target,
            "module_output": module_output,
            "timestamp":     _now(),
        }
        for plugin in plugins:
            result = PluginRunner(plugin).execute(ctx)
            results.append(result)
        return results


class PluginScaffolder:
    def __init__(self, plugins_dir: str = "~/.shadow313/plugins") -> None:
        self.plugins_dir = Path(plugins_dir).expanduser()

    def create(self, name: str, hook: str = "recon.post", author: str = "") -> Path:
        dest = self.plugins_dir / name
        dest.mkdir(parents=True, exist_ok=True)
        manifest = MANIFEST_TEMPLATE.replace("my-plugin", name)
        if author:
            manifest = manifest.replace("author: handle", f"author: {author}")
        (dest / "plugin.yaml").write_text(manifest)
        (dest / "plugin.py").write_text(PLUGIN_ENTRY_TEMPLATE.format(name=name, hook=hook))
        (dest / "README.md").write_text(
            f"# {name}\n\nA Shadow313 plugin.\n\n"
            f"## Hook\n`{hook}`\n\n"
            "## Usage\n```bash\n"
            f"shadow313 plugins --install ./{name}/\n"
            f"shadow313 plugins --enable {name}\n```\n"
        )
        return dest