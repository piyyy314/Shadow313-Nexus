"""shadow313.modules.plugins.plugins_module — PluginManager CLI handler."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

from .manager import PluginRegistry, HookDispatcher, PluginScaffolder


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PluginManager:
    """shadow313.plugins — Plugin lifecycle management."""

    def __init__(self, kernel) -> None:
        self.kernel     = kernel
        cfg             = kernel.config.get("plugins", default={})
        plugins_dir     = cfg.get("dir", "~/.shadow313/plugins")
        self.out        = kernel.out
        self.session    = kernel.session
        self.registry   = PluginRegistry(plugins_dir)
        self.dispatcher = HookDispatcher(self.registry, kernel.session.id)
        self.scaffolder = PluginScaffolder(plugins_dir)
        for name in cfg.get("enabled", []):
            self.registry.discover()
            self.registry.enable(name)

    def register(self, kernel) -> None:
        kernel.register("plugins", self.run)

    def run(self, list_plugins: bool = False,
            install: str = "", enable: str = "", disable: str = "",
            remove: str = "", new: str = "", hook: str = "",
            new_author: str = "") -> dict:
        self.out.section("PLUGIN MANAGER")
        result: dict[str, Any] = {"timestamp": _now()}

        if list_plugins or not any([install, enable, disable, remove, new]):
            plugins = self.registry.list_all()
            result["plugins"] = plugins
            if plugins:
                rows = [[p["name"], p["version"], p["author"],
                         ", ".join(p["hooks"]), "✓" if p["enabled"] else ""]
                        for p in plugins]
                self.out.table(["Name", "Version", "Author", "Hooks", "Enabled"],
                               rows, f"Installed Plugins ({len(plugins)})")
            else:
                self.out.info("No plugins installed. Use: shadow313 plugins --install ./my-plugin/")

        if install:
            ok, msg = self.registry.install(install)
            if ok:
                self.out.success(msg)
                result["installed"] = install
            else:
                self.out.error(msg)

        if enable:
            if self.registry.enable(enable):
                self.out.success(f"Plugin '{enable}' enabled.")
            else:
                self.out.error(f"Plugin '{enable}' not found.")

        if disable:
            self.registry.disable(disable)
            self.out.success(f"Plugin '{disable}' disabled.")

        if remove:
            ok, msg = self.registry.remove(remove)
            if ok:
                self.out.success(msg)
            else:
                self.out.error(msg)

        if new:
            path = self.scaffolder.create(new, hook=hook or "recon.post", author=new_author)
            self.out.success(f"Plugin scaffold created → {path}")
            result["scaffold_path"] = str(path)

        self.session.audit("plugins", "run")
        return result

    def fire_hook(self, hook: str, module: str,
                  output: Any = None, target: str = "") -> list[dict]:
        return self.dispatcher.fire(hook, module, output, target)

    def ai_context(self) -> dict:
        plugins = self.registry.list_all()
        return {
            "module":          "plugins",
            "installed_count": len(plugins),
            "enabled_count":   sum(1 for p in plugins if p.get("enabled")),
        }