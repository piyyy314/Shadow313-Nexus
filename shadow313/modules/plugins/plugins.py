"""Public plugin manager facade backed by the canonical lifecycle implementation."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .manager import HookDispatcher, PluginRegistry, PluginScaffolder


def _now() -> str:
    return datetime.now(UTC).isoformat()


class PluginManager:
    """Integrate the canonical plugin registry with the NEXUS kernel interface."""

    def __init__(self, kernel: Any) -> None:
        config = kernel.config.get("plugins", default={})
        plugins_dir = config.get("dir", "~/.shadow313/plugins")
        self.out = kernel.out
        self.session = kernel.session
        self.registry = PluginRegistry(plugins_dir)
        self.dispatcher = HookDispatcher(self.registry, kernel.session.id)
        self.scaffolder = PluginScaffolder(plugins_dir)

        self.registry.discover()
        for name in config.get("enabled", []):
            self.registry.enable(name)

    def register(self, kernel: Any) -> None:
        kernel.register("plugins", self.run)

    def run(
        self,
        list_plugins: bool = False,
        install: str = "",
        enable: str = "",
        disable: str = "",
        remove: str = "",
        new: str = "",
        hook: str = "",
        new_author: str = "",
    ) -> dict:
        self.out.section("PLUGIN MANAGER")
        result: dict[str, Any] = {"timestamp": _now()}

        if list_plugins or not any((install, enable, disable, remove, new)):
            plugins = self.registry.list_all()
            result["plugins"] = plugins
            if plugins:
                rows = [
                    [
                        plugin["name"],
                        plugin["version"],
                        plugin["author"],
                        ", ".join(plugin["hooks"]),
                        "✓" if plugin["enabled"] else "",
                    ]
                    for plugin in plugins
                ]
                self.out.table(
                    ["Name", "Version", "Author", "Hooks", "Enabled"],
                    rows,
                    f"Installed Plugins ({len(plugins)})",
                )
            else:
                self.out.info(
                    "No plugins installed. Use: shadow313 plugin --install ./my-plugin/"
                )

        if install:
            ok, message = self.registry.install(install)
            self.out.success(message) if ok else self.out.error(message)
            if ok:
                result["installed"] = install

        if enable:
            if self.registry.enable(enable):
                self.out.success(f"Plugin '{enable}' enabled.")
            else:
                self.out.error(f"Plugin '{enable}' not found.")

        if disable:
            self.registry.disable(disable)
            self.out.success(f"Plugin '{disable}' disabled.")

        if remove:
            ok, message = self.registry.remove(remove)
            self.out.success(message) if ok else self.out.error(message)

        if new:
            path = self.scaffolder.create(
                new,
                hook=hook or "recon.post",
                author=new_author,
            )
            self.out.success(f"Plugin scaffold created → {path}")
            result["scaffold_path"] = str(path)

        self.session.audit("plugins", "run")
        return result

    def fire_hook(
        self,
        hook: str,
        module: str,
        output: Any = None,
        target: str = "",
    ) -> list[dict]:
        return self.dispatcher.fire(hook, module, output, target)
