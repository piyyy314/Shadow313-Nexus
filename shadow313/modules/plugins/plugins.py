"""Public plugin manager facade backed by the canonical lifecycle implementation."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .manager import HookDispatcher, PluginRegistry, PluginScaffolder
from .manifest import (
    MANIFEST_TEMPLATE,
    PLUGIN_ENTRY_TEMPLATE,
    VALID_HOOKS,
    PluginManifest,
)
from .runner import PluginRunner

# Backward-compatible name retained for callers of the previous v4 facade.
PluginExecutor = PluginRunner


def _now() -> str:
    return datetime.now(UTC).isoformat()


class PluginManager:
    """Integrate the canonical plugin registry with the NEXUS kernel interface."""

    def __init__(self, kernel: Any) -> None:
        config = kernel.config.get("plugins", default={})
        plugins_dir = config.get("dir", "~/.shadow313/plugins")
        self.out = kernel.out
        self.session = kernel.session
        self.registry = PluginRegistry(
            plugins_dir,
            require_signed=bool(config.get("require_signed", False)),
        )
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
        sign: str = "",
        verify: str = "",
        verify_all: bool = False,
    ) -> dict:
        self.out.section("PLUGIN MANAGER")
        result: dict[str, Any] = {"timestamp": _now()}

        if list_plugins or not any(
            (install, enable, disable, remove, new, sign, verify, verify_all)
        ):
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

        if sign:
            ok, message = self.registry.sign(sign)
            self.out.success(message) if ok else self.out.error(message)
            if ok:
                result["signed"] = sign

        if verify:
            verification = self.registry.verify(verify)
            result["verification"] = verification
            if verification.get("valid"):
                self.out.success("Plugin artifact signature verified.")
            else:
                self.out.error(
                    verification.get("reason", "Plugin artifact signature invalid")
                )

        if verify_all:
            verifications = self.registry.verify_all()
            result["verifications"] = verifications
            for verification in verifications:
                if verification.get("valid"):
                    self.out.success(
                        "Verified plugin artifact: "
                        f"{verification.get('plugin', 'unknown')}"
                    )
                else:
                    self.out.error(
                        verification.get("reason", "Plugin artifact signature invalid")
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
