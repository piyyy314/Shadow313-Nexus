"""Compatibility import for the canonical Shadow313 plugin manager."""
from __future__ import annotations

from typing import Any

from .plugins import PluginManager as CanonicalPluginManager


class PluginManager(CanonicalPluginManager):
    """Preserve the historical module path without duplicating plugin logic."""

    def ai_context(self) -> dict[str, Any]:
        plugins = self.registry.list_all()
        return {
            "module": "plugins",
            "installed_count": len(plugins),
            "enabled_count": sum(
                1 for plugin in plugins if plugin.get("enabled")
            ),
        }
