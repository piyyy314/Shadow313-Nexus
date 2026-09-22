"""
shadow313.core.binding_sdk.registry
─────────────────────────────────────
Registry of all VANGUARD-313 apps that use the 313 Temporal Binding protocol.

Every app in the ecosystem is registered here with its identity.
This enables cross-app receipt verification — you can verify a receipt
from Ghost-Watch using the Shadow313 CLI, or vice versa.
"""
from __future__ import annotations

from .binder import AppIdentity, Binder313

# ── Registered Apps ───────────────────────────────────────────────────────────

REGISTERED_APPS: dict[str, AppIdentity] = {
    "shadow313": AppIdentity(
        app_id="shadow313",
        app_name="Shadow313 CLI",
        version="3.0.0",
        prefix="S313",
    ),
    "aegis-pqc": AppIdentity(
        app_id="aegis-pqc",
        app_name="Aegis PQC Audit",
        version="2.4",
        prefix="AEGIS",
    ),
    "ghost-watch": AppIdentity(
        app_id="ghost-watch",
        app_name="Ghost-Watch C2 Terminal",
        version="4.5.0",
        prefix="GHOST",
    ),
    "aegis-nexus-vsat": AppIdentity(
        app_id="aegis-nexus-vsat",
        app_name="Aegis Nexus VSAT",
        version="5.0",
        prefix="VSAT",
    ),
    "sovereign-shield": AppIdentity(
        app_id="sovereign-shield",
        app_name="Sovereign-Shield PQC",
        version="1.0.0",
        prefix="SOVR",
    ),
    "oncosim": AppIdentity(
        app_id="oncosim",
        app_name="OncoSim Bio-Nexus",
        version="2.8",
        prefix="ONCO",
    ),
    "aegisfortress": AppIdentity(
        app_id="aegisfortress",
        app_name="AegisFortress OmniSec",
        version="1.0.0",
        prefix="FORT",
    ),
    "nexus-engine": AppIdentity(
        app_id="nexus-engine",
        app_name="NEXUS Detection Engine",
        version="1.0.0",
        prefix="NEXUS",
    ),
    "acts": AppIdentity(
        app_id="acts",
        app_name="ACTS Canary Trap System",
        version="1.0.0",
        prefix="ACTS",
    ),
    "quantum-advanced-cli": AppIdentity(
        app_id="quantum-advanced-cli",
        app_name="Shadow313 Advanced CLI (QTE)",
        version="2.0.0",
        prefix="QTE",
    ),
}


class AppRegistry:
    """
    Registry for creating pre-configured Binder313 instances
    for any registered VANGUARD-313 app.
    """

    @staticmethod
    def get_binder(app_id: str, **kwargs) -> Binder313:
        """
        Get a Binder313 instance for a registered app.

        Args:
            app_id: One of the registered app IDs
            **kwargs: Additional args passed to Binder313

        Returns:
            Configured Binder313 instance

        Raises:
            KeyError: If app_id is not registered
        """
        if app_id not in REGISTERED_APPS:
            raise KeyError(
                f"App '{app_id}' not registered. "
                f"Available: {list(REGISTERED_APPS.keys())}"
            )
        identity = REGISTERED_APPS[app_id]
        return Binder313(identity=identity, **kwargs)

    @staticmethod
    def register(identity: AppIdentity) -> None:
        """Register a new app in the ecosystem."""
        REGISTERED_APPS[identity.app_id] = identity

    @staticmethod
    def list_apps() -> list[dict]:
        """List all registered apps."""
        return [
            {
                "app_id": a.app_id,
                "app_name": a.app_name,
                "version": a.version,
                "prefix": a.prefix,
                "bind_id_format": f"313-{a.prefix}-XXXXXXXX",
            }
            for a in REGISTERED_APPS.values()
        ]