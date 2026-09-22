"""
shadow313.integrations.stia
────────────────────────────
STIA (Satellite Threat Intelligence & Analysis) integration.

Parses STIA scan results and binds them with 313 Temporal Binding receipts.

Public API:
    from shadow313.integrations.stia import STIABinder, STIAParser, STIAScanResult
"""
from .parser import STIAParser, STIAScanResult
from .binder import STIABinder

__all__ = ["STIABinder", "STIAParser", "STIAScanResult"]