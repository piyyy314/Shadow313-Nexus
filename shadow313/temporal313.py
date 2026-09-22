"""
shadow313.temporal313 — v1 compatibility shim
Redirects to shadow313.v4.temporal_binding.temporal_binding
"""
from shadow313.v4.temporal_binding.temporal_binding import (
    TemporalBindingEngine as Temporal313Protocol,
    Bind313Receipt,
)
__all__ = ["Temporal313Protocol", "Bind313Receipt"]
