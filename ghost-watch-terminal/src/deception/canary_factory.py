"""
Ghost-Watch Terminal — Canary Factory
=======================================
WE-FORGE lure generation and ACTS canary trap management.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from ghost_watch_terminal.src.core.engine import ACTSEngine, PQCLayer, LureDocument
from typing import Optional

__all__ = ["CanaryFactory"]


class CanaryFactory:
    """
    High-level canary factory wrapping ACTSEngine.
    Generates uniquely watermarked lure documents for attribution.
    """

    def __init__(self) -> None:
        self._pqc  = PQCLayer()
        self._acts = ACTSEngine(self._pqc)

    def create_lure(self, target: str, template: str = "NIST FIPS 213 (ML-KEM-768) Secret Parameter Set") -> LureDocument:
        return self._acts.forge_lure(target, template)

    def check_trigger(self, content: str) -> Optional[LureDocument]:
        return self._acts.detect_trigger(content)

    def attribute(self, watermark_id: str) -> Optional[str]:
        return self._acts.attribution_lookup(watermark_id)

    def list_lures(self) -> list[dict]:
        return [
            {"lure_id": l.lure_id, "target": l.target,
             "triggered": l.triggered, "deployed_at": l.deployed_at}
            for l in self._acts._lures.values()
        ]