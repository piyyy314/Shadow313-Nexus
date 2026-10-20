"""
shadow313.v4.ghost_watch.we_forge
WE-FORGE: Watermarked Evidence Forge — linguistic watermarking + lure generation.
"""
from __future__ import annotations
import hashlib
import secrets
import time
from typing import Optional


class WEForge:
    """Advanced Canary Trap System — generates uniquely watermarked lure documents."""

    WATERMARK_STYLES = ["synonym_swap", "whitespace_inject", "unicode_homoglyph", "metadata_embed"]

    def __init__(self, attribution_db: Optional[dict] = None):
        self.attribution_db: dict = attribution_db or {}
        self.lure_registry: list = []

    def generate_lure(self, template: str, target_id: str, style: str = "synonym_swap") -> dict:
        lure_id = f"GW-LURE_{int(time.time() * 1000)}_{secrets.token_hex(4).upper()}"
        watermark = self._embed_watermark(template, lure_id, style)
        signature = hashlib.sha3_256(watermark.encode()).hexdigest()
        lure = {
            "lure_id": lure_id,
            "target_id": target_id,
            "style": style,
            "content": watermark,
            "signature": signature,
            "created_at": time.time(),
            "triggered": False,
            "trigger_count": 0,
        }
        self.lure_registry.append(lure)
        self.attribution_db[lure_id] = target_id
        return lure

    def _embed_watermark(self, text: str, lure_id: str, style: str) -> str:
        if style == "whitespace_inject":
            return text + f"\u200b{lure_id}\u200b"
        elif style == "unicode_homoglyph":
            return text.replace("a", "\u0430").replace("e", "\u0435") + f"<!-- {lure_id} -->"
        elif style == "metadata_embed":
            return f"<!-- WE-FORGE:{lure_id} -->\n" + text
        else:
            return (
                text.replace("important", "critical").replace("data", "intelligence")
                + f"\n[REF:{lure_id}]"
            )

    def check_trigger(self, lure_id: str) -> dict:
        for lure in self.lure_registry:
            if lure["lure_id"] == lure_id:
                lure["triggered"] = True
                lure["trigger_count"] += 1
                return {"triggered": True, "lure": lure, "target": self.attribution_db.get(lure_id)}
        return {"triggered": False, "lure_id": lure_id}

    def attribute_access(self, signature: str) -> Optional[str]:
        for lure in self.lure_registry:
            if lure["signature"] == signature:
                return self.attribution_db.get(lure["lure_id"])
        return None

    def export_registry(self) -> list:
        return self.lure_registry.copy()

    def purge_lure(self, lure_id: str) -> bool:
        before = len(self.lure_registry)
        self.lure_registry = [l for l in self.lure_registry if l["lure_id"] != lure_id]
        self.attribution_db.pop(lure_id, None)
        return len(self.lure_registry) < before