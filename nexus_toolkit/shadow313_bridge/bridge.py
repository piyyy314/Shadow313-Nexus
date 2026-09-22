"""
nexus_toolkit.shadow313_bridge.bridge
───────────────────────────────────────
Bridge between nexus_toolkit and Shadow313 NEXUS v4.

Routes nexus_toolkit detections to:
  - Shadow313 313-BIND temporal receipts
  - Shadow313 enforcement engine (process termination)
  - Shadow313 ledger (tamper-evident audit trail)
  - Shadow313 event bus
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("nexus_toolkit.bridge")


@dataclass
class BridgeResult:
    """Result of routing a detection through the Shadow313 bridge."""
    detection_id:   str
    bind_id:        Optional[str]
    ledger_seq:     Optional[int]
    enforced:       bool
    enforcement_action: str = ""
    error:          str = ""


class Shadow313Bridge:
    """
    Bridge between nexus_toolkit detections and Shadow313 NEXUS v4.

    Provides:
      - route_detection(): bind detection to 313-BIND receipt
      - enforce(): trigger enforcement engine for critical threats
      - audit(): write to Shadow313 ledger
    """

    def __init__(self) -> None:
        self._temporal_engine = self._load_temporal_engine()
        self._enforcement     = self._load_enforcement()
        self._ledger          = self._load_ledger()

    def _load_temporal_engine(self):
        try:
            from shadow313.v4.temporal_binding.temporal_binding import TemporalBindingEngine
            return TemporalBindingEngine()
        except Exception as exc:
            logger.debug("TemporalBindingEngine unavailable: %s", exc)
            return None

    def _load_enforcement(self):
        try:
            from shadow313.v4.detection.enforcement import EnforcementEngine
            return EnforcementEngine()
        except Exception as exc:
            logger.debug("EnforcementEngine unavailable: %s", exc)
            return None

    def _load_ledger(self):
        try:
            from shadow313.v4.ledger.ledger_engine import LedgerSyncEngine
            return LedgerSyncEngine("nexus-bridge", [])
        except Exception as exc:
            logger.debug("LedgerSyncEngine unavailable: %s", exc)
            return None

    def route_detection(self, detection) -> BridgeResult:
        """
        Route a NexusDetectionEngine result through Shadow313.

        Creates a 313-BIND receipt and writes to the ledger.
        """
        bind_id    = None
        ledger_seq = None
        error      = ""

        payload = {
            "log_id":       detection.log_id,
            "threat_level": detection.threat_level,
            "techniques":   detection.techniques,
            "indicators":   detection.indicators,
            "score":        detection.anomaly_score.score,
        }

        # 313-BIND receipt
        if self._temporal_engine:
            try:
                receipt = self._temporal_engine.bind(payload)
                bind_id = receipt.receipt_id
                detection.bind_id = bind_id
            except Exception as exc:
                logger.warning("313-BIND failed: %s", exc)
                error = str(exc)

        # Ledger entry
        if self._ledger:
            try:
                entry = self._ledger.append(
                    key     = f"detection:{detection.log_id}",
                    payload = payload,
                )
                ledger_seq = entry.sequence
            except Exception as exc:
                logger.debug("Ledger write failed: %s", exc)

        return BridgeResult(
            detection_id = detection.log_id,
            bind_id      = bind_id,
            ledger_seq   = ledger_seq,
            enforced     = False,
            error        = error,
        )

    def enforce(self, detection, pid: Optional[int] = None) -> BridgeResult:
        """
        Trigger enforcement for a critical detection.
        Kills the offending process if PID is provided.
        """
        result = self.route_detection(detection)

        if self._enforcement and pid and detection.threat_level in ("CRITICAL", "HIGH"):
            try:
                kill_result = self._enforcement.terminator.kill_pid(
                    pid, f"nexus_toolkit: {detection.threat_level} threat"
                )
                result.enforced = True
                result.enforcement_action = f"killed PID {pid}: {kill_result.get('status', 'unknown')}"
            except Exception as exc:
                logger.warning("Enforcement failed for PID %s: %s", pid, exc)

        return result

    def status(self) -> dict:
        return {
            "temporal_engine": self._temporal_engine is not None,
            "enforcement":     self._enforcement is not None,
            "ledger":          self._ledger is not None,
        }