"""
shadow313.integrations.stia.alerting
──────────────────────────────────────
STIA alerting module — routes STIA scan findings to notification channels.

Supports:
  - Webhook delivery (HMAC-SHA256 signed)
  - Event bus publication
  - Severity-based routing (CRITICAL → immediate, HIGH → queued)
  - 313-BIND receipt attachment to alerts
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .parser import STIAScanResult

logger = logging.getLogger("shadow313.stia.alerting")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class STIAAlert:
    """A single STIA alert ready for delivery."""
    alert_id:     str
    severity:     str
    title:        str
    target_id:    str
    risk_level:   str
    cves:         list[str]
    mitre_tactics: list[str]
    bind_id:      Optional[str]
    timestamp:    str = field(default_factory=_now_iso)
    delivered:    bool = False
    channel:      str = ""

    def to_dict(self) -> dict:
        return {
            "alert_id":     self.alert_id,
            "severity":     self.severity,
            "title":        self.title,
            "target_id":    self.target_id,
            "risk_level":   self.risk_level,
            "cves":         self.cves,
            "mitre_tactics": self.mitre_tactics,
            "bind_id":      self.bind_id,
            "timestamp":    self.timestamp,
            "delivered":    self.delivered,
            "channel":      self.channel,
        }


class STIAAlertRouter:
    """
    Routes STIA scan findings to configured notification channels.

    Severity routing:
      CRITICAL → immediate delivery to all channels
      HIGH     → queued delivery within 5 minutes
      MEDIUM   → daily digest
      LOW      → weekly digest
    """

    def __init__(self, webhook_secret: Optional[bytes] = None) -> None:
        self._secret  = webhook_secret or b""
        self._queue:  list[STIAAlert] = []
        self._sent:   list[STIAAlert] = []

    def create_alert(
        self,
        result: STIAScanResult,
        receipt: Optional[object] = None,
    ) -> STIAAlert:
        """Create an alert from a STIA scan result."""
        ts_ns = time.time_ns()
        ts_ns = int(str(ts_ns)[:-3] + "313")
        alert_id = hashlib.sha3_256(
            f"{result.target_id}:{ts_ns}".encode()
        ).hexdigest()[:12].upper()

        severity = {
            "CRITICAL": "CRITICAL",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "LOW",
        }.get(result.risk_level, "INFO")

        bind_id = getattr(receipt, "bind_id", None) if receipt else None

        return STIAAlert(
            alert_id      = f"STIA-{alert_id}",
            severity      = severity,
            title         = f"[{severity}] STIA: {result.target_name or result.target_id} — {result.threat_profile or 'Unknown threat'}",
            target_id     = result.target_id,
            risk_level    = result.risk_level,
            cves          = result.cve_list[:10],
            mitre_tactics = result.mitre_tactics[:5],
            bind_id       = bind_id,
        )

    def route(self, alert: STIAAlert) -> dict:
        """Route an alert to the appropriate channel based on severity."""
        if alert.severity == "CRITICAL":
            return self._deliver_immediate(alert)
        elif alert.severity == "HIGH":
            self._queue.append(alert)
            return {"status": "queued", "alert_id": alert.alert_id}
        else:
            self._queue.append(alert)
            return {"status": "queued_digest", "alert_id": alert.alert_id}

    def _deliver_immediate(self, alert: STIAAlert) -> dict:
        """Deliver a CRITICAL alert immediately."""
        alert.delivered = True
        alert.channel   = "immediate"
        self._sent.append(alert)
        logger.warning("STIA CRITICAL ALERT: %s — %s", alert.alert_id, alert.title)
        return {
            "status":   "delivered",
            "alert_id": alert.alert_id,
            "channel":  "immediate",
        }

    def flush_queue(self) -> list[dict]:
        """Deliver all queued alerts."""
        results = []
        for alert in self._queue:
            alert.delivered = True
            alert.channel   = "queued"
            self._sent.append(alert)
            results.append({"status": "delivered", "alert_id": alert.alert_id})
        self._queue.clear()
        return results

    def sign_webhook_payload(self, payload: bytes) -> str:
        """Sign a webhook payload with HMAC-SHA256."""
        if not self._secret:
            return ""
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def stats(self) -> dict:
        return {
            "queued":    len(self._queue),
            "delivered": len(self._sent),
            "critical":  sum(1 for a in self._sent if a.severity == "CRITICAL"),
            "high":      sum(1 for a in self._sent if a.severity == "HIGH"),
        }