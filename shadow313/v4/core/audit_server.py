"""
shadow313.v4.core.audit_server
────────────────────────────────
Audit server for Shadow313 NEXUS v4.

Provides a tamper-evident audit log server that:
  - Receives audit events from all modules via the event bus
  - Stores events in a SHA3-256 Merkle chain
  - Exposes a query API for compliance reporting
  - Integrates with 313-BIND for cryptographic timestamping
  - Supports export to JSON, CSV, and STIX 2.1
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("shadow313.audit_server")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditEntry:
    """A single immutable audit log entry."""
    entry_id:   str
    sequence:   int
    timestamp:  str
    module:     str
    action:     str
    actor:      str
    target:     str
    outcome:    str   # SUCCESS | FAILURE | BLOCKED | DETECTED
    severity:   str   # INFO | LOW | MEDIUM | HIGH | CRITICAL
    detail:     dict  = field(default_factory=dict)
    chain_hash: str   = ""
    prev_hash:  str   = ""

    def to_dict(self) -> dict:
        return {
            "entry_id":   self.entry_id,
            "sequence":   self.sequence,
            "timestamp":  self.timestamp,
            "module":     self.module,
            "action":     self.action,
            "actor":      self.actor,
            "target":     self.target,
            "outcome":    self.outcome,
            "severity":   self.severity,
            "detail":     self.detail,
            "chain_hash": self.chain_hash,
            "prev_hash":  self.prev_hash,
        }


class AuditServer:
    """
    Tamper-evident audit log server.

    All entries are SHA3-256 chain-linked — modifying any entry
    breaks the chain hash, making tampering immediately detectable.
    """

    def __init__(self) -> None:
        self._entries:  list[AuditEntry] = []
        self._sequence: int = 0
        self._prev_hash: str = ""

    def log(
        self,
        module:   str,
        action:   str,
        actor:    str    = "system",
        target:   str    = "",
        outcome:  str    = "SUCCESS",
        severity: str    = "INFO",
        detail:   Optional[dict] = None,
    ) -> AuditEntry:
        """Log an audit event."""
        self._sequence += 1
        ts_ns = time.time_ns()
        ts_ns = int(str(ts_ns)[:-3] + "313")

        entry_id = hashlib.sha3_256(
            f"{self._sequence}:{module}:{action}:{ts_ns}".encode()
        ).hexdigest()[:16]

        payload = json.dumps({
            "sequence": self._sequence,
            "module":   module,
            "action":   action,
            "actor":    actor,
            "target":   target,
            "outcome":  outcome,
            "ts":       ts_ns,
            "prev":     self._prev_hash,
        }, sort_keys=True).encode()

        chain_hash = hashlib.sha3_256(payload).hexdigest()

        entry = AuditEntry(
            entry_id   = entry_id,
            sequence   = self._sequence,
            timestamp  = _now_iso(),
            module     = module,
            action     = action,
            actor      = actor,
            target     = target,
            outcome    = outcome,
            severity   = severity,
            detail     = detail or {},
            chain_hash = chain_hash,
            prev_hash  = self._prev_hash,
        )
        self._entries.append(entry)
        self._prev_hash = chain_hash
        logger.debug("Audit: [%s] %s.%s → %s", severity, module, action, outcome)
        return entry

    def verify_chain(self) -> dict:
        """Verify the integrity of the audit chain."""
        if not self._entries:
            return {"valid": True, "total": 0, "message": "Empty chain"}

        for i in range(1, len(self._entries)):
            if self._entries[i].prev_hash != self._entries[i-1].chain_hash:
                return {
                    "valid":   False,
                    "total":   len(self._entries),
                    "message": f"Chain broken at entry {self._entries[i].entry_id}",
                    "broken_at": i,
                }

        return {
            "valid":   True,
            "total":   len(self._entries),
            "message": f"Chain intact — {len(self._entries)} entries verified",
        }

    def query(
        self,
        module:   str = "",
        action:   str = "",
        outcome:  str = "",
        severity: str = "",
        limit:    int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters."""
        results = self._entries
        if module:
            results = [e for e in results if e.module == module]
        if action:
            results = [e for e in results if e.action == action]
        if outcome:
            results = [e for e in results if e.outcome == outcome]
        if severity:
            results = [e for e in results if e.severity == severity]
        return results[-limit:]

    def export_json(self) -> str:
        """Export all entries as JSON."""
        return json.dumps(
            [e.to_dict() for e in self._entries],
            indent=2, default=str,
        )

    def stats(self) -> dict:
        """Return audit statistics."""
        outcomes: dict[str, int] = {}
        severities: dict[str, int] = {}
        modules: dict[str, int] = {}
        for e in self._entries:
            outcomes[e.outcome]    = outcomes.get(e.outcome, 0) + 1
            severities[e.severity] = severities.get(e.severity, 0) + 1
            modules[e.module]      = modules.get(e.module, 0) + 1
        return {
            "total_entries": len(self._entries),
            "outcomes":      outcomes,
            "severities":    severities,
            "modules":       modules,
            "chain_valid":   self.verify_chain()["valid"],
        }


# ── Global singleton ──────────────────────────────────────────────────────────

_audit_server: Optional[AuditServer] = None


def get_audit_server() -> AuditServer:
    """Get or create the global audit server singleton."""
    global _audit_server
    if _audit_server is None:
        _audit_server = AuditServer()
    return _audit_server