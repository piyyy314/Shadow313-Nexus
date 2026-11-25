"""Shadow313 NEXUS SOAR playbook engine.

This module orchestrates explicitly registered response adapters. It never
claims that a containment action occurred merely because a playbook ran.
"""
from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from enum import Enum
from collections.abc import Callable
from typing import Any


class PlaybookAction(Enum):
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    QUARANTINE_HOST = "quarantine_host"
    ROTATE_CREDS = "rotate_credentials"
    ALERT_TELEGRAM = "alert_telegram"
    CREATE_TICKET = "create_ticket"
    SNAPSHOT_HOST = "snapshot_host"
    REVERT_HOST = "revert_host"
    EXPORT_SIGMA = "export_sigma"
    EXPORT_STIX = "export_stix"
    GENERATE_RECEIPT = "generate_313_receipt"
    BGP_BLACKHOLE = "bgp_blackhole"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    ISOLATE_NETWORK = "isolate_network"
    COLLECT_FORENSICS = "collect_forensics"


PLAYBOOKS = {
    "malicious_ip": {
        "name": "Malicious IP Auto-Block",
        "trigger": {"type": "alert", "severity": ["CRITICAL", "HIGH"]},
        "actions": [
            PlaybookAction.BLOCK_IP,
            PlaybookAction.GENERATE_RECEIPT,
            PlaybookAction.ALERT_TELEGRAM,
        ],
        "mitre_mitigations": ["M1037"],
    },
    "credential_dump": {
        "name": "Credential Dump Response",
        "trigger": {"type": "technique", "id": "T1003"},
        "actions": [
            PlaybookAction.ROTATE_CREDS,
            PlaybookAction.QUARANTINE_HOST,
            PlaybookAction.COLLECT_FORENSICS,
            PlaybookAction.GENERATE_RECEIPT,
        ],
        "mitre_mitigations": ["M1027", "M1026"],
    },
    "ransomware": {
        "name": "Ransomware Containment",
        "trigger": {"type": "technique", "id": "T1486"},
        "actions": [
            PlaybookAction.ISOLATE_NETWORK,
            PlaybookAction.SNAPSHOT_HOST,
            PlaybookAction.COLLECT_FORENSICS,
            PlaybookAction.ALERT_TELEGRAM,
            PlaybookAction.GENERATE_RECEIPT,
        ],
        "mitre_mitigations": ["M1053", "M1040"],
    },
    "c2_beacon": {
        "name": "C2 Beacon Disruption",
        "trigger": {"type": "technique", "id": "T1071"},
        "actions": [
            PlaybookAction.BLOCK_IP,
            PlaybookAction.BGP_BLACKHOLE,
            PlaybookAction.DEPLOY_HONEYPOT,
            PlaybookAction.GENERATE_RECEIPT,
        ],
        "mitre_mitigations": ["M1031", "M1037"],
    },
    "lateral_movement": {
        "name": "Lateral Movement Containment",
        "trigger": {"type": "technique", "id": "T1021"},
        "actions": [
            PlaybookAction.ISOLATE_NETWORK,
            PlaybookAction.KILL_PROCESS,
            PlaybookAction.COLLECT_FORENSICS,
        ],
        "mitre_mitigations": ["M1035", "M1030"],
    },
}


Adapter = Callable[[dict[str, Any]], dict[str, Any]]


class SOAREngine:
    """SOAR orchestration with fail-closed, explicitly registered adapters.

    Dry-run mode is the default. In live mode, an action is only reported as
    completed when its registered adapter returns status="completed".
    """

    def __init__(
        self,
        dry_run: bool = True,
        adapters: dict[PlaybookAction | str, Adapter] | None = None,
    ) -> None:
        self.dry_run = dry_run
        self._log: list[dict[str, Any]] = []
        self._adapters: dict[PlaybookAction, Adapter] = {}
        self._handlers: dict[PlaybookAction, Callable[[dict[str, Any]], dict[str, Any]]] = {}
        for action, adapter in (adapters or {}).items():
            self.register_adapter(action, adapter)
        self._register_handlers()

    def register_adapter(self, action: PlaybookAction | str, adapter: Adapter) -> None:
        """Register a trusted integration adapter for one response action."""
        if isinstance(action, str):
            action = PlaybookAction(action)
        if not isinstance(action, PlaybookAction):
            raise TypeError("action must be a PlaybookAction or valid action value")
        if not callable(adapter):
            raise TypeError("adapter must be callable")
        self._adapters[action] = adapter

    def _register_handlers(self) -> None:
        for action in PlaybookAction:
            self._handlers[action] = (
                lambda alert, selected=action: self._execute_action(selected, alert)
            )

    def _execute_action(self, action: PlaybookAction, alert: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return {
                "action": action.value,
                "status": "simulated",
                "reason": "dry_run_enabled; no external operation was attempted",
            }

        adapter = self._adapters.get(action)
        if adapter is None:
            return {
                "action": action.value,
                "status": "not_configured",
                "reason": "No trusted adapter is registered for this action",
            }

        result = adapter(dict(alert))
        if not isinstance(result, dict):
            return {
                "action": action.value,
                "status": "failed",
                "reason": "Adapter returned a non-dictionary result",
            }

        adapter_status = str(result.get("status", "")).lower()
        if adapter_status != "completed":
            return {
                **result,
                "action": action.value,
                "status": adapter_status
                if adapter_status in {"failed", "not_configured", "pending"}
                else "failed",
                "reason": result.get(
                    "reason",
                    "Adapter did not explicitly confirm completed",
                ),
            }

        return {**result, "action": action.value, "status": "completed"}

    def trigger(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Run the matching playbook and preserve each action's truthful status."""
        started = time.monotonic()
        playbook_id = self._match_playbook(alert)
        if not playbook_id:
            return {"triggered": False, "status": "not_matched", "reason": "No matching playbook"}

        playbook = PLAYBOOKS[playbook_id]
        results = []
        for action in playbook["actions"]:
            handler = self._handlers.get(action)
            if handler is None:
                result = {
                    "action": action.value,
                    "status": "not_configured",
                    "reason": "No action handler is registered",
                }
            else:
                try:
                    result = handler(alert)
                except Exception as exc:
                    result = {
                        "action": action.value,
                        "status": "failed",
                        "reason": f"Adapter execution failed: {type(exc).__name__}",
                    }
            results.append(result)

        statuses = [item["status"] for item in results]
        if statuses and all(status == "completed" for status in statuses):
            overall_status = "completed"
        elif statuses and all(status == "simulated" for status in statuses):
            overall_status = "simulated"
        elif statuses and all(status == "not_configured" for status in statuses):
            overall_status = "not_configured"
        elif any(status == "completed" for status in statuses):
            overall_status = "partial"
        elif any(status == "failed" for status in statuses):
            overall_status = "failed"
        else:
            overall_status = "partial"

        entry = {
            "id": str(uuid.uuid4())[:8],
            "playbook": playbook["name"],
            "alert": dict(alert),
            "actions": results,
            "status": overall_status,
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
            "timestamp": datetime.now(UTC).isoformat(),
            "dry_run": self.dry_run,
        }
        self._log.append(entry)
        return entry

    def _match_playbook(self, alert: dict[str, Any]) -> str | None:
        technique = str(alert.get("technique_id", "")).upper()
        severity = str(alert.get("severity", "")).upper()
        for playbook_id, playbook in PLAYBOOKS.items():
            trigger = playbook["trigger"]
            if trigger["type"] == "technique" and technique.startswith(trigger["id"]):
                return playbook_id
            if trigger["type"] == "alert" and severity in trigger.get("severity", []):
                return playbook_id
        return None

    def get_log(self) -> list[dict[str, Any]]:
        """Return a copy of the execution log."""
        return [
            dict(entry, actions=[dict(action) for action in entry["actions"]])
            for entry in self._log
        ]

    def get_stats(self) -> dict[str, Any]:
        if not self._log:
            return {"total": 0, "avg_duration_ms": 0}
        durations = [entry["duration_ms"] for entry in self._log]
        return {
            "total": len(self._log),
            "avg_duration_ms": round(sum(durations) / len(durations), 1),
            "min_duration_ms": min(durations),
            "max_duration_ms": max(durations),
            "playbooks_fired": sorted({entry["playbook"] for entry in self._log}),
            "status_counts": {
                status: sum(entry["status"] == status for entry in self._log)
                for status in sorted({entry["status"] for entry in self._log})
            },
        }
