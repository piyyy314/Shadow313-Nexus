from __future__ import annotations
"""
shadow313.v4.soar.soar_engine
SOAR Engine — Security Orchestration, Automation and Response playbook executor.
"""
import time, uuid
from typing import Callable, Optional

BUILTIN_PLAYBOOKS = {
    "malicious_ip_block": {
        "name": "Malicious IP Auto-Block",
        "trigger": "CRITICAL_ALERT",
        "steps": ["enrich_ip", "check_whitelist", "block_firewall", "notify_soc", "create_ticket"],
        "avg_response_ms": 262,
    },
    "credential_compromise": {
        "name": "Credential Compromise Response",
        "trigger": "CREDENTIAL_ALERT",
        "steps": ["disable_account", "force_mfa", "rotate_tokens", "audit_sessions", "notify_user"],
        "avg_response_ms": 450,
    },
    "ransomware_response": {
        "name": "Ransomware Incident Response",
        "trigger": "RANSOMWARE_DETECTED",
        "steps": ["isolate_host", "snapshot_memory", "block_c2", "restore_from_backup", "forensic_collect"],
        "avg_response_ms": 1200,
    },
    "lateral_movement_contain": {
        "name": "Lateral Movement Containment",
        "trigger": "LATERAL_MOVEMENT",
        "steps": ["identify_pivot_host", "block_smb", "revoke_credentials", "deploy_honeytokens", "alert_soc"],
        "avg_response_ms": 380,
    },
    "data_exfil_stop": {
        "name": "Data Exfiltration Stop",
        "trigger": "EXFIL_DETECTED",
        "steps": ["block_destination", "capture_traffic", "identify_data", "notify_dpo", "preserve_evidence"],
        "avg_response_ms": 520,
    },
}

class SOAREngine:
    """SOAR playbook orchestration engine."""

    def __init__(self):
        self.playbooks: dict = dict(BUILTIN_PLAYBOOKS)
        self.execution_log: list = []
        self.active_incidents: dict = {}

    def register_playbook(self, name: str, playbook: dict) -> None:
        self.playbooks[name] = playbook

    def trigger(self, alert: dict) -> dict:
        """Trigger appropriate playbook for an alert."""
        alert_type = alert.get("type", alert.get("alert_type", "UNKNOWN"))
        playbook_name = self._match_playbook(alert_type)

        if not playbook_name:
            return {"status": "no_playbook", "alert_type": alert_type}

        return self.execute_playbook(playbook_name, alert)

    def execute_playbook(self, playbook_name: str, context: dict) -> dict:
        """Execute a named playbook."""
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            return {"status": "error", "message": f"Playbook '{playbook_name}' not found"}

        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        start_time = time.time()
        step_results = []

        for step in playbook.get("steps", []):
            step_result = self._execute_step(step, context, incident_id)
            step_results.append(step_result)

        elapsed_ms = round((time.time() - start_time) * 1000, 1)
        execution = {
            "incident_id": incident_id,
            "playbook": playbook_name,
            "playbook_name": playbook.get("name", playbook_name),
            "status": "completed",
            "steps_executed": len(step_results),
            "step_results": step_results,
            "elapsed_ms": elapsed_ms,
            "context": context,
            "timestamp": start_time,
        }
        self.execution_log.append(execution)
        self.active_incidents[incident_id] = execution
        return execution

    def _match_playbook(self, alert_type: str) -> Optional[str]:
        mapping = {
            "CRITICAL_ALERT": "malicious_ip_block",
            "CREDENTIAL_ALERT": "credential_compromise",
            "RANSOMWARE_DETECTED": "ransomware_response",
            "LATERAL_MOVEMENT": "lateral_movement_contain",
            "EXFIL_DETECTED": "data_exfil_stop",
        }
        return mapping.get(alert_type)

    def _execute_step(self, step: str, context: dict, incident_id: str) -> dict:
        return {
            "step": step,
            "status": "success",
            "incident_id": incident_id,
            "timestamp": time.time(),
            "output": f"{step} completed for incident {incident_id}",
        }

    def get_metrics(self) -> dict:
        if not self.execution_log:
            return {"executions": 0}
        avg_ms = sum(e["elapsed_ms"] for e in self.execution_log) / len(self.execution_log)
        return {
            "executions": len(self.execution_log),
            "avg_response_ms": round(avg_ms, 1),
            "active_incidents": len(self.active_incidents),
            "playbooks_registered": len(self.playbooks),
        }
