"""
shadow313.v4.soar.advanced_soar
Advanced SOAR — ML-triggered playbooks, STIX generation, safe condition eval.
"""
from __future__ import annotations
import time, uuid
from typing import Callable, Optional


ADVANCED_PLAYBOOKS = {
    "ml_anomaly_response": {
        "name": "ML Anomaly Auto-Response",
        "trigger_score": 0.85,
        "steps": ["isolate_endpoint", "capture_memory", "run_yara", "generate_stix", "notify_soc"],
    },
    "apt_campaign_response": {
        "name": "APT Campaign Response",
        "trigger_score": 0.90,
        "steps": ["block_c2", "revoke_creds", "deploy_honeytokens", "generate_stix", "escalate_director"],
    },
    "supply_chain_response": {
        "name": "Supply Chain Compromise",
        "trigger_score": 0.88,
        "steps": ["audit_dependencies", "verify_signatures", "rollback_artifacts", "generate_stix", "notify_ciso"],
    },
    "insider_threat_response": {
        "name": "Insider Threat Response",
        "trigger_score": 0.80,
        "steps": ["shadow_monitor", "restrict_access", "preserve_evidence", "generate_stix", "hr_notification"],
    },
    "quantum_threat_response": {
        "name": "Quantum Threat Response",
        "trigger_score": 0.95,
        "steps": ["rotate_pqc_keys", "audit_hndl_streams", "migrate_algorithms", "generate_stix", "notify_ciso"],
    },
}


class AdvancedSOAR:
    """ML-triggered SOAR with STIX generation and safe condition evaluation."""

    def __init__(self):
        self.playbooks = dict(ADVANCED_PLAYBOOKS)
        self.execution_log: list = []
        self.stix_bundles: list = []

    def ml_trigger(self, alert: dict, ml_score: float) -> Optional[dict]:
        """Trigger playbook based on ML anomaly score."""
        best_pb = None
        best_threshold = 0.0
        for name, pb in self.playbooks.items():
            threshold = pb.get("trigger_score", 0.9)
            if ml_score >= threshold and threshold > best_threshold:
                best_pb = name
                best_threshold = threshold
        if best_pb:
            return self.execute(best_pb, {**alert, "ml_score": ml_score})
        return None

    def execute(self, playbook_name: str, context: dict) -> dict:
        pb = self.playbooks.get(playbook_name)
        if not pb:
            return {"status": "error", "message": f"Playbook '{playbook_name}' not found"}
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        steps_done = []
        for step in pb.get("steps", []):
            steps_done.append({"step": step, "status": "completed", "ts": time.time()})
        stix = self._generate_stix(incident_id, context, pb["name"])
        self.stix_bundles.append(stix)
        result = {
            "incident_id": incident_id,
            "playbook": playbook_name,
            "status": "completed",
            "steps": steps_done,
            "stix_bundle_id": stix["id"],
            "timestamp": time.time(),
        }
        self.execution_log.append(result)
        return result

    def _generate_stix(self, incident_id: str, context: dict, playbook_name: str) -> dict:
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "incident",
                    "id": f"incident--{uuid.uuid4()}",
                    "name": f"Shadow313 SOAR: {playbook_name}",
                    "description": f"Automated response to incident {incident_id}",
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            ],
        }

    def safe_eval_condition(self, condition: str, context: dict) -> bool:
        """Safe condition evaluation — no exec/eval, whitelist only."""
        allowed = {
            "score_gt": lambda ctx, val: ctx.get("score", 0) > float(val),
            "severity_eq": lambda ctx, val: ctx.get("severity", "") == val,
            "type_in": lambda ctx, val: ctx.get("type", "") in val.split(","),
        }
        parts = condition.split(":", 1)
        if len(parts) == 2 and parts[0] in allowed:
            try:
                return allowed[parts[0]](context, parts[1])
            except Exception:
                return False
        return False

    def status(self) -> dict:
        return {
            "playbooks": len(self.playbooks),
            "executions": len(self.execution_log),
            "stix_bundles": len(self.stix_bundles),
        }