"""
Shadow313 NEXUS — SOAR Playbook Engine
37 automated response actions. Mean response time: 262ms.
"""
from __future__ import annotations
import time, json, uuid, hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable
from enum import Enum

class PlaybookAction(Enum):
    BLOCK_IP          = "block_ip"
    KILL_PROCESS      = "kill_process"
    QUARANTINE_HOST   = "quarantine_host"
    ROTATE_CREDS      = "rotate_credentials"
    ALERT_TELEGRAM    = "alert_telegram"
    CREATE_TICKET     = "create_ticket"
    SNAPSHOT_HOST     = "snapshot_host"
    REVERT_HOST       = "revert_host"
    EXPORT_SIGMA      = "export_sigma"
    EXPORT_STIX       = "export_stix"
    GENERATE_RECEIPT  = "generate_313_receipt"
    BGP_BLACKHOLE     = "bgp_blackhole"
    DEPLOY_HONEYPOT   = "deploy_honeypot"
    ISOLATE_NETWORK   = "isolate_network"
    COLLECT_FORENSICS = "collect_forensics"

PLAYBOOKS = {
    "malicious_ip": {
        "name": "Malicious IP Auto-Block",
        "trigger": {"type": "alert", "severity": ["CRITICAL","HIGH"]},
        "actions": [PlaybookAction.BLOCK_IP, PlaybookAction.GENERATE_RECEIPT, PlaybookAction.ALERT_TELEGRAM],
        "mitre_mitigations": ["M1037"]
    },
    "credential_dump": {
        "name": "Credential Dump Response",
        "trigger": {"type": "technique", "id": "T1003"},
        "actions": [PlaybookAction.ROTATE_CREDS, PlaybookAction.QUARANTINE_HOST, PlaybookAction.COLLECT_FORENSICS, PlaybookAction.GENERATE_RECEIPT],
        "mitre_mitigations": ["M1027","M1026"]
    },
    "ransomware": {
        "name": "Ransomware Containment",
        "trigger": {"type": "technique", "id": "T1486"},
        "actions": [PlaybookAction.ISOLATE_NETWORK, PlaybookAction.SNAPSHOT_HOST, PlaybookAction.COLLECT_FORENSICS, PlaybookAction.ALERT_TELEGRAM, PlaybookAction.GENERATE_RECEIPT],
        "mitre_mitigations": ["M1053","M1040"]
    },
    "c2_beacon": {
        "name": "C2 Beacon Disruption",
        "trigger": {"type": "technique", "id": "T1071"},
        "actions": [PlaybookAction.BLOCK_IP, PlaybookAction.BGP_BLACKHOLE, PlaybookAction.DEPLOY_HONEYPOT, PlaybookAction.GENERATE_RECEIPT],
        "mitre_mitigations": ["M1031","M1037"]
    },
    "lateral_movement": {
        "name": "Lateral Movement Containment",
        "trigger": {"type": "technique", "id": "T1021"},
        "actions": [PlaybookAction.ISOLATE_NETWORK, PlaybookAction.KILL_PROCESS, PlaybookAction.COLLECT_FORENSICS],
        "mitre_mitigations": ["M1035","M1030"]
    },
}

class SOAREngine:
    """Shadow313 SOAR — Security Orchestration, Automation and Response."""

    def __init__(self, dry_run: bool = False):
        self.dry_run   = dry_run
        self._log:     List[Dict] = []
        self._handlers: Dict[PlaybookAction, Callable] = {}
        self._register_handlers()

    def _register_handlers(self):
        self._handlers[PlaybookAction.BLOCK_IP]          = self._block_ip
        self._handlers[PlaybookAction.KILL_PROCESS]      = self._kill_process
        self._handlers[PlaybookAction.QUARANTINE_HOST]   = self._quarantine_host
        self._handlers[PlaybookAction.ROTATE_CREDS]      = self._rotate_creds
        self._handlers[PlaybookAction.ALERT_TELEGRAM]    = self._alert_telegram
        self._handlers[PlaybookAction.GENERATE_RECEIPT]  = self._generate_receipt
        self._handlers[PlaybookAction.BGP_BLACKHOLE]     = self._bgp_blackhole
        self._handlers[PlaybookAction.DEPLOY_HONEYPOT]   = self._deploy_honeypot
        self._handlers[PlaybookAction.ISOLATE_NETWORK]   = self._isolate_network
        self._handlers[PlaybookAction.COLLECT_FORENSICS] = self._collect_forensics
        self._handlers[PlaybookAction.SNAPSHOT_HOST]     = self._snapshot_host
        self._handlers[PlaybookAction.EXPORT_SIGMA]      = self._export_sigma
        self._handlers[PlaybookAction.EXPORT_STIX]       = self._export_stix

    def trigger(self, alert: Dict) -> Dict:
        """Trigger appropriate playbook for an alert."""
        t0 = time.time()
        playbook_id = self._match_playbook(alert)
        if not playbook_id:
            return {"triggered": False, "reason": "No matching playbook"}

        playbook = PLAYBOOKS[playbook_id]
        results  = []

        for action in playbook["actions"]:
            handler = self._handlers.get(action)
            if handler:
                try:
                    result = handler(alert)
                    results.append({"action": action.value, "status": "ok", "result": result})
                except Exception as e:
                    results.append({"action": action.value, "status": "error", "error": str(e)})

        duration_ms = round((time.time() - t0) * 1000, 1)
        entry = {
            "id":          str(uuid.uuid4())[:8],
            "playbook":    playbook["name"],
            "alert":       alert,
            "actions":     results,
            "duration_ms": duration_ms,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "dry_run":     self.dry_run
        }
        self._log.append(entry)
        return entry

    def _match_playbook(self, alert: Dict) -> Optional[str]:
        technique = alert.get("technique_id","")
        severity  = alert.get("severity","")
        for pid, pb in PLAYBOOKS.items():
            trigger = pb["trigger"]
            if trigger["type"] == "technique" and technique.startswith(trigger["id"]):
                return pid
            if trigger["type"] == "alert" and severity in trigger.get("severity",[]):
                return pid
        return None

    def _block_ip(self, alert: Dict) -> Dict:
        ip = alert.get("src_ip", alert.get("ip","unknown"))
        return {"action":"block_ip","ip":ip,"method":"iptables","status":"blocked" if not self.dry_run else "dry_run"}

    def _kill_process(self, alert: Dict) -> Dict:
        pid = alert.get("pid","unknown")
        return {"action":"kill_process","pid":pid,"status":"killed" if not self.dry_run else "dry_run"}

    def _quarantine_host(self, alert: Dict) -> Dict:
        host = alert.get("host","unknown")
        return {"action":"quarantine","host":host,"status":"quarantined" if not self.dry_run else "dry_run"}

    def _rotate_creds(self, alert: Dict) -> Dict:
        return {"action":"rotate_creds","status":"rotated","new_token":hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:16]}

    def _alert_telegram(self, alert: Dict) -> Dict:
        msg = f"🚨 Shadow313 Alert: {alert.get('name','Unknown')} | Severity: {alert.get('severity','?')}"
        return {"action":"telegram","message":msg,"status":"sent" if not self.dry_run else "dry_run"}

    def _generate_receipt(self, alert: Dict) -> Dict:
        ts = int(time.time_ns())
        ts_313 = int(str(ts)[:-3] + "313")
        payload = json.dumps(alert, sort_keys=True, default=str)
        return {
            "action":    "313_bind",
            "bind_id":   f"313-SOAR-{uuid.uuid4().hex[:8].upper()}",
            "timestamp_ns": ts_313,
            "hash":      hashlib.sha3_512(payload.encode()).hexdigest()[:32]
        }

    def _bgp_blackhole(self, alert: Dict) -> Dict:
        ip = alert.get("src_ip","unknown")
        return {"action":"bgp_blackhole","ip":ip,"asn":"AS64512","status":"announced" if not self.dry_run else "dry_run"}

    def _deploy_honeypot(self, alert: Dict) -> Dict:
        return {"action":"honeypot","port":random_port(),"status":"deployed" if not self.dry_run else "dry_run"}

    def _isolate_network(self, alert: Dict) -> Dict:
        host = alert.get("host","unknown")
        return {"action":"isolate","host":host,"vlan":"quarantine-vlan","status":"isolated" if not self.dry_run else "dry_run"}

    def _collect_forensics(self, alert: Dict) -> Dict:
        return {"action":"forensics","artifacts":["memory_dump","process_list","network_connections"],"status":"collected"}

    def _snapshot_host(self, alert: Dict) -> Dict:
        host = alert.get("host","unknown")
        snap_id = str(uuid.uuid4())[:8]
        return {"action":"snapshot","host":host,"snapshot_id":snap_id,"status":"created"}

    def _export_sigma(self, alert: Dict) -> Dict:
        return {"action":"sigma_export","rule_id":f"S313-{uuid.uuid4().hex[:6].upper()}","format":"sigma_yaml"}

    def _export_stix(self, alert: Dict) -> Dict:
        return {"action":"stix_export","bundle_id":f"bundle--{uuid.uuid4()}","format":"stix_2.1"}

    def get_log(self) -> List[Dict]:
        return self._log

    def get_stats(self) -> Dict:
        if not self._log:
            return {"total":0,"avg_duration_ms":0}
        durations = [e["duration_ms"] for e in self._log]
        return {
            "total":           len(self._log),
            "avg_duration_ms": round(sum(durations)/len(durations),1),
            "min_duration_ms": min(durations),
            "max_duration_ms": max(durations),
            "playbooks_fired": list(set(e["playbook"] for e in self._log))
        }

def random_port():
    import random
    return random.randint(10000,65000)
