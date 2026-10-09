"""
Shadow313 NEXUS — APT Lateral Movement Simulation
APT29-style kill chain: Phishing → LSASS → PtH → PrintNightmare → DCSync → Exfil
"""
from __future__ import annotations
import time, uuid
from datetime import datetime, timezone
from typing import Dict, List

APT_KILL_CHAIN = [
    {"step":1,"technique":"T1566.001","name":"Initial Access (Phishing)","target":"HR-LAPTOP-01","ip":"10.0.4.15"},
    {"step":2,"technique":"T1046","name":"Network Discovery","target":"HR-LAPTOP-01","ip":"10.0.4.15"},
    {"step":3,"technique":"T1003.001","name":"Credential Dumping (LSASS)","target":"HR-LAPTOP-01","ip":"10.0.4.15"},
    {"step":4,"technique":"T1550.002","name":"Lateral Movement (Pass-the-Hash)","target":"WEB-SRV-01","ip":"10.0.10.5"},
    {"step":5,"technique":"T1068","name":"Privilege Escalation (PrintNightmare)","target":"WEB-SRV-01","ip":"10.0.10.5"},
    {"step":6,"technique":"T1003.006","name":"Domain Controller Compromise (DCSync)","target":"DC-PRIMARY","ip":"10.0.20.2"},
    {"step":7,"technique":"T1005","name":"Database Collection","target":"SQL-CUSTOMER-DB","ip":"10.0.30.50"},
    {"step":8,"technique":"T1048","name":"Exfiltration (DNS Tunneling)","target":"SQL-CUSTOMER-DB","ip":"10.0.30.50"},
]

class APTSimulator:
    def __init__(self, delay: float = 0.05):
        self.delay = delay
        self._events: List[Dict] = []

    def run_full_chain(self) -> Dict:
        sim_id = str(uuid.uuid4())[:8]
        for step in APT_KILL_CHAIN:
            time.sleep(self.delay)
            self._events.append({
                "sim_id": sim_id, "step": step["step"],
                "technique": step["technique"], "name": step["name"],
                "target": step["target"], "ip": step["ip"],
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        return {"sim_id": sim_id, "steps": len(APT_KILL_CHAIN), "events": self._events}

    def get_coverage(self, detected: List[str]) -> Dict:
        total = len(APT_KILL_CHAIN)
        det = sum(1 for s in APT_KILL_CHAIN if s["technique"] in detected)
        return {"total": total, "detected": det, "coverage_pct": round(det/total*100, 1)}
