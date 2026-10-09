"""
Shadow313 NEXUS — Campaign Manager
Multi-target security assessment campaign orchestration.
"""
from __future__ import annotations
import uuid, json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pathlib import Path

class Campaign:
    def __init__(self, name: str, targets: List[str], operator: str = "unknown"):
        self.id = str(uuid.uuid4()); self.name = name; self.targets = targets
        self.operator = operator; self.created = datetime.now(timezone.utc).isoformat()
        self.status = "active"; self.findings = []; self.receipts = []; self.score = 0.0

    def add_finding(self, finding: Dict):
        finding["campaign_id"] = self.id
        finding["timestamp"]   = datetime.now(timezone.utc).isoformat()
        self.findings.append(finding)
        weights = {"CRITICAL":10,"HIGH":7,"MEDIUM":4,"LOW":1,"INFO":0}
        total = sum(weights.get(f.get("severity","INFO"),0) for f in self.findings)
        self.score = min(total/max(len(self.targets),1), 100.0)

    def to_dict(self) -> Dict:
        return {"id":self.id,"name":self.name,"targets":self.targets,"operator":self.operator,
                "created":self.created,"status":self.status,"findings_count":len(self.findings),
                "risk_score":self.score}

class CampaignManager:
    def __init__(self, store_dir: str = "~/.shadow313/campaigns"):
        self.store_dir = Path(store_dir).expanduser()
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._campaigns: Dict[str, Campaign] = {}

    def create(self, name: str, targets: List[str], operator: str = "unknown") -> Campaign:
        c = Campaign(name, targets, operator)
        self._campaigns[c.id] = c
        return c

    def get(self, cid: str) -> Optional[Campaign]:
        return self._campaigns.get(cid)

    def list_all(self) -> List[Dict]:
        return [c.to_dict() for c in self._campaigns.values()]

    def add_finding(self, cid: str, finding: Dict) -> bool:
        c = self.get(cid)
        if not c: return False
        c.add_finding(finding)
        return True

    def generate_report(self, cid: str) -> Dict:
        c = self.get(cid)
        if not c: return {}
        critical = [f for f in c.findings if f.get("severity")=="CRITICAL"]
        return {
            "campaign": c.to_dict(),
            "summary": {"total_targets":len(c.targets),"total_findings":len(c.findings),
                        "critical":len(critical),"risk_score":c.score,
                        "risk_level":"CRITICAL" if c.score>70 else "HIGH" if c.score>40 else "MEDIUM"},
            "findings": c.findings,
            "generated": datetime.now(timezone.utc).isoformat()
        }
