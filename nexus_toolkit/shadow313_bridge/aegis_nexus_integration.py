"""
Aegis-NEXUS Integration
=======================
Bridges AegisAudit hardening findings into the NEXUS ML detection pipeline.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

SEVERITY_SCORE = {
    "CRITICAL": 0.92, "HIGH": 0.75, "MEDIUM": 0.55, "LOW": 0.35, "INFO": 0.15,
}

MITRE_TO_THREAT_CLASS = {
    "T1562.004": "DEFENSE_EVASION",
    "T1053.003": "PERSISTENCE",
    "T1003.008": "CREDENTIAL_ACCESS",
    "T1049":     "DISCOVERY",
    "T1222":     "DEFENSE_EVASION",
    "T1040":     "CREDENTIAL_ACCESS",
    "T1110.001": "CREDENTIAL_ACCESS",
    "T1078.003": "PRIVILEGE_ESCALATION",
}

SOAR_TRIGGERS = {
    "T1562.004": "firewall_disabled_response",
    "T1053.003": "suspicious_cron_response",
    "T1049":     "highrisk_port_response",
    "T1040":     "promiscuous_interface_response",
}

MITRE_EVENT_IDS = {
    "T1562.004": 4950, "T1053.003": 4698, "T1003.008": 4663,
    "T1049": 4656, "T1222": 4670, "T1040": 4657,
    "T1110.001": 4625, "T1078.003": 4624,
}


class AegisNexusIntegration:
    """Converts AegisAudit findings into NEXUS detection pipeline events."""

    def __init__(self, nexus_engine=None, soar_engine=None):
        self.nexus_engine = nexus_engine
        self.soar_engine  = soar_engine
        self._alerts: list[dict] = []

    async def process_aegis_findings(
        self, aegis_result: dict, auto_soar: bool = True,
    ) -> dict[str, Any]:
        findings = aegis_result.get("findings", [])
        target   = aegis_result.get("target", "localhost")
        score    = aegis_result.get("score", 100)
        alerts, soar_actions, coverage = [], [], []

        for finding in findings:
            mitre        = self._extract_mitre(finding)
            severity     = finding.get("severity", "MEDIUM")
            threat_class = MITRE_TO_THREAT_CLASS.get(mitre, "IMPACT")
            log_entry    = self._build_log_entry(finding, target, mitre, threat_class)
            nexus_score  = await self._score_with_nexus(log_entry)

            alert = {
                "alert_id":        f"AEGIS-{hashlib.md5(finding.get('title','').encode()).hexdigest()[:8].upper()}",
                "source":          "AegisAudit",
                "target":          target,
                "title":           finding.get("title", ""),
                "severity":        severity,
                "threat_class":    threat_class,
                "mitre_technique": mitre,
                "nexus_score":     nexus_score,
                "timestamp":       datetime.now(timezone.utc).isoformat(),
                "log_entry":       log_entry,
                "remediation":     finding.get("remediation", ""),
                "cis_control":     self._extract_cis(finding),
            }
            alerts.append(alert)
            if mitre and mitre not in coverage:
                coverage.append(mitre)
            if auto_soar and severity == "CRITICAL" and mitre in SOAR_TRIGGERS:
                soar_actions.append(await self._trigger_soar(SOAR_TRIGGERS[mitre], alert))

        drift = "CRITICAL" if score < 40 else "HIGH" if score < 60 else "MEDIUM" if score < 80 else "LOW"
        self._alerts = alerts
        return {
            "integration_status":       "complete",
            "target":                   target,
            "aegis_score":              score,
            "drift_severity":           drift,
            "alerts_generated":         len(alerts),
            "soar_actions_triggered":   len(soar_actions),
            "attck_techniques_covered": coverage,
            "alerts":                   alerts,
            "soar_actions":             soar_actions,
            "summary":                  self._generate_summary(alerts, score, target),
        }

    def _build_log_entry(self, finding, target, mitre, threat_class):
        title = finding.get("title", "")
        sev   = finding.get("severity", "MEDIUM")
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "aegis_audit", "host": target,
            "event_id": MITRE_EVENT_IDS.get(mitre, 4688),
            "severity": sev, "threat_class": threat_class,
            "mitre_technique": mitre, "message": title,
            "raw": {"finding_title": title, "finding_severity": sev,
                    "mitre": mitre, "cis": self._extract_cis(finding),
                    "remediation": finding.get("remediation", "")},
            "command_line": self._finding_to_cmdline(finding),
            "process_name": "aegis_audit",
            "file_path": self._extract_file_path(finding),
            "network_bytes": 0, "user_name": "root",
        }

    async def _score_with_nexus(self, log_entry: dict) -> float:
        if self.nexus_engine is None:
            return SEVERITY_SCORE.get(log_entry.get("severity", "MEDIUM"), 0.5)
        try:
            from nexus_toolkit.core.log_parser import LogEntry
            return float(self.nexus_engine.score_entry(LogEntry.from_dict(log_entry)))
        except Exception:
            return SEVERITY_SCORE.get(log_entry.get("severity", "MEDIUM"), 0.5)

    async def _trigger_soar(self, playbook: str, alert: dict) -> dict:
        if self.soar_engine is None:
            return {"playbook": playbook, "status": "simulated",
                    "alert_id": alert["alert_id"],
                    "action": f"Would execute: {playbook}",
                    "timestamp": datetime.now(timezone.utc).isoformat()}
        try:
            result = await self.soar_engine.execute_playbook(
                playbook_name=playbook,
                context={"alert_id": alert["alert_id"], "target": alert["target"],
                         "mitre": alert["mitre_technique"], "severity": alert["severity"]}
            )
            return {"playbook": playbook, "status": "executed", "result": result}
        except Exception as e:
            return {"playbook": playbook, "status": "error", "error": str(e)}

    def _extract_mitre(self, finding: dict) -> str:
        m = re.search(r'T\d{4}(?:\.\d{3})?', finding.get("description", ""))
        return m.group(0) if m else ""

    def _extract_cis(self, finding: dict) -> str:
        m = re.search(r'CIS-[\d.]+', finding.get("description", ""))
        return m.group(0) if m else ""

    def _finding_to_cmdline(self, finding: dict) -> str:
        t = finding.get("title", "").lower()
        if "firewall" in t:       return "ufw disable"
        if "cron" in t:           return "crontab -e"
        if "shadow" in t:         return "chmod 777 /etc/shadow"
        if "port" in t:           return "nc -lvp 4444"
        if "promisc" in t:        return "ip link set eth0 promisc on"
        if "world-writable" in t: return "chmod o+w /etc/passwd"
        return ""

    def _extract_file_path(self, finding: dict) -> str:
        m = re.search(r'(/etc/\S+)', finding.get("title", ""))
        return m.group(1) if m else ""

    def _generate_summary(self, alerts, score, target) -> str:
        crit  = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        high  = sum(1 for a in alerts if a["severity"] == "HIGH")
        techs = list({a["mitre_technique"] for a in alerts if a["mitre_technique"]})
        return (f"AegisAudit on {target}: score {score}%. "
                f"{len(alerts)} findings ({crit} CRITICAL, {high} HIGH). "
                f"ATT&CK: {', '.join(techs[:5])}. "
                f"{'Immediate remediation required.' if score < 60 else 'Review findings.'}")

    def get_alerts(self) -> list[dict]:
        return self._alerts