"""
shadow313.v4.detection.swift_process_monitor
SWIFT Process Monitor — detects FASTCash JAR injection and SWIFT message manipulation.
Maps to T1565.001 (Stored Data Manipulation), T1055 (Process Injection).
"""
from __future__ import annotations
import time
import re
from typing import Optional

SWIFT_SUSPICIOUS_PATTERNS = [
    r"FASTCash",
    r"\.jar.*inject",
    r"swiftadm",
    r"SWIFT.*Alliance.*Gateway",
    r"MT202.*COV",
    r"RCBCPHMMXXX",
]


class SWIFTProcessMonitor:
    """Monitors SWIFT messaging processes for FASTCash-style manipulation."""

    def __init__(self):
        self.monitored_processes: list = []
        self.alerts: list = []
        self.mt103_count: int = 0
        self.suspicious_transfers: list = []

    def monitor_process(self, process: dict) -> dict:
        name = process.get("name", "")
        cmdline = process.get("cmdline", "")
        pid = process.get("pid", 0)
        findings = []
        for pattern in SWIFT_SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE) or re.search(pattern, name, re.IGNORECASE):
                findings.append({"pattern": pattern, "matched_in": "cmdline"})
        event = {
            "pid": pid, "name": name, "cmdline": cmdline[:200],
            "timestamp": time.time(), "suspicious": len(findings) > 0, "findings": findings,
        }
        self.monitored_processes.append(event)
        if findings:
            alert = {
                "alert_type": "SWIFT_PROCESS_ANOMALY", "severity": "CRITICAL",
                "pid": pid, "process_name": name, "findings": findings,
                "mitre_technique": "T1565.001", "timestamp": time.time(),
            }
            self.alerts.append(alert)
            return {"event": event, "alert": alert}
        return {"event": event, "alert": None}

    def analyze_mt103(self, message: str) -> dict:
        self.mt103_count += 1
        amount_match = re.search(r":32A:\d{6}([A-Z]{3})(\d+,\d+)", message)
        bic_match = re.search(r":57A:([A-Z]{8,11})", message)
        amount = float(amount_match.group(2).replace(",", ".")) if amount_match else 0
        bic = bic_match.group(1) if bic_match else "UNKNOWN"
        suspicious = amount > 1_000_000 or bic in ["RCBCPHMMXXX", "FISMIDJ1XXX"]
        result = {
            "message_type": "MT103", "amount": amount,
            "currency": amount_match.group(1) if amount_match else "UNK",
            "beneficiary_bic": bic, "suspicious": suspicious, "timestamp": time.time(),
        }
        if suspicious:
            self.suspicious_transfers.append(result)
        return result

    def status(self) -> dict:
        return {
            "processes_monitored": len(self.monitored_processes),
            "alerts_generated": len(self.alerts),
            "mt103_analyzed": self.mt103_count,
            "suspicious_transfers": len(self.suspicious_transfers),
        }