"""
shadow313.v4.detection.file_access_monitor
File Access Monitor — detects unauthorized file access, path traversal, and sensitive file reads.
Maps to T1083 (File and Directory Discovery), T1005 (Data from Local System).
"""
from __future__ import annotations
import time
import re
from typing import Optional

SENSITIVE_PATHS = [
    r"/etc/passwd", r"/etc/shadow", r"/etc/sudoers",
    r"\.ssh/id_rsa", r"\.ssh/authorized_keys",
    r"\.aws/credentials", r"\.env",
    r"/proc/\d+/mem", r"/dev/mem",
    r"ntds\.dit", r"SAM$", r"SYSTEM$",
    r"wallet\.dat", r"keystore",
]

TRAVERSAL_PATTERNS = [r"\.\./", r"\.\.\\", r"%2e%2e", r"\.\.%2f"]


class FileAccessMonitor:
    """Detects suspicious file access patterns."""

    def __init__(self, alert_threshold: int = 3):
        self.alert_threshold = alert_threshold
        self.access_log: list = []
        self.alerts: list = []
        self._access_counts: dict = {}

    def monitor_access(self, path: str, user: str = "unknown", pid: int = 0) -> dict:
        event = {
            "path": path,
            "user": user,
            "pid": pid,
            "timestamp": time.time(),
            "sensitive": self._is_sensitive(path),
            "traversal": self._is_traversal(path),
        }
        self.access_log.append(event)
        key = f"{user}:{path}"
        self._access_counts[key] = self._access_counts.get(key, 0) + 1

        alert = None
        if event["traversal"]:
            alert = self._create_alert("PATH_TRAVERSAL_ATTEMPT", event, "CRITICAL")
        elif event["sensitive"]:
            alert = self._create_alert("SENSITIVE_FILE_ACCESS", event, "HIGH")
        elif self._access_counts[key] >= self.alert_threshold:
            alert = self._create_alert("REPEATED_FILE_ACCESS", event, "MEDIUM")

        if alert:
            self.alerts.append(alert)
        return {"event": event, "alert": alert}

    def _is_sensitive(self, path: str) -> bool:
        return any(re.search(p, path, re.IGNORECASE) for p in SENSITIVE_PATHS)

    def _is_traversal(self, path: str) -> bool:
        return any(re.search(p, path, re.IGNORECASE) for p in TRAVERSAL_PATTERNS)

    def _create_alert(self, alert_type: str, event: dict, severity: str) -> dict:
        return {
            "alert_type": alert_type,
            "severity": severity,
            "path": event["path"],
            "user": event["user"],
            "pid": event["pid"],
            "timestamp": event["timestamp"],
            "mitre_technique": "T1083" if "REPEATED" in alert_type else "T1005",
        }

    def get_alerts(self, severity: Optional[str] = None) -> list:
        if severity:
            return [a for a in self.alerts if a["severity"] == severity]
        return self.alerts

    def status(self) -> dict:
        return {
            "events_monitored": len(self.access_log),
            "alerts_generated": len(self.alerts),
            "unique_paths": len(set(e["path"] for e in self.access_log)),
        }