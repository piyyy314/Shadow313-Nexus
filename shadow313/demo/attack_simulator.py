"""
shadow313.demo.attack_simulator
─────────────────────────────────
APT Attack Simulator — generates realistic attack scenarios for demos.

Simulates full kill chains for:
  - APT29 (Cozy Bear) — spearphishing → credential theft → lateral movement
  - APT41 (Double Dragon) — supply chain → persistence → exfiltration
  - Lazarus Group — watering hole → C2 → financial theft
  - FIN7 (Carbanak) — phishing → POS malware → data exfiltration
  - Ransomware (BlackCat/ALPHV) — initial access → encryption → ransom

Each simulation produces log entries compatible with the 37-dim feature extractor.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SimulatedAttack:
    """A complete simulated attack scenario."""
    scenario:   str
    actor:      str
    log_entries: list[dict]
    kill_chain:  list[str]   # ATT&CK tactic sequence
    techniques:  list[str]   # ATT&CK technique IDs
    iocs:        list[dict]  # Indicators of compromise
    duration_s:  float = 0.0


class APTAttackSimulator:
    """
    Generates realistic APT attack scenarios for Shadow313 demos.

    Each scenario produces a sequence of log entries that can be
    fed into the NexusDetectionEngine for detection testing.
    """

    def __init__(self, seed: int = 313) -> None:
        random.seed(seed)
        self._base_time = time.time()

    def _ts(self, offset_s: float) -> float:
        return self._base_time + offset_s

    def simulate_apt29(self) -> SimulatedAttack:
        """APT29 (Cozy Bear) — spearphishing → WMI persistence → DCSync."""
        entries = [
            {"log_id": "APT29-001", "event_id": 4688, "event_type": "process_creation",
             "process": "winword.exe", "parent": "outlook.exe",
             "command_line": "winword.exe /n Q4_Report.docm",
             "user": "jsmith", "host": "WS-07", "severity": "info",
             "timestamp": _now_iso()},
            {"log_id": "APT29-002", "event_id": 4688, "event_type": "process_creation",
             "process": "powershell.exe", "parent": "winword.exe",
             "command_line": "powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
             "user": "jsmith", "host": "WS-07", "severity": "high",
             "timestamp": _now_iso()},
            {"log_id": "APT29-003", "event_id": 10, "event_type": "process_access",
             "process": "powershell.exe", "parent": "powershell.exe",
             "command_line": "sekurlsa::logonpasswords",
             "TargetImage": "C:\\Windows\\System32\\lsass.exe",
             "GrantedAccess": "0x1010",
             "user": "SYSTEM", "host": "WS-07", "severity": "critical",
             "timestamp": _now_iso()},
            {"log_id": "APT29-004", "event_id": 4662, "event_type": "directory_service_access",
             "process": "powershell.exe",
             "command_line": "Invoke-Mimikatz -Command \"lsadump::dcsync /domain:corp.local\"",
             "user": "SYSTEM", "host": "WS-07", "severity": "critical",
             "timestamp": _now_iso()},
        ]
        return SimulatedAttack(
            scenario    = "APT29 Cozy Bear Kill Chain",
            actor       = "APT29",
            log_entries = entries,
            kill_chain  = ["Initial Access", "Execution", "Credential Access", "Lateral Movement"],
            techniques  = ["T1566.001", "T1059.001", "T1003.001", "T1003.006"],
            iocs        = [{"type": "domain", "value": "update.microsoft-cdn.net"}],
        )

    def simulate_ransomware(self) -> SimulatedAttack:
        """BlackCat/ALPHV ransomware kill chain."""
        entries = [
            {"log_id": "RANSOM-001", "event_id": 4688, "event_type": "process_creation",
             "process": "powershell.exe", "parent": "explorer.exe",
             "command_line": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
             "user": "administrator", "host": "DC-01", "severity": "high",
             "timestamp": _now_iso()},
            {"log_id": "RANSOM-002", "event_id": 4688, "event_type": "process_creation",
             "process": "vssadmin.exe", "parent": "cmd.exe",
             "command_line": "vssadmin delete shadows /all /quiet",
             "user": "administrator", "host": "DC-01", "severity": "critical",
             "timestamp": _now_iso()},
            {"log_id": "RANSOM-003", "event_id": 4688, "event_type": "process_creation",
             "process": "7z.exe", "parent": "cmd.exe",
             "command_line": "7z.exe a -p\"S3cr3t!\" C:\\Windows\\Temp\\data.zip C:\\Users\\*\\Documents\\*",
             "file_path": "C:\\Windows\\Temp\\data.zip",
             "user": "administrator", "host": "DC-01", "severity": "high",
             "timestamp": _now_iso()},
        ]
        return SimulatedAttack(
            scenario    = "BlackCat/ALPHV Ransomware",
            actor       = "BlackCat",
            log_entries = entries,
            kill_chain  = ["Defense Evasion", "Impact", "Collection"],
            techniques  = ["T1562.001", "T1490", "T1560.001"],
            iocs        = [{"type": "hash", "value": "blackcat_sample_hash"}],
        )

    def simulate_fin7(self) -> SimulatedAttack:
        """FIN7 (Carbanak) — COM hijacking → POS malware."""
        entries = [
            {"log_id": "FIN7-001", "event_id": 4688, "event_type": "process_creation",
             "process": "rundll32.exe", "parent": "explorer.exe",
             "command_line": "rundll32.exe C:\\Users\\Public\\AppData\\evil.dll,DllMain",
             "file_path": "C:\\Users\\Public\\AppData\\evil.dll",
             "user": "cashier01", "host": "POS-01", "severity": "critical",
             "timestamp": _now_iso()},
        ]
        return SimulatedAttack(
            scenario    = "FIN7 COM Hijacking",
            actor       = "FIN7",
            log_entries = entries,
            kill_chain  = ["Persistence", "Defense Evasion"],
            techniques  = ["T1546.015", "T1218.011"],
            iocs        = [{"type": "domain", "value": "fin7-c2.evil.com"}],
        )

    def run_all(self) -> list[SimulatedAttack]:
        """Run all attack simulations."""
        return [
            self.simulate_apt29(),
            self.simulate_ransomware(),
            self.simulate_fin7(),
        ]

    def get_all_log_entries(self) -> list[dict]:
        """Get all log entries from all simulations."""
        entries = []
        for sim in self.run_all():
            entries.extend(sim.log_entries)
        return entries