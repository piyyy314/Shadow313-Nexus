"""
shadow313.v4.detection.user_execution_detector
User Execution Detector — T1204

Detects malicious file execution triggered by user interaction:
- T1204.001: Malicious Link (clicking URLs that execute code)
- T1204.002: Malicious File (double-clicking malicious attachments)

Covers:
- Office macro execution chains (Word/Excel spawning cmd/powershell)
- ISO/IMG mount + execute patterns (bypasses Mark-of-the-Web)
- LNK file execution (shortcut-based execution)
- Double-click execution of .js, .vbs, .hta, .bat files
- HTML smuggling patterns
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Malicious file extension patterns ────────────────────────────────────────

MALICIOUS_EXTENSIONS = {
    # Script files — high risk
    ".hta":  {"risk": 0.90, "technique": "T1204.002", "desc": "HTML Application — executes VBScript/JScript"},
    ".vbs":  {"risk": 0.85, "technique": "T1204.002", "desc": "VBScript — executes arbitrary commands"},
    ".vbe":  {"risk": 0.88, "technique": "T1204.002", "desc": "Encoded VBScript — obfuscated execution"},
    ".js":   {"risk": 0.82, "technique": "T1204.002", "desc": "JScript — Windows Script Host execution"},
    ".jse":  {"risk": 0.85, "technique": "T1204.002", "desc": "Encoded JScript — obfuscated execution"},
    ".wsf":  {"risk": 0.83, "technique": "T1204.002", "desc": "Windows Script File — multi-language scripts"},
    ".wsh":  {"risk": 0.80, "technique": "T1204.002", "desc": "Windows Script Host settings file"},
    ".bat":  {"risk": 0.75, "technique": "T1204.002", "desc": "Batch file — command execution"},
    ".cmd":  {"risk": 0.75, "technique": "T1204.002", "desc": "Command file — command execution"},
    ".ps1":  {"risk": 0.80, "technique": "T1204.002", "desc": "PowerShell script"},
    ".lnk":  {"risk": 0.85, "technique": "T1204.002", "desc": "LNK shortcut — can execute arbitrary commands"},
    # Container files — medium-high risk (MOTW bypass)
    ".iso":  {"risk": 0.88, "technique": "T1204.002", "desc": "ISO image — bypasses Mark-of-the-Web"},
    ".img":  {"risk": 0.85, "technique": "T1204.002", "desc": "Disk image — bypasses Mark-of-the-Web"},
    ".vhd":  {"risk": 0.83, "technique": "T1204.002", "desc": "Virtual Hard Disk — MOTW bypass"},
    ".vhdx": {"risk": 0.83, "technique": "T1204.002", "desc": "Virtual Hard Disk — MOTW bypass"},
    # Office files with macros
    ".xlsm": {"risk": 0.80, "technique": "T1204.002", "desc": "Excel macro-enabled workbook"},
    ".xlsb": {"risk": 0.78, "technique": "T1204.002", "desc": "Excel binary workbook (can contain macros)"},
    ".docm": {"risk": 0.80, "technique": "T1204.002", "desc": "Word macro-enabled document"},
    ".pptm": {"risk": 0.78, "technique": "T1204.002", "desc": "PowerPoint macro-enabled presentation"},
    ".xll":  {"risk": 0.85, "technique": "T1204.002", "desc": "Excel add-in — DLL execution via Excel"},
    ".xlam": {"risk": 0.82, "technique": "T1204.002", "desc": "Excel macro-enabled add-in"},
}

# ── Office macro execution chain patterns ────────────────────────────────────

OFFICE_PROCESSES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "access.exe", "publisher.exe", "visio.exe",
    "msproject.exe", "infopath.exe",
}

MACRO_CHILD_PROCESSES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe",
    "installutil.exe", "odbcconf.exe", "forfiles.exe",
}

# ── LNK file suspicious patterns ─────────────────────────────────────────────

LNK_SUSPICIOUS_PATTERNS = [
    r"powershell.*-enc",           # encoded PowerShell
    r"cmd.*\/c.*http",             # cmd downloading from URL
    r"mshta.*http",                # mshta remote execution
    r"wscript.*http",              # wscript remote execution
    r"certutil.*-urlcache",        # certutil download
    r"bitsadmin.*\/transfer",      # BITS download
    r"\\\\.*\\.*\.exe",            # UNC path execution
    r"-windowstyle\s+hidden",      # hidden window
    r"-noprofile.*-noninteractive", # PowerShell stealth flags
]

# ── HTML smuggling indicators ─────────────────────────────────────────────────

HTML_SMUGGLING_PATTERNS = [
    r"msSaveOrOpenBlob",           # IE/Edge blob download
    r"createObjectURL",            # URL.createObjectURL
    r"atob\(",                     # base64 decode in JS
    r"Uint8Array",                 # binary array construction
    r"navigator\.msSaveBlob",      # IE save blob
    r"download.*\.exe",            # forced download of executable
    r"download.*\.zip",            # forced download of archive
]


@dataclass
class UserExecutionAlert:
    """Alert for user execution of malicious file."""
    technique:       str
    technique_name:  str
    risk_score:      float
    execution_type:  str   # "malicious_file", "macro_chain", "lnk", "iso_motw", "html_smuggling"
    file_path:       str
    file_extension:  str
    parent_process:  str
    child_process:   str
    command_line:    str
    severity:        str
    description:     str
    timestamp:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique":      self.technique,
            "technique_name": self.technique_name,
            "risk_score":     self.risk_score,
            "execution_type": self.execution_type,
            "file_path":      self.file_path,
            "file_extension": self.file_extension,
            "parent_process": self.parent_process,
            "child_process":  self.child_process,
            "command_line":   self.command_line[:200],
            "severity":       self.severity,
            "description":    self.description,
            "timestamp":      self.timestamp,
        }


class UserExecutionDetector:
    """
    Detects malicious user execution patterns.

    Covers:
    - T1204.001: Malicious Link
    - T1204.002: Malicious File

    Detection methods:
    1. Malicious file extension execution
    2. Office macro → shell child process chains
    3. LNK file with suspicious command
    4. ISO/IMG mount + execute (MOTW bypass)
    5. HTML smuggling indicators

    Usage:
        detector = UserExecutionDetector()

        # Check file execution
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Downloads\\invoice.hta",
            "parent_process": "explorer.exe",
        })

        # Check process chain (macro execution)
        alert = detector.analyze_process_chain({
            "parent_process": "winword.exe",
            "child_process": "cmd.exe",
            "command_line": "cmd.exe /c powershell -enc JABj...",
        })
    """

    def __init__(self):
        self._alerts: list[UserExecutionAlert] = []
        self._lnk_patterns = [re.compile(p, re.IGNORECASE) for p in LNK_SUSPICIOUS_PATTERNS]
        self._html_patterns = [re.compile(p, re.IGNORECASE) for p in HTML_SMUGGLING_PATTERNS]

    def analyze_file_execution(self, event: dict) -> Optional[UserExecutionAlert]:
        """
        Analyze a file execution event for malicious patterns.

        Args:
            event: dict with:
                - file_path: str
                - parent_process: str (optional)
                - command_line: str (optional)
        """
        file_path    = event.get("file_path", "")
        parent       = event.get("parent_process", "explorer.exe").lower()
        command_line = event.get("command_line", "")

        # Extract extension
        ext = ""
        for candidate_ext in MALICIOUS_EXTENSIONS:
            if file_path.lower().endswith(candidate_ext):
                ext = candidate_ext
                break

        if not ext:
            return None

        sig  = MALICIOUS_EXTENSIONS[ext]
        risk = sig["risk"]

        # Boost risk for ISO/IMG (MOTW bypass)
        execution_type = "malicious_file"
        if ext in (".iso", ".img", ".vhd", ".vhdx"):
            execution_type = "iso_motw_bypass"
            risk = min(1.0, risk + 0.05)

        # Boost risk for LNK files with suspicious commands
        if ext == ".lnk":
            execution_type = "lnk_execution"
            for pattern in self._lnk_patterns:
                if pattern.search(command_line):
                    risk = min(1.0, risk + 0.08)
                    break

        # Boost if downloaded (common download paths)
        download_paths = ["\\downloads\\", "\\temp\\", "\\appdata\\local\\temp\\",
                          "/tmp/", "/downloads/"]
        if any(p in file_path.lower() for p in download_paths):
            risk = min(1.0, risk + 0.05)

        severity = self._severity(risk)

        alert = UserExecutionAlert(
            technique       = sig["technique"],
            technique_name  = "Malicious File",
            risk_score      = round(risk, 3),
            execution_type  = execution_type,
            file_path       = file_path,
            file_extension  = ext,
            parent_process  = parent,
            child_process   = "",
            command_line    = command_line,
            severity        = severity,
            description     = sig["desc"],
            recommendations = [
                f"Quarantine file: {file_path}",
                f"Scan with AV/EDR — extension {ext} is high-risk",
                f"Check if file was downloaded from internet (MOTW)",
                f"ATT&CK: {sig['technique']} — User Execution: Malicious File",
            ],
        )
        self._alerts.append(alert)
        return alert

    def analyze_process_chain(self, event: dict) -> Optional[UserExecutionAlert]:
        """
        Analyze a parent→child process chain for macro execution patterns.

        Args:
            event: dict with:
                - parent_process: str
                - child_process: str
                - command_line: str (optional)
        """
        parent       = event.get("parent_process", "").lower()
        child        = event.get("child_process", "").lower()
        command_line = event.get("command_line", "")

        # Check for Office → shell child (macro execution)
        is_office_parent = any(op in parent for op in OFFICE_PROCESSES)
        is_shell_child   = any(cp in child for cp in MACRO_CHILD_PROCESSES)

        if not (is_office_parent and is_shell_child):
            return None

        risk = 0.88  # Office spawning shell is always high risk

        # Boost for encoded commands
        if re.search(r"-enc\b|-encodedcommand\b", command_line, re.IGNORECASE):
            risk = min(1.0, risk + 0.08)

        # Boost for network activity
        if re.search(r"http[s]?://|\\\\[^\\]+\\", command_line, re.IGNORECASE):
            risk = min(1.0, risk + 0.05)

        severity = self._severity(risk)

        alert = UserExecutionAlert(
            technique       = "T1204.002",
            technique_name  = "Malicious File — Office Macro Chain",
            risk_score      = round(risk, 3),
            execution_type  = "macro_chain",
            file_path       = "",
            file_extension  = "",
            parent_process  = parent,
            child_process   = child,
            command_line    = command_line,
            severity        = severity,
            description     = f"Office application '{parent}' spawned shell process '{child}' — likely macro execution",
            recommendations = [
                f"CRITICAL: {parent} spawned {child} — macro execution detected",
                "Isolate host immediately",
                "Check recently opened Office documents",
                "Review email attachments in last 24h",
                "ATT&CK: T1204.002 — User Execution: Malicious File",
            ],
        )
        self._alerts.append(alert)
        return alert

    def analyze_html_content(self, html_content: str, source_url: str = "") -> Optional[UserExecutionAlert]:
        """
        Analyze HTML content for smuggling patterns.

        Args:
            html_content: HTML source to analyze
            source_url: URL where HTML was served from
        """
        matched = []
        for pattern in self._html_patterns:
            if pattern.search(html_content):
                matched.append(pattern.pattern)

        if len(matched) < 2:  # Require at least 2 indicators
            return None

        risk = min(1.0, 0.70 + len(matched) * 0.05)
        severity = self._severity(risk)

        alert = UserExecutionAlert(
            technique       = "T1204.001",
            technique_name  = "Malicious Link — HTML Smuggling",
            risk_score      = round(risk, 3),
            execution_type  = "html_smuggling",
            file_path       = source_url,
            file_extension  = ".html",
            parent_process  = "browser",
            child_process   = "",
            command_line    = "",
            severity        = severity,
            description     = f"HTML smuggling detected — {len(matched)} indicators: {matched[:3]}",
            recommendations = [
                "Block URL at proxy/firewall",
                "Check for downloaded files from this page",
                "Scan endpoint for recently created executables",
                "ATT&CK: T1204.001 — User Execution: Malicious Link",
            ],
        )
        self._alerts.append(alert)
        return alert

    def get_alerts(self) -> list[UserExecutionAlert]:
        return list(self._alerts)

    def get_stats(self) -> dict:
        by_type: dict[str, int] = {}
        by_ext:  dict[str, int] = {}
        for a in self._alerts:
            by_type[a.execution_type] = by_type.get(a.execution_type, 0) + 1
            if a.file_extension:
                by_ext[a.file_extension] = by_ext.get(a.file_extension, 0) + 1
        return {
            "total_alerts": len(self._alerts),
            "by_type":      by_type,
            "by_extension": by_ext,
        }

    def clear(self) -> None:
        self._alerts.clear()

    @staticmethod
    def _severity(risk: float) -> str:
        if risk >= 0.90: return "CRITICAL"
        if risk >= 0.80: return "HIGH"
        if risk >= 0.65: return "MEDIUM"
        return "LOW"

    @staticmethod
    def list_monitored_extensions() -> list[str]:
        return list(MALICIOUS_EXTENSIONS.keys())