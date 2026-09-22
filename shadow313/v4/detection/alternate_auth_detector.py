"""
shadow313.v4.detection.alternate_auth_detector
Alternate Authentication Material Detector — T1550

Detects abuse of alternate authentication material:
- T1550.002: Pass-the-Hash (PtH) — NTLM hash reuse
- T1550.003: Pass-the-Ticket (PtT) — Kerberos ticket reuse
- T1550.004: Web Session Cookie theft
- T1558.003: Kerberoasting (SPN ticket requests)
- T1558.001: Golden Ticket attacks
- T1558.002: Silver Ticket attacks

Extends IDENTITY-7 LOTLAuthBypassDetector with hash/ticket-specific detection.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Pass-the-Hash indicators ──────────────────────────────────────────────────

PTH_TOOL_PATTERNS = [
    # Mimikatz sekurlsa::pth
    r"sekurlsa::pth",
    r"sekurlsa::logonpasswords",
    r"sekurlsa::wdigest",
    # Impacket tools
    r"psexec\.py.*-hashes",
    r"wmiexec\.py.*-hashes",
    r"smbexec\.py.*-hashes",
    r"atexec\.py.*-hashes",
    r"dcomexec\.py.*-hashes",
    # CrackMapExec
    r"crackmapexec.*-H\s+[a-fA-F0-9]{32}",
    r"cme\s+.*-H\s+[a-fA-F0-9]{32}",
    # Generic NTLM hash patterns in command lines
    r"-hashes\s+[a-fA-F0-9:]{32,65}",
    r"--hashes\s+[a-fA-F0-9:]{32,65}",
    # Invoke-TheHash
    r"invoke-thehash",
    r"invoke-wmiexec.*hash",
    r"invoke-smbexec.*hash",
]

# ── Pass-the-Ticket indicators ────────────────────────────────────────────────

PTT_TOOL_PATTERNS = [
    # Mimikatz kerberos::ptt
    r"kerberos::ptt",
    r"kerberos::golden",
    r"kerberos::silver",
    r"kerberos::list",
    # Rubeus
    r"rubeus\.exe\s+ptt",
    r"rubeus\.exe\s+asktgt",
    r"rubeus\.exe\s+asktgs",
    r"rubeus\.exe\s+s4u",
    r"rubeus\.exe\s+harvest",
    r"rubeus\.exe\s+kerberoast",
    r"rubeus\.exe\s+asreproast",
    # Impacket
    r"getTGT\.py",
    r"getST\.py",
    r"ticketer\.py",
    r"raiseChild\.py",
    # Generic ticket patterns
    r"\.kirbi\b",                  # Kerberos ticket file
    r"ticket\.kirbi",
    r"/ticket:[a-zA-Z0-9+/=]{20,}", # base64 ticket
]

# ── Kerberoasting indicators ──────────────────────────────────────────────────

KERBEROASTING_PATTERNS = [
    # Rubeus kerberoast
    r"rubeus.*kerberoast",
    r"rubeus.*asreproast",
    # Impacket
    r"getuserspns\.py",
    r"getnpusers\.py",
    # PowerShell
    r"invoke-kerberoast",
    r"get-domainspnticket",
    r"request-spnticket",
    # Generic SPN enumeration
    r"setspn\s+-[qQ]",
    r"ldapsearch.*serviceprincipalname",
]

# ── Golden/Silver ticket indicators ──────────────────────────────────────────

GOLDEN_SILVER_PATTERNS = [
    r"kerberos::golden",           # Mimikatz golden ticket
    r"kerberos::silver",           # Mimikatz silver ticket
    r"ticketer\.py.*-nthash",      # Impacket golden ticket
    r"ticketer\.py.*-aeskey",      # Impacket AES golden ticket
    r"rubeus.*golden",             # Rubeus golden ticket
    r"rubeus.*silver",             # Rubeus silver ticket
    r"/krbtgt:",                   # KRBTGT hash usage
    r"-domain-sid\s+S-1-5",       # Domain SID in ticket creation
]

# ── Web session cookie theft indicators ──────────────────────────────────────

COOKIE_THEFT_PATTERNS = [
    # Browser cookie extraction
    r"cookies\.sqlite",            # Firefox cookies
    r"cookies\.db",                # Chrome cookies
    r"appdata.*chrome.*cookies",   # Chrome cookie path
    r"appdata.*firefox.*cookies",  # Firefox cookie path
    # Token theft tools
    r"sharpchrome",
    r"invoke-sharpchrome",
    r"cookiemonster",
    r"evilginx",
    r"modlishka",
    # Session token patterns
    r"document\.cookie",           # JS cookie access
    r"set-cookie.*session",        # Session cookie setting
]

# ── Windows Event IDs associated with PtH/PtT ────────────────────────────────

SUSPICIOUS_EVENT_IDS = {
    4624: "Logon Success",
    4625: "Logon Failure",
    4648: "Logon with Explicit Credentials",
    4768: "Kerberos TGT Request",
    4769: "Kerberos Service Ticket Request",
    4771: "Kerberos Pre-auth Failed",
    4776: "NTLM Authentication",
    4672: "Special Privileges Assigned",
}

# Logon types associated with PtH
PTH_LOGON_TYPES = {3, 9}  # Network logon, NewCredentials

# ── NTLM hash pattern ─────────────────────────────────────────────────────────
NTLM_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
NTLM_PAIR_RE = re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b")  # LM:NTLM


@dataclass
class AlternateAuthAlert:
    """Alert for alternate authentication material abuse."""
    technique:       str
    technique_name:  str
    sub_technique:   str
    risk_score:      float
    attack_type:     str   # "pth", "ptt", "kerberoasting", "golden_ticket", "cookie_theft"
    source_ip:       str
    target_ip:       str
    username:        str
    command_line:    str
    event_id:        Optional[int]
    logon_type:      Optional[int]
    matched_pattern: str
    severity:        str
    description:     str
    timestamp:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique":       self.technique,
            "technique_name":  self.technique_name,
            "sub_technique":   self.sub_technique,
            "risk_score":      self.risk_score,
            "attack_type":     self.attack_type,
            "source_ip":       self.source_ip,
            "target_ip":       self.target_ip,
            "username":        self.username,
            "command_line":    self.command_line[:200],
            "event_id":        self.event_id,
            "logon_type":      self.logon_type,
            "matched_pattern": self.matched_pattern,
            "severity":        self.severity,
            "description":     self.description,
            "timestamp":       self.timestamp,
        }


class AlternateAuthDetector:
    """
    Detects alternate authentication material abuse.

    Covers T1550 and related techniques:
    - T1550.002: Pass-the-Hash
    - T1550.003: Pass-the-Ticket
    - T1550.004: Web Session Cookie
    - T1558.003: Kerberoasting
    - T1558.001: Golden Ticket
    - T1558.002: Silver Ticket

    Extends IDENTITY-7 LOTLAuthBypassDetector with:
    - NTLM hash pattern detection in command lines
    - Kerberos ticket file detection
    - Suspicious logon type analysis
    - SPN ticket request anomaly detection

    Usage:
        detector = AlternateAuthDetector()

        # Analyze command line
        alert = detector.analyze_command(
            "rubeus.exe kerberoast /outfile:hashes.txt",
            source_ip="10.0.0.1"
        )

        # Analyze Windows event
        alert = detector.analyze_event({
            "event_id": 4769,
            "username": "svc_account",
            "source_ip": "10.0.0.1",
            "ticket_encryption": 0x17,  # RC4 — Kerberoastable
        })
    """

    def __init__(self):
        self._alerts: list[AlternateAuthAlert] = []
        self._spn_requests: dict[str, list] = defaultdict(list)  # user → [timestamps]
        self._failed_logins: dict[str, int] = defaultdict(int)   # user → count

        # Compile patterns
        self._pth_patterns    = [re.compile(p, re.IGNORECASE) for p in PTH_TOOL_PATTERNS]
        self._ptt_patterns    = [re.compile(p, re.IGNORECASE) for p in PTT_TOOL_PATTERNS]
        self._kerb_patterns   = [re.compile(p, re.IGNORECASE) for p in KERBEROASTING_PATTERNS]
        self._golden_patterns = [re.compile(p, re.IGNORECASE) for p in GOLDEN_SILVER_PATTERNS]
        self._cookie_patterns = [re.compile(p, re.IGNORECASE) for p in COOKIE_THEFT_PATTERNS]

    def analyze_command(
        self,
        command_line: str,
        source_ip: str = "",
        username:   str = "",
        target_ip:  str = "",
    ) -> Optional[AlternateAuthAlert]:
        """Analyze a command line for alternate auth abuse patterns."""

        # Check Golden/Silver ticket FIRST (most specific — subset of PTT patterns)
        for pattern in self._golden_patterns:
            if pattern.search(command_line):
                return self._make_alert(
                    technique      = "T1558.001",
                    technique_name = "Steal or Forge Kerberos Tickets",
                    sub_technique  = "Golden Ticket",
                    attack_type    = "golden_ticket",
                    risk_score     = 0.97,
                    command_line   = command_line,
                    source_ip      = source_ip,
                    target_ip      = target_ip,
                    username       = username,
                    matched_pattern = pattern.pattern,
                    description    = "Golden/Silver ticket creation detected — KRBTGT hash compromise",
                    recommendations = [
                        "CRITICAL: Reset KRBTGT password TWICE immediately",
                        "Assume full domain compromise — initiate IR",
                        "Audit all privileged account activity",
                        "Deploy Microsoft Defender for Identity",
                        "ATT&CK: T1558.001 — Golden Ticket",
                    ],
                )

        # Check Kerberoasting BEFORE PTT (rubeus kerberoast matches PTT otherwise)
        for pattern in self._kerb_patterns:
            if pattern.search(command_line):
                return self._make_alert(
                    technique      = "T1558.003",
                    technique_name = "Steal or Forge Kerberos Tickets",
                    sub_technique  = "Kerberoasting",
                    attack_type    = "kerberoasting",
                    risk_score     = 0.88,
                    command_line   = command_line,
                    source_ip      = source_ip,
                    target_ip      = target_ip,
                    username       = username,
                    matched_pattern = pattern.pattern,
                    description    = "Kerberoasting tool detected — SPN ticket harvesting for offline cracking",
                    recommendations = [
                        "Audit service accounts with SPNs",
                        "Enforce strong passwords on service accounts (25+ chars)",
                        "Use Group Managed Service Accounts (gMSA)",
                        "Enable AES encryption for Kerberos (disable RC4)",
                        "ATT&CK: T1558.003 — Kerberoasting",
                    ],
                )

        # Check PtH patterns
        for pattern in self._pth_patterns:
            if pattern.search(command_line):
                return self._make_alert(
                    technique      = "T1550.002",
                    technique_name = "Use Alternate Authentication Material",
                    sub_technique  = "Pass-the-Hash",
                    attack_type    = "pth",
                    risk_score     = 0.92,
                    command_line   = command_line,
                    source_ip      = source_ip,
                    target_ip      = target_ip,
                    username       = username,
                    matched_pattern = pattern.pattern,
                    description    = "Pass-the-Hash tool pattern detected in command line",
                    recommendations = [
                        "Isolate source host immediately",
                        "Reset NTLM hashes for affected accounts",
                        "Enable Protected Users security group",
                        "Disable NTLM authentication where possible",
                        "ATT&CK: T1550.002 — Pass-the-Hash",
                    ],
                )

        # Check PtT patterns
        for pattern in self._ptt_patterns:
            if pattern.search(command_line):
                return self._make_alert(
                    technique      = "T1550.003",
                    technique_name = "Use Alternate Authentication Material",
                    sub_technique  = "Pass-the-Ticket",
                    attack_type    = "ptt",
                    risk_score     = 0.93,
                    command_line   = command_line,
                    source_ip      = source_ip,
                    target_ip      = target_ip,
                    username       = username,
                    matched_pattern = pattern.pattern,
                    description    = "Pass-the-Ticket tool pattern detected — Kerberos ticket injection",
                    recommendations = [
                        "Purge Kerberos tickets on affected hosts: klist purge",
                        "Reset KRBTGT password twice (golden ticket invalidation)",
                        "Review Kerberos ticket lifetimes",
                        "Enable Kerberos armoring (FAST)",
                        "ATT&CK: T1550.003 — Pass-the-Ticket",
                    ],
                )

        # Check cookie theft patterns
        for pattern in self._cookie_patterns:
            if pattern.search(command_line):
                return self._make_alert(
                    technique      = "T1550.004",
                    technique_name = "Use Alternate Authentication Material",
                    sub_technique  = "Web Session Cookie",
                    attack_type    = "cookie_theft",
                    risk_score     = 0.82,
                    command_line   = command_line,
                    source_ip      = source_ip,
                    target_ip      = target_ip,
                    username       = username,
                    matched_pattern = pattern.pattern,
                    description    = "Web session cookie theft pattern detected",
                    recommendations = [
                        "Invalidate all active sessions for affected users",
                        "Enable MFA for web applications",
                        "Implement short session timeouts",
                        "Enable Secure and HttpOnly cookie flags",
                        "ATT&CK: T1550.004 — Web Session Cookie",
                    ],
                )

        # Check for raw NTLM hash in command line
        if NTLM_PAIR_RE.search(command_line):
            return self._make_alert(
                technique      = "T1550.002",
                technique_name = "Use Alternate Authentication Material",
                sub_technique  = "Pass-the-Hash (NTLM hash in command)",
                attack_type    = "pth",
                risk_score     = 0.90,
                command_line   = command_line,
                source_ip      = source_ip,
                target_ip      = target_ip,
                username       = username,
                matched_pattern = "LM:NTLM hash pair pattern",
                description    = "NTLM hash pair detected in command line — possible PtH attack",
                recommendations = [
                    "Investigate source of NTLM hash",
                    "Reset affected account credentials",
                    "ATT&CK: T1550.002 — Pass-the-Hash",
                ],
            )

        return None

    def analyze_event(self, event: dict) -> Optional[AlternateAuthAlert]:
        """
        Analyze a Windows security event for alternate auth patterns.

        Args:
            event: dict with:
                - event_id: int (Windows Event ID)
                - username: str
                - source_ip: str
                - target_ip: str (optional)
                - logon_type: int (optional)
                - ticket_encryption: int (optional, for Event 4769)
                - failure_reason: str (optional)
        """
        event_id       = event.get("event_id")
        username       = event.get("username", "")
        source_ip      = event.get("source_ip", "")
        target_ip      = event.get("target_ip", "")
        logon_type     = event.get("logon_type")
        ticket_enc     = event.get("ticket_encryption")

        # Event 4769: Kerberos Service Ticket Request
        # RC4 encryption (0x17) = Kerberoastable
        if event_id == 4769 and ticket_enc == 0x17:
            # Track SPN requests per user
            self._spn_requests[username].append(datetime.now(timezone.utc).isoformat())
            spn_count = len(self._spn_requests[username])

            if spn_count >= 3:  # Multiple SPN requests = Kerberoasting
                return self._make_alert(
                    technique      = "T1558.003",
                    technique_name = "Steal or Forge Kerberos Tickets",
                    sub_technique  = "Kerberoasting (Event 4769 RC4)",
                    attack_type    = "kerberoasting",
                    risk_score     = min(1.0, 0.75 + spn_count * 0.03),
                    command_line   = "",
                    source_ip      = source_ip,
                    target_ip      = target_ip,
                    username       = username,
                    event_id       = event_id,
                    logon_type     = logon_type,
                    matched_pattern = f"Event 4769 RC4 encryption × {spn_count}",
                    description    = f"Kerberoasting: {spn_count} RC4 SPN ticket requests from {username}@{source_ip}",
                    recommendations = [
                        f"Investigate {username} — {spn_count} RC4 SPN requests",
                        "Enforce AES encryption for Kerberos",
                        "Audit service accounts with SPNs",
                        "ATT&CK: T1558.003 — Kerberoasting",
                    ],
                )

        # Event 4624: Logon Success with suspicious logon type
        if event_id == 4624 and logon_type in PTH_LOGON_TYPES:
            # Logon type 9 (NewCredentials) from non-interactive source = PtH indicator
            if logon_type == 9 and source_ip and source_ip not in ("127.0.0.1", "::1"):
                return self._make_alert(
                    technique      = "T1550.002",
                    technique_name = "Use Alternate Authentication Material",
                    sub_technique  = "Pass-the-Hash (Logon Type 9)",
                    attack_type    = "pth",
                    risk_score     = 0.78,
                    command_line   = "",
                    source_ip      = source_ip,
                    target_ip      = target_ip,
                    username       = username,
                    event_id       = event_id,
                    logon_type     = logon_type,
                    matched_pattern = "Event 4624 LogonType=9 from remote IP",
                    description    = f"Suspicious NewCredentials logon (Type 9) from {source_ip} — possible PtH",
                    recommendations = [
                        "Investigate logon source",
                        "Check for Mimikatz or similar tools on source host",
                        "ATT&CK: T1550.002 — Pass-the-Hash",
                    ],
                )

        return None

    def _make_alert(self, technique: str, technique_name: str, sub_technique: str,
                    attack_type: str, risk_score: float, command_line: str,
                    source_ip: str, target_ip: str, username: str,
                    matched_pattern: str, description: str, recommendations: list[str],
                    event_id: Optional[int] = None,
                    logon_type: Optional[int] = None) -> AlternateAuthAlert:
        severity = self._severity(risk_score)
        alert = AlternateAuthAlert(
            technique       = technique,
            technique_name  = technique_name,
            sub_technique   = sub_technique,
            risk_score      = round(risk_score, 3),
            attack_type     = attack_type,
            source_ip       = source_ip,
            target_ip       = target_ip,
            username        = username,
            command_line    = command_line,
            event_id        = event_id,
            logon_type      = logon_type,
            matched_pattern = matched_pattern,
            severity        = severity,
            description     = description,
            recommendations = recommendations,
        )
        self._alerts.append(alert)
        return alert

    def get_alerts(self) -> list[AlternateAuthAlert]:
        return list(self._alerts)

    def get_stats(self) -> dict:
        by_type: dict[str, int] = {}
        by_technique: dict[str, int] = {}
        for a in self._alerts:
            by_type[a.attack_type]       = by_type.get(a.attack_type, 0) + 1
            by_technique[a.technique]    = by_technique.get(a.technique, 0) + 1
        return {
            "total_alerts":  len(self._alerts),
            "by_type":       by_type,
            "by_technique":  by_technique,
            "spn_requesters": {k: len(v) for k, v in self._spn_requests.items()},
        }

    def clear(self) -> None:
        self._alerts.clear()
        self._spn_requests.clear()
        self._failed_logins.clear()

    @staticmethod
    def _severity(risk: float) -> str:
        if risk >= 0.90: return "CRITICAL"
        if risk >= 0.80: return "HIGH"
        if risk >= 0.65: return "MEDIUM"
        return "LOW"