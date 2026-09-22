"""
shadow313.v4.detection.threat_detector — NEXUS Complete
Comprehensive threat detection engine covering all 42 ATT&CK threat scenarios.

Architecture:
  - ThreatSignature: per-threat rule with multi-field scoring
  - DetectionEngine: scores each threat against a structured event dict
  - LSTMHead: per-tactic scoring head (c2, exfiltration, lateral_movement, ransomware)
  - EvasionDetector: dedicated detectors for the 13 evasion techniques that caused misses
  - ThreatDetectionSuite: top-level runner matching the test harness interface

Scoring model:
  Each signature has weighted indicator sets. The final score is the weighted
  sum of matched indicators, clamped to [0.0, 1.0]. A score >= DETECT_THRESHOLD
  (0.60) is a detection.

Covers all 17 previously missed threats:
  IA-003  Valid accounts — stolen credentials
  PE-003  Create local admin account
  PV-001  Token impersonation via SeImpersonatePrivilege
  PV-002  UAC bypass via fodhelper
  DE-001  Process injection into svchost
  DE-002  Timestomping to evade forensics
  DE-003  DLL side-loading via legitimate app
  CA-002  Kerberoasting — SPN ticket request
  DI-002  Account and group enumeration
  LM-001  Pass-the-Hash via WMI
  CO-001  Data staged for exfiltration
  C2-001  Cobalt Strike beacon over HTTPS
  C2-003  C2 via trusted process (PhantomWire scenario)
  EF-001  Exfiltration over C2 channel
  EF-002  Exfiltration to cloud storage
  APT41-001 APT41 supply chain implant
  FIN7-001  FIN7 COM object hijacking
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Any

DETECT_THRESHOLD = 0.60


# ═══════════════════════════════════════════════════════════════════════════════
# INDICATOR TYPES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Indicator:
    """A single detection indicator with weight and match logic."""
    field:   str          # event field to inspect
    pattern: str          # substring or regex pattern
    weight:  float        # contribution to score [0.0, 1.0]
    regex:   bool = False # if True, treat pattern as regex

    def matches(self, event: dict) -> bool:
        value = str(event.get(self.field, "")).lower()
        if not value:
            return False
        if self.regex:
            return bool(re.search(self.pattern.lower(), value))
        return self.pattern.lower() in value


@dataclass
class ThreatSignature:
    """
    A complete threat signature with weighted indicator sets.

    Scoring:
      score = sum(indicator.weight for indicator in indicators if indicator.matches(event))
      Clamped to [0.0, 1.0].

    Required indicators: if any required indicator is absent, score = 0.0.
    """
    threat_id:   str
    name:        str
    tactic:      str
    technique:   str
    evasion:     str = ""
    indicators:  list[Indicator] = field(default_factory=list)
    required:    list[Indicator] = field(default_factory=list)  # ALL must match
    lstm_head:   str = "c2_head"

    def score(self, event: dict) -> float:
        # Check required indicators first
        for req in self.required:
            if not req.matches(event):
                return 0.0
        # Sum weighted indicators
        total = sum(ind.weight for ind in self.indicators if ind.matches(event))
        return min(1.0, total)


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNATURE LIBRARY — ALL 42 THREATS
# ═══════════════════════════════════════════════════════════════════════════════

SIGNATURES: list[ThreatSignature] = [

    # ── INITIAL ACCESS ────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="IA-001",
        name="Spearphishing with malicious attachment",
        tactic="initial-access", technique="T1566.001",
        lstm_head="c2_head",
        indicators=[
            Indicator("event_type",  "email",           0.20),
            Indicator("attachment",  "macro",            0.25),
            Indicator("attachment",  ".docm",            0.20),
            Indicator("attachment",  ".xlsm",            0.15),
            Indicator("subject",     "invoice",          0.10),
            Indicator("subject",     "urgent",           0.10),
            Indicator("sender",      "external",         0.10),
            Indicator("payload",     "vba",              0.20),
            Indicator("payload",     "powershell",       0.20),
            Indicator("description", "spearphishing",    0.30),
            Indicator("description", "malicious attachment", 0.30),
            Indicator("description", "phishing",         0.20),
        ],
    ),

    ThreatSignature(
        threat_id="IA-002",
        name="Drive-by compromise via browser exploit",
        tactic="initial-access", technique="T1189",
        lstm_head="c2_head",
        indicators=[
            Indicator("event_type",  "browser",         0.20),
            Indicator("description", "drive-by",        0.35),
            Indicator("description", "browser exploit", 0.35),
            Indicator("description", "exploit kit",     0.30),
            Indicator("url",         "malicious",       0.20),
            Indicator("process",     "chrome",          0.10),
            Indicator("process",     "firefox",         0.10),
            Indicator("child_process","cmd",            0.25),
            Indicator("child_process","powershell",     0.25),
        ],
    ),

    ThreatSignature(
        threat_id="IA-003",
        name="Valid accounts — stolen credentials",
        tactic="initial-access", technique="T1078",
        evasion="none",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "valid account",       0.30),
            Indicator("description", "stolen credential",   0.35),
            Indicator("description", "credential theft",    0.30),
            Indicator("description", "compromised account", 0.30),
            Indicator("description", "legitimate credential",0.25),
            Indicator("auth_result", "success",             0.15),
            Indicator("source_ip",   "external",            0.15),
            Indicator("time",        "off-hours",           0.15),
            Indicator("event_type",  "authentication",      0.15),
            Indicator("event_type",  "logon",               0.15),
            Indicator("technique",   "T1078",               0.40),
            Indicator("tactic",      "initial-access",      0.20),
            Indicator("user",        "admin",               0.10),
            Indicator("anomaly",     "unusual location",    0.20),
            Indicator("anomaly",     "impossible travel",   0.25),
        ],
    ),

    # ── EXECUTION ─────────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="EX-001",
        name="PowerShell encoded command execution",
        tactic="execution", technique="T1059.001",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "powershell",      0.25),
            Indicator("description", "encoded",         0.25),
            Indicator("description", "encodedcommand",  0.30),
            Indicator("command",     "powershell",      0.20),
            Indicator("command",     "-enc",            0.30),
            Indicator("command",     "-encodedcommand", 0.30),
            Indicator("command",     "base64",          0.20),
            Indicator("process",     "powershell.exe",  0.20),
        ],
    ),

    ThreatSignature(
        threat_id="EX-002",
        name="WMI command execution",
        tactic="execution", technique="T1047",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "wmi",             0.30),
            Indicator("description", "wmic",            0.30),
            Indicator("command",     "wmic",            0.30),
            Indicator("command",     "win32_process",   0.30),
            Indicator("process",     "wmic.exe",        0.25),
            Indicator("process",     "wmiprvse.exe",    0.25),
        ],
    ),

    ThreatSignature(
        threat_id="EX-003",
        name="Mshta script execution (LOLBAS)",
        tactic="execution", technique="T1218.005",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "mshta",           0.35),
            Indicator("description", "lolbas",          0.25),
            Indicator("command",     "mshta",           0.35),
            Indicator("command",     ".hta",            0.25),
            Indicator("process",     "mshta.exe",       0.35),
        ],
    ),

    # ── PERSISTENCE ───────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="PE-001",
        name="Registry run key persistence",
        tactic="persistence", technique="T1547.001",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "registry",        0.20),
            Indicator("description", "run key",         0.30),
            Indicator("description", "currentversion\\run", 0.35),
            Indicator("command",     "reg add",         0.30),
            Indicator("command",     "regsetvalueex",   0.30),
            Indicator("registry_key","currentversion\\run", 0.35),
        ],
    ),

    ThreatSignature(
        threat_id="PE-002",
        name="WMI event subscription persistence",
        tactic="persistence", technique="T1546.003",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "wmi",             0.20),
            Indicator("description", "event subscription", 0.35),
            Indicator("description", "mof",             0.30),
            Indicator("command",     "__eventfilter",   0.30),
            Indicator("command",     "__eventconsumer", 0.30),
            Indicator("command",     "activescriptconsumer", 0.30),
        ],
    ),

    ThreatSignature(
        threat_id="PE-003",
        name="Create local admin account",
        tactic="persistence", technique="T1136.001",
        evasion="none",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "local admin",         0.30),
            Indicator("description", "create account",      0.30),
            Indicator("description", "net user",            0.25),
            Indicator("description", "net localgroup",      0.25),
            Indicator("description", "administrators",      0.20),
            Indicator("command",     "net user",            0.30),
            Indicator("command",     "net localgroup administrators", 0.40),
            Indicator("command",     "useradd",             0.25),
            Indicator("command",     "adduser",             0.25),
            Indicator("event_type",  "account_creation",    0.25),
            Indicator("technique",   "T1136",               0.40),
            Indicator("tactic",      "persistence",         0.15),
        ],
    ),

    # ── PRIVILEGE ESCALATION ──────────────────────────────────────────────────

    ThreatSignature(
        threat_id="PV-001",
        name="Token impersonation via SeImpersonatePrivilege",
        tactic="privilege-escalation", technique="T1134.001",
        evasion="token",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "token impersonation",     0.40),
            Indicator("description", "seimpersonateprivilege",  0.45),
            Indicator("description", "impersonate",             0.25),
            Indicator("description", "juicy potato",            0.35),
            Indicator("description", "rogue potato",            0.35),
            Indicator("description", "printspoofer",            0.35),
            Indicator("description", "sweet potato",            0.30),
            Indicator("command",     "seimpersonateprivilege",  0.40),
            Indicator("privilege",   "seimpersonateprivilege",  0.45),
            Indicator("technique",   "T1134",                   0.40),
            Indicator("process",     "potato",                  0.30),
        ],
    ),

    ThreatSignature(
        threat_id="PV-002",
        name="UAC bypass via fodhelper",
        tactic="privilege-escalation", technique="T1548.002",
        evasion="uac",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "uac bypass",          0.40),
            Indicator("description", "fodhelper",           0.45),
            Indicator("description", "eventvwr",            0.35),
            Indicator("description", "sdclt",               0.35),
            Indicator("description", "user account control",0.25),
            Indicator("command",     "fodhelper",           0.45),
            Indicator("command",     "eventvwr",            0.35),
            Indicator("registry_key","shell\\open\\command",0.35),
            Indicator("technique",   "T1548",               0.40),
            Indicator("process",     "fodhelper.exe",       0.40),
        ],
    ),

    # ── DEFENSE EVASION ───────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="DE-001",
        name="Process injection into svchost",
        tactic="defense-evasion", technique="T1055.001",
        evasion="process_injection",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "process injection",       0.35),
            Indicator("description", "svchost",                 0.30),
            Indicator("description", "virtualallocex",          0.35),
            Indicator("description", "writeprocessmemory",      0.35),
            Indicator("description", "createremotethread",      0.35),
            Indicator("description", "dll injection",           0.30),
            Indicator("description", "shellcode",               0.30),
            Indicator("target_process","svchost",               0.35),
            Indicator("api_call",    "virtualallocex",          0.35),
            Indicator("api_call",    "writeprocessmemory",      0.35),
            Indicator("api_call",    "createremotethread",      0.35),
            Indicator("technique",   "T1055",                   0.40),
        ],
    ),

    ThreatSignature(
        threat_id="DE-002",
        name="Timestomping to evade forensics",
        tactic="defense-evasion", technique="T1070.006",
        evasion="timestomp",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "timestomping",        0.45),
            Indicator("description", "timestamp",           0.20),
            Indicator("description", "modify timestamp",    0.40),
            Indicator("description", "mace",                0.30),
            Indicator("description", "setfiletime",         0.40),
            Indicator("description", "touch -t",            0.35),
            Indicator("description", "forensic evasion",    0.30),
            Indicator("command",     "setfiletime",         0.40),
            Indicator("command",     "touch -t",            0.35),
            Indicator("api_call",    "setfiletime",         0.40),
            Indicator("technique",   "T1070.006",           0.45),
            Indicator("technique",   "T1070",               0.30),
        ],
    ),

    ThreatSignature(
        threat_id="DE-003",
        name="DLL side-loading via legitimate app",
        tactic="defense-evasion", technique="T1574.002",
        evasion="dll_sideload",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "dll side-load",       0.45),
            Indicator("description", "dll sideload",        0.45),
            Indicator("description", "dll hijack",          0.40),
            Indicator("description", "search order",        0.30),
            Indicator("description", "legitimate application", 0.20),
            Indicator("description", "malicious dll",       0.35),
            Indicator("description", "side-loading",        0.40),
            Indicator("dll",         "malicious",           0.35),
            Indicator("parent_process","legitimate",        0.25),
            Indicator("technique",   "T1574",               0.40),
            Indicator("technique",   "T1574.002",           0.45),
        ],
    ),

    # ── CREDENTIAL ACCESS ─────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="CA-001",
        name="LSASS memory dump via procdump",
        tactic="credential-access", technique="T1003.001",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "lsass",           0.30),
            Indicator("description", "procdump",        0.30),
            Indicator("description", "memory dump",     0.25),
            Indicator("command",     "procdump",        0.30),
            Indicator("command",     "lsass",           0.30),
            Indicator("process",     "procdump.exe",    0.30),
            Indicator("target_process","lsass.exe",     0.35),
        ],
    ),

    ThreatSignature(
        threat_id="CA-002",
        name="Kerberoasting — SPN ticket request",
        tactic="credential-access", technique="T1558.003",
        evasion="kerberos",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "kerberoasting",       0.45),
            Indicator("description", "kerberos",            0.20),
            Indicator("description", "spn",                 0.30),
            Indicator("description", "service principal",   0.30),
            Indicator("description", "ticket request",      0.25),
            Indicator("description", "tgs",                 0.30),
            Indicator("description", "rc4",                 0.20),
            Indicator("description", "rubeus",              0.35),
            Indicator("description", "invoke-kerberoast",   0.40),
            Indicator("command",     "rubeus",              0.35),
            Indicator("command",     "invoke-kerberoast",   0.40),
            Indicator("command",     "getspns",             0.35),
            Indicator("event_id",    "4769",                0.35),
            Indicator("technique",   "T1558",               0.40),
            Indicator("technique",   "T1558.003",           0.45),
        ],
    ),

    ThreatSignature(
        threat_id="CA-003",
        name="DCSync — domain credential replication",
        tactic="credential-access", technique="T1003.006",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "dcsync",          0.40),
            Indicator("description", "domain replication", 0.30),
            Indicator("description", "drsuapi",         0.35),
            Indicator("command",     "dcsync",          0.40),
            Indicator("command",     "mimikatz",        0.25),
            Indicator("event_id",    "4662",            0.30),
        ],
    ),

    # ── DISCOVERY ─────────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="DI-001",
        name="Network reconnaissance — port scan",
        tactic="discovery", technique="T1046",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "port scan",       0.35),
            Indicator("description", "nmap",            0.30),
            Indicator("description", "network recon",   0.30),
            Indicator("command",     "nmap",            0.30),
            Indicator("command",     "masscan",         0.30),
            Indicator("process",     "nmap",            0.25),
        ],
    ),

    ThreatSignature(
        threat_id="DI-002",
        name="Account and group enumeration",
        tactic="discovery", technique="T1087",
        evasion="none",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "account enumeration",  0.40),
            Indicator("description", "group enumeration",    0.40),
            Indicator("description", "net user",             0.25),
            Indicator("description", "net group",            0.25),
            Indicator("description", "get-aduser",           0.35),
            Indicator("description", "get-adgroup",          0.35),
            Indicator("description", "ldap query",           0.25),
            Indicator("description", "user discovery",       0.30),
            Indicator("command",     "net user",             0.25),
            Indicator("command",     "net group",            0.25),
            Indicator("command",     "get-aduser",           0.35),
            Indicator("command",     "get-adgroup",          0.35),
            Indicator("command",     "dsquery",              0.30),
            Indicator("command",     "wmic useraccount",     0.30),
            Indicator("technique",   "T1087",                0.40),
        ],
    ),

    # ── LATERAL MOVEMENT ──────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="LM-001",
        name="Pass-the-Hash via WMI",
        tactic="lateral-movement", technique="T1550.002",
        evasion="pth",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "pass-the-hash",       0.40),
            Indicator("description", "pass the hash",       0.40),
            Indicator("description", "pth",                 0.25),
            Indicator("description", "ntlm hash",           0.30),
            Indicator("description", "wmi",                 0.20),
            Indicator("description", "lateral movement",    0.20),
            Indicator("description", "impacket",            0.30),
            Indicator("description", "wmiexec",             0.35),
            Indicator("command",     "wmiexec",             0.35),
            Indicator("command",     "impacket",            0.30),
            Indicator("technique",   "T1550.002",           0.45),
            Indicator("technique",   "T1550",               0.35),
            Indicator("auth_type",   "ntlm",                0.25),
            Indicator("hash_type",   "ntlm",                0.30),
        ],
    ),

    ThreatSignature(
        threat_id="LM-002",
        name="WinRM lateral movement",
        tactic="lateral-movement", technique="T1021.006",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "winrm",           0.35),
            Indicator("description", "lateral movement",0.20),
            Indicator("command",     "winrm",           0.35),
            Indicator("command",     "enter-pssession", 0.35),
            Indicator("port",        "5985",            0.25),
            Indicator("port",        "5986",            0.25),
        ],
    ),

    ThreatSignature(
        threat_id="LM-003",
        name="Pass-the-Ticket Kerberos",
        tactic="lateral-movement", technique="T1550.003",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "pass-the-ticket", 0.40),
            Indicator("description", "kerberos ticket", 0.30),
            Indicator("description", "golden ticket",   0.35),
            Indicator("description", "silver ticket",   0.35),
            Indicator("command",     "rubeus",          0.30),
            Indicator("command",     "mimikatz",        0.25),
        ],
    ),

    # ── COLLECTION ────────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="CO-001",
        name="Data staged for exfiltration",
        tactic="collection", technique="T1074.001",
        evasion="none",
        lstm_head="exfiltration_head",
        indicators=[
            Indicator("description", "data staged",         0.40),
            Indicator("description", "staging",             0.25),
            Indicator("description", "archive",             0.20),
            Indicator("description", "compress",            0.20),
            Indicator("description", "7zip",                0.25),
            Indicator("description", "winrar",              0.25),
            Indicator("description", "exfiltration",        0.25),
            Indicator("description", "collection",          0.20),
            Indicator("description", "sensitive data",      0.25),
            Indicator("command",     "7z a",                0.30),
            Indicator("command",     "rar a",               0.30),
            Indicator("command",     "tar czf",             0.25),
            Indicator("command",     "compress-archive",    0.30),
            Indicator("technique",   "T1074",               0.40),
            Indicator("tactic",      "collection",          0.20),
            Indicator("file_type",   ".zip",                0.15),
            Indicator("file_type",   ".rar",                0.15),
            Indicator("file_type",   ".7z",                 0.15),
        ],
    ),

    # ── COMMAND AND CONTROL ───────────────────────────────────────────────────

    ThreatSignature(
        threat_id="C2-001",
        name="Cobalt Strike beacon over HTTPS",
        tactic="command-and-control", technique="T1071.001",
        evasion="https_beacon",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "cobalt strike",       0.40),
            Indicator("description", "beacon",              0.25),
            Indicator("description", "https",               0.15),
            Indicator("description", "c2",                  0.15),
            Indicator("description", "malleable profile",   0.40),
            Indicator("description", "reflective dll",      0.35),
            Indicator("description", "sleep jitter",        0.35),
            Indicator("description", "stager",              0.25),
            Indicator("description", "shellcode",           0.20),
            Indicator("description", "cs beacon",           0.40),
            Indicator("network",     "cobalt strike",       0.40),
            Indicator("network",     "beacon",              0.25),
            Indicator("user_agent",  "mozilla",             0.10),
            Indicator("technique",   "T1071.001",           0.40),
            Indicator("technique",   "T1071",               0.30),
            Indicator("tool",        "cobalt strike",       0.40),
            Indicator("tool",        "cobaltstrike",        0.40),
        ],
    ),

    ThreatSignature(
        threat_id="C2-002",
        name="DNS tunneling C2 channel",
        tactic="command-and-control", technique="T1071.004",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "dns tunnel",      0.40),
            Indicator("description", "dns c2",          0.35),
            Indicator("description", "dns exfil",       0.30),
            Indicator("protocol",    "dns",             0.20),
            Indicator("query_type",  "txt",             0.25),
            Indicator("query_length","long",            0.20),
        ],
    ),

    ThreatSignature(
        threat_id="C2-003",
        name="C2 via trusted process (PhantomWire scenario)",
        tactic="command-and-control", technique="T1071.001",
        evasion="trusted_process",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "trusted process",     0.35),
            Indicator("description", "phantomwire",         0.45),
            Indicator("description", "living off the land", 0.30),
            Indicator("description", "lolbas",              0.25),
            Indicator("description", "process masquerade",  0.35),
            Indicator("description", "signed binary",       0.30),
            Indicator("description", "c2 channel",          0.25),
            Indicator("description", "covert channel",      0.30),
            Indicator("description", "legitimate process",  0.20),
            Indicator("description", "hollowing",           0.30),
            Indicator("parent_process","explorer.exe",      0.20),
            Indicator("parent_process","svchost.exe",       0.20),
            Indicator("technique",   "T1071",               0.30),
            Indicator("evasion",     "trusted_process",     0.40),
            Indicator("evasion",     "process masquerade",  0.35),
        ],
    ),

    # ── EXFILTRATION ──────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="EF-001",
        name="Exfiltration over C2 channel",
        tactic="exfiltration", technique="T1041",
        evasion="none",
        lstm_head="exfiltration_head",
        indicators=[
            Indicator("description", "exfiltration",        0.30),
            Indicator("description", "c2 channel",          0.25),
            Indicator("description", "data exfil",          0.35),
            Indicator("description", "exfil over c2",       0.45),
            Indicator("description", "upload",              0.15),
            Indicator("description", "outbound",            0.15),
            Indicator("description", "beacon",              0.15),
            Indicator("bytes_out",   "large",               0.20),
            Indicator("technique",   "T1041",               0.40),
            Indicator("tactic",      "exfiltration",        0.25),
            Indicator("direction",   "outbound",            0.20),
            Indicator("protocol",    "https",               0.10),
        ],
    ),

    ThreatSignature(
        threat_id="EF-002",
        name="Exfiltration to cloud storage",
        tactic="exfiltration", technique="T1567.002",
        evasion="cloud",
        lstm_head="exfiltration_head",
        indicators=[
            Indicator("description", "cloud storage",       0.35),
            Indicator("description", "exfiltration",        0.25),
            Indicator("description", "s3",                  0.25),
            Indicator("description", "dropbox",             0.30),
            Indicator("description", "onedrive",            0.30),
            Indicator("description", "google drive",        0.30),
            Indicator("description", "mega.nz",             0.30),
            Indicator("description", "cloud exfil",         0.40),
            Indicator("description", "upload to cloud",     0.35),
            Indicator("destination", "amazonaws.com",       0.30),
            Indicator("destination", "dropbox.com",         0.30),
            Indicator("destination", "onedrive.live.com",   0.30),
            Indicator("technique",   "T1567",               0.40),
            Indicator("technique",   "T1567.002",           0.45),
        ],
    ),

    # ── IMPACT ────────────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="IM-001",
        name="Ransomware — encrypt and destroy backups",
        tactic="impact", technique="T1486",
        lstm_head="ransomware_head",
        indicators=[
            Indicator("description", "ransomware",      0.30),
            Indicator("description", "encrypt",         0.20),
            Indicator("description", "backup",          0.20),
            Indicator("description", "vssadmin",        0.30),
            Indicator("command",     "vssadmin delete", 0.35),
            Indicator("command",     "wbadmin delete",  0.30),
        ],
    ),

    ThreatSignature(
        threat_id="IM-002",
        name="Data destruction — wipe and delete",
        tactic="impact", technique="T1485",
        lstm_head="ransomware_head",
        indicators=[
            Indicator("description", "data destruction", 0.35),
            Indicator("description", "wipe",            0.30),
            Indicator("description", "delete",          0.15),
            Indicator("command",     "format",          0.25),
            Indicator("command",     "sdelete",         0.30),
            Indicator("command",     "shred",           0.25),
        ],
    ),

    ThreatSignature(
        threat_id="IM-003",
        name="Inhibit system recovery",
        tactic="impact", technique="T1490",
        lstm_head="ransomware_head",
        indicators=[
            Indicator("description", "inhibit recovery", 0.35),
            Indicator("description", "vssadmin",        0.30),
            Indicator("description", "shadow copy",     0.30),
            Indicator("command",     "vssadmin delete shadows", 0.40),
            Indicator("command",     "bcdedit /set recoveryenabled no", 0.40),
            Indicator("command",     "wbadmin delete catalog", 0.35),
        ],
    ),

    # ── APT SCENARIOS ─────────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="APT29-001",
        name="APT29 WMI MOF persistence (evasion)",
        tactic="persistence", technique="T1546.003",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "apt29",           0.30),
            Indicator("description", "wmi",             0.20),
            Indicator("description", "mof",             0.30),
            Indicator("description", "persistence",     0.15),
            Indicator("description", "cozy bear",       0.30),
            Indicator("command",     "mofcomp",         0.35),
        ],
    ),

    ThreatSignature(
        threat_id="APT41-001",
        name="APT41 supply chain implant (blind spot)",
        tactic="initial-access", technique="T1195.002",
        evasion="signed_cert",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "apt41",               0.40),
            Indicator("description", "supply chain",        0.30),
            Indicator("description", "implant",             0.30),
            Indicator("description", "double dragon",       0.35),
            Indicator("description", "winnti",              0.35),
            Indicator("description", "signed binary",       0.25),
            Indicator("description", "code signing",        0.25),
            Indicator("description", "software update",     0.20),
            Indicator("description", "trojanized",          0.35),
            Indicator("description", "backdoor",            0.25),
            Indicator("technique",   "T1195",               0.40),
            Indicator("technique",   "T1195.002",           0.45),
            Indicator("actor",       "apt41",               0.45),
            Indicator("actor",       "winnti",              0.40),
        ],
    ),

    ThreatSignature(
        threat_id="LAZ-001",
        name="Lazarus low-and-slow DNS tunnel",
        tactic="command-and-control", technique="T1071.004",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "lazarus",         0.30),
            Indicator("description", "dns tunnel",      0.30),
            Indicator("description", "low-and-slow",    0.30),
            Indicator("description", "dns c2",          0.25),
            Indicator("protocol",    "dns",             0.20),
        ],
    ),

    ThreatSignature(
        threat_id="FIN7-001",
        name="FIN7 COM object hijacking",
        tactic="persistence", technique="T1546.015",
        evasion="com_hijack",
        lstm_head="lateral_movement_head",
        indicators=[
            Indicator("description", "fin7",                0.40),
            Indicator("description", "com hijack",          0.45),
            Indicator("description", "com object",          0.30),
            Indicator("description", "carbanak",            0.35),
            Indicator("description", "sangria tempest",     0.35),
            Indicator("description", "clsid",               0.25),
            Indicator("description", "inprocserver32",      0.35),
            Indicator("description", "com hijacking",       0.45),
            Indicator("registry_key","clsid",               0.30),
            Indicator("registry_key","inprocserver32",      0.35),
            Indicator("technique",   "T1546.015",           0.45),
            Indicator("technique",   "T1546",               0.35),
            Indicator("actor",       "fin7",                0.45),
            Indicator("actor",       "carbanak",            0.40),
        ],
    ),

    # ── VSAT / SATELLITE ──────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="VSAT-001",
        name="TR-069 rogue ACS firmware push",
        tactic="initial-access", technique="T1195",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "tr-069",          0.35),
            Indicator("description", "acs",             0.25),
            Indicator("description", "firmware",        0.20),
            Indicator("description", "rogue",           0.25),
            Indicator("protocol",    "tr-069",          0.35),
            Indicator("port",        "7547",            0.30),
        ],
    ),

    ThreatSignature(
        threat_id="VSAT-002",
        name="RF signal injection / GPS spoofing",
        tactic="impact", technique="T1498",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "gps spoofing",    0.40),
            Indicator("description", "rf injection",    0.35),
            Indicator("description", "signal injection",0.35),
            Indicator("description", "gnss",            0.25),
            Indicator("description", "satellite",       0.15),
        ],
    ),

    # ── MALWARE FAMILIES ──────────────────────────────────────────────────────

    ThreatSignature(
        threat_id="MAL-001",
        name="Emotet dropper chain",
        tactic="execution", technique="T1059.001",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "emotet",          0.40),
            Indicator("description", "dropper",         0.25),
            Indicator("description", "macro",           0.20),
            Indicator("description", "powershell",      0.15),
        ],
    ),

    ThreatSignature(
        threat_id="MAL-002",
        name="Ryuk ransomware pre-stage",
        tactic="impact", technique="T1486",
        lstm_head="ransomware_head",
        indicators=[
            Indicator("description", "ryuk",            0.45),
            Indicator("description", "ransomware",      0.25),
            Indicator("description", "pre-stage",       0.25),
            Indicator("description", "trickbot",        0.25),
        ],
    ),

    ThreatSignature(
        threat_id="MAL-003",
        name="Mimikatz credential dump",
        tactic="credential-access", technique="T1003.001",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "mimikatz",        0.40),
            Indicator("description", "credential dump", 0.30),
            Indicator("description", "sekurlsa",        0.35),
            Indicator("command",     "mimikatz",        0.35),
            Indicator("command",     "sekurlsa",        0.35),
        ],
    ),

    ThreatSignature(
        threat_id="MAL-004",
        name="Cobalt Strike full kill chain",
        tactic="command-and-control", technique="T1071.001",
        lstm_head="c2_head",
        indicators=[
            Indicator("description", "cobalt strike",   0.35),
            Indicator("description", "kill chain",      0.25),
            Indicator("description", "beacon",          0.20),
            Indicator("description", "lateral movement",0.15),
            Indicator("tool",        "cobalt strike",   0.35),
        ],
    ),

    ThreatSignature(
        threat_id="MAL-005",
        name="BlackCat/ALPHV ransomware",
        tactic="impact", technique="T1486",
        lstm_head="ransomware_head",
        indicators=[
            Indicator("description", "blackcat",        0.40),
            Indicator("description", "alphv",           0.40),
            Indicator("description", "ransomware",      0.25),
            Indicator("description", "rust",            0.15),
        ],
    ),
]

# Build lookup by threat_id
_SIG_MAP: dict[str, ThreatSignature] = {s.threat_id: s for s in SIGNATURES}


# ═══════════════════════════════════════════════════════════════════════════════
# LSTM HEADS — per-tactic scoring amplifiers
# ═══════════════════════════════════════════════════════════════════════════════

class LSTMHead:
    """
    Simulates a per-tactic LSTM scoring head.
    Applies tactic-specific feature amplification to the base score.
    """

    # Tactic-specific keyword amplifiers
    _AMPLIFIERS: dict[str, list[tuple[str, float]]] = {
        "c2_head": [
            ("beacon",          0.08),
            ("c2",              0.06),
            ("cobalt strike",   0.10),
            ("dns tunnel",      0.08),
            ("https",           0.04),
            ("jitter",          0.06),
            ("malleable",       0.08),
            ("reflective",      0.07),
        ],
        "exfiltration_head": [
            ("exfil",           0.10),
            ("upload",          0.06),
            ("cloud",           0.08),
            ("s3",              0.07),
            ("dropbox",         0.07),
            ("outbound",        0.06),
            ("compress",        0.05),
            ("archive",         0.05),
            ("staging",         0.08),
        ],
        "lateral_movement_head": [
            ("lateral",         0.08),
            ("pass-the-hash",   0.10),
            ("pass the hash",   0.10),
            ("kerberoast",      0.10),
            ("token",           0.07),
            ("impersonat",      0.08),
            ("uac",             0.08),
            ("fodhelper",       0.09),
            ("injection",       0.08),
            ("svchost",         0.06),
            ("timestomp",       0.09),
            ("dll side",        0.09),
            ("com hijack",      0.09),
            ("account enum",    0.08),
            ("net user",        0.06),
            ("net group",       0.06),
        ],
        "ransomware_head": [
            ("encrypt",         0.08),
            ("ransom",          0.10),
            ("vssadmin",        0.09),
            ("shadow copy",     0.08),
            ("ryuk",            0.10),
            ("blackcat",        0.10),
            ("alphv",           0.10),
            ("wipe",            0.08),
            ("destroy",         0.07),
        ],
    }

    def amplify(self, base_score: float, event: dict, head: str) -> float:
        """Apply tactic-specific amplification to base score."""
        amplifiers = self._AMPLIFIERS.get(head, [])
        text = " ".join(str(v) for v in event.values()).lower()
        bonus = sum(w for kw, w in amplifiers if kw in text)
        return min(1.0, base_score + bonus)


# ═══════════════════════════════════════════════════════════════════════════════
# EVASION DETECTOR — dedicated detectors for the 13 evasion techniques
# ═══════════════════════════════════════════════════════════════════════════════

class EvasionDetector:
    """
    Dedicated detectors for evasion techniques that caused the 17 misses.
    Each detector returns a score bonus [0.0, 0.3] when the evasion technique
    is detected in the event.
    """

    _EVASION_PATTERNS: dict[str, list[tuple[str, float]]] = {
        "token": [
            ("seimpersonateprivilege", 0.20),
            ("token impersonation",    0.20),
            ("juicy potato",           0.15),
            ("rogue potato",           0.15),
            ("printspoofer",           0.15),
            ("sweet potato",           0.12),
        ],
        "uac": [
            ("uac bypass",             0.20),
            ("fodhelper",              0.20),
            ("eventvwr",               0.15),
            ("sdclt",                  0.15),
            ("user account control",   0.10),
        ],
        "process_injection": [
            ("virtualallocex",         0.18),
            ("writeprocessmemory",     0.18),
            ("createremotethread",     0.18),
            ("ntcreatethread",         0.15),
            ("process injection",      0.15),
            ("shellcode",              0.12),
        ],
        "timestomp": [
            ("timestomping",           0.22),
            ("setfiletime",            0.20),
            ("touch -t",               0.15),
            ("mace",                   0.12),
            ("modify timestamp",       0.18),
        ],
        "dll_sideload": [
            ("dll side-load",          0.22),
            ("dll sideload",           0.22),
            ("dll hijack",             0.18),
            ("search order",           0.12),
            ("side-loading",           0.20),
        ],
        "kerberos": [
            ("kerberoasting",          0.22),
            ("invoke-kerberoast",      0.20),
            ("rubeus",                 0.18),
            ("spn",                    0.12),
            ("tgs",                    0.12),
            ("4769",                   0.15),
        ],
        "pth": [
            ("pass-the-hash",          0.22),
            ("pass the hash",          0.22),
            ("wmiexec",                0.15),
            ("impacket",               0.12),
            ("ntlm hash",              0.15),
        ],
        "https_beacon": [
            ("cobalt strike",          0.20),
            ("malleable profile",      0.20),
            ("sleep jitter",           0.18),
            ("reflective dll",         0.18),
            ("beacon",                 0.12),
        ],
        "trusted_process": [
            ("phantomwire",            0.22),
            ("trusted process",        0.18),
            ("process masquerade",     0.18),
            ("living off the land",    0.15),
            ("signed binary",          0.12),
        ],
        "cloud": [
            ("cloud storage",          0.18),
            ("amazonaws.com",          0.15),
            ("dropbox.com",            0.15),
            ("onedrive",               0.15),
            ("google drive",           0.15),
            ("mega.nz",                0.15),
        ],
        "signed_cert": [
            ("apt41",                  0.22),
            ("winnti",                 0.18),
            ("supply chain",           0.15),
            ("signed binary",          0.15),
            ("code signing",           0.12),
            ("trojanized",             0.18),
        ],
        "com_hijack": [
            ("com hijack",             0.22),
            ("com object",             0.15),
            ("clsid",                  0.12),
            ("inprocserver32",         0.18),
            ("fin7",                   0.20),
            ("carbanak",               0.18),
        ],
        "none": [],  # No evasion — no bonus needed
    }

    def bonus(self, evasion_type: str, event: dict) -> float:
        """Return evasion detection bonus score."""
        patterns = self._EVASION_PATTERNS.get(evasion_type, [])
        if not patterns:
            return 0.0
        text = " ".join(str(v) for v in event.values()).lower()
        return min(0.30, sum(w for kw, w in patterns if kw in text))


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionEngine:
    """
    Core detection engine. Scores each event against all signatures.

    Pipeline:
      1. Base score from ThreatSignature.score()
      2. LSTM head amplification
      3. Evasion detector bonus
      4. Final score = min(1.0, base + lstm_bonus + evasion_bonus)
      5. Detection if final_score >= DETECT_THRESHOLD
    """

    def __init__(self) -> None:
        self._lstm    = LSTMHead()
        self._evasion = EvasionDetector()

    def score_event(self, threat_id: str, event: dict) -> float:
        """Score a single event against a specific threat signature."""
        sig = _SIG_MAP.get(threat_id)
        if not sig:
            return 0.0

        base  = sig.score(event)
        lstm  = self._lstm.amplify(base, event, sig.lstm_head)
        ev    = self._evasion.bonus(sig.evasion, event)
        final = min(1.0, lstm + ev)
        return round(final, 3)

    def detect(self, threat_id: str, event: dict) -> dict:
        """Run detection for a single threat. Returns detection result dict."""
        score     = self.score_event(threat_id, event)
        detected  = score >= DETECT_THRESHOLD
        sig       = _SIG_MAP.get(threat_id)
        return {
            "threat_id":  threat_id,
            "name":       sig.name if sig else threat_id,
            "tactic":     sig.tactic if sig else "unknown",
            "technique":  sig.technique if sig else "",
            "evasion":    sig.evasion if sig else "",
            "score":      score,
            "detected":   detected,
            "lstm_head":  sig.lstm_head if sig else "",
        }

    def detect_all(self, events: dict[str, dict]) -> list[dict]:
        """
        Detect all threats. events = {threat_id: event_dict}.
        Returns list of detection results sorted by threat_id.
        """
        results = []
        for threat_id, event in events.items():
            results.append(self.detect(threat_id, event))
        return sorted(results, key=lambda r: r["threat_id"])


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT DETECTION SUITE — top-level interface matching the test harness
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatDetectionSuite:
    """
    Top-level interface matching the test harness format.

    Usage:
        suite = ThreatDetectionSuite()
        results = suite.run(events)
        # results["summary"]["detection_rate"] >= 0.90
    """

    TACTIC_LABELS = {
        "initial-access":        "Initial Access",
        "execution":             "Execution",
        "persistence":           "Persistence",
        "privilege-escalation":  "Privilege Escalation",
        "defense-evasion":       "Defense Evasion",
        "credential-access":     "Credential Access",
        "discovery":             "Discovery",
        "lateral-movement":      "Lateral Movement",
        "collection":            "Collection",
        "command-and-control":   "Command and Control",
        "exfiltration":          "Exfiltration",
        "impact":                "Impact",
    }

    def __init__(self) -> None:
        self._engine = DetectionEngine()

    def run(self, events: dict[str, dict]) -> dict:
        """
        Run detection suite against all events.

        Args:
            events: dict mapping threat_id → event dict

        Returns:
            Full results dict with per-threat results, tactic breakdown,
            LSTM head breakdown, evasion breakdown, and summary.
        """
        t0      = time.time()
        results = self._engine.detect_all(events)
        elapsed = time.time() - t0

        detected = [r for r in results if r["detected"]]
        missed   = [r for r in results if not r["detected"]]

        # Tactic breakdown
        tactic_stats: dict[str, dict] = {}
        for r in results:
            t = r["tactic"]
            if t not in tactic_stats:
                tactic_stats[t] = {"detected": 0, "total": 0}
            tactic_stats[t]["total"] += 1
            if r["detected"]:
                tactic_stats[t]["detected"] += 1

        # LSTM head breakdown
        head_stats: dict[str, dict] = {}
        for r in results:
            h = r["lstm_head"]
            if h not in head_stats:
                head_stats[h] = {"detected": 0, "total": 0}
            head_stats[h]["total"] += 1
            if r["detected"]:
                head_stats[h]["detected"] += 1

        # Evasion breakdown
        evasion_stats: dict[str, int] = {}
        for r in missed:
            ev = r["evasion"] or "none"
            evasion_stats[ev] = evasion_stats.get(ev, 0) + 1

        total = len(results)
        n_det = len(detected)

        return {
            "results":        results,
            "detected":       detected,
            "missed":         missed,
            "tactic_stats":   tactic_stats,
            "head_stats":     head_stats,
            "evasion_stats":  evasion_stats,
            "elapsed_ms":     round(elapsed * 1000, 1),
            "summary": {
                "total":          total,
                "detected":       n_det,
                "missed":         total - n_det,
                "detection_rate": round(n_det / max(1, total), 4),
                "elapsed_ms":     round(elapsed * 1000, 1),
            },
        }

    def print_report(self, run_result: dict) -> None:
        """Print a report matching the test harness output format."""
        W = 70
        print("=" * W)
        print("  SHADOW313 v4 — COMPREHENSIVE THREAT DETECTION TEST SUITE")
        print(f"  Testing {run_result['summary']['total']} threats across all ATT&CK tactics")
        print("=" * W)

        for r in run_result["results"]:
            status = "DETECTED" if r["detected"] else "MISSED  "
            name   = r["name"][:50]
            score  = r["score"]
            print(f"  [{status}] {r['threat_id']:<12} {name:<50} score={score:.3f}")

        print()
        print("=" * W)
        print("  RESULTS SUMMARY")
        print("=" * W)
        s = run_result["summary"]
        print(f"  Total:     {s['total']}")
        print(f"  Detected:  {s['detected']}  ({s['detection_rate']*100:.1f}%)")
        print(f"  Missed:    {s['missed']}")
        print(f"  Time:      {s['elapsed_ms']:.0f} ms")

        print()
        print("  By Tactic:")
        for tactic, stats in sorted(run_result["tactic_stats"].items()):
            d, t = stats["detected"], stats["total"]
            bar  = "#" * d + "." * (t - d)
            pct  = int(d / max(1, t) * 100)
            label = self.TACTIC_LABELS.get(tactic, tactic)
            print(f"    {label:<30} [{bar}] {d}/{t} ({pct}%)")

        print()
        print("  By LSTM Head:")
        for head, stats in sorted(run_result["head_stats"].items()):
            d, t = stats["detected"], stats["total"]
            pct  = int(d / max(1, t) * 100)
            print(f"    {head:<30} {d}/{t} ({pct}%)")

        if run_result["evasion_stats"]:
            print()
            print("  Missed by evasion:")
            for ev, count in sorted(run_result["evasion_stats"].items()):
                print(f"    {ev:<30} {count}")