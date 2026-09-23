"""
shadow313.v4.intelligence.honeypot_analyzer
Honeypot Event Analyzer — ATT&CK Mapper

Maps live honeypot telemetry from Aegis honeypot to MITRE ATT&CK techniques.
Ingests events from:
- SSH honeypot (port 2222) — brute force, credential stuffing
- Telnet honeypot (port 2323) — Mirai botnet, IoT attacks, SATCOM abuse
- Web traps (port 3000/80) — .env probes, scanner fingerprinting
- SATCOM intercepts — VSAT uplink manipulation, MODBUS abuse

ATT&CK techniques covered:
T1110.001 Brute Force: Password Guessing
T1552.001 Credentials In Files (.env probe)
T1105    Ingress Tool Transfer (wget malware)
T1059.004 Unix Shell (reverse shells, command injection)
T1498    Network Denial of Service (Mirai botnet)
T1565.001 Data Manipulation: Stored (VSAT/SATCOM)
T1548.001 Abuse Elevation Control: Setuid
T1003.008 OS Credential Dumping (/etc/shadow)
T1046    Network Service Discovery (port scanning)
T1598    Phishing for Information (WE-FORGE decoy)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── ATT&CK Technique Definitions ─────────────────────────────────────────────

HONEYPOT_ATTCK_MAP: list[dict] = [
    # Credential Access
    {
        "technique":   "T1110.001",
        "name":        "Brute Force: Password Guessing",
        "tactic":      "credential_access",
        "risk":        0.92,
        "indicators":  ["brute", "password123", "root:root", "admin:admin",
                        "cisco:cisco", "SSH.*Auth.*password", "hydra"],
        "services":    ["SSH", "TELNET"],
        "description": "Automated credential brute-forcing against SSH/Telnet services",
    },
    {
        "technique":   "T1552.001",
        "name":        "Credentials In Files",
        "tactic":      "credential_access",
        "risk":        0.88,
        "indicators":  [r"\.env", "GET.*\.env", "environment.*config", "api.key", "secret"],
        "services":    ["WEB", "HTTP"],
        "description": "Probing for .env files containing credentials and API keys",
    },
    {
        "technique":   "T1003.008",
        "name":        "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic":      "credential_access",
        "risk":        0.95,
        "indicators":  ["/etc/shadow", "/etc/passwd", "cat.*shadow", "openat.*shadow"],
        "services":    ["SSH", "TELNET", "EBPF"],
        "description": "Attempting to read /etc/shadow for offline password cracking",
    },
    # Execution
    {
        "technique":   "T1059.004",
        "name":        "Command and Scripting Interpreter: Unix Shell",
        "tactic":      "execution",
        "risk":        0.96,
        "indicators":  [r"nc.*-e.*/bin/sh", r"nc.*-lvp", r"/bin/sh", r"/bin/bash",
                        r"bash -i", r"execve.*payload\.sh", r"wget.*\|.*sh",
                        r"curl.*\|.*sh", r"os\.system", r"shell_equals_True"],
        "services":    ["TELNET", "SSH", "EBPF", "AST"],
        "description": "Unix shell execution via reverse shells, command injection, or scripting",
    },
    # Command and Control
    {
        "technique":   "T1105",
        "name":        "Ingress Tool Transfer",
        "tactic":      "command_and_control",
        "risk":        0.94,
        "indicators":  ["wget.*http", "curl.*http.*payload", "mirai", "dropper",
                        "chmod.*777.*tmp", "/tmp/drop", "bins/mirai"],
        "services":    ["TELNET", "SSH", "EBPF"],
        "description": "Downloading malware/tools from C2 server (Mirai botnet staging)",
    },
    {
        "technique":   "T1095",
        "name":        "Non-Application Layer Protocol",
        "tactic":      "command_and_control",
        "risk":        0.85,
        "indicators":  ["MODBUS", "IPoS", "SatCom Channel", "CWMP", "TR-069"],
        "services":    ["SATCOM"],
        "description": "C2 over non-standard protocols (MODBUS, SATCOM telemetry)",
    },
    # Impact
    {
        "technique":   "T1498",
        "name":        "Network Denial of Service",
        "tactic":      "impact",
        "risk":        0.90,
        "indicators":  ["mirai", "botnet", "DDoS", "flood", "arm7", "mips"],
        "services":    ["TELNET", "SSH"],
        "description": "Mirai botnet recruitment for DDoS amplification attacks",
    },
    {
        "technique":   "T1565.001",
        "name":        "Data Manipulation: Stored Data Manipulation",
        "tactic":      "impact",
        "risk":        0.93,
        "indicators":  ["SET_UPLINK_GAIN", "STIA_OVERRIDE", "MODBUS.*override",
                        "uplink.*gain", "teleport.*sector", "link budget"],
        "services":    ["SATCOM"],
        "description": "VSAT/SATCOM uplink parameter manipulation — signal disruption",
    },
    # Privilege Escalation
    {
        "technique":   "T1548.001",
        "name":        "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "tactic":      "privilege_escalation",
        "risk":        0.91,
        "indicators":  ["setuid.*0", "setuid(0)", "chmod.*s", "suid", "sudo su"],
        "services":    ["EBPF", "SSH"],
        "description": "Setuid(0) call to escalate to root privileges",
    },
    # Discovery
    {
        "technique":   "T1046",
        "name":        "Network Service Discovery",
        "tactic":      "discovery",
        "risk":        0.75,
        "indicators":  ["CensysInspect", "Shodan", "masscan", "nmap", "port.*scan",
                        "show running-config", "cat /proc/mounts"],
        "services":    ["WEB", "SSH", "TELNET"],
        "description": "Automated network scanning and service enumeration",
    },
    # Reconnaissance (Deception layer)
    {
        "technique":   "T1598",
        "name":        "Phishing for Information",
        "tactic":      "reconnaissance",
        "risk":        0.70,
        "indicators":  ["GW-LURE", "WE-FORGE", "decoy", "DNS Token Beacon",
                        "audit-vault", "ghost.watch.local"],
        "services":    ["WE-FORGE"],
        "description": "WE-FORGE decoy document accessed — attacker fingerprinted",
    },
    # Initial Access
    {
        "technique":   "T1190",
        "name":        "Exploit Public-Facing Application",
        "tactic":      "initial_access",
        "risk":        0.89,
        "indicators":  ["Hydra-Recon-PQC", "libssh", "exploit", "CVE-", "RCE"],
        "services":    ["WEB", "SSH"],
        "description": "Exploitation attempt against public-facing services",
    },
]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class HoneypotFinding:
    """A single ATT&CK-mapped honeypot finding."""
    technique:    str
    name:         str
    tactic:       str
    risk_score:   float
    source_ip:    str
    service:      str
    raw_event:    str
    description:  str
    matched_indicator: str
    timestamp:    str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "technique":          self.technique,
            "name":               self.name,
            "tactic":             self.tactic,
            "risk_score":         self.risk_score,
            "source_ip":          self.source_ip,
            "service":            self.service,
            "raw_event":          self.raw_event[:200],
            "description":        self.description,
            "matched_indicator":  self.matched_indicator,
            "timestamp":          self.timestamp,
        }


@dataclass
class HoneypotAnalysisResult:
    """Complete honeypot session analysis."""
    findings:          list[HoneypotFinding] = field(default_factory=list)
    banned_ips:        list[str]             = field(default_factory=list)
    total_connections: int  = 0
    credentials_harvested: int = 0
    techniques_detected:   list[str] = field(default_factory=list)
    tactics_detected:      list[str] = field(default_factory=list)
    risk_score:        float = 0.0
    timestamp:         str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "total_connections":      self.total_connections,
            "credentials_harvested":  self.credentials_harvested,
            "banned_ips":             self.banned_ips,
            "finding_count":          len(self.findings),
            "techniques_detected":    self.techniques_detected,
            "tactics_detected":       self.tactics_detected,
            "risk_score":             round(self.risk_score, 4),
            "findings":               [f.to_dict() for f in self.findings],
            "timestamp":              self.timestamp,
        }


# ── Analyzer ──────────────────────────────────────────────────────────────────

class HoneypotAnalyzer:
    """
    Maps honeypot telemetry events to MITRE ATT&CK techniques.

    Usage:
        analyzer = HoneypotAnalyzer()

        # Analyze a single event
        findings = analyzer.analyze_event(
            source_ip="185.220.101.5",
            service="WEB",
            action="HTTP GET /.env",
            payload="GET /.env HTTP/1.1",
        )

        # Analyze full honeypot session dump
        result = analyzer.analyze_session(honeypot_json)
    """

    def __init__(self) -> None:
        self._compiled = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        import re
        for entry in HONEYPOT_ATTCK_MAP:
            patterns = [re.compile(p, re.IGNORECASE) for p in entry["indicators"]]
            self._compiled.append((entry, patterns))

    def analyze_event(
        self,
        source_ip:  str,
        service:    str,
        action:     str,
        payload:    str = "",
        command:    str = "",
        credentials: Optional[dict] = None,
    ) -> list[HoneypotFinding]:
        """Map a single honeypot event to ATT&CK techniques."""
        findings = []
        text = f"{action} {payload} {command}".strip()

        for entry, patterns in self._compiled:
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    finding = HoneypotFinding(
                        technique=entry["technique"],
                        name=entry["name"],
                        tactic=entry["tactic"],
                        risk_score=entry["risk"],
                        source_ip=source_ip,
                        service=service,
                        raw_event=text[:200],
                        description=entry["description"],
                        matched_indicator=match.group(0),
                    )
                    findings.append(finding)
                    break  # one match per technique

        return findings

    def analyze_session(self, session_data: dict) -> HoneypotAnalysisResult:
        """
        Analyze a complete honeypot session JSON dump.
        Compatible with Aegis honeypot forensics format.
        """
        result = HoneypotAnalysisResult()

        # Extract metadata
        status = session_data.get("status", {})
        result.total_connections    = status.get("totalConnectionsCaught", 0)
        result.credentials_harvested = status.get("totalCredentialsHarvested", 0)

        # Extract banned IPs
        for rule in session_data.get("activeFirewallRules", []):
            ip = rule.get("ip", "")
            if ip and ip not in result.banned_ips:
                result.banned_ips.append(ip)

        # Analyze each intercepted log
        for log in session_data.get("interceptedLogs", []):
            source_ip = log.get("sourceIp", "unknown")
            service   = log.get("service", "UNKNOWN")
            action    = log.get("action", "")
            payload   = log.get("payload", "")
            command   = log.get("command", "")
            creds     = log.get("credentials")

            findings = self.analyze_event(
                source_ip=source_ip,
                service=service,
                action=action,
                payload=payload,
                command=command,
                credentials=creds,
            )
            result.findings.extend(findings)

        # Aggregate
        result.techniques_detected = list(set(f.technique for f in result.findings))
        result.tactics_detected    = list(set(f.tactic    for f in result.findings))
        result.risk_score          = self._aggregate_score(result.findings)

        return result

    def analyze_ebpf_events(self, ebpf_data: dict) -> list[HoneypotFinding]:
        """Analyze eBPF kernel telemetry events."""
        findings = []
        alerts = ebpf_data.get("alerts", [])

        for alert in alerts:
            if alert.get("status") != "intercepted":
                continue
            comm    = alert.get("comm", "")
            syscall = alert.get("syscall", "")
            args    = alert.get("args", "")
            text    = f"{comm} {syscall} {args}"

            event_findings = self.analyze_event(
                source_ip="localhost",
                service="EBPF",
                action=f"Kernel Intercept: {syscall} on {comm}",
                payload=args,
            )
            findings.extend(event_findings)

        return findings

    def analyze_ast_findings(self, ast_data: dict) -> list[HoneypotFinding]:
        """Analyze AST static analysis findings."""
        findings = []
        for vuln in ast_data.get("findings", []):
            vuln_type = vuln.get("type", "")
            code      = vuln.get("codeSnippet", "")
            text      = f"{vuln_type} {code}"

            event_findings = self.analyze_event(
                source_ip="localhost",
                service="AST",
                action=f"Static Threat: {vuln_type}",
                payload=code,
            )
            findings.extend(event_findings)

        return findings

    @staticmethod
    def _aggregate_score(findings: list[HoneypotFinding]) -> float:
        if not findings:
            return 0.0
        scores = sorted([f.risk_score for f in findings], reverse=True)
        total = scores[0]
        for i, s in enumerate(scores[1:], 1):
            total += s * (0.4 ** i)
        return min(total, 1.0)


# ── WE-FORGE Decoy Tracker ────────────────────────────────────────────────────

class WEForgeTracker:
    """
    Tracks WE-FORGE decoy document interactions.
    When a decoy is accessed, the attacker is fingerprinted via DNS beacon.
    """

    def __init__(self) -> None:
        self._decoys: list[dict] = []

    def register_decoy(self, decoy_data: dict) -> None:
        """Register a WE-FORGE decoy document."""
        self._decoys.append({
            "id":           decoy_data.get("ID", ""),
            "target_node":  decoy_data.get("Target Node", ""),
            "title":        decoy_data.get("Document Title", ""),
            "watermark":    decoy_data.get("Watermark Type", ""),
            "dns_beacon":   decoy_data.get("DNS Token Beacon", ""),
            "checksum":     decoy_data.get("Checksum", ""),
            "created":      decoy_data.get("Created Stamp", ""),
        })

    def get_active_decoys(self) -> list[dict]:
        return self._decoys

    def map_to_attck(self) -> list[dict]:
        """Map WE-FORGE decoy interactions to ATT&CK."""
        return [{
            "technique":   "T1598",
            "name":        "Phishing for Information",
            "tactic":      "reconnaissance",
            "description": "WE-FORGE decoy accessed — attacker fingerprinted via DNS beacon",
            "decoys":      self._decoys,
        }]
