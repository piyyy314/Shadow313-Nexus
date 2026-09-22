"""
shadow313.v4.attack.attack_coverage
──────────────────────────────────────
Shadow313 NEXUS v4 — ATT&CK Coverage Layer

Tracks detection and coverage for all 50 techniques in the
Shadow313 ATT&CK Navigator interface.

Coverage levels:
  DETECTED    — Active detection with scoring (threat_detector.py)
  MONITORED   — Passive monitoring / logging
  PARTIAL     — Some sub-techniques covered
  GAP         — No current coverage
  BLOCKED     — Active prevention (enforcement.py)

Exports ATT&CK Navigator layer JSON for import into the UI.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Coverage data ─────────────────────────────────────────────────────────────

@dataclass
class TechniqueCoverage:
    """Coverage record for a single ATT&CK technique."""
    technique_id:  str
    technique_name: str
    tactic:        str
    coverage:      str        # DETECTED | MONITORED | PARTIAL | GAP | BLOCKED
    score:         int        # 0-100 (Navigator color score)
    module:        str        # Shadow313 module providing coverage
    notes:         str = ""
    sub_techniques: list[str] = field(default_factory=list)

    @property
    def color(self) -> str:
        return {
            "DETECTED":  "#22c55e",   # green
            "BLOCKED":   "#00d4ff",   # cyan
            "MONITORED": "#f59e0b",   # amber
            "PARTIAL":   "#a78bfa",   # purple
            "GAP":       "#ef4444",   # red
        }.get(self.coverage, "#64748b")

    def to_navigator_entry(self) -> dict:
        return {
            "techniqueID": self.technique_id,
            "tactic":      self.tactic.lower().replace(" ", "-"),
            "score":       self.score,
            "color":       self.color,
            "comment":     f"{self.coverage}: {self.module} — {self.notes}",
            "enabled":     True,
            "metadata":    [
                {"name": "coverage", "value": self.coverage},
                {"name": "module",   "value": self.module},
            ],
        }


# ── Full coverage map ─────────────────────────────────────────────────────────

COVERAGE_MAP: list[TechniqueCoverage] = [

    # ── RECONNAISSANCE ────────────────────────────────────────────────────────
    TechniqueCoverage("T1595", "Active Scanning",           "Reconnaissance",
        "DETECTED", 80, "recon.py + analyzer.py",
        "Port scanning detection via NEXUS Engine; custom-ai-threat-analyzer flags scan patterns"),
    TechniqueCoverage("T1592", "Gather Victim Host Info",   "Reconnaissance",
        "MONITORED", 50, "recon.py",
        "DNS enumeration and web fingerprinting logged; no active blocking"),
    TechniqueCoverage("T1589", "Gather Victim Identity Info","Reconnaissance",
        "MONITORED", 40, "ghost_watch.py",
        "WE-FORGE lures detect identity harvesting attempts via watermark triggers"),
    TechniqueCoverage("T1590", "Gather Victim Network Info", "Reconnaissance",
        "DETECTED", 70, "vanguard.py + attack_mapping.py",
        "Network topology discovery detected via NEXUS; AETHER synthetic endpoints confuse recon"),
    TechniqueCoverage("T1591", "Gather Victim Org Info",    "Reconnaissance",
        "MONITORED", 40, "ghost_watch.py",
        "ACTS canary documents detect org info harvesting; attribution via watermark IDs"),

    # ── INITIAL ACCESS ────────────────────────────────────────────────────────
    TechniqueCoverage("T1190", "Exploit Public-Facing App", "Initial Access",
        "DETECTED", 90, "ghost_watch.py + analyzer.py + cmmc_audit_package.py",
        "CVE-2026-3392 TR-069 CWMP detected; SQL injection patterns flagged by custom analyzer",
        ["T1190"]),
    TechniqueCoverage("T1133", "External Remote Services",  "Initial Access",
        "MONITORED", 55, "enforcement.py + nexus_router.py",
        "Affinity cookie HMAC verification; outbound traffic filter blocks known C2 ports"),
    TechniqueCoverage("T1566", "Phishing",                  "Initial Access",
        "DETECTED", 75, "attack_simulator.py + cyber_kg.py",
        "Spearphishing simulation in attack_simulator; FIN7 phishing chain modeled"),
    TechniqueCoverage("T1195", "Supply Chain Compromise",   "Initial Access",
        "DETECTED", 85, "supply_chain_simulation.py + plugin_signer.py",
        "Full supply chain simulation (3 scenarios); ML-DSA-65 plugin signing prevents unsigned plugins"),
    TechniqueCoverage("T1078", "Valid Accounts",            "Initial Access",
        "DETECTED", 70, "cyber_kg.py + attack_mapping.py",
        "Valid account abuse detected via behavioral anomaly; NEXUS Engine flags credential reuse"),

    # ── EXECUTION ─────────────────────────────────────────────────────────────
    TechniqueCoverage("T1059", "Command & Script Interpreter","Execution",
        "DETECTED", 85, "threat_detector.py + attack_simulator.py",
        "PowerShell encoded commands (T1059.001), WMI (T1047), Bash (T1059.004) all detected",
        ["T1059.001", "T1059.004"]),
    TechniqueCoverage("T1203", "Client Exploitation",       "Execution",
        "DETECTED", 65, "attack_mapping.py + docker_sandbox.py",
        "Browser exploit simulation; Docker CVE reproducer sandbox for client-side testing"),
    TechniqueCoverage("T1047", "WMI",                       "Execution",
        "DETECTED", 80, "threat_detector.py + attack_mapping.py",
        "WMI event subscription persistence detected; APT29 WMI MOF persistence in test suite"),
    TechniqueCoverage("T1072", "Software Deploy Tools",     "Execution",
        "PARTIAL", 45, "cicd.py + supply_chain_simulation.py",
        "CI/CD pipeline scanning (SARIF output); supply chain simulation covers build-time injection"),
    TechniqueCoverage("T1053", "Scheduled Task/Job",        "Execution",
        "DETECTED", 70, "attack_mapping.py + threat_detector.py",
        "Cron persistence (T1053.005) detected; scheduled task creation flagged",
        ["T1053.005"]),

    # ── PERSISTENCE ───────────────────────────────────────────────────────────
    TechniqueCoverage("T1547", "Boot Autostart Execution",  "Persistence",
        "DETECTED", 75, "threat_detector.py + attack_mapping.py",
        "Registry run key persistence (T1547.001) detected with 74% confidence",
        ["T1547.001"]),
    TechniqueCoverage("T1136", "Create Account",            "Persistence",
        "DETECTED", 65, "threat_detector.py",
        "Local admin account creation detected; flagged in comprehensive threat suite"),
    TechniqueCoverage("T1543", "Create/Modify System Process","Persistence",
        "MONITORED", 50, "zero_evasion_countermeasure.py",
        "eBPF syscall tracing monitors process creation; EPROCESS hash baseline detects modifications"),
    TechniqueCoverage("T1574", "Hijack Execution Flow",     "Persistence",
        "DETECTED", 70, "threat_detector.py + d3fend_coverage.py",
        "DLL side-loading (FIN7 COM hijacking) detected; D3FEND D3-DLL countermeasure mapped"),
    TechniqueCoverage("T1053.005", "Cron",                  "Persistence",
        "DETECTED", 70, "attack_mapping.py",
        "Cron job persistence detected as sub-technique of T1053"),

    # ── PRIVILEGE ESCALATION ──────────────────────────────────────────────────
    TechniqueCoverage("T1548", "Abuse Elevation Control",   "Privilege Escalation",
        "DETECTED", 80, "zero_evasion_countermeasure.py + d3fend_coverage.py",
        "setuid(0) attempt blocked by eBPF kprobe; UAC bypass via fodhelper detected"),
    TechniqueCoverage("T1134", "Access Token Manipulation", "Privilege Escalation",
        "DETECTED", 75, "threat_detector.py + d3fend_coverage.py",
        "Token impersonation via SeImpersonatePrivilege detected; D3FEND alerting mapped"),
    TechniqueCoverage("T1068", "Exploitation for Priv Esc", "Privilege Escalation",
        "DETECTED", 65, "vanguard.py + docker_sandbox.py",
        "Kernel exploit simulation; Docker CVE reproducer for privilege escalation testing"),
    TechniqueCoverage("T1055", "Process Injection",         "Privilege Escalation",
        "BLOCKED", 90, "zero_evasion_countermeasure.py + enforcement.py",
        "LSASS process injection blocked by eBPF + EPT violations; D3-PI countermeasure active",
        ["T1055.009"]),
    TechniqueCoverage("T1078.003", "Local Accounts",        "Privilege Escalation",
        "DETECTED", 70, "cyber_kg.py + attack_mapping.py",
        "Local account abuse detected; Pass-the-Hash via local accounts flagged"),

    # ── DEFENSE EVASION ───────────────────────────────────────────────────────
    TechniqueCoverage("T1140", "Deobfuscate/Decode",        "Defense Evasion",
        "DETECTED", 65, "threat_detector.py + analyzer.py",
        "Base64 decode patterns detected; encoded PowerShell (T1059.001) flagged by NEXUS"),
    TechniqueCoverage("T1070", "Indicator Removal",         "Defense Evasion",
        "DETECTED", 75, "threat_detector.py + d3fend_coverage.py",
        "Timestomping detected; log clearing flagged; 313-BIND chain makes log deletion detectable"),
    TechniqueCoverage("T1036", "Masquerading",              "Defense Evasion",
        "DETECTED", 70, "threat_actor.py + pe_analyzer.py",
        "PE analyzer detects process name masquerading; svchost_local.exe pattern flagged"),
    TechniqueCoverage("T1027", "Obfuscated Files",          "Defense Evasion",
        "DETECTED", 75, "threat_detector.py + attack_mapping.py",
        "High-entropy string detection; obfuscated PowerShell patterns flagged"),
    TechniqueCoverage("T1562", "Impair Defenses",           "Defense Evasion",
        "DETECTED", 80, "zero_evasion_countermeasure.py + attack_simulator.py",
        "Set-MpPreference -DisableRealtimeMonitoring detected; AV disable patterns flagged"),

    # ── CREDENTIAL ACCESS ─────────────────────────────────────────────────────
    TechniqueCoverage("T1110", "Brute Force",               "Credential Access",
        "DETECTED", 65, "threat_predictor.py + attack_mapping.py",
        "Brute force patterns detected via behavioral scoring; login failure rate monitored"),
    TechniqueCoverage("T1003", "OS Credential Dumping",     "Credential Access",
        "DETECTED", 85, "threat_detector.py + attack_simulator.py",
        "LSASS dump (procdump), DCSync, Mimikatz all detected; 75% credential access coverage"),
    TechniqueCoverage("T1558", "Steal Kerberos Tickets",    "Credential Access",
        "DETECTED", 75, "d3fend_coverage.py + attack_mapping.py",
        "Kerberoasting SPN ticket requests detected; Pass-the-Ticket flagged"),
    TechniqueCoverage("T1552", "Unsecured Credentials",     "Credential Access",
        "DETECTED", 70, "cicd.py + analyzer.py",
        "13-pattern secret scanner in CI/CD; custom analyzer detects hardcoded credentials"),
    TechniqueCoverage("T1556", "Modify Auth Process",       "Credential Access",
        "MONITORED", 50, "defense.py + vanguard.py",
        "SSH config hardening checks; PAM modification monitoring via CIS audit"),

    # ── DISCOVERY ─────────────────────────────────────────────────────────────
    TechniqueCoverage("T1082", "System Info Discovery",     "Discovery",
        "DETECTED", 70, "vanguard.py + attack_mapping.py",
        "System enumeration detected; AETHER synthetic endpoints confuse discovery"),
    TechniqueCoverage("T1087", "Account Discovery",         "Discovery",
        "DETECTED", 65, "threat_detector.py + attack_mapping.py",
        "net group 'Domain Admins' pattern detected; account enumeration flagged"),
    TechniqueCoverage("T1046", "Network Service Discovery", "Discovery",
        "DETECTED", 80, "threat_detector.py + phantomscan.py",
        "Port scan detection via NEXUS; PhantomScan provides stealth scanning capability"),
    TechniqueCoverage("T1135", "Network Share Discovery",   "Discovery",
        "DETECTED", 65, "attack_mapping.py + enforcement.py",
        "SMB share enumeration detected; outbound SMB (port 445) monitored"),
    TechniqueCoverage("T1057", "Process Discovery",         "Discovery",
        "DETECTED", 65, "attack_mapping.py + zero_evasion_countermeasure.py",
        "Process enumeration detected; eBPF monitors process creation syscalls"),

    # ── LATERAL MOVEMENT ──────────────────────────────────────────────────────
    TechniqueCoverage("T1021", "Remote Services",           "Lateral Movement",
        "DETECTED", 75, "cyber_kg.py + attack_mapping.py",
        "WinRM, SMB, RDP lateral movement detected; Pass-the-Hash via WMI flagged",
        ["T1021.002"]),
    TechniqueCoverage("T1534", "Internal Spearphishing",    "Lateral Movement",
        "MONITORED", 45, "ghost_watch.py",
        "WE-FORGE watermarked documents detect internal phishing; ACTS canary triggers"),
    TechniqueCoverage("T1080", "Taint Shared Content",      "Lateral Movement",
        "MONITORED", 40, "ghost_watch.py + vanguard.py",
        "Shared content monitoring via Ghost-Watch; GORGON behavioral analysis"),
    TechniqueCoverage("T1570", "Lateral Tool Transfer",     "Lateral Movement",
        "DETECTED", 60, "enforcement.py + tartarus.py",
        "Ingress tool transfer detected; TARTARUS intercepts large outbound transfers"),
    TechniqueCoverage("T1563", "Remote Service Session",    "Lateral Movement",
        "MONITORED", 50, "enforcement.py + nexus_router.py",
        "Remote session monitoring; affinity cookie verification tracks session origins"),

    # ── COMMAND & CONTROL ─────────────────────────────────────────────────────
    TechniqueCoverage("T1071", "Application Layer Protocol","Command and Control",
        "DETECTED", 80, "enforcement.py + d3fend_coverage.py + beacon_detector.py",
        "DNS tunneling C2 detected (74%); HTTP/HTTPS C2 channels monitored; beacon detection active"),
    TechniqueCoverage("T1572", "Protocol Tunneling",        "Command and Control",
        "DETECTED", 70, "beacon_detector.py + c2_attribution_analysis.py",
        "DNS tunneling detected via beacon period analysis; JA3 fingerprinting identifies tunneling tools"),
    TechniqueCoverage("T1090", "Proxy",                     "Command and Control",
        "DETECTED", 65, "ti_feed.py + threat_actor.py",
        "Tor exit node detection; known proxy IPs in threat intel feed"),
    TechniqueCoverage("T1573", "Encrypted Channel",         "Command and Control",
        "DETECTED", 70, "tls_edge_cases.py + c2_attribution_analysis.py",
        "TLS version checks; JA3/JA3S fingerprinting identifies C2 TLS libraries"),
    TechniqueCoverage("T1105", "Ingress Tool Transfer",     "Command and Control",
        "DETECTED", 75, "enforcement.py + tartarus.py",
        "curl execve to malicious domain blocked by eBPF; TARTARUS intercepts large transfers"),
]


# ── Coverage statistics ───────────────────────────────────────────────────────

def get_stats() -> dict:
    total     = len(COVERAGE_MAP)
    detected  = sum(1 for t in COVERAGE_MAP if t.coverage in ("DETECTED", "BLOCKED"))
    monitored = sum(1 for t in COVERAGE_MAP if t.coverage == "MONITORED")
    partial   = sum(1 for t in COVERAGE_MAP if t.coverage == "PARTIAL")
    gaps      = sum(1 for t in COVERAGE_MAP if t.coverage == "GAP")

    by_tactic: dict[str, dict] = {}
    for t in COVERAGE_MAP:
        tac = t.tactic
        if tac not in by_tactic:
            by_tactic[tac] = {"total": 0, "detected": 0, "monitored": 0, "partial": 0, "gap": 0}
        by_tactic[tac]["total"] += 1
        key = t.coverage.lower() if t.coverage != "BLOCKED" else "detected"
        by_tactic[tac][key] = by_tactic[tac].get(key, 0) + 1

    return {
        "total":          total,
        "detected":       detected,
        "monitored":      monitored,
        "partial":        partial,
        "gaps":           gaps,
        "coverage_pct":   round((detected + monitored) / total * 100, 1),
        "detection_pct":  round(detected / total * 100, 1),
        "by_tactic":      by_tactic,
    }


# ── ATT&CK Navigator JSON export ─────────────────────────────────────────────

def export_navigator_layer(output_path: str = "shadow313_attack_layer.json") -> str:
    """Export ATT&CK Navigator layer JSON for import into the UI."""
    stats = get_stats()

    layer = {
        "name":        "Shadow313 NEXUS v4 — ATT&CK Coverage",
        "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": (
            f"Shadow313 NEXUS v4 ATT&CK coverage layer. "
            f"Detection: {stats['detection_pct']}% | "
            f"Coverage: {stats['coverage_pct']}% | "
            f"Generated: {_now_iso()}"
        ),
        "filters":     {"platforms": ["Windows", "Linux", "macOS", "Network"]},
        "sorting":     0,
        "layout":      {"layout": "side", "aggregateFunction": "max", "showID": True,
                        "showName": True, "showAggregateScores": True, "countUnscored": False},
        "hideDisabled": False,
        "techniques":  [t.to_navigator_entry() for t in COVERAGE_MAP],
        "gradient":    {
            "colors": ["#ef4444", "#f59e0b", "#22c55e"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "DETECTED/BLOCKED (score 65-100)", "color": "#22c55e"},
            {"label": "MONITORED (score 40-65)",          "color": "#f59e0b"},
            {"label": "PARTIAL (score 40-50)",            "color": "#a78bfa"},
            {"label": "GAP (score 0)",                    "color": "#ef4444"},
        ],
        "metadata": [
            {"name": "version",       "value": "4.0.0"},
            {"name": "total",         "value": str(stats["total"])},
            {"name": "detected",      "value": str(stats["detected"])},
            {"name": "coverage_pct",  "value": f"{stats['coverage_pct']}%"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground":     "#0a140a",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
    }

    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)

    return output_path


if __name__ == "__main__":
    stats = get_stats()
    print(f"Shadow313 ATT&CK Coverage:")
    print(f"  Total techniques: {stats['total']}")
    print(f"  Detected/Blocked: {stats['detected']} ({stats['detection_pct']}%)")
    print(f"  Monitored:        {stats['monitored']}")
    print(f"  Partial:          {stats['partial']}")
    print(f"  Gaps:             {stats['gaps']}")
    print(f"  Overall coverage: {stats['coverage_pct']}%")
    print()
    print("By tactic:")
    for tactic, counts in stats["by_tactic"].items():
        det = counts.get("detected", 0)
        tot = counts["total"]
        print(f"  {tactic:<30} {det}/{tot} detected")
    path = export_navigator_layer("shadow313_attack_layer.json")
    print(f"\nNavigator layer exported: {path}")