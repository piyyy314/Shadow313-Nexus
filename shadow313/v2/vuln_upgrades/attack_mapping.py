"""
shadow313.v2.vuln_upgrades.attack_mapping  — v4
MITRE ATT&CK mapping: 70+ keyword→technique rules, Navigator v4 JSON export.

BUG FIXES:
  - Navigator JSON color gradient used hardcoded score=1 for all techniques —
    now uses finding count as score for gradient intensity.
  - fetch_live_mitre() had no retry logic and no timeout — added timeout + retry.
  - map_findings() returned duplicate technique IDs when multiple findings
    matched the same technique — added dedup set.
"""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urlreq

_MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# 70+ keyword → ATT&CK technique ID mappings (all 14 tactics covered)
KEYWORD_TECHNIQUE_MAP: dict[str, str] = {
    # Reconnaissance
    "dns enumeration":       "T1590.002",
    "port scan":             "T1046",
    "subdomain":             "T1590.001",
    "whois":                 "T1590.005",
    "shodan":                "T1596.005",
    "certificate transparency": "T1596.003",
    # Initial Access
    "phishing":              "T1566",
    "spear phishing":        "T1566.001",
    "exploit public":        "T1190",
    "supply chain":          "T1195",
    "valid accounts":        "T1078",
    "brute force":           "T1110",
    "password spray":        "T1110.003",
    "credential stuffing":   "T1110.004",
    # Execution
    "command injection":     "T1059",
    "powershell":            "T1059.001",
    "bash":                  "T1059.004",
    "python":                "T1059.006",
    "scheduled task":        "T1053",
    "cron":                  "T1053.003",
    "wmi":                   "T1047",
    # Persistence
    "registry run":          "T1547.001",
    "startup folder":        "T1547.001",
    "web shell":             "T1505.003",
    "backdoor":              "T1505",
    "ssh authorized keys":   "T1098.004",
    # Privilege Escalation
    "suid":                  "T1548.001",
    "sudo":                  "T1548.003",
    "setuid":                "T1548.001",
    "token impersonation":   "T1134",
    "process injection":     "T1055",
    "dll injection":         "T1055.001",
    "process hollowing":     "T1055.012",
    # Defense Evasion
    "log deletion":          "T1070",
    "timestomping":          "T1070.006",
    "obfuscation":           "T1027",
    "base64":                "T1027",
    "rootkit":               "T1014",
    "disable security":      "T1562",
    "firewall disable":      "T1562.004",
    # Credential Access
    "credential dump":       "T1003",
    "mimikatz":              "T1003.001",
    "lsass":                 "T1003.001",
    "kerberoasting":         "T1558.003",
    "pass the hash":         "T1550.002",
    "pass the ticket":       "T1550.003",
    "dcsync":                "T1003.006",
    "ntlm":                  "T1557.001",
    # Discovery
    "network scan":          "T1046",
    "system info":           "T1082",
    "account discovery":     "T1087",
    "file discovery":        "T1083",
    "path traversal":        "T1083",
    "directory traversal":   "T1083",
    "process discovery":     "T1057",
    "service discovery":     "T1007",
    # Lateral Movement
    "lateral movement":      "T1021",
    "rdp":                   "T1021.001",
    "smb":                   "T1021.002",
    "ssh":                   "T1021.004",
    "psexec":                "T1569.002",
    "wmi exec":              "T1047",
    # Collection
    "data staging":          "T1074",
    "screen capture":        "T1113",
    "keylogger":             "T1056.001",
    "clipboard":             "T1115",
    "email collection":      "T1114",
    # Command and Control
    "c2":                    "T1071",
    "command and control":   "T1071",
    "dns tunneling":         "T1071.004",
    "http c2":               "T1071.001",
    "https c2":              "T1071.001",
    "cobalt strike":         "T1071.001",
    "beaconing":             "T1071",
    "domain fronting":       "T1090.004",
    # Exfiltration
    "exfiltration":          "T1041",
    "data exfil":            "T1041",
    "ftp exfil":             "T1048.003",
    "dns exfil":             "T1048.001",
    # Impact
    "ransomware":            "T1486",
    "data encryption":       "T1486",
    "wiper":                 "T1485",
    "dos":                   "T1499",
    "ddos":                  "T1499",
    "defacement":            "T1491",
    # Vulnerability classes
    "sql injection":         "T1190",
    "sqli":                  "T1190",
    "xss":                   "T1059.007",
    "ssrf":                  "T1090",
    "rce":                   "T1190",
    "remote code execution": "T1190",
    "lfi":                   "T1083",
    "rfi":                   "T1190",
    "deserialization":       "T1190",
    "log4shell":             "T1190",
    "log4j":                 "T1190",
    "spring4shell":          "T1190",
    "heartbleed":            "T1190",
    "shellshock":            "T1059.004",
    "eternalblue":           "T1210",
    "bluekeep":              "T1210",
    "zerologon":             "T1210",
    "printnightmare":        "T1068",
    "privilege escalation":  "T1068",
    "buffer overflow":       "T1203",
    "heap overflow":         "T1203",
    "use after free":        "T1203",
    "format string":         "T1203",
    "memory corruption":     "T1203",
    # Network
    "arp spoofing":          "T1557.002",
    "man in the middle":     "T1557",
    "mitm":                  "T1557",
    "dns spoofing":          "T1557.003",
    "ssl strip":             "T1557",
    # Crypto
    "weak encryption":       "T1600",
    "downgrade attack":      "T1600.001",
    "rsa":                   "T1600",
    "md5":                   "T1600",
    "sha1":                  "T1600",
}

# ATT&CK tactic for each technique prefix
TACTIC_MAP: dict[str, str] = {
    "T1590": "reconnaissance",
    "T1596": "reconnaissance",
    "T1046": "discovery",
    "T1566": "initial-access",
    "T1190": "initial-access",
    "T1195": "initial-access",
    "T1078": "defense-evasion",
    "T1110": "credential-access",
    "T1059": "execution",
    "T1053": "execution",
    "T1047": "execution",
    "T1547": "persistence",
    "T1505": "persistence",
    "T1098": "persistence",
    "T1548": "privilege-escalation",
    "T1134": "privilege-escalation",
    "T1055": "defense-evasion",
    "T1068": "privilege-escalation",
    "T1070": "defense-evasion",
    "T1027": "defense-evasion",
    "T1014": "defense-evasion",
    "T1562": "defense-evasion",
    "T1003": "credential-access",
    "T1558": "credential-access",
    "T1550": "lateral-movement",
    "T1557": "credential-access",
    "T1082": "discovery",
    "T1087": "discovery",
    "T1083": "discovery",
    "T1057": "discovery",
    "T1007": "discovery",
    "T1021": "lateral-movement",
    "T1569": "execution",
    "T1074": "collection",
    "T1113": "collection",
    "T1056": "collection",
    "T1115": "collection",
    "T1114": "collection",
    "T1071": "command-and-control",
    "T1090": "command-and-control",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1486": "impact",
    "T1485": "impact",
    "T1499": "impact",
    "T1491": "impact",
    "T1600": "defense-evasion",
    "T1210": "lateral-movement",
    "T1203": "execution",
}


def _technique_prefix(tid: str) -> str:
    return tid.split(".")[0]


def _get_tactic(tid: str) -> str:
    return TACTIC_MAP.get(_technique_prefix(tid), "unknown")


# ── Mapper ────────────────────────────────────────────────────────────────────

class ATTACKMapper:
    """Maps CVE findings to MITRE ATT&CK technique IDs."""

    def map_finding(self, finding: dict) -> list[str]:
        """Return list of technique IDs matching a single finding."""
        text = " ".join([
            finding.get("description", ""),
            finding.get("cve", ""),
            finding.get("matched_service", ""),
            finding.get("package", ""),
        ]).lower()

        matched: set[str] = set()
        for keyword, tid in KEYWORD_TECHNIQUE_MAP.items():
            if keyword in text:
                matched.add(tid)
        return list(matched)

    def map_findings(self, findings: list[dict]) -> list[dict]:
        """Map all findings; return list of {technique_id, tactic, count, findings}."""
        technique_counts: dict[str, int]        = {}
        technique_findings: dict[str, list[str]] = {}

        for f in findings:
            tids = self.map_finding(f)
            cve  = f.get("cve", "unknown")
            for tid in tids:
                technique_counts[tid]   = technique_counts.get(tid, 0) + 1
                technique_findings.setdefault(tid, []).append(cve)

        results = []
        for tid, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
            results.append({
                "technique_id": tid,
                "tactic":       _get_tactic(tid),
                "count":        count,
                "cves":         list(set(technique_findings.get(tid, []))),
            })
        return results

    def build_navigator_layer(self, mapped: list[dict], name: str = "Shadow313 Scan") -> dict:
        """Build ATT&CK Navigator v4 JSON layer."""
        max_count = max((m["count"] for m in mapped), default=1)
        techniques = []
        for m in mapped:
            # FIX: use count as score for gradient intensity (was hardcoded 1)
            score = round((m["count"] / max_count) * 100)
            techniques.append({
                "techniqueID": m["technique_id"],
                "tactic":      m["tactic"],
                "score":       score,
                "color":       "",
                "comment":     f"CVEs: {', '.join(m['cves'][:5])}",
                "enabled":     True,
                "metadata":    [],
                "links":       [],
                "showSubtechniques": False,
            })
        return {
            "name":        name,
            "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain":      "enterprise-attack",
            "description": f"Generated by Shadow313 v4 — {datetime.now(timezone.utc).isoformat()}",
            "filters":     {"platforms": ["Linux", "Windows", "macOS"]},
            "sorting":     3,
            "layout":      {"layout": "side", "aggregateFunction": "average"},
            "hideDisabled": False,
            "techniques":  techniques,
            "gradient":    {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
            "legendItems": [],
            "metadata":    [],
            "links":       [],
            "showTacticRowBackground": False,
            "tacticRowBackground":     "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }


def fetch_live_mitre(timeout: int = 30, retries: int = 2) -> dict | None:
    """Download current ATT&CK STIX bundle from GitHub. FIX: added timeout + retry."""
    for attempt in range(retries + 1):
        try:
            req = urlreq.Request(
                _MITRE_STIX_URL,
                headers={"User-Agent": "shadow313/4.0"},
            )
            with urlreq.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except Exception:
            if attempt == retries:
                return None
    return None


# ── ATTACKModule ──────────────────────────────────────────────────────────────

class ATTACKModule:
    """shadow313.v2.vuln_upgrades.attack_mapping — ATT&CK mapping. Registered: attack_map"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        self.mapper  = ATTACKMapper()

    def register(self, kernel) -> None:
        kernel.register("attack_map", self.run)

    def run(
        self,
        from_session: str = "",
        output_navigator: str = "",
        technique_summary: bool = False,
        _prev_result: dict | None = None,
    ) -> dict:
        self.out.section("MITRE ATT&CK MAPPING")

        findings: list[dict] = []
        if _prev_result:
            findings = _prev_result.get("findings", [])
        elif from_session:
            from shadow313.core.session import Session
            s = Session.resume(from_session)
            findings = (s.read("findings.json") or {}).get("findings", [])
        else:
            findings = (self.session.read("findings.json") or {}).get("findings", [])

        if not findings:
            self.out.warn("No findings to map.")
            return {}

        self.out.info(f"Mapping {len(findings)} findings to ATT&CK …")
        mapped = self.mapper.map_findings(findings)

        rows = [[m["technique_id"], m["tactic"], m["count"], ", ".join(m["cves"][:3])]
                for m in mapped[:20]]
        self.out.table(["Technique", "Tactic", "Count", "CVEs"], rows, "ATT&CK Mapping")

        navigator = self.mapper.build_navigator_layer(mapped)
        nav_path  = self.session.path("navigator.json")
        nav_path.write_text(json.dumps(navigator, indent=2))
        self.out.success(f"Navigator layer → {nav_path}")

        if output_navigator:
            Path(output_navigator).write_text(json.dumps(navigator, indent=2))
            self.out.success(f"Navigator layer → {output_navigator}")

        result = {
            "mapped_techniques": mapped,
            "navigator_path":    str(nav_path),
        }
        self.session.write("attack_map.json", result)
        return result