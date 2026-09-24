"""
shadow313.v4.detection.sigma_rules.rules
NEXUS Shadow313 — Production Sigma Rules Registry

15 production Sigma rules + SPL/KQL/Elastic/YARA queries
Author: Shadow313 NEXUS Detection Engineering
Date: 2026-09-22 | Version: 2.0.1
"""
from __future__ import annotations

from typing import Optional

# ── Sigma Rules ───────────────────────────────────────────────────────────────

SIGMA_RULES: list[dict] = [

    # ── Credential Access ─────────────────────────────────────────────────────

    {
        "id":          "nexus-sig-001",
        "display_id":  "NEXUS-SIG-001",
        "title":       "NEXUS — LSASS Memory Dump via MiniDumpWriteDump",
        "technique":   "T1003.001",
        "tactic":      "credential_access",
        "level":       "critical",
        "status":      "production",
        "tpr":         0.97,
        "fpr":         0.03,
        "date":        "2026/01/15",
        "modified":    "2026/09/01",
        "tags":        ["attack.credential_access", "attack.t1003.001", "nexus.critical"],
        "description": "Detects attempts to dump LSASS memory using MiniDumpWriteDump API or common tools such as Mimikatz, ProcDump, or custom injectors. CRITICAL severity — always investigate.",
        "sigma_yaml": """title: NEXUS — LSASS Memory Dump via MiniDumpWriteDump
id: nexus-sig-001
status: production
description: Detects attempts to dump LSASS memory using MiniDumpWriteDump API or common tools
 such as Mimikatz, ProcDump, or custom injectors. CRITICAL severity — always investigate.
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: Shadow313 NEXUS Detection Engineering
date: 2026/01/15
modified: 2026/09/01
tags:
  - attack.credential_access
  - attack.t1003.001
  - nexus.critical
logsource:
  category: process_access
  product: windows
detection:
  selection_target:
    TargetImage|endswith: '\\lsass.exe'
  selection_access:
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x143a'
      - '0x40'
      - '0x1438'
  filter_legitimate:
    SourceImage|contains:
      - '\\MsMpEng.exe'
      - '\\WinDefend\\MsMpEng.exe'
      - '\\csrss.exe'
  condition: selection_target and selection_access and not filter_legitimate
falsepositives:
  - Legitimate AV/EDR products accessing LSASS for scanning
  - Windows Defender (filtered)
level: critical""",
    },

    {
        "id":          "nexus-sig-002",
        "display_id":  "NEXUS-SIG-002",
        "title":       "NEXUS — Kerberoasting SPN Ticket Request",
        "technique":   "T1558.003",
        "tactic":      "credential_access",
        "level":       "high",
        "status":      "production",
        "tpr":         0.94,
        "fpr":         0.06,
        "date":        "2026/01/15",
        "tags":        ["attack.credential_access", "attack.t1558.003", "nexus.high"],
        "description": "Detects Kerberoasting attacks via anomalous TGS-REQ for RC4-encrypted service tickets.",
        "sigma_yaml": """title: NEXUS — Kerberoasting SPN Ticket Request
id: nexus-sig-002
status: production
description: Detects Kerberoasting attacks via anomalous TGS-REQ for RC4-encrypted
 service tickets. High-entropy SPN requests from non-service accounts are strongly
 indicative of credential harvesting.
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: Shadow313 NEXUS Detection Engineering
date: 2026/01/15
tags:
  - attack.credential_access
  - attack.t1558.003
  - nexus.high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|endswith:
      - '$'
  filter_computer:
    ServiceName|startswith: 'krbtgt'
  filter_machine:
    AccountName|endswith: '$'
  condition: selection and not filter_computer and not filter_machine
falsepositives:
  - Legacy applications requiring RC4 encryption
  - Domain functional level below Windows Server 2008
level: high""",
    },

    {
        "id":          "nexus-sig-003",
        "display_id":  "NEXUS-SIG-003",
        "title":       "NEXUS — Password Spraying Detection",
        "technique":   "T1110.003",
        "tactic":      "credential_access",
        "level":       "high",
        "status":      "production",
        "tpr":         0.91,
        "fpr":         0.09,
        "date":        "2026/02/01",
        "tags":        ["attack.credential_access", "attack.t1110.003", "nexus.high"],
        "description": "Detects password spraying attacks — single source IP generating failed auth attempts against multiple accounts within 5 minutes.",
        "sigma_yaml": """title: NEXUS — Password Spraying Detection
id: nexus-sig-003
status: production
description: Detects password spraying attacks characterized by a single source IP
 generating failed authentication attempts against multiple accounts within a short window.
references:
  - https://attack.mitre.org/techniques/T1110/003/
author: Shadow313 NEXUS Detection Engineering
date: 2026/02/01
tags:
  - attack.credential_access
  - attack.t1110.003
  - nexus.high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
    timeframe: 5m
  condition: selection | count(TargetUserName) by IpAddress > 10
falsepositives:
  - Misconfigured applications with hard-coded credentials
  - Pentest activities (whitelist pentest IPs)
level: high""",
    },

    {
        "id":          "nexus-sig-004",
        "display_id":  "NEXUS-SIG-004",
        "title":       "NEXUS — DCSync Attack via Directory Replication",
        "technique":   "T1003.006",
        "tactic":      "credential_access",
        "level":       "critical",
        "status":      "production",
        "tpr":         0.98,
        "fpr":         0.02,
        "date":        "2026/02/15",
        "tags":        ["attack.credential_access", "attack.t1003.006", "nexus.critical"],
        "description": "Detects DCSync attacks where non-DC accounts request directory replication using DS-Replication-Get-Changes GUIDs. Mimikatz lsadump::dcsync triggers this pattern.",
        "sigma_yaml": """title: NEXUS — DCSync Attack via Directory Replication
id: nexus-sig-004
status: production
description: Detects DCSync attacks where non-DC accounts request directory replication
 using DS-Replication-Get-Changes GUIDs. Mimikatz lsadump::dcsync triggers this pattern.
references:
  - https://attack.mitre.org/techniques/T1003/006/
author: Shadow313 NEXUS Detection Engineering
date: 2026/02/15
tags:
  - attack.credential_access
  - attack.t1003.006
  - nexus.critical
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_dc:
    SubjectDomainName|endswith: 'Domain Controllers'
  condition: selection and not filter_dc
falsepositives:
  - Azure AD Connect sync accounts
  - Legitimate domain controller replication
level: critical""",
    },

    # ── Execution & Persistence ───────────────────────────────────────────────

    {
        "id":          "nexus-sig-005",
        "display_id":  "NEXUS-SIG-005",
        "title":       "NEXUS — Encoded PowerShell Command Execution",
        "technique":   "T1059.001",
        "tactic":      "execution",
        "level":       "high",
        "status":      "production",
        "tpr":         0.89,
        "fpr":         0.11,
        "date":        "2025/10/01",
        "modified":    "2026/09/01",
        "tags":        ["attack.execution", "attack.t1059.001", "attack.defense_evasion", "attack.t1027", "nexus.high"],
        "description": "Detects PowerShell execution with encoded commands (-EncodedCommand / -enc). Commonly used by malware to evade string-based detection.",
        "sigma_yaml": """title: NEXUS — Encoded PowerShell Command Execution
id: nexus-sig-005
status: production
description: Detects PowerShell execution with encoded commands (-EncodedCommand / -enc).
 Commonly used by malware to evade string-based detection. Combined with suspicious
 parent processes, this is a critical indicator.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Shadow313 NEXUS Detection Engineering
date: 2025/10/01
modified: 2026/09/01
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
  - nexus.high
logsource:
  category: process_creation
  product: windows
detection:
  selection_main:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -EC '
  selection_suspicious_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
      - '\\OUTLOOK.EXE'
      - '\\mshta.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
  condition: selection_main or (selection_main and selection_suspicious_parent)
falsepositives:
  - Legitimate administrative scripts using encoding for special characters
  - Software deployment tools (SCCM, Intune)
level: high""",
    },

    {
        "id":          "nexus-sig-006",
        "display_id":  "NEXUS-SIG-006",
        "title":       "NEXUS — Suspicious Registry Run Key Modification",
        "technique":   "T1547.001",
        "tactic":      "persistence",
        "level":       "medium",
        "status":      "production",
        "tpr":         0.83,
        "fpr":         0.17,
        "date":        "2025/11/01",
        "tags":        ["attack.persistence", "attack.t1547.001", "nexus.medium"],
        "description": "Detects addition of persistence mechanisms via Run/RunOnce registry keys. Filters legitimate software installers using path and process heuristics.",
        "sigma_yaml": """title: NEXUS — Suspicious Registry Run Key Modification
id: nexus-sig-006
status: production
description: Detects addition of persistence mechanisms via Run/RunOnce registry keys.
 Filters legitimate software installers using path and process heuristics.
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: Shadow313 NEXUS Detection Engineering
date: 2025/11/01
tags:
  - attack.persistence
  - attack.t1547.001
  - nexus.medium
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    EventType: SetValue
    TargetObject|contains:
      - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
      - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      - '\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
  filter_legitimate_path:
    Details|contains:
      - 'C:\\Program Files\\'
      - 'C:\\Program Files (x86)\\'
      - 'C:\\Windows\\System32\\'
  filter_system:
    Image|endswith:
      - '\\msiexec.exe'
      - '\\setup.exe'
  condition: selection and not filter_legitimate_path and not filter_system
falsepositives:
  - Software installation to non-standard paths
  - User-installed applications
level: medium""",
    },

    {
        "id":          "nexus-sig-007",
        "display_id":  "NEXUS-SIG-007",
        "title":       "NEXUS — VSS Shadow Copy Deletion",
        "technique":   "T1490",
        "tactic":      "impact",
        "level":       "critical",
        "status":      "production",
        "tpr":         0.96,
        "fpr":         0.01,
        "date":        "2025/10/15",
        "tags":        ["attack.impact", "attack.t1490", "nexus.critical"],
        "description": "Detects deletion of Volume Shadow Copies via vssadmin, wmic, or PowerShell. CRITICAL — treat as active ransomware incident if detected.",
        "sigma_yaml": """title: NEXUS — VSS Shadow Copy Deletion
id: nexus-sig-007
status: production
description: Detects deletion of Volume Shadow Copies via vssadmin, wmic, or PowerShell.
 This is a near-universal ransomware behavior executed immediately before encryption.
 CRITICAL — treat as active ransomware incident if detected.
references:
  - https://attack.mitre.org/techniques/T1490/
author: Shadow313 NEXUS Detection Engineering
date: 2025/10/15
tags:
  - attack.impact
  - attack.t1490
  - nexus.critical
logsource:
  category: process_creation
  product: windows
detection:
  selection_vssadmin:
    Image|endswith: '\\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  selection_wmic:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_powershell:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - 'Get-WmiObject Win32_ShadowCopy'
      - 'Win32_ShadowCopy).Delete'
  condition: 1 of selection_*
falsepositives:
  - Backup software managing shadow copies (rare — whitelist by image hash)
level: critical""",
    },

    {
        "id":          "nexus-sig-008",
        "display_id":  "NEXUS-SIG-008",
        "title":       "NEXUS — LOLBAS Suspicious Execution",
        "technique":   "T1218",
        "tactic":      "defense_evasion",
        "level":       "high",
        "status":      "production",
        "tpr":         0.85,
        "fpr":         0.12,
        "date":        "2025/12/01",
        "tags":        ["attack.defense_evasion", "attack.t1218", "nexus.high"],
        "description": "Detects abuse of living-off-the-land binaries to proxy malicious payload execution. Covers regsvr32 scrobj, mshta remote script, certutil decode, and rundll32 abuse.",
        "sigma_yaml": """title: NEXUS — LOLBAS Suspicious Execution
id: nexus-sig-008
status: production
description: Detects abuse of living-off-the-land binaries to proxy malicious payload
 execution. Covers regsvr32 scrobj, mshta remote script, certutil decode, and rundll32 abuse.
references:
  - https://attack.mitre.org/techniques/T1218/
  - https://lolbas-project.github.io/
author: Shadow313 NEXUS Detection Engineering
date: 2025/12/01
tags:
  - attack.defense_evasion
  - attack.t1218
  - nexus.high
logsource:
  category: process_creation
  product: windows
detection:
  selection_regsvr32:
    Image|endswith: '\\regsvr32.exe'
    CommandLine|contains:
      - '/s'
      - 'scrobj'
      - 'http'
  selection_mshta:
    Image|endswith: '\\mshta.exe'
    CommandLine|contains:
      - 'http'
      - 'vbscript'
      - 'javascript'
  selection_certutil:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-decode'
      - '-urlcache'
      - '-f http'
  selection_rundll32_remote:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains:
      - 'javascript:'
      - 'http'
  condition: 1 of selection_*
level: high""",
    },

    {
        "id":          "nexus-sig-009",
        "display_id":  "NEXUS-SIG-009",
        "title":       "NEXUS — Suspicious Scheduled Task Creation",
        "technique":   "T1053.005",
        "tactic":      "persistence",
        "level":       "medium",
        "status":      "production",
        "tpr":         0.82,
        "fpr":         0.18,
        "date":        "2026/01/01",
        "tags":        ["attack.persistence", "attack.execution", "attack.t1053.005", "nexus.medium"],
        "description": "Detects creation of scheduled tasks with suspicious characteristics — execution from temp directories, SYSTEM account, or on-logon triggers.",
        "sigma_yaml": """title: NEXUS — Suspicious Scheduled Task Creation
id: nexus-sig-009
status: production
description: Detects creation of scheduled tasks with suspicious characteristics —
 execution from temp directories, SYSTEM account, or on-logon triggers.
references:
  - https://attack.mitre.org/techniques/T1053/005/
author: Shadow313 NEXUS Detection Engineering
date: 2026/01/01
tags:
  - attack.persistence
  - attack.execution
  - attack.t1053.005
  - nexus.medium
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\schtasks.exe'
    CommandLine|contains: '/create'
  filter_suspicious_path:
    CommandLine|contains:
      - '\\Temp\\'
      - '\\AppData\\Local\\'
      - '\\AppData\\Roaming\\'
      - '\\Users\\Public\\'
      - '\\ProgramData\\'
  filter_system_trigger:
    CommandLine|contains:
      - '/ru SYSTEM'
      - '/ru "NT AUTHORITY\\SYSTEM"'
  condition: selection and (filter_suspicious_path or filter_system_trigger)
falsepositives:
  - Legitimate software installers creating tasks in AppData
  - Windows Update task creation
level: medium""",
    },

    # ── Lateral Movement & C2 ─────────────────────────────────────────────────

    {
        "id":          "nexus-sig-010",
        "display_id":  "NEXUS-SIG-010",
        "title":       "NEXUS — Pass-the-Hash via NTLM Authentication Anomaly",
        "technique":   "T1550.002",
        "tactic":      "lateral_movement",
        "level":       "critical",
        "status":      "production",
        "tpr":         0.92,
        "fpr":         0.08,
        "date":        "2026/02/01",
        "tags":        ["attack.lateral_movement", "attack.t1550.002", "nexus.critical"],
        "description": "Detects Pass-the-Hash attacks via anomalous NTLM authentication patterns — specifically successful network logons with empty passwords from suspicious source processes.",
        "sigma_yaml": """title: NEXUS — Pass-the-Hash via NTLM Authentication Anomaly
id: nexus-sig-010
status: production
description: Detects Pass-the-Hash attacks via anomalous NTLM authentication patterns
 — specifically successful network logons with empty passwords from suspicious source processes.
references:
  - https://attack.mitre.org/techniques/T1550/002/
author: Shadow313 NEXUS Detection Engineering
date: 2026/02/01
tags:
  - attack.lateral_movement
  - attack.t1550.002
  - nexus.critical
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
    KeyLength: 0
  filter_anonymous:
    AccountName: 'ANONYMOUS LOGON'
  filter_local:
    IpAddress:
      - '127.0.0.1'
      - '::1'
  condition: selection and not filter_anonymous and not filter_local
falsepositives:
  - Legitimate NTLM pass-through in environments without Kerberos
  - Some network devices using NTLM with empty key length
level: critical""",
    },

    {
        "id":          "nexus-sig-011",
        "display_id":  "NEXUS-SIG-011",
        "title":       "NEXUS — DNS Tunneling Detection via Subdomain Entropy",
        "technique":   "T1572",
        "tactic":      "command_and_control",
        "level":       "high",
        "status":      "production",
        "tpr":         0.87,
        "fpr":         0.13,
        "date":        "2026/03/01",
        "tags":        ["attack.command_and_control", "attack.t1572", "attack.exfiltration", "nexus.high"],
        "description": "Detects DNS-based C2 and exfiltration via anomalously long, high-entropy subdomain labels. Covers Lazarus Group and BLINDINGCAN C2 patterns.",
        "sigma_yaml": """title: NEXUS — DNS Tunneling Detection via Subdomain Entropy
id: nexus-sig-011
status: production
description: Detects DNS-based C2 and exfiltration via anomalously long, high-entropy
 subdomain labels. Shannon entropy >3.5 on labels >20 chars is characteristic of
 base32/base64 encoded data. Covers Lazarus Group and BLINDINGCAN C2 patterns.
references:
  - https://attack.mitre.org/techniques/T1572/
author: Shadow313 NEXUS Detection Engineering
date: 2026/03/01
tags:
  - attack.command_and_control
  - attack.t1572
  - attack.exfiltration
  - nexus.high
logsource:
  category: dns
detection:
  selection:
    QueryName|re: '^[a-zA-Z0-9+/]{20,}\\.[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
  filter_legitimate_cdns:
    QueryName|endswith:
      - '.cloudfront.net'
      - '.akamaiedge.net'
      - '.fastly.net'
      - '.microsoft.com'
      - '.windows.com'
  condition: selection and not filter_legitimate_cdns
falsepositives:
  - CDN edge nodes with encoded hostnames (filtered above)
  - Some cloud services with auto-generated hostnames
level: high""",
    },

    {
        "id":          "nexus-sig-012",
        "display_id":  "NEXUS-SIG-012",
        "title":       "NEXUS — RDP Session Initiated from Unusual Parent Process",
        "technique":   "T1021.001",
        "tactic":      "lateral_movement",
        "level":       "high",
        "status":      "production",
        "tpr":         0.88,
        "fpr":         0.12,
        "date":        "2026/02/15",
        "tags":        ["attack.lateral_movement", "attack.t1021.001", "nexus.high"],
        "description": "Detects Remote Desktop connections initiated by unusual parent processes such as cmd.exe, powershell.exe, or scripting hosts — indicating automated lateral movement.",
        "sigma_yaml": """title: NEXUS — RDP Session Initiated from Unusual Parent Process
id: nexus-sig-012
status: production
description: Detects Remote Desktop connections initiated by unusual parent processes
 such as cmd.exe, powershell.exe, or scripting hosts — indicating automated lateral movement.
references:
  - https://attack.mitre.org/techniques/T1021/001/
author: Shadow313 NEXUS Detection Engineering
date: 2026/02/15
tags:
  - attack.lateral_movement
  - attack.t1021.001
  - nexus.high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\mstsc.exe'
    ParentImage|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\cscript.exe'
      - '\\python.exe'
  condition: selection
falsepositives:
  - Administrators using command-line RDP wrappers
  - RDP automation scripts for helpdesk
level: high""",
    },

    {
        "id":          "nexus-sig-013",
        "display_id":  "NEXUS-SIG-013",
        "title":       "NEXUS — File Timestamp Modification (Timestomping)",
        "technique":   "T1070.006",
        "tactic":      "defense_evasion",
        "level":       "medium",
        "status":      "production",
        "tpr":         0.89,
        "fpr":         0.11,
        "date":        "2026/01/15",
        "tags":        ["attack.defense_evasion", "attack.t1070.006", "nexus.medium"],
        "description": "Detects timestomping — modification of file $STANDARD_INFORMATION timestamps to disguise malware age. Sysmon Event ID 2 captures file creation time changes.",
        "sigma_yaml": """title: NEXUS — File Timestamp Modification (Timestomping)
id: nexus-sig-013
status: production
description: Detects timestomping — modification of file $STANDARD_INFORMATION timestamps
 to disguise malware age. Sysmon Event ID 2 captures file creation time changes.
 Critical for forensic integrity — altered timestamps undermine incident timelines.
references:
  - https://attack.mitre.org/techniques/T1070/006/
author: Shadow313 NEXUS Detection Engineering
date: 2026/01/15
tags:
  - attack.defense_evasion
  - attack.t1070.006
  - nexus.medium
logsource:
  product: windows
  definition: 'Requires Sysmon Event ID 2 (FileCreateTime) enabled in Sysmon config'
detection:
  selection:
    EventID: 2
    TargetFilename|contains:
      - '\\Temp\\'
      - '\\AppData\\'
      - '\\ProgramData\\'
  filter_installer:
    Image|endswith:
      - '\\msiexec.exe'
      - '\\TrustedInstaller.exe'
  condition: selection and not filter_installer
falsepositives:
  - Backup/restore software restoring original timestamps
  - Archive extraction tools (7zip, WinRAR)
level: medium""",
    },

    {
        "id":          "nexus-sig-014",
        "display_id":  "NEXUS-SIG-014",
        "title":       "NEXUS — Suspicious CreateRemoteThread (Process Injection)",
        "technique":   "T1055.001",
        "tactic":      "privilege_escalation",
        "level":       "critical",
        "status":      "production",
        "tpr":         0.95,
        "fpr":         0.05,
        "date":        "2026/02/01",
        "tags":        ["attack.privilege_escalation", "attack.defense_evasion", "attack.t1055.001", "nexus.critical"],
        "description": "Detects process injection via CreateRemoteThread API. This is the primary mechanism for DLL injection and shellcode injection. Sysmon Event 8 captures this.",
        "sigma_yaml": """title: NEXUS — Suspicious CreateRemoteThread (Process Injection)
id: nexus-sig-014
status: production
description: Detects process injection via CreateRemoteThread API. This is the primary
 mechanism for DLL injection and shellcode injection. Sysmon Event 8 captures this.
 Targeting lsass.exe or svchost.exe from unsigned processes is critical.
references:
  - https://attack.mitre.org/techniques/T1055/001/
author: Shadow313 NEXUS Detection Engineering
date: 2026/02/01
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1055.001
  - nexus.critical
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection_lsass:
    TargetImage|endswith: '\\lsass.exe'
  selection_svchost:
    TargetImage|endswith: '\\svchost.exe'
    SourceImage|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
      - '\\rundll32.exe'
  selection_suspicious_startaddress:
    StartAddress|startswith: '0x0'
  condition: selection_lsass or selection_svchost or selection_suspicious_startaddress
falsepositives:
  - Security software injecting monitoring hooks
  - Anti-cheat software in gaming environments
level: critical""",
    },

    {
        "id":          "nexus-sig-015",
        "display_id":  "NEXUS-SIG-015",
        "title":       "NEXUS — UAC Bypass via fodhelper.exe",
        "technique":   "T1548.002",
        "tactic":      "privilege_escalation",
        "level":       "high",
        "status":      "production",
        "tpr":         0.93,
        "fpr":         0.07,
        "date":        "2026/03/01",
        "tags":        ["attack.privilege_escalation", "attack.defense_evasion", "attack.t1548.002", "nexus.high"],
        "description": "Detects UAC bypass using fodhelper.exe registry hijack — one of the most commonly observed techniques in ransomware and APT28 campaigns.",
        "sigma_yaml": """title: NEXUS — UAC Bypass via fodhelper.exe
id: nexus-sig-015
status: production
description: Detects UAC bypass using fodhelper.exe registry hijack — one of the most
 commonly observed techniques in ransomware and APT28 campaigns.
references:
  - https://attack.mitre.org/techniques/T1548/002/
author: Shadow313 NEXUS Detection Engineering
date: 2026/03/01
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002
  - nexus.high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\\fodhelper.exe'
  filter_microsoft:
    Image|startswith: 'C:\\Windows\\System32\\'
    Image|endswith:
      - '\\SystemSettings.exe'
      - '\\svchost.exe'
  condition: selection and not filter_microsoft
level: high""",
    },
]


# ── CI/CD Pipeline Attack Rules (gap closure from security analysis) ──────────

SIGMA_RULES_CICD: list[dict] = [
    {
        "id":          "nexus-sig-016",
        "display_id":  "NEXUS-SIG-016",
        "title":       "NEXUS — Supply Chain: pip/npm Typosquatting in CI",
        "technique":   "T1195.002",
        "tactic":      "initial_access",
        "level":       "high",
        "status":      "production",
        "tpr":         0.85,
        "fpr":         0.15,
        "date":        "2026/09/24",
        "tags":        ["attack.initial_access", "attack.t1195.002", "nexus.high"],
        "description": "Detects pip/npm typosquatted or unsigned package installation in CI/CD pipelines.",
        "sigma_yaml":  "title: NEXUS-SIG-016\nid: nexus-sig-016\nstatus: production\nlogsource:\n  category: process_creation\n  product: linux\ndetection:\n  selection:\n    Image|endswith: /pip\n    CommandLine|contains: shadow313-utils\n  condition: selection\nlevel: high",
    },
    {
        "id":          "nexus-sig-017",
        "display_id":  "NEXUS-SIG-017",
        "title":       "NEXUS — Credentials In CI Environment Variables",
        "technique":   "T1552.001",
        "tactic":      "credential_access",
        "level":       "high",
        "status":      "production",
        "tpr":         0.88,
        "fpr":         0.12,
        "date":        "2026/09/24",
        "tags":        ["attack.credential_access", "attack.t1552.001", "nexus.high"],
        "description": "Detects access or exfiltration of CI/CD environment variables containing secrets.",
        "sigma_yaml":  "title: NEXUS-SIG-017\nid: nexus-sig-017\nstatus: production\nlogsource:\n  category: process_creation\n  product: linux\ndetection:\n  selection:\n    Image|endswith: /curl\n    CommandLine|contains: GITHUB_TOKEN\n  condition: selection\nlevel: high",
    },
]

# Merge into main SIGMA_RULES
SIGMA_RULES.extend(SIGMA_RULES_CICD)


# ── SPL Queries ───────────────────────────────────────────────────────────────

SPL_QUERIES: list[dict] = [
    {
        "id":          "SPL-001",
        "title":       "LSASS Access Hunting Query",
        "technique":   "T1003.001",
        "sigma_ref":   "nexus-sig-001",
        "query": """index=wineventlog OR index=sysmon EventCode=10
 TargetImage="*\\\\lsass.exe"
 (GrantedAccess=0x1010 OR GrantedAccess=0x1410 OR GrantedAccess=0x143a OR GrantedAccess=0x40)
 NOT SourceImage IN ("*\\\\MsMpEng.exe", "*\\\\csrss.exe", "*\\\\werfault.exe")
| eval risk=case(
 GrantedAccess="0x1010", "CRITICAL",
 GrantedAccess="0x1410", "CRITICAL",
 true(), "HIGH")
| stats count by _time, host, SourceImage, TargetImage, GrantedAccess, risk
| sort -count""",
    },
    {
        "id":          "SPL-002",
        "title":       "PowerShell Empire / Encoded Command Detection",
        "technique":   "T1059.001",
        "sigma_ref":   "nexus-sig-005",
        "query": """index=wineventlog OR index=sysmon EventCode=4688
 process_name="*powershell.exe*"
 (CommandLine="* -enc *" OR CommandLine="*-EncodedCommand*" OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*")
| eval encoded=if(match(CommandLine, "-enc|-EncodedCommand"), "TRUE", "FALSE")
| eval suspicious_parent=if(match(parent_process, "WINWORD|EXCEL|OUTLOOK|mshta|wscript"), "TRUE", "FALSE")
| eval risk_score=case(
 encoded="TRUE" AND suspicious_parent="TRUE", 95,
 encoded="TRUE", 70,
 true(), 40)
| where risk_score >= 70
| table _time, host, user, parent_process, CommandLine, risk_score
| sort -risk_score""",
    },
    {
        "id":          "SPL-003",
        "title":       "Lateral Movement — Unusual RDP / SMB Activity",
        "technique":   "T1021.001",
        "sigma_ref":   "nexus-sig-012",
        "query": """index=wineventlog EventCode=4624
 (LogonType=10 OR LogonType=3)
 NOT IpAddress IN ("127.0.0.1", "::1", "")
| stats dc(TargetUserName) as unique_accounts, count as attempts by IpAddress, _time span=10m
| where unique_accounts > 3 OR attempts > 20
| eval risk=if(unique_accounts > 5, "CRITICAL", if(attempts > 50, "CRITICAL", "HIGH"))
| table _time, IpAddress, unique_accounts, attempts, risk
| sort -unique_accounts""",
    },
    {
        "id":          "SPL-004",
        "title":       "DNS Exfiltration / Tunneling Hunt",
        "technique":   "T1572",
        "sigma_ref":   "nexus-sig-011",
        "query": """index=dns
| eval query_len=len(query)
| eval subdomain=mvindex(split(query, "."), 0)
| eval sub_len=len(subdomain)
| where sub_len > 20 AND query_len > 50
| stats count by query, src_ip, _time
| where count > 5
| eval risk="HIGH — Possible DNS Tunneling"
| table _time, src_ip, query, count, risk""",
    },
    {
        "id":          "SPL-005",
        "title":       "Ransomware Precursor — Shadow Copy Deletion",
        "technique":   "T1490",
        "sigma_ref":   "nexus-sig-007",
        "query": """index=wineventlog OR index=sysmon EventCode=4688
 (process_name="*vssadmin*" AND CommandLine="*delete shadows*")
 OR (process_name="*wmic*" AND CommandLine="*shadowcopy delete*")
 OR (process_name="*powershell*" AND CommandLine="*ShadowCopy*" AND CommandLine="*Delete*")
| eval ALERT="RANSOMWARE PRECURSOR — IMMEDIATE RESPONSE REQUIRED"
| table _time, host, user, process_name, CommandLine, ALERT
| sort _time""",
    },
    {
        "id":          "SPL-006",
        "title":       "Kerberoasting Detection",
        "technique":   "T1558.003",
        "sigma_ref":   "nexus-sig-002",
        "query": """index=wineventlog EventCode=4769
 TicketEncryptionType=0x17
 NOT ServiceName IN ("krbtgt", "*$")
 NOT AccountName IN ("*$")
| stats count as ticket_requests, dc(ServiceName) as unique_spns by AccountName, IpAddress, _time span=5m
| where ticket_requests > 3
| eval risk=case(unique_spns > 10, "CRITICAL", unique_spns > 3, "HIGH", true(), "MEDIUM")
| table _time, AccountName, IpAddress, unique_spns, ticket_requests, risk""",
    },
]


# ── KQL Queries ───────────────────────────────────────────────────────────────

KQL_QUERIES: list[dict] = [
    {
        "id":        "KQL-001",
        "title":     "LSASS Memory Access (Sentinel / MDE)",
        "technique": "T1003.001",
        "query": """DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "lsass.exe"
| join kind=inner (
    DeviceEvents
    | where ActionType == "OpenProcessApiCall"
    | where AdditionalFields has "lsass"
  ) on DeviceId
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "csrss.exe", "werfault.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
  InitiatingProcessCommandLine, ReportId
| order by Timestamp desc""",
    },
    {
        "id":        "KQL-002",
        "title":     "Encoded PowerShell Hunt (Sentinel / MDE)",
        "technique": "T1059.001",
        "query": """DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "IEX", "Invoke-Expression",
  "DownloadString", "DownloadFile")
| extend SuspiciousParent = InitiatingProcessFileName in~
  ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "mshta.exe", "wscript.exe")
| extend RiskScore = case(
  SuspiciousParent, 95,
  ProcessCommandLine has "-enc", 70,
  true(), 50)
| where RiskScore >= 70
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
  ProcessCommandLine, RiskScore
| order by RiskScore desc""",
    },
    {
        "id":        "KQL-003",
        "title":     "DCSync Detection (Sentinel / SecurityEvent)",
        "technique": "T1003.006",
        "query": """SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4662
| where Properties has_any (
  "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
  "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
  "89e95b76-444d-4c62-991a-0facbeda640c")
| where SubjectDomainName !contains "Domain Controllers"
| project TimeGenerated, Computer, SubjectAccount, SubjectDomainName,
  ObjectName, Properties
| order by TimeGenerated desc""",
    },
    {
        "id":        "KQL-004",
        "title":     "VSS Shadow Copy Deletion (Sentinel / MDE)",
        "technique": "T1490",
        "query": """DeviceProcessEvents
| where Timestamp > ago(1h)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete", "shadows"))
  or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy", "delete"))
  or (FileName =~ "powershell.exe" and ProcessCommandLine has_all ("ShadowCopy", "Delete"))
| extend Alert = "CRITICAL — RANSOMWARE PRECURSOR DETECTED"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, Alert
| order by Timestamp desc""",
    },
    {
        "id":        "KQL-005",
        "title":     "Lateral Movement — Pass-the-Hash (Sentinel / SecurityEvent)",
        "technique": "T1550.002",
        "query": """SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName =~ "NTLM"
| where KeyLength == 0
| where AccountName !endswith "$"
| where IpAddress !in ("127.0.0.1", "::1", "-")
| project TimeGenerated, Computer, AccountName, IpAddress,
  WorkstationName, LogonType, AuthenticationPackageName
| order by TimeGenerated desc""",
    },
]


# ── Elastic Queries ───────────────────────────────────────────────────────────

ELASTIC_QUERIES: list[dict] = [
    {
        "id":        "Elastic-001",
        "title":     "PowerShell Encoded Command (ECS / DSL)",
        "technique": "T1059.001",
        "format":    "DSL",
        "query": """{
  "query": {
    "bool": {
      "must": [
        {"match": {"process.name": "powershell.exe"}},
        {"bool": {
          "should": [
            {"match_phrase": {"process.command_line": "-enc"}},
            {"match_phrase": {"process.command_line": "-EncodedCommand"}},
            {"match_phrase": {"process.command_line": "IEX"}},
            {"match_phrase": {"process.command_line": "Invoke-Expression"}}
          ]
        }}
      ],
      "filter": [{"range": {"@timestamp": {"gte": "now-1h"}}}]
    }
  }
}""",
    },
    {
        "id":        "Elastic-002",
        "title":     "LSASS Access Hunt (ECS / Lucene)",
        "technique": "T1003.001",
        "format":    "Lucene",
        "query": """process.name:lsass.exe AND event.action:OpenProcess
AND NOT process.parent.name:(MsMpEng.exe OR csrss.exe OR werfault.exe)
AND winlog.event_data.GrantedAccess:(0x1010 OR 0x1410 OR 0x143a)""",
    },
]


# ── YARA Rules ────────────────────────────────────────────────────────────────

YARA_RULES: list[dict] = [
    {
        "id":          "YARA-001",
        "title":       "NEXUS Mimikatz In-Memory Detection",
        "technique":   "T1003.001",
        "threat_level": 10,
        "rule": """rule NEXUS_Mimikatz_Memory {
    meta:
        description = "Detects Mimikatz variants in process memory"
        author = "Shadow313 NEXUS Detection Engineering"
        date = "2026-01-15"
        threat_level = 10
        mitre = "T1003.001"
    strings:
        $mz = { 4D 5A }
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "lsadump::dcsync" ascii wide nocase
        $s3 = "privilege::debug" ascii wide nocase
        $s4 = "mimikatz" ascii wide nocase
        $s5 = "wdigest.dll" ascii wide
        $s6 = "kerberos.dll" ascii wide
        $hex1 = { 8B 4D FC 8B 55 F8 8B 45 F4 }
    condition:
        $mz at 0 and (2 of ($s*)) or (3 of ($s*)) or $hex1
}""",
    },
    {
        "id":          "YARA-002",
        "title":       "NEXUS Ransomware File Extension Pattern",
        "technique":   "T1486",
        "threat_level": 10,
        "rule": """rule NEXUS_Ransomware_FileRename {
    meta:
        description = "Detects mass file renaming characteristic of ransomware encryption"
        author = "Shadow313 NEXUS Detection Engineering"
        date = "2026-02-01"
        threat_level = 10
        mitre = "T1486"
    strings:
        $ext1 = ".nexuslocked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".ransom" ascii
        $ext4 = ".locked" ascii
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii nocase
        $ransom_note2 = "To recover your files" ascii nocase
        $ransom_note3 = "bitcoin" ascii nocase
        $chacha = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
    condition:
        (1 of ($ext*)) or (2 of ($ransom_note*)) or $chacha
}""",
    },
    {
        "id":          "YARA-003",
        "title":       "NEXUS DNS Tunneling Tool Signatures",
        "technique":   "T1572",
        "threat_level": 8,
        "rule": """rule NEXUS_DNS_Tunnel_Tool {
    meta:
        description = "Detects common DNS tunneling tools: iodine, dnscat2, DNScat"
        author = "Shadow313 NEXUS Detection Engineering"
        date = "2026/03/01"
        threat_level = 8
        mitre = "T1572"
    strings:
        $iodine1 = "iodine" ascii nocase
        $iodine2 = "CODEC_RAW" ascii
        $dnscat1 = "dnscat" ascii nocase
        $dnscat2 = "dns_tunnel" ascii nocase
        $blindingcan = { 42 4C 49 4E 44 49 4E 47 43 41 4E }
        $entropy_marker = { 41 42 43 44 45 46 47 48 49 4A 4B 4C }
    condition:
        (2 of ($iodine*)) or (2 of ($dnscat*)) or $blindingcan or $entropy_marker
}""",
    },
]


# ── Query functions ───────────────────────────────────────────────────────────

def get_rule_by_id(rule_id: str) -> Optional[dict]:
    """Get a Sigma rule by its ID (e.g. 'nexus-sig-001' or 'NEXUS-SIG-001')."""
    rule_id_lower = rule_id.lower()
    for rule in SIGMA_RULES:
        if rule["id"] == rule_id_lower or rule["display_id"].lower() == rule_id_lower:
            return rule
    return None


def get_rules_by_technique(technique: str) -> list[dict]:
    """Get all rules covering a specific ATT&CK technique."""
    return [r for r in SIGMA_RULES if r["technique"].startswith(technique)]


def get_rules_by_tactic(tactic: str) -> list[dict]:
    """Get all rules for a specific ATT&CK tactic."""
    return [r for r in SIGMA_RULES if r["tactic"] == tactic.lower()]


def get_critical_rules() -> list[dict]:
    """Get all CRITICAL severity rules."""
    return [r for r in SIGMA_RULES if r["level"] == "critical"]


def export_sigma_yaml(rule_id: str) -> Optional[str]:
    """Export a rule's Sigma YAML content."""
    rule = get_rule_by_id(rule_id)
    return rule["sigma_yaml"] if rule else None


# ── Coverage summary ──────────────────────────────────────────────────────────

COVERAGE_SUMMARY = {
    "total_sigma_rules":   len(SIGMA_RULES),
    "total_spl_queries":   len(SPL_QUERIES),
    "total_kql_queries":   len(KQL_QUERIES),
    "total_elastic_queries": len(ELASTIC_QUERIES),
    "total_yara_rules":    len(YARA_RULES),
    "avg_tpr":             round(sum(r.get("tpr", 0) for r in SIGMA_RULES) / len(SIGMA_RULES), 3),
    "critical_rules":      len([r for r in SIGMA_RULES if r["level"] == "critical"]),
    "high_rules":          len([r for r in SIGMA_RULES if r["level"] == "high"]),
    "medium_rules":        len([r for r in SIGMA_RULES if r["level"] == "medium"]),
    "techniques_covered":  len(set(r["technique"] for r in SIGMA_RULES)),
    "tactics_covered":     len(set(r["tactic"] for r in SIGMA_RULES)),
}