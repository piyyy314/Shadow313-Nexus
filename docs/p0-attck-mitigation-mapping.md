# Shadow313 NEXUS — P0 Controls → ATT&CK Mitigation Mapping
**Date:** 2026-09-24 | **Sigma Rules:** 17 | **Techniques Tracked:** 17

---

## Complete P0 Control → M-Series → T-Series Mapping

| P0 Control | ATT&CK Mitigations | Neutralizes (Full) | Degrades (Partial) |
|------------|-------------------|-------------------|-------------------|
| **P0-1** Bind 127.0.0.1 only | M1030 Network Segmentation · M1035 Limit Access | T1046, T1190, T1595 | T1071.001, T1095 |
| **P0-2** SHA3-256 hash headers | M1045 Code Signing · M1022 Restrict Permissions | T1036.005, T1070.006 | T1565.001, T1195.002 |
| **P0-3** Self-hash daemon.py | M1045 Code Signing · M1051 Update Software | T1195.002, T1036.005 | T1027, T1055.001 |
| **P0-4** Secret scanner pre-build | M1047 Audit · M1017 User Training | T1552.001, T1552.004 | T1078, T1110.001 |
| **P0-5** Rate limiting 100 rpm | M1037 Filter Network Traffic · M1036 Limit Install | T1498, T1110.003 | T1046, T1595 |
| **P0-6** Provenance REAL_OBSERVATION | M1047 Audit · M1057 Data Backup | T1565.001 | T1036.005, T1195.002 |
| **P0-7** 313-BIND receipt per download | M1047 Audit · M1022 Restrict Permissions | T1070.006, T1565.001 | T1036.005, T1027 |
| **P0-8** No shell=True | M1038 Execution Prevention · M1026 Privileged Acct | T1059.001, T1059.004 | T1218, T1055.001 |

---

## Residual Coverage Gaps — 10 Techniques with NO P0 Control

These 10 techniques are tracked in our Sigma rules but have **zero P0 daemon control** addressing them. They require P1/P2 controls or are outside the daemon's scope (endpoint/AD attacks):

| Technique | Sigma Rule | Severity | Gap Type | Recommended P1 Control |
|-----------|-----------|----------|----------|------------------------|
| **T1003.001** LSASS Memory Dump | NEXUS-SIG-001 | CRITICAL | Endpoint attack — outside daemon scope | Endpoint EDR (CrowdStrike/Defender) |
| **T1003.006** DCSync | NEXUS-SIG-004 | CRITICAL | AD attack — outside daemon scope | AD monitoring + NEXUS-SIG-004 SIEM |
| **T1021.001** RDP Lateral Movement | NEXUS-SIG-012 | HIGH | Network attack — outside daemon scope | Network segmentation + MFA |
| **T1053.005** Scheduled Task | NEXUS-SIG-009 | MEDIUM | Persistence — partially addressable | Systemd sandboxing (already in service file) |
| **T1490** VSS Shadow Copy Deletion | NEXUS-SIG-007 | CRITICAL | Ransomware — outside daemon scope | Backup isolation + NEXUS-SIG-007 SIEM |
| **T1547.001** Registry Run Key | NEXUS-SIG-006 | MEDIUM | Persistence — outside daemon scope | AppLocker/WDAC policy |
| **T1548.002** UAC Bypass fodhelper | NEXUS-SIG-015 | HIGH | Priv esc — outside daemon scope | UAC enforcement + standard user |
| **T1550.002** Pass-the-Hash | NEXUS-SIG-010 | CRITICAL | Credential attack — outside daemon scope | Credential Guard + NEXUS-SIG-010 SIEM |
| **T1558.003** Kerberoasting | NEXUS-SIG-002 | HIGH | AD attack — outside daemon scope | Managed service accounts + AES-only |
| **T1572** DNS Tunneling | NEXUS-SIG-011 | HIGH | Network C2 — partially addressable | DNS filtering + NEXUS-SIG-011 SIEM |

### Gap Analysis: Why These 10 Are Outside Daemon Scope

The 10 residual gaps fall into 3 categories:

**Category A — Endpoint/OS attacks (6 techniques):**
T1003.001, T1003.006, T1021.001, T1547.001, T1548.002, T1550.002
→ These attack the Windows/Linux OS or Active Directory, not the delivery daemon.
→ The daemon cannot prevent LSASS dumps or DCSync — that requires EDR + AD controls.
→ **Correct mitigation:** Deploy NEXUS Sigma rules in SIEM + endpoint EDR.

**Category B — Ransomware/Destructive (1 technique):**
T1490 VSS Shadow Copy Deletion
→ Ransomware targets the OS backup system, not the daemon.
→ **Correct mitigation:** Isolated backups + NEXUS-SIG-007 SIEM alert.

**Category C — Network C2 (2 techniques):**
T1572 DNS Tunneling, T1021.001 RDP
→ Network-layer attacks that bypass the daemon entirely.
→ **Correct mitigation:** DNS filtering + network segmentation.

**Category D — Partially addressable (1 technique):**
T1053.005 Scheduled Task
→ The systemd service file already uses `ProtectSystem=strict` which limits scheduled task persistence.
→ **Residual risk:** Attacker with local access could still create user-level cron jobs.

---

## P1 Controls to Close Residual Gaps

### P1-1: Systemd Hardening (closes T1053.005, T1547.001 partially)
```ini
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
CapabilityBoundingSet=
SystemCallFilter=@system-service
MemoryDenyWriteExecute=true
IPAddressAllow=127.0.0.1/8
IPAddressDeny=any
```
**Mitigations:** M1038 Execution Prevention · M1026 Privileged Account Management

### P1-2: SIEM Integration for Residual Gaps (closes T1003.001, T1003.006, T1490, T1550.002)
Deploy NEXUS Sigma rules SIG-001, SIG-004, SIG-007, SIG-010 to production SIEM.
These rules detect the attacks even though the daemon cannot prevent them.
**Mitigations:** M1047 Audit · M1049 Antivirus/Antimalware

### P1-3: DNS Filtering (closes T1572 partially)
Configure Quad9 (9.9.9.9) with DoH — already done on laptop.
Add local DNS blocklist for known C2 domains.
**Mitigations:** M1037 Filter Network Traffic

### P1-4: Credential Guard (closes T1003.001, T1550.002)
Enable Windows Credential Guard on the development machine.
Prevents LSASS memory dumps and Pass-the-Hash attacks.
**Mitigations:** M1043 Credential Access Protection

### P1-5: File Integrity Monitoring (closes T1070.006 fully, T1027 partially)
Add inotify/polling baseline for docs/ — alert if files change outside daemon watch window.
**Mitigations:** M1022 Restrict File and Directory Permissions

---

## Coverage Summary After P0 + P1

| Technique | P0 Coverage | P1 Coverage | Final Status |
|-----------|------------|------------|--------------|
| T1003.001 LSASS | ❌ None | ✅ P1-2 SIEM + P1-4 Cred Guard | DETECTED |
| T1003.006 DCSync | ❌ None | ✅ P1-2 SIEM | DETECTED |
| T1021.001 RDP | ❌ None | ✅ P1-3 DNS + network seg | DEGRADED |
| T1036.005 Masquerade | ⚠️ P0-2,P0-3 | ✅ P1-5 FIM | DETECTED |
| T1053.005 Sched Task | ⚠️ P0-8 | ✅ P1-1 Systemd | DEGRADED |
| T1059.001 PowerShell | ✅ P0-8 | — | NEUTRALIZED |
| T1070.006 Timestomp | ✅ P0-2,P0-7 | ✅ P1-5 FIM | NEUTRALIZED |
| T1110.003 Pwd Spray | ✅ P0-5 | — | NEUTRALIZED |
| T1195.002 Supply Chain | ✅ P0-3,P0-4 | — | NEUTRALIZED |
| T1490 VSS Deletion | ❌ None | ✅ P1-2 SIEM | DETECTED |
| T1547.001 Run Key | ❌ None | ✅ P1-1 Systemd | DEGRADED |
| T1548.002 UAC Bypass | ❌ None | ✅ P1-2 SIEM | DETECTED |
| T1550.002 PtH | ❌ None | ✅ P1-2 SIEM + P1-4 | DETECTED |
| T1552.001 Creds in Files | ✅ P0-4 | — | NEUTRALIZED |
| T1558.003 Kerberoasting | ❌ None | ✅ P1-2 SIEM | DETECTED |
| T1572 DNS Tunnel | ❌ None | ✅ P1-3 DNS filter | DEGRADED |
| T1218 LOLBAS | ⚠️ P0-8 | ✅ P1-1 Systemd | DEGRADED |

**After P0 + P1: 5 NEUTRALIZED · 6 DETECTED · 4 DEGRADED · 2 UNADDRESSED**

The 2 truly unaddressed techniques (T1021.001 RDP lateral movement, T1558.003 Kerberoasting)
require Active Directory controls outside the scope of a single-machine delivery daemon.
