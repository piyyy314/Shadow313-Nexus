"""
shadow313.v4.detection.d3fend_coverage — NEXUS Complete
MITRE D3FEND v1.5.0 coverage model for Shadow313 v4.

Provides:
  - D3FENDTechnique: dataclass representing a single D3FEND primitive
  - CoverageRating: enum (FULL, PARTIAL, ABSENT)
  - D3FENDCoverageMap: complete mapping of all 13 evasion techniques to
    their D3FEND countermeasures with coverage ratings
  - CoverageAnalyzer: query engine for coverage gaps, priorities, and reports
  - PriorityIntegration: ranked list of next D3FEND primitives to implement

All D3FEND IDs and definitions sourced from d3fend.mitre.org v1.5.0.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS AND DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class CoverageRating(str, Enum):
    FULL    = "full"      # Shadow313 implements the D3FEND primitive's core mechanism
    PARTIAL = "partial"   # Shadow313 detects the artifact but does not enforce/prevent
    ABSENT  = "absent"    # No corresponding implementation in Shadow313 v4


class D3FENDTactic(str, Enum):
    MODEL   = "Model"
    HARDEN  = "Harden"
    DETECT  = "Detect"
    ISOLATE = "Isolate"
    DECEIVE = "Deceive"
    EVICT   = "Evict"
    RESTORE = "Restore"


@dataclass
class D3FENDTechnique:
    """A single MITRE D3FEND v1.5.0 defensive technique."""
    d3fend_id:   str              # e.g. "D3-PSA"
    name:        str              # e.g. "Process Spawn Analysis"
    tactic:      D3FENDTactic
    definition:  str              # Official D3FEND definition
    url:         str = ""         # d3fend.mitre.org URL


@dataclass
class CoverageEntry:
    """Coverage of a D3FEND technique for a specific ATT&CK evasion technique."""
    d3fend:          D3FENDTechnique
    rating:          CoverageRating
    shadow313_impl:  str   # What Shadow313 currently does (or doesn't do)
    gap_detail:      str   # Specific gap between current impl and full D3FEND coverage
    attack_id:       str   # ATT&CK technique ID (e.g. "T1134.001")
    evasion_id:      str   # Shadow313 evasion ID (e.g. "PV-001")


@dataclass
class PriorityIntegration:
    """A recommended next D3FEND primitive integration."""
    priority:        int
    d3fend_ids:      list[str]    # One or more D3FEND IDs this integration covers
    title:           str
    evasion_ids:     list[str]    # Shadow313 evasion IDs addressed
    attack_ids:      list[str]    # ATT&CK IDs addressed
    rationale:       str
    impl_path:       str          # Concrete implementation path
    effort_weeks:    tuple[int, int]  # (min, max) weeks


# ═══════════════════════════════════════════════════════════════════════════════
# D3FEND TECHNIQUE CATALOG (v1.5.0 — sourced from d3fend.mitre.org)
# ═══════════════════════════════════════════════════════════════════════════════

_T = D3FENDTechnique  # alias for brevity

D3FEND_TECHNIQUES: dict[str, D3FENDTechnique] = {t.d3fend_id: t for t in [

    # ── Harden ────────────────────────────────────────────────────────────────
    _T("D3-SCF",  "System Call Filtering",
       D3FENDTactic.HARDEN,
       "Configuring the operating system to restrict which system calls a process may invoke.",
       "https://d3fend.mitre.org/technique/d3f:SystemCallFiltering/"),

    _T("D3-HBPI", "Hardware-based Process Isolation",
       D3FENDTactic.HARDEN,
       "Preventing one process from accessing the resources of another process using hardware-based controls.",
       "https://d3fend.mitre.org/technique/d3f:HardwareBasedProcessIsolation/"),

    _T("D3-EAL",  "Executable Allowlisting",
       D3FENDTactic.HARDEN,
       "Using a whitelist to block execution of unauthorized executables.",
       "https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/"),

    _T("D3-DLIC", "Driver Load Integrity Checking",
       D3FENDTactic.HARDEN,
       "Ensuring the integrity of drivers loaded during initialization of the operating system.",
       "https://d3fend.mitre.org/technique/d3f:DriverLoadIntegrityChecking/"),

    _T("D3-SBV",  "Service Binary Verification",
       D3FENDTactic.HARDEN,
       "Analyzing changes in service binary files by comparing to a source of truth.",
       "https://d3fend.mitre.org/technique/d3f:ServiceBinaryVerification/"),

    _T("D3-SCP",  "System Configuration Permissions",
       D3FENDTactic.HARDEN,
       "Restricting access to system configuration files and registry keys.",
       "https://d3fend.mitre.org/technique/d3f:SystemConfigurationPermissions/"),

    _T("D3-ACH",  "Application Configuration Hardening",
       D3FENDTactic.HARDEN,
       "Modifying an application's configuration to reduce its attack surface.",
       "https://d3fend.mitre.org/technique/d3f:ApplicationConfigurationHardening/"),

    _T("D3-SPP",  "Strong Password Policy",
       D3FENDTactic.HARDEN,
       "Modifying system configuration to increase password strength.",
       "https://d3fend.mitre.org/technique/d3f:StrongPasswordPolicy/"),

    _T("D3-OTP",  "One-time Password",
       D3FENDTactic.HARDEN,
       "A one-time password is valid for only one user authentication.",
       "https://d3fend.mitre.org/technique/d3f:OneTimePassword/"),

    _T("D3-CRO",  "Credential Rotation",
       D3FENDTactic.HARDEN,
       "Regularly changing authentication credentials to minimize the risk of unauthorized access.",
       "https://d3fend.mitre.org/technique/d3f:CredentialRotation/"),

    # ── Detect ────────────────────────────────────────────────────────────────
    _T("D3-PSA",  "Process Spawn Analysis",
       D3FENDTactic.DETECT,
       "Analyzing spawn arguments or attributes of a process to detect processes that are unauthorized.",
       "https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/"),

    _T("D3-PLA",  "Process Lineage Analysis",
       D3FENDTactic.DETECT,
       "Identification of suspicious processes by examining the ancestry and siblings of a process.",
       "https://d3fend.mitre.org/technique/d3f:ProcessLineageAnalysis/"),

    _T("D3-SCA",  "System Call Analysis",
       D3FENDTactic.DETECT,
       "Analyzing system calls to determine whether a process is exhibiting unauthorized behavior.",
       "https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis/"),

    _T("D3-SSC",  "Shadow Stack Comparisons",
       D3FENDTactic.DETECT,
       "Comparing a call stack in system memory with a shadow call stack maintained by the processor.",
       "https://d3fend.mitre.org/technique/d3f:ShadowStackComparisons/"),

    _T("D3-PSMD", "Process Self-Modification Detection",
       D3FENDTactic.DETECT,
       "Detects processes that modify, change, or replace their own code at runtime.",
       "https://d3fend.mitre.org/technique/d3f:ProcessSelfModificationDetection/"),

    _T("D3-PCSV", "Process Code Segment Verification",
       D3FENDTactic.DETECT,
       "Comparing the 'text' or 'code' memory segments to a source of truth.",
       "https://d3fend.mitre.org/technique/d3f:ProcessCodeSegmentVerification/"),

    _T("D3-FIM",  "File Integrity Monitoring",
       D3FENDTactic.DETECT,
       "Detecting any suspicious changes to files in a computer system.",
       "https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring/"),

    _T("D3-SFA",  "System File Analysis",
       D3FENDTactic.DETECT,
       "Monitoring system files such as authentication databases, configuration files, and executables for modification.",
       "https://d3fend.mitre.org/technique/d3f:SystemFileAnalysis/"),

    _T("D3-FCA",  "File Creation Analysis",
       D3FENDTactic.DETECT,
       "Analyzing the properties of file create system call invocations.",
       "https://d3fend.mitre.org/technique/d3f:FileCreationAnalysis/"),

    _T("D3-FAPA", "File Access Pattern Analysis",
       D3FENDTactic.DETECT,
       "Analyzing the files accessed by a process to identify unauthorized activity.",
       "https://d3fend.mitre.org/technique/d3f:FileAccessPatternAnalysis/"),

    _T("D3-ANET", "Authentication Event Thresholding",
       D3FENDTactic.DETECT,
       "Aggregating authentication events and applying threshold-based detection.",
       "https://d3fend.mitre.org/technique/d3f:AuthenticationEventThresholding/"),

    _T("D3-LAM",  "Local Account Monitoring",
       D3FENDTactic.DETECT,
       "Monitoring local accounts to detect unauthorized activity.",
       "https://d3fend.mitre.org/technique/d3f:LocalAccountMonitoring/"),

    _T("D3-DAM",  "Domain Account Monitoring",
       D3FENDTactic.DETECT,
       "Monitoring domain accounts to detect unauthorized activity.",
       "https://d3fend.mitre.org/technique/d3f:DomainAccountMonitoring/"),

    _T("D3-NTA",  "Network Traffic Analysis",
       D3FENDTactic.DETECT,
       "Analyzing network traffic to detect adversary activity.",
       "https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/"),

    _T("D3-PHDURA", "Per Host Download-Upload Ratio Analysis",
       D3FENDTactic.DETECT,
       "Detecting anomalies by comparing the amount of data downloaded versus data uploaded by a host.",
       "https://d3fend.mitre.org/technique/d3f:PerHostDownload-UploadRatioAnalysis/"),

    _T("D3-UDTA", "User Data Transfer Analysis",
       D3FENDTactic.DETECT,
       "Analyzing the amount of data transferred by a user.",
       "https://d3fend.mitre.org/technique/d3f:UserDataTransferAnalysis/"),

    _T("D3-CPSP", "Client-server Payload Profiling",
       D3FENDTactic.DETECT,
       "Comparing client-server payloads to a baseline to detect anomalies.",
       "https://d3fend.mitre.org/technique/d3f:Client-serverPayloadProfiling/"),

    _T("D3-RPTA", "Relay Pattern Analysis",
       D3FENDTactic.DETECT,
       "Analyzing network traffic for relay patterns that indicate C2 communication.",
       "https://d3fend.mitre.org/technique/d3f:RelayPatternAnalysis/"),

    # ── Isolate ───────────────────────────────────────────────────────────────
    _T("D3-ANCI", "Authentication Cache Invalidation",
       D3FENDTactic.ISOLATE,
       "Removing tokens or credentials from an authentication cache to prevent their further use.",
       "https://d3fend.mitre.org/technique/d3f:AuthenticationCacheInvalidation/"),

    _T("D3-NI",   "Network Isolation",
       D3FENDTactic.ISOLATE,
       "Restricting network access to limit lateral movement.",
       "https://d3fend.mitre.org/technique/d3f:NetworkIsolation/"),

    _T("D3-OTF",  "Outbound Traffic Filtering",
       D3FENDTactic.ISOLATE,
       "Filtering outbound network traffic to prevent unauthorized data transfer.",
       "https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/"),

    _T("D3-DNSAL","DNS Allowlisting",
       D3FENDTactic.ISOLATE,
       "Permitting only approved DNS queries.",
       "https://d3fend.mitre.org/technique/d3f:DNSAllowlisting/"),

    _T("D3-DNSDL","DNS Denylisting",
       D3FENDTactic.ISOLATE,
       "Blocking DNS queries to known malicious or unauthorized domains.",
       "https://d3fend.mitre.org/technique/d3f:DNSDenylisting/"),

    _T("D3-EBWSAM","Endpoint-based Web Server Access Mediation",
       D3FENDTactic.ISOLATE,
       "Controlling access to web servers from endpoints.",
       "https://d3fend.mitre.org/technique/d3f:Endpoint-basedWebServerAccessMediation/"),

    _T("D3-PBWSAM","Proxy-based Web Server Access Mediation",
       D3FENDTactic.ISOLATE,
       "Controlling access to web servers via a proxy.",
       "https://d3fend.mitre.org/technique/d3f:Proxy-basedWebServerAccessMediation/"),

    # ── Deceive ───────────────────────────────────────────────────────────────
    _T("D3-DO",   "Decoy Object",
       D3FENDTactic.DECEIVE,
       "A Decoy Object is created and deployed for the purposes of deceiving attackers.",
       "https://d3fend.mitre.org/technique/d3f:DecoyObject/"),

    _T("D3-DUC",  "Decoy User Credential",
       D3FENDTactic.DECEIVE,
       "A Credential created for the purpose of deceiving an adversary.",
       "https://d3fend.mitre.org/technique/d3f:DecoyUserCredential/"),
]}


# ═══════════════════════════════════════════════════════════════════════════════
# COVERAGE MAP — 13 evasion techniques × D3FEND countermeasures
# ═══════════════════════════════════════════════════════════════════════════════

def _t(d3fend_id: str) -> D3FENDTechnique:
    return D3FEND_TECHNIQUES[d3fend_id]


COVERAGE_MAP: list[CoverageEntry] = [

    # ── PV-001: Token Impersonation (T1134.001) ───────────────────────────────
    CoverageEntry(
        d3fend=_t("D3-SCF"), rating=CoverageRating.ABSENT,
        attack_id="T1134.001", evasion_id="PV-001",
        shadow313_impl="None — no system call filtering in Shadow313 v4.",
        gap_detail="D3-SCF would block NtCreateToken/ImpersonateLoggedOnUser before completion. "
                   "EvasionDetector fires post-hoc on logged event data only.",
    ),
    CoverageEntry(
        d3fend=_t("D3-HBPI"), rating=CoverageRating.ABSENT,
        attack_id="T1134.001", evasion_id="PV-001",
        shadow313_impl="None — no hardware isolation layer.",
        gap_detail="Hardware isolation (Intel TDX, AMD SEV-SNP) would prevent cross-process "
                   "token access. Identified as 2027 deployment target in PQ threat analysis.",
    ),
    CoverageEntry(
        d3fend=_t("D3-LAM"), rating=CoverageRating.PARTIAL,
        attack_id="T1134.001", evasion_id="PV-001",
        shadow313_impl="EvasionDetector fires on SeImpersonatePrivilege in event descriptions.",
        gap_detail="Reactive detection only. D3-LAM requires proactive monitoring of privilege "
                   "assignments — alerting when SeImpersonatePrivilege is granted to a new account.",
    ),
    CoverageEntry(
        d3fend=_t("D3-ANET"), rating=CoverageRating.PARTIAL,
        attack_id="T1134.001", evasion_id="PV-001",
        shadow313_impl="IA-003 signature monitors authentication anomalies (impossible travel, off-hours).",
        gap_detail="No threshold-based aggregation across multiple authentication events over time. "
                   "Token impersonation produces Event ID 4624 LogonType 9 — not currently aggregated.",
    ),

    # ── PV-002: UAC Bypass via Fodhelper (T1548.002) ──────────────────────────
    CoverageEntry(
        d3fend=_t("D3-PSA"), rating=CoverageRating.PARTIAL,
        attack_id="T1548.002", evasion_id="PV-002",
        shadow313_impl="EvasionDetector fires on 'fodhelper' in event descriptions.",
        gap_detail="D3-PSA requires parent-child process relationship analysis: "
                   "fodhelper.exe → cmd.exe/powershell.exe is the anomalous pattern. "
                   "Shadow313 detects the binary name but not the process lineage.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PLA"), rating=CoverageRating.ABSENT,
        attack_id="T1548.002", evasion_id="PV-002",
        shadow313_impl="None — no process tree analysis capability.",
        gap_detail="Process lineage analysis is the primary D3FEND countermeasure for UAC bypass. "
                   "Shadow313 has no process ancestry graph traversal.",
    ),
    CoverageEntry(
        d3fend=_t("D3-SCP"), rating=CoverageRating.ABSENT,
        attack_id="T1548.002", evasion_id="PV-002",
        shadow313_impl="None — no registry ACL enforcement.",
        gap_detail="Restricting write access to HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command "
                   "would prevent the bypass entirely. Shadow313 detects the key in event data only.",
    ),
    CoverageEntry(
        d3fend=_t("D3-ACH"), rating=CoverageRating.ABSENT,
        attack_id="T1548.002", evasion_id="PV-002",
        shadow313_impl="None — no UAC configuration audit.",
        gap_detail="Setting UAC to 'Always notify' prevents auto-elevation of fodhelper.exe. "
                   "Shadow313 does not audit or enforce UAC configuration levels.",
    ),

    # ── DE-001: Process Injection into Svchost (T1055.001) ────────────────────
    CoverageEntry(
        d3fend=_t("D3-SCA"), rating=CoverageRating.PARTIAL,
        attack_id="T1055.001", evasion_id="DE-001",
        shadow313_impl="EvasionDetector fires on VirtualAllocEx, WriteProcessMemory, "
                       "CreateRemoteThread in event data.",
        gap_detail="Post-hoc detection of system call names in log data. True D3-SCA operates "
                   "at kernel level, intercepting calls in real time before completion.",
    ),
    CoverageEntry(
        d3fend=_t("D3-SSC"), rating=CoverageRating.ABSENT,
        attack_id="T1055.001", evasion_id="DE-001",
        shadow313_impl="None — no shadow stack analysis.",
        gap_detail="Intel CET shadow stack comparisons detect ROP chains used in shellcode injection. "
                   "Shadow313 has no shadow stack analysis capability.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PSMD"), rating=CoverageRating.ABSENT,
        attack_id="T1055.001", evasion_id="DE-001",
        shadow313_impl="None — no process self-modification detection.",
        gap_detail="Process hollowing involves a process replacing its own code segment. "
                   "D3-PSMD detects writes to a process's own code segment.",
    ),
    CoverageEntry(
        d3fend=_t("D3-HBPI"), rating=CoverageRating.ABSENT,
        attack_id="T1055.001", evasion_id="DE-001",
        shadow313_impl="None — no hardware isolation layer.",
        gap_detail="Hardware isolation would prevent VirtualAllocEx/WriteProcessMemory from "
                   "succeeding across process boundaries for non-privileged callers.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PCSV"), rating=CoverageRating.ABSENT,
        attack_id="T1055.001", evasion_id="DE-001",
        shadow313_impl="None — no code segment verification.",
        gap_detail="After injection, svchost.exe code segment differs from the known-good binary. "
                   "D3-PCSV would detect this discrepancy.",
    ),

    # ── DE-002: Timestomping (T1070.006) ──────────────────────────────────────
    CoverageEntry(
        d3fend=_t("D3-FIM"), rating=CoverageRating.PARTIAL,
        attack_id="T1070.006", evasion_id="DE-002",
        shadow313_impl="EvasionDetector fires on SetFileTime, touch -t, MACE in event data.",
        gap_detail="Detection of the timestomping operation in logs. D3-FIM's full implementation "
                   "compares current file metadata against a cryptographic baseline (hash + timestamp). "
                   "Shadow313 has no baseline snapshot capability.",
    ),
    CoverageEntry(
        d3fend=_t("D3-SFA"), rating=CoverageRating.PARTIAL,
        attack_id="T1070.006", evasion_id="DE-002",
        shadow313_impl="pe_analyzer.py performs PE static header analysis and entropy profiling.",
        gap_detail="Does not specifically monitor NTFS MACE timestamps or compare against baseline. "
                   "Entropy profiling detects packed/encrypted content but not timestamp manipulation.",
    ),
    CoverageEntry(
        d3fend=_t("D3-FCA"), rating=CoverageRating.ABSENT,
        attack_id="T1070.006", evasion_id="DE-002",
        shadow313_impl="None — no file creation system call analysis.",
        gap_detail="Timestomping at file creation time (backdated timestamp during initial write) "
                   "would be detected by D3-FCA monitoring NtCreateFile parameters.",
    ),

    # ── DE-003: DLL Side-Loading (T1574.002) ──────────────────────────────────
    CoverageEntry(
        d3fend=_t("D3-DLIC"), rating=CoverageRating.PARTIAL,
        attack_id="T1574.002", evasion_id="DE-003",
        shadow313_impl="Plugin trust registry (HMAC-SHA256 + cosign) verifies Shadow313 plugins.",
        gap_detail="Covers Shadow313's own plugins only. Does not extend to arbitrary DLLs "
                   "loaded by third-party applications — the DLL side-loading attack surface.",
    ),
    CoverageEntry(
        d3fend=_t("D3-EAL"), rating=CoverageRating.ABSENT,
        attack_id="T1574.002", evasion_id="DE-003",
        shadow313_impl="None — no executable allowlisting enforcement.",
        gap_detail="WDAC/AppLocker configured to restrict DLL loads from user-writable directories "
                   "is the most effective preventive control (OPTIX, April 2026). "
                   "Shadow313 has no allowlisting enforcement capability.",
    ),
    CoverageEntry(
        d3fend=_t("D3-SBV"), rating=CoverageRating.PARTIAL,
        attack_id="T1574.002", evasion_id="DE-003",
        shadow313_impl="updater.py performs integrity verification of Shadow313's own binaries.",
        gap_detail="Covers Shadow313's own components only. Does not extend to third-party "
                   "application DLLs that are the target of side-loading attacks.",
    ),
    CoverageEntry(
        d3fend=_t("D3-SCF"), rating=CoverageRating.ABSENT,
        attack_id="T1574.002", evasion_id="DE-003",
        shadow313_impl="None — no system call filtering.",
        gap_detail="System call filtering can restrict LoadLibrary calls to paths outside "
                   "user-writable directories, preventing DLL side-loading at the OS level.",
    ),

    # ── CA-002: Kerberoasting (T1558.003) ─────────────────────────────────────
    CoverageEntry(
        d3fend=_t("D3-SPP"), rating=CoverageRating.ABSENT,
        attack_id="T1558.003", evasion_id="CA-002",
        shadow313_impl="None — no password policy audit.",
        gap_detail="Kerberoasting is only effective when service account passwords are weak. "
                   "Enforcing 25+ character passwords (Specops, 2025) makes it computationally infeasible. "
                   "Shadow313 does not audit service account password strength.",
    ),
    CoverageEntry(
        d3fend=_t("D3-OTP"), rating=CoverageRating.ABSENT,
        attack_id="T1558.003", evasion_id="CA-002",
        shadow313_impl="None — no gMSA audit.",
        gap_detail="Group Managed Service Accounts (gMSAs) use automatically rotated 240-character "
                   "passwords — effectively one-time passwords. Shadow313 does not audit whether "
                   "service accounts use gMSAs.",
    ),
    CoverageEntry(
        d3fend=_t("D3-ANET"), rating=CoverageRating.PARTIAL,
        attack_id="T1558.003", evasion_id="CA-002",
        shadow313_impl="EvasionDetector fires on Event ID 4769 in event data.",
        gap_detail="BeyondTrust (July 2025): effective Kerberoasting detection requires statistical "
                   "analysis of TGS request patterns, not just presence of a single 4769 event. "
                   "Shadow313 detects the event ID but not the statistical anomaly.",
    ),
    CoverageEntry(
        d3fend=_t("D3-DAM"), rating=CoverageRating.PARTIAL,
        attack_id="T1558.003", evasion_id="CA-002",
        shadow313_impl="DI-002 signature detects account enumeration (Get-ADUser, Get-ADGroup, dsquery).",
        gap_detail="Detects enumeration precursor to Kerberoasting. Does not continuously monitor "
                   "domain accounts for SPN assignments or flag accounts with SPNs and weak passwords.",
    ),
    CoverageEntry(
        d3fend=_t("D3-CRO"), rating=CoverageRating.ABSENT,
        attack_id="T1558.003", evasion_id="CA-002",
        shadow313_impl="None — no credential rotation audit.",
        gap_detail="Regular KRBTGT password rotation limits the window during which a cracked "
                   "Kerberos ticket is valid. Shadow313 does not audit rotation schedules.",
    ),

    # ── LM-001: Pass-the-Hash via WMI (T1550.002) ─────────────────────────────
    CoverageEntry(
        d3fend=_t("D3-ANCI"), rating=CoverageRating.ABSENT,
        attack_id="T1550.002", evasion_id="LM-001",
        shadow313_impl="None — no Credential Guard audit.",
        gap_detail="Credential Guard moves NTLM hash storage into a Hyper-V isolated container, "
                   "preventing hash extraction. Shadow313 does not audit whether Credential Guard "
                   "is enabled on monitored hosts.",
    ),
    CoverageEntry(
        d3fend=_t("D3-HBPI"), rating=CoverageRating.ABSENT,
        attack_id="T1550.002", evasion_id="LM-001",
        shadow313_impl="None — no hardware isolation layer.",
        gap_detail="Credential Guard uses VBS (Virtualization Based Security) to protect NTLM hashes "
                   "in a separate security domain. Shadow313 has no hardware isolation capability.",
    ),
    CoverageEntry(
        d3fend=_t("D3-ANET"), rating=CoverageRating.PARTIAL,
        attack_id="T1550.002", evasion_id="LM-001",
        shadow313_impl="EvasionDetector fires on ntlm hash, wmiexec, impacket in event data.",
        gap_detail="Detects tool names and technique ID. Does not implement threshold-based NTLM "
                   "authentication monitoring (e.g., same account authenticating to 10 hosts in 60s).",
    ),
    CoverageEntry(
        d3fend=_t("D3-NI"), rating=CoverageRating.ABSENT,
        attack_id="T1550.002", evasion_id="LM-001",
        shadow313_impl="None — no network segmentation enforcement.",
        gap_detail="Network segmentation restricting WMI traffic (TCP 135, dynamic RPC ports) "
                   "between workstations prevents WMI-based lateral movement.",
    ),

    # ── CO-001: Data Staged for Exfiltration (T1074.001) ──────────────────────
    CoverageEntry(
        d3fend=_t("D3-FAPA"), rating=CoverageRating.ABSENT,
        attack_id="T1074.001", evasion_id="CO-001",
        shadow313_impl="None — no file access pattern analysis.",
        gap_detail="Data staging involves accessing many files across sensitive directories before "
                   "archiving. D3-FAPA detects this access pattern. Shadow313 detects the archive "
                   "creation command but not the file access pattern that precedes it.",
    ),
    CoverageEntry(
        d3fend=_t("D3-UDTA"), rating=CoverageRating.PARTIAL,
        attack_id="T1074.001", evasion_id="CO-001",
        shadow313_impl="EF-001 signature detects 'bytes_out: large' in event data.",
        gap_detail="Keyword detection only. D3-UDTA requires baselining normal data transfer "
                   "volumes per user and flagging deviations. No baseline-based anomaly detection.",
    ),
    CoverageEntry(
        d3fend=_t("D3-FCA"), rating=CoverageRating.ABSENT,
        attack_id="T1074.001", evasion_id="CO-001",
        shadow313_impl="None — no file creation analysis.",
        gap_detail="Data staging creates archive files in specific directories. D3-FCA would detect "
                   "creation of large archive files in unusual locations (e.g., %TEMP%).",
    ),

    # ── C2-001: Cobalt Strike Beacon over HTTPS (T1071.001) ───────────────────
    CoverageEntry(
        d3fend=_t("D3-NTA"), rating=CoverageRating.PARTIAL,
        attack_id="T1071.001", evasion_id="C2-001",
        shadow313_impl="ja3_fingerprint.py implements JA3/JA3S TLS fingerprinting.",
        gap_detail="Catches default Cobalt Strike JA3 fingerprint. Does not detect custom malleable "
                   "profiles that randomize the TLS handshake. Strongest partial coverage in architecture.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PHDURA"), rating=CoverageRating.PARTIAL,
        attack_id="T1071.001", evasion_id="C2-001",
        shadow313_impl="ml_anomaly.py IsolationForest includes byte_rate and packet_rate features.",
        gap_detail="Flow-level analysis only. D3-PHDURA requires per-host ratio analysis over "
                   "time windows (1h, 24h). Current model analyzes individual flows, not aggregated ratios.",
    ),
    CoverageEntry(
        d3fend=_t("D3-CPSP"), rating=CoverageRating.ABSENT,
        attack_id="T1071.001", evasion_id="C2-001",
        shadow313_impl="None — no client-server payload profiling.",
        gap_detail="Cobalt Strike malleable C2 profiles modify HTTP request/response structure. "
                   "D3-CPSP would detect deviations from expected payload structure for a given domain.",
    ),
    CoverageEntry(
        d3fend=_t("D3-DNSAL"), rating=CoverageRating.ABSENT,
        attack_id="T1071.001", evasion_id="C2-001",
        shadow313_impl="None — no DNS allowlisting enforcement.",
        gap_detail="Cobalt Strike beacons often use newly registered domains. DNS allowlisting "
                   "would block connections to domains not on an approved list.",
    ),

    # ── C2-003: Trusted Process C2 / PhantomWire (T1071.001) ─────────────────
    CoverageEntry(
        d3fend=_t("D3-PSA"), rating=CoverageRating.PARTIAL,
        attack_id="T1071.001", evasion_id="C2-003",
        shadow313_impl="EvasionDetector fires on 'phantomwire', 'trusted process', "
                       "'process masquerade' in event data.",
        gap_detail="Detects technique description keywords. D3-PSA's full implementation analyzes "
                   "process spawn attributes including image path, parent process, and command-line.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PLA"), rating=CoverageRating.ABSENT,
        attack_id="T1071.001", evasion_id="C2-003",
        shadow313_impl="None — no process lineage analysis.",
        gap_detail="PhantomWire involves a legitimate process making unexpected network connections. "
                   "D3-PLA detects processes whose network behavior deviates from their expected lineage.",
    ),
    CoverageEntry(
        d3fend=_t("D3-RPTA"), rating=CoverageRating.ABSENT,
        attack_id="T1071.001", evasion_id="C2-003",
        shadow313_impl="None — no relay pattern analysis.",
        gap_detail="Trusted process C2 often uses a relay pattern (e.g., Google Calendar, OneDrive). "
                   "D3-RPTA would detect the relay pattern in network traffic.",
    ),

    # ── EF-001: Exfiltration over C2 Channel (T1041) ─────────────────────────
    CoverageEntry(
        d3fend=_t("D3-UDTA"), rating=CoverageRating.PARTIAL,
        attack_id="T1041", evasion_id="EF-001",
        shadow313_impl="EF-001 signature detects 'bytes_out: large' and 'direction: outbound'.",
        gap_detail="Keyword detection only. D3-UDTA requires baselining normal outbound transfer "
                   "volumes per user/host and flagging deviations.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PHDURA"), rating=CoverageRating.PARTIAL,
        attack_id="T1041", evasion_id="EF-001",
        shadow313_impl="ml_anomaly.py byte_rate feature captures upload volume.",
        gap_detail="Per-host ratio analysis over time windows not implemented. "
                   "Current model analyzes individual flows, not aggregated per-host ratios.",
    ),
    CoverageEntry(
        d3fend=_t("D3-OTF"), rating=CoverageRating.ABSENT,
        attack_id="T1041", evasion_id="EF-001",
        shadow313_impl="None — no outbound traffic filtering.",
        gap_detail="DLP outbound traffic filtering would block large outbound transfers "
                   "to non-approved destinations. Shadow313 has no outbound filtering capability.",
    ),

    # ── EF-002: Exfiltration to Cloud Storage (T1567.002) ────────────────────
    CoverageEntry(
        d3fend=_t("D3-EBWSAM"), rating=CoverageRating.ABSENT,
        attack_id="T1567.002", evasion_id="EF-002",
        shadow313_impl="None — no endpoint-based web server access mediation.",
        gap_detail="Endpoint-based mediation would block connections to unauthorized cloud storage "
                   "domains (e.g., mega.nz, personal Dropbox). Shadow313 detects domains in event data only.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PBWSAM"), rating=CoverageRating.ABSENT,
        attack_id="T1567.002", evasion_id="EF-002",
        shadow313_impl="None — no proxy integration.",
        gap_detail="Proxy-based solution (Zscaler, Netskope) can inspect and block uploads to "
                   "unauthorized cloud storage services. Shadow313 has no proxy integration.",
    ),
    CoverageEntry(
        d3fend=_t("D3-UDTA"), rating=CoverageRating.PARTIAL,
        attack_id="T1567.002", evasion_id="EF-002",
        shadow313_impl="EF-002 signature detects cloud storage destination domains in event data.",
        gap_detail="MITRE DET0570 (Oct 2025): full detection correlates destination domain with "
                   "transfer volume and initiating process. Shadow313 detects domain only.",
    ),
    CoverageEntry(
        d3fend=_t("D3-DNSDL"), rating=CoverageRating.ABSENT,
        attack_id="T1567.002", evasion_id="EF-002",
        shadow313_impl="None — no DNS denylisting enforcement.",
        gap_detail="DNS denylisting for unauthorized cloud storage domains (e.g., mega.nz) would "
                   "prevent the initial DNS resolution required for exfiltration.",
    ),

    # ── FIN7-001: COM Object Hijacking (T1546.015) ────────────────────────────
    CoverageEntry(
        d3fend=_t("D3-SCP"), rating=CoverageRating.ABSENT,
        attack_id="T1546.015", evasion_id="FIN7-001",
        shadow313_impl="None — no registry ACL enforcement.",
        gap_detail="Restricting write access to CLSID registry keys in HKCU would prevent COM "
                   "hijacking. Shadow313 detects the registry key in event data only.",
    ),
    CoverageEntry(
        d3fend=_t("D3-SFA"), rating=CoverageRating.PARTIAL,
        attack_id="T1546.015", evasion_id="FIN7-001",
        shadow313_impl="EvasionDetector fires on 'clsid' and 'inprocserver32' in event data.",
        gap_detail="Detects these patterns in event descriptions. Does not continuously monitor "
                   "the CLSID registry hive for unauthorized modifications.",
    ),
    CoverageEntry(
        d3fend=_t("D3-DO"), rating=CoverageRating.FULL,
        attack_id="T1546.015", evasion_id="FIN7-001",
        shadow313_impl="ghost_watch.py implements AETHER decoys and WE-FORGE linguistic watermarking. "
                       "Decoy CLSID registry entries attract and detect COM hijacking attempts.",
        gap_detail="Full coverage — Ghost-Watch's decoy infrastructure directly implements D3-DO. "
                   "Deploying decoy CLSID entries (mimicking high-value COM objects like NGEN CLSID "
                   "used by Curly COMrades) provides early warning of COM hijacking.",
    ),
    CoverageEntry(
        d3fend=_t("D3-DUC"), rating=CoverageRating.FULL,
        attack_id="T1546.015", evasion_id="FIN7-001",
        shadow313_impl="ghost_watch.py AETHER decoy system includes decoy credentials. "
                       "Decoy service account credentials with SPNs attract Kerberoasting and COM hijacking.",
        gap_detail="Full coverage — Ghost-Watch's decoy credential system directly implements D3-DUC.",
    ),
    CoverageEntry(
        d3fend=_t("D3-PSA"), rating=CoverageRating.PARTIAL,
        attack_id="T1546.015", evasion_id="FIN7-001",
        shadow313_impl="EvasionDetector fires on COM hijacking technique in event data.",
        gap_detail="COM hijacking causes a legitimate application to load a malicious DLL which may "
                   "spawn child processes. D3-PSA would detect unexpected child processes from the "
                   "COM host application. Shadow313 detects the technique but not the resulting spawn.",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# PRIORITY INTEGRATIONS
# ═══════════════════════════════════════════════════════════════════════════════

PRIORITY_INTEGRATIONS: list[PriorityIntegration] = [
    PriorityIntegration(
        priority=1,
        d3fend_ids=["D3-PLA", "D3-PSA"],
        title="Process Lineage Analysis",
        evasion_ids=["PV-002", "C2-003", "FIN7-001"],
        attack_ids=["T1548.002", "T1071.001", "T1546.015"],
        rationale="Single primitive closing the most gaps simultaneously. UAC bypass, trusted "
                  "process C2, and COM hijacking all produce anomalous parent-child process "
                  "relationships invisible to flat event analysis but detectable via process tree traversal.",
        impl_path="Sysmon Event ID 1 (ProcessCreate) → build parent-child graph → flag: "
                  "(auto-elevated binary → shell), (legitimate process → unexpected network connection), "
                  "(COM host → unexpected child process).",
        effort_weeks=(2, 3),
    ),
    PriorityIntegration(
        priority=2,
        d3fend_ids=["D3-SCA", "D3-SCF", "D3-HBPI"],
        title="System Call Analysis (real-time kernel-level)",
        evasion_ids=["DE-001", "PV-001", "DE-003", "LM-001"],
        attack_ids=["T1055.001", "T1134.001", "T1574.002", "T1550.002"],
        rationale="Converts Shadow313's post-hoc detection into real-time prevention. "
                  "EvasionDetector already identifies the correct system calls. Adding a kernel-level "
                  "hook (D3-SCA) with system call filtering (D3-SCF) and process isolation (D3-HBPI) "
                  "converts detection into prevention for the highest-severity injection techniques.",
        impl_path="eBPF program attached to sys_enter_write and sys_enter_mmap → check if target PID "
                  "is a protected process → block and alert. Windows: ETW kernel provider + "
                  "WFP for system call filtering. TEE execution (Intel TDX) for hardware isolation.",
        effort_weeks=(3, 4),
    ),
    PriorityIntegration(
        priority=3,
        d3fend_ids=["D3-ANET"],
        title="Authentication Event Thresholding (statistical Kerberos/NTLM)",
        evasion_ids=["CA-002", "LM-001", "PV-001"],
        attack_ids=["T1558.003", "T1550.002", "T1134.001"],
        rationale="Extends existing ml_anomaly.py IsolationForest pipeline with two new feature sets. "
                  "Kerberos TGS request rate analysis and NTLM authentication pattern analysis "
                  "close the statistical detection gap identified by BeyondTrust (July 2025).",
        impl_path="New feature extractor for Kerberos/NTLM events → feed into existing IsolationForest "
                  "→ add Kerberos-specific threshold rules: >10 TGS requests in 60s from single user.",
        effort_weeks=(1, 2),
    ),
    PriorityIntegration(
        priority=4,
        d3fend_ids=["D3-FIM", "D3-SFA"],
        title="File Integrity Monitoring with Timestamp Baseline",
        evasion_ids=["DE-002", "DE-003"],
        attack_ids=["T1070.006", "T1574.002"],
        rationale="Extends pe_analyzer.py to maintain a baseline database and detect timestamp-only "
                  "changes (timestomping signature) and new DLLs in signed application directories "
                  "(side-loading signature).",
        impl_path="Extend pe_analyzer.py → add baseline snapshot (SHA3-256 hash + MACE timestamps) "
                  "→ periodic comparison → alert on: (hash unchanged + timestamp changed) = timestomping; "
                  "(new DLL in signed app directory) = side-loading candidate.",
        effort_weeks=(1, 2),
    ),
    PriorityIntegration(
        priority=5,
        d3fend_ids=["D3-FAPA"],
        title="File Access Pattern Analysis",
        evasion_ids=["CO-001", "EF-002"],
        attack_ids=["T1074.001", "T1567.002"],
        rationale="Closes the pre-exfiltration detection gap. Data staging involves accessing many "
                  "files across sensitive directories before archiving — detectable by monitoring "
                  "file access rates per process. Integrates with existing ghost_watch.py event bus.",
        impl_path="Monitor file access events (inotify on Linux, ReadDirectoryChangesW on Windows) "
                  "→ compute per-process file access rate → flag: >100 file accesses across >3 "
                  "directories in <60 seconds.",
        effort_weeks=(2, 2),
    ),
    PriorityIntegration(
        priority=6,
        d3fend_ids=["D3-ANCI"],
        title="Authentication Cache Invalidation Audit (Credential Guard)",
        evasion_ids=["LM-001", "CA-002"],
        attack_ids=["T1550.002", "T1558.003"],
        rationale="Configuration audit that checks whether Credential Guard is enabled on monitored "
                  "hosts and flags hosts where NTLM hash extraction is possible. Implementable as "
                  "a new health check in health_check.py.",
        impl_path="Add to health_check.py → check HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard "
                  "→ flag hosts where EnableVirtualizationBasedSecurity=0 or Credential Guard not required.",
        effort_weeks=(1, 1),
    ),
    PriorityIntegration(
        priority=7,
        d3fend_ids=["D3-PHDURA", "D3-UDTA"],
        title="Per Host Download-Upload Ratio Analysis",
        evasion_ids=["C2-001", "EF-001", "EF-002"],
        attack_ids=["T1071.001", "T1041", "T1567.002"],
        rationale="Extends existing ml_anomaly.py to aggregate per-host upload/download ratios "
                  "over time windows and flag hosts where upload ratio exceeds 3× baseline. "
                  "No new infrastructure required.",
        impl_path="Add time-windowed aggregation to ml_anomaly.py → compute per-host upload/download "
                  "ratio over 1h and 24h windows → flag deviations >3σ from baseline.",
        effort_weeks=(1, 1),
    ),
    PriorityIntegration(
        priority=8,
        d3fend_ids=["D3-EAL"],
        title="Executable Allowlisting — DLL Path Enforcement Audit",
        evasion_ids=["DE-003", "C2-003"],
        attack_ids=["T1574.002", "T1071.001"],
        rationale="DLL allowlisting enforcement is the most effective preventive control for DLL "
                  "side-loading (OPTIX, April 2026). Audit mode checks WDAC/AppArmor policy and "
                  "flags applications loading DLLs from user-writable directories.",
        impl_path="Shadow313 audit module → check WDAC/AppArmor policy → flag applications that "
                  "load DLLs from user-writable directories → generate remediation recommendation.",
        effort_weeks=(2, 6),
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# COVERAGE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class CoverageAnalyzer:
    """
    Query engine for D3FEND coverage analysis.

    Usage:
        analyzer = CoverageAnalyzer()
        report   = analyzer.full_report()
        gaps     = analyzer.absent_entries()
        priority = analyzer.priority_integrations()
    """

    def __init__(
        self,
        coverage_map: list[CoverageEntry]         = COVERAGE_MAP,
        priorities:   list[PriorityIntegration]   = PRIORITY_INTEGRATIONS,
    ) -> None:
        self._map        = coverage_map
        self._priorities = priorities

    # ── Counts ────────────────────────────────────────────────────────────────

    def count_by_rating(self) -> dict[str, int]:
        counts: dict[str, int] = {r.value: 0 for r in CoverageRating}
        for e in self._map:
            counts[e.rating.value] += 1
        return counts

    def total_entries(self) -> int:
        return len(self._map)

    def coverage_percentage(self) -> float:
        """Percentage of entries that are FULL or PARTIAL."""
        covered = sum(1 for e in self._map if e.rating != CoverageRating.ABSENT)
        return round(covered / max(1, len(self._map)) * 100, 1)

    def full_coverage_percentage(self) -> float:
        """Percentage of entries that are FULL only."""
        full = sum(1 for e in self._map if e.rating == CoverageRating.FULL)
        return round(full / max(1, len(self._map)) * 100, 1)

    # ── Filters ───────────────────────────────────────────────────────────────

    def entries_by_rating(self, rating: CoverageRating) -> list[CoverageEntry]:
        return [e for e in self._map if e.rating == rating]

    def absent_entries(self) -> list[CoverageEntry]:
        return self.entries_by_rating(CoverageRating.ABSENT)

    def full_entries(self) -> list[CoverageEntry]:
        return self.entries_by_rating(CoverageRating.FULL)

    def partial_entries(self) -> list[CoverageEntry]:
        return self.entries_by_rating(CoverageRating.PARTIAL)

    def entries_for_evasion(self, evasion_id: str) -> list[CoverageEntry]:
        return [e for e in self._map if e.evasion_id == evasion_id]

    def entries_for_d3fend(self, d3fend_id: str) -> list[CoverageEntry]:
        return [e for e in self._map if e.d3fend.d3fend_id == d3fend_id]

    def entries_for_tactic(self, tactic: D3FENDTactic) -> list[CoverageEntry]:
        return [e for e in self._map if e.d3fend.tactic == tactic]

    # ── Aggregations ──────────────────────────────────────────────────────────

    def coverage_by_evasion(self) -> dict[str, dict[str, int]]:
        """Per-evasion-technique coverage breakdown."""
        result: dict[str, dict[str, int]] = {}
        for e in self._map:
            if e.evasion_id not in result:
                result[e.evasion_id] = {r.value: 0 for r in CoverageRating}
            result[e.evasion_id][e.rating.value] += 1
        return result

    def coverage_by_tactic(self) -> dict[str, dict[str, int]]:
        """Per-D3FEND-tactic coverage breakdown."""
        result: dict[str, dict[str, int]] = {}
        for e in self._map:
            tactic = e.d3fend.tactic.value
            if tactic not in result:
                result[tactic] = {r.value: 0 for r in CoverageRating}
            result[tactic][e.rating.value] += 1
        return result

    def most_absent_d3fend_techniques(self, top_n: int = 10) -> list[tuple[str, int]]:
        """D3FEND techniques with the most ABSENT entries (highest gap impact)."""
        counts: dict[str, int] = {}
        for e in self.absent_entries():
            counts[e.d3fend.d3fend_id] = counts.get(e.d3fend.d3fend_id, 0) + 1
        return sorted(counts.items(), key=lambda x: -x[1])[:top_n]

    # ── Priority integrations ─────────────────────────────────────────────────

    def priority_integrations(self) -> list[PriorityIntegration]:
        return sorted(self._priorities, key=lambda p: p.priority)

    def total_effort_range(self) -> tuple[int, int]:
        """Total estimated effort range across all priority integrations."""
        min_w = sum(p.effort_weeks[0] for p in self._priorities)
        max_w = sum(p.effort_weeks[1] for p in self._priorities)
        return (min_w, max_w)

    # ── Full report ───────────────────────────────────────────────────────────

    def full_report(self) -> dict[str, Any]:
        counts = self.count_by_rating()
        return {
            "summary": {
                "total_entries":          self.total_entries(),
                "full_count":             counts[CoverageRating.FULL.value],
                "partial_count":          counts[CoverageRating.PARTIAL.value],
                "absent_count":           counts[CoverageRating.ABSENT.value],
                "coverage_pct":           self.coverage_percentage(),
                "full_coverage_pct":      self.full_coverage_percentage(),
                "total_effort_min_weeks": self.total_effort_range()[0],
                "total_effort_max_weeks": self.total_effort_range()[1],
            },
            "coverage_by_evasion":    self.coverage_by_evasion(),
            "coverage_by_tactic":     self.coverage_by_tactic(),
            "most_absent_techniques": self.most_absent_d3fend_techniques(),
            "priority_integrations": [
                {
                    "priority":      p.priority,
                    "title":         p.title,
                    "d3fend_ids":    p.d3fend_ids,
                    "evasion_ids":   p.evasion_ids,
                    "attack_ids":    p.attack_ids,
                    "effort_weeks":  p.effort_weeks,
                    "rationale":     p.rationale[:120] + "...",
                }
                for p in self.priority_integrations()
            ],
            "full_entries": [
                {
                    "d3fend_id":  e.d3fend.d3fend_id,
                    "name":       e.d3fend.name,
                    "evasion_id": e.evasion_id,
                    "impl":       e.shadow313_impl[:80] + "...",
                }
                for e in self.full_entries()
            ],
        }