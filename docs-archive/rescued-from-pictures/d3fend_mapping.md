# Shadow313 v4 × MITRE D3FEND v1.5.0 — Countermeasure Coverage Analysis

**Date:** 2026-08-29  
**D3FEND Version:** 1.5.0 (current as of August 2026)  
**Confidence:** High for D3FEND technique definitions (official d3fend.mitre.org v1.5.0). High for Shadow313 architecture coverage (based on implemented codebase). Medium for gap prioritization (analytical judgment grounded in ATT&CK-to-D3FEND mappings from d3fend.mitre.org/mappings/attack-mitigations/).

---

## Coverage Rating Definitions

| Rating | Meaning |
|--------|---------|
| **✅ Full** | Shadow313 implements the D3FEND primitive's core mechanism. The EvasionDetector, ThreatSignature, or an existing module directly performs the described defensive action. |
| **⚠️ Partial** | Shadow313 detects the artifact or event that the D3FEND primitive targets, but does not implement the preventive or hardening aspect. Detection without enforcement. |
| **❌ Absent** | The D3FEND primitive has no corresponding implementation in Shadow313 v4. The gap is real and exploitable. |

---

## Technique 1: Token Impersonation (T1134.001) — PV-001

### D3FEND Countermeasures Mapped

**D3-SCF — System Call Filtering**  
*Definition: Configuring the operating system to restrict which system calls a process may invoke.*  
**Shadow313 Coverage: ❌ Absent**  
System call filtering (seccomp on Linux, Windows Filtering Platform on Windows) would prevent a process from calling `NtCreateToken`, `ImpersonateLoggedOnUser`, or `DuplicateTokenEx` — the three system calls required for token impersonation. Shadow313 detects the presence of `SeImpersonatePrivilege` in event data but does not enforce any system call restriction. The EvasionDetector fires after the fact; D3-SCF would prevent the call from completing.

**D3-HBPI — Hardware-based Process Isolation**  
*Definition: Preventing one process from accessing the resources of another process using hardware-based controls.*  
**Shadow313 Coverage: ❌ Absent**  
Hardware-based isolation (Intel TDX, AMD SEV-SNP, ARM TrustZone) would prevent a compromised service account process from accessing the token of a higher-privileged process. Shadow313 has no hardware isolation layer. This is the same gap identified in the SLH-DSA Rowhammer analysis — TEE execution is a 2027 deployment target.

**D3-LAM — Local Account Monitoring**  
*Definition: Monitoring local accounts to detect unauthorized activity.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on `SeImpersonatePrivilege` in event descriptions, which is a form of account privilege monitoring. However, Shadow313 does not continuously monitor local account privilege assignments or alert when `SeImpersonatePrivilege` is granted to a new account. The detection is reactive (fires when the privilege is used) rather than proactive (fires when the privilege is assigned).

**D3-ANET — Authentication Event Thresholding**  
*Definition: Aggregating authentication events and applying threshold-based detection.*  
**Shadow313 Coverage: ⚠️ Partial**  
The IA-003 signature monitors authentication events and anomalies (impossible travel, off-hours logon). Token impersonation produces authentication events (Event ID 4624 with LogonType 9 — NewCredentials). Shadow313 detects the description of these events but does not implement threshold-based aggregation across multiple authentication events over time.

**Recommended next integration:** D3-SCF via seccomp profile enforcement in the Shadow313 agent process, blocking `NtCreateToken` and `ImpersonateLoggedOnUser` calls from non-privileged contexts.

---

## Technique 2: UAC Bypass via Fodhelper (T1548.002) — PV-002

### D3FEND Countermeasures Mapped

**D3-PSA — Process Spawn Analysis**  
*Definition: Analyzing spawn arguments or attributes of a process to detect processes that are unauthorized.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on `fodhelper` in event descriptions, which corresponds to detecting the auto-elevated binary in process spawn data. However, D3-PSA's full implementation requires analyzing the parent-child process relationship: `fodhelper.exe` spawning `cmd.exe` or `powershell.exe` is the anomalous pattern. Shadow313 detects the binary name but not the parent-child lineage.

**D3-PLA — Process Lineage Analysis**  
*Definition: Identification of suspicious processes by examining the ancestry and siblings of a process, and the associated metadata of each node on the tree.*  
**Shadow313 Coverage: ❌ Absent**  
Process lineage analysis is the primary D3FEND countermeasure for UAC bypass. The detection signal is: `fodhelper.exe` (auto-elevated, no UAC prompt) → spawns → `cmd.exe` or `powershell.exe` (elevated). Shadow313 has no process tree analysis capability. The EvasionDetector fires on the binary name in a flat event dict; it cannot traverse a process ancestry graph.

**D3-SCP — System Configuration Permissions**  
*Definition: Restricting access to system configuration files and registry keys.*  
**Shadow313 Coverage: ❌ Absent**  
The UAC bypass writes to `HKCU\Software\Classes\ms-settings\Shell\Open\command`. Restricting write access to this registry key path (via registry ACLs) would prevent the bypass entirely. Shadow313 detects the registry key in event data but does not enforce registry ACL restrictions.

**D3-ACH — Application Configuration Hardening**  
*Definition: Modifying an application's configuration to reduce its attack surface.*  
**Shadow313 Coverage: ❌ Absent**  
Setting UAC to "Always notify" (the highest level) prevents auto-elevation of binaries like `fodhelper.exe`. Shadow313 does not audit or enforce UAC configuration levels.

**Recommended next integration:** D3-PLA via a process lineage analyzer that builds parent-child trees from Sysmon Event ID 1 data and flags auto-elevated binaries spawning shells.

---

## Technique 3: Process Injection into Svchost (T1055.001) — DE-001

### D3FEND Countermeasures Mapped

**D3-SCA — System Call Analysis**  
*Definition: Analyzing system calls to determine whether a process is exhibiting unauthorized behavior.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` in event data — these are the system calls that process injection requires. This is detection of the system call names in log data, which is a form of D3-SCA. However, true D3-SCA operates at the kernel level, intercepting system calls in real time before they complete. Shadow313's detection is post-hoc (fires on logged event data) rather than real-time (intercepts the call).

**D3-SSC — Shadow Stack Comparisons**  
*Definition: Comparing a call stack in system memory with a shadow call stack maintained by the processor to determine unauthorized shellcode activity.*  
**Shadow313 Coverage: ❌ Absent**  
Shadow stack comparisons (Intel CET — Control-flow Enforcement Technology) detect return-oriented programming (ROP) chains used in shellcode injection. When injected shellcode executes, it typically violates the shadow stack invariant — the return address on the shadow stack does not match the return address on the regular stack. Shadow313 has no shadow stack analysis capability.

**D3-PSMD — Process Self-Modification Detection**  
*Definition: Detects processes that modify, change, or replace their own code at runtime.*  
**Shadow313 Coverage: ❌ Absent**  
Process hollowing (a variant of process injection) involves a process replacing its own code segment with malicious code. D3-PSMD detects this by monitoring for writes to a process's own code segment. Shadow313 detects the API call names but not the self-modification pattern.

**D3-HBPI — Hardware-based Process Isolation**  
*Definition: Preventing one process from accessing the resources of another process using hardware-based controls.*  
**Shadow313 Coverage: ❌ Absent**  
Hardware-based isolation would prevent `VirtualAllocEx` and `WriteProcessMemory` from succeeding across process boundaries for non-privileged callers. This is the preventive complement to Shadow313's detective capability.

**D3-PCSV — Process Code Segment Verification**  
*Definition: Comparing the "text" or "code" memory segments to a source of truth.*  
**Shadow313 Coverage: ❌ Absent**  
After injection, the `svchost.exe` code segment differs from the known-good binary on disk. D3-PCSV would detect this discrepancy. Shadow313 has no code segment verification capability.

**Recommended next integration:** D3-SCA via a kernel-level system call monitor (eBPF on Linux, ETW on Windows) that intercepts `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` calls in real time and blocks cross-process writes to protected processes.

---

## Technique 4: Timestomping (T1070.006) — DE-002

### D3FEND Countermeasures Mapped

**D3-FIM — File Integrity Monitoring**  
*Definition: Detecting any suspicious changes to files in a computer system.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on `SetFileTime`, `touch -t`, and `MACE` in event data — these are the operations that timestomping uses. This is detection of the timestomping operation, which is a form of FIM. However, D3-FIM's full implementation compares current file metadata against a cryptographic baseline (hash + timestamp snapshot). Shadow313 detects the timestomping operation in event logs but does not maintain a baseline of expected file timestamps for comparison.

**D3-SFA — System File Analysis**  
*Definition: Monitoring system files such as authentication databases, configuration files, system logs, and system executables for modification or tampering.*  
**Shadow313 Coverage: ⚠️ Partial**  
The `shadow313/v4/aegis/pe_analyzer.py` module performs PE static header analysis and entropy profiling — a form of system file analysis. However, it does not specifically monitor NTFS MACE timestamps or compare them against a known-good baseline.

**D3-FCA — File Creation Analysis**  
*Definition: Analyzing the properties of file create system call invocations.*  
**Shadow313 Coverage: ❌ Absent**  
File creation analysis monitors `NtCreateFile` system calls and their parameters, including the timestamp fields. Timestomping that occurs at file creation time (setting a backdated timestamp during the initial write) would be detected by D3-FCA but not by Shadow313's current implementation.

**Recommended next integration:** D3-FIM via a baseline snapshot module that records SHA3-256 hashes and NTFS timestamps for all files in monitored directories, with periodic comparison and alerting on timestamp-only changes (content hash unchanged but timestamp changed — the signature of timestomping).

---

## Technique 5: DLL Side-Loading (T1574.002) — DE-003

### D3FEND Countermeasures Mapped

**D3-DLIC — Driver Load Integrity Checking**  
*Definition: Ensuring the integrity of drivers loaded during initialization of the operating system.*  
**Shadow313 Coverage: ⚠️ Partial**  
The D3FEND definition of D3-DLIC extends to DLL integrity checking via code signing verification. Shadow313's plugin trust registry (HMAC-SHA256 + cosign) implements a form of this for Shadow313 plugins. However, it does not extend to arbitrary DLLs loaded by third-party applications — the attack surface for DLL side-loading.

**D3-EAL — Executable Allowlisting**  
*Definition: Using a whitelist to block execution of unauthorized executables.*  
**Shadow313 Coverage: ❌ Absent**  
Executable allowlisting (Windows Defender Application Control / WDAC, AppLocker) configured to restrict DLL loads from user-writable directories is identified by OPTIX (April 2026) as "the most effective preventive control" for DLL side-loading. Shadow313 has no allowlisting enforcement capability.

**D3-SBV — Service Binary Verification**  
*Definition: Analyzing changes in service binary files by comparing to a source of truth.*  
**Shadow313 Coverage: ⚠️ Partial**  
The `shadow313/v4/update/updater.py` module performs integrity verification of Shadow313's own binaries. This is a form of D3-SBV for Shadow313's own components. It does not extend to third-party application DLLs.

**D3-SCF — System Call Filtering**  
*Definition: Configuring the operating system to restrict which system calls a process may invoke.*  
**Shadow313 Coverage: ❌ Absent**  
System call filtering can restrict `LoadLibrary` calls to paths outside user-writable directories, preventing DLL side-loading at the OS level. Shadow313 has no system call filtering capability.

**Recommended next integration:** D3-EAL via a DLL load path monitor that flags any DLL loaded by a signed application from a user-writable directory (e.g., `%TEMP%`, `%APPDATA%`, `%USERPROFILE%`). This is implementable as a Sysmon Event ID 7 (ImageLoad) analysis module.

---

## Technique 6: Kerberoasting (T1558.003) — CA-002

### D3FEND Countermeasures Mapped

**D3-SPP — Strong Password Policy**  
*Definition: Modifying system configuration to increase password strength.*  
**Shadow313 Coverage: ❌ Absent**  
Kerberoasting is only effective when service account passwords are weak enough to crack offline. Enforcing 25+ character passwords for service accounts (Specops, 2025) makes Kerberoasting computationally infeasible. Shadow313 detects Kerberoasting attempts but does not audit or enforce service account password strength.

**D3-OTP — One-time Password**  
*Definition: A one-time password is valid for only one user authentication.*  
**Shadow313 Coverage: ❌ Absent**  
Managed Service Accounts (MSAs) and Group Managed Service Accounts (gMSAs) in Active Directory use automatically rotated, 240-character passwords — effectively one-time passwords for each authentication cycle. Shadow313 does not audit whether service accounts use gMSAs.

**D3-ANET — Authentication Event Thresholding**  
*Definition: Aggregating authentication events and applying threshold-based detection.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on Event ID 4769 (TGS requests) in event data. The BeyondTrust research (July 2025) identifies that effective Kerberoasting detection requires statistical analysis of TGS request patterns — not just the presence of a single 4769 event. Shadow313 detects the event ID but does not implement the statistical framework for distinguishing legitimate from malicious TGS request patterns.

**D3-DAM — Domain Account Monitoring**  
*Definition: Monitoring domain accounts to detect unauthorized activity.*  
**Shadow313 Coverage: ⚠️ Partial**  
The DI-002 signature detects account enumeration (Get-ADUser, Get-ADGroup, dsquery) — a precursor to Kerberoasting. This is a form of domain account monitoring. However, Shadow313 does not continuously monitor domain accounts for SPN assignments or flag accounts with SPNs and weak passwords.

**D3-CRO — Credential Rotation**  
*Definition: Regularly changing authentication credentials to minimize the risk of unauthorized access.*  
**Shadow313 Coverage: ❌ Absent**  
Regular KRBTGT password rotation (Microsoft recommends twice per year) limits the window during which a cracked Kerberos ticket is valid. Shadow313 does not audit or enforce credential rotation schedules.

**Recommended next integration:** D3-ANET via a Kerberos statistical anomaly detector that baselines TGS request rates per user and flags deviations (e.g., a user requesting TGS tickets for 50 SPNs in 30 seconds — the Kerberoasting signature). This integrates with the existing `shadow313/v2/network_upgrades/ml_anomaly.py` ML pipeline.

---

## Technique 7: Pass-the-Hash via WMI (T1550.002) — LM-001

### D3FEND Countermeasures Mapped

**D3-ANCI — Authentication Cache Invalidation**  
*Definition: Removing tokens or credentials from an authentication cache to prevent their further use.*  
**Shadow313 Coverage: ❌ Absent**  
Pass-the-Hash exploits cached NTLM hashes in LSASS memory. Authentication cache invalidation (enabling Credential Guard, which moves NTLM hash storage into a Hyper-V isolated container) prevents hash extraction entirely. Shadow313 detects PtH attempts but does not audit whether Credential Guard is enabled.

**D3-HBPI — Hardware-based Process Isolation**  
*Definition: Preventing one process from accessing the resources of another process using hardware-based controls.*  
**Shadow313 Coverage: ❌ Absent**  
Credential Guard uses hardware-based isolation (VBS — Virtualization Based Security) to protect NTLM hashes in a separate security domain that LSASS cannot access directly. Shadow313 has no hardware isolation capability.

**D3-ANET — Authentication Event Thresholding**  
*Definition: Aggregating authentication events and applying threshold-based detection.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on `ntlm hash`, `wmiexec`, and `impacket` in event data. The `operatoronthewire.com` detection reference identifies Event ID 4776 (NTLM authentication) as the primary detection signal. Shadow313 detects the tool names and technique ID but does not implement threshold-based NTLM authentication monitoring (e.g., flagging an account authenticating to 10 hosts in 60 seconds via NTLM).

**D3-NI — Network Isolation**  
*Definition: Restricting network access to limit lateral movement.*  
**Shadow313 Coverage: ❌ Absent**  
Network segmentation that restricts WMI traffic (TCP 135, dynamic RPC ports) between workstations prevents WMI-based lateral movement. Shadow313 does not audit or enforce network segmentation policies.

**Recommended next integration:** D3-ANCI via a Credential Guard audit module that checks whether VBS and Credential Guard are enabled on monitored hosts, and flags hosts where NTLM hash extraction is possible (Credential Guard disabled, LSASS not running in protected mode).

---

## Technique 8: Data Staged for Exfiltration (T1074.001) — CO-001

### D3FEND Countermeasures Mapped

**D3-FAPA — File Access Pattern Analysis**  
*Definition: Analyzing the files accessed by a process to identify unauthorized activity.*  
**Shadow313 Coverage: ❌ Absent**  
Data staging involves a process accessing a large number of files across sensitive directories (Documents, Desktop, network shares) in a short time window, then writing them to an archive. D3-FAPA would detect this access pattern. Shadow313 detects the archive creation command but not the file access pattern that precedes it.

**D3-UDTA — User Data Transfer Analysis**  
*Definition: Analyzing the amount of data transferred by a user.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EF-001 signature detects `bytes_out: large` in event data — a form of data transfer analysis. However, D3-UDTA's full implementation requires baselining normal data transfer volumes per user and flagging deviations. Shadow313 detects the keyword `large` in a field but does not implement baseline-based anomaly detection.

**D3-FCA — File Creation Analysis**  
*Definition: Analyzing the properties of file create system call invocations.*  
**Shadow313 Coverage: ❌ Absent**  
Data staging creates archive files (`.zip`, `.7z`, `.rar`) in specific directories. D3-FCA would detect the creation of large archive files in unusual locations (e.g., `%TEMP%`, `C:\Windows\Temp`). Shadow313 detects the archive command in event data but not the file creation event itself.

**Recommended next integration:** D3-FAPA via a file access pattern analyzer that monitors process file access rates and flags processes that access >100 files across >3 directories in <60 seconds — the data staging signature.

---

## Technique 9: Cobalt Strike Beacon over HTTPS (T1071.001) — C2-001

### D3FEND Countermeasures Mapped

**D3-NTA — Network Traffic Analysis**  
*Definition: Analyzing network traffic to detect adversary activity.*  
**Shadow313 Coverage: ⚠️ Partial**  
The `shadow313/v2/network_upgrades/ja3_fingerprint.py` module implements JA3/JA3S TLS fingerprinting — a form of network traffic analysis specifically effective against Cobalt Strike beacons. Cobalt Strike's default JA3 fingerprint (`769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0`) is well-known and detectable. This is a **genuine partial coverage** — JA3 fingerprinting catches default Cobalt Strike configurations but not custom malleable profiles that randomize the TLS handshake.

**D3-PHDURA — Per Host Download-Upload Ratio Analysis**  
*Definition: Detecting anomalies by comparing the amount of data downloaded versus data uploaded by a host.*  
**Shadow313 Coverage: ⚠️ Partial**  
Cobalt Strike beacons have a characteristic upload-heavy ratio (small check-in downloads, larger command output uploads). The `shadow313/v2/network_upgrades/ml_anomaly.py` module's 14-dimensional feature vector includes `byte_rate` and `packet_rate` — features that capture this ratio. However, the current implementation uses IsolationForest on flow-level features, not per-host ratio analysis over time windows.

**D3-CPSP — Client-server Payload Profiling**  
*Definition: Comparing client-server payloads to a baseline to detect anomalies.*  
**Shadow313 Coverage: ❌ Absent**  
Cobalt Strike's malleable C2 profile modifies the HTTP request/response structure to mimic legitimate applications. Client-server payload profiling would detect deviations from the expected payload structure for a given domain (e.g., a domain claiming to be `microsoft.com` but with non-Microsoft payload patterns). Shadow313 has no payload profiling capability.

**D3-DNSAL — DNS Allowlisting**  
*Definition: Permitting only approved DNS queries.*  
**Shadow313 Coverage: ❌ Absent**  
Cobalt Strike beacons often use newly registered domains for C2. DNS allowlisting would block connections to domains not on an approved list. Shadow313 has no DNS allowlisting enforcement.

**Recommended next integration:** D3-CPSP via a beacon payload profiler that analyzes HTTP request/response patterns for known Cobalt Strike malleable profile signatures (URI patterns, header ordering, body encoding) — extending the existing JA3 fingerprinting module.

---

## Technique 10: C2 via Trusted Process — PhantomWire (T1071.001) — C2-003

### D3FEND Countermeasures Mapped

**D3-PSA — Process Spawn Analysis**  
*Definition: Analyzing spawn arguments or attributes of a process to detect processes that are unauthorized.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on `phantomwire`, `trusted process`, and `process masquerade` in event data. D3-PSA's full implementation analyzes process spawn attributes including the image path, parent process, and command-line arguments. Shadow313 detects the technique description but not the process spawn attributes directly.

**D3-PLA — Process Lineage Analysis**  
*Definition: Identification of suspicious processes by examining the ancestry and siblings of a process.*  
**Shadow313 Coverage: ❌ Absent**  
The PhantomWire scenario involves a legitimate process (e.g., `explorer.exe`) making unexpected network connections. D3-PLA would detect this by flagging processes whose network behavior deviates from their expected lineage (e.g., `explorer.exe` making POST requests to an external IP is anomalous). Shadow313 has no process lineage analysis capability.

**D3-RPTA — Relay Pattern Analysis**  
*Definition: Analyzing network traffic for relay patterns that indicate C2 communication.*  
**Shadow313 Coverage: ❌ Absent**  
Trusted process C2 often uses a relay pattern: the trusted process connects to a legitimate service (e.g., Google Calendar, OneDrive) which relays commands. D3-RPTA would detect the relay pattern in network traffic. Shadow313 has no relay pattern analysis capability.

**Recommended next integration:** D3-PLA via a process-network correlation module that maps each process's network connections to its expected behavior profile and flags deviations (e.g., `svchost.exe` making connections to non-Microsoft IPs, `explorer.exe` making POST requests to external hosts).

---

## Technique 11: Exfiltration over C2 Channel (T1041) — EF-001

### D3FEND Countermeasures Mapped

**D3-UDTA — User Data Transfer Analysis**  
*Definition: Analyzing the amount of data transferred by a user.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EF-001 signature detects `bytes_out: large` and `direction: outbound`. D3-UDTA's full implementation requires baselining normal outbound transfer volumes per user/host and flagging deviations. Shadow313 detects the keyword but not the baseline deviation.

**D3-PHDURA — Per Host Download-Upload Ratio Analysis**  
*Definition: Detecting anomalies by comparing download versus upload ratios.*  
**Shadow313 Coverage: ⚠️ Partial**  
The `ml_anomaly.py` module's `byte_rate` feature captures upload volume. However, per-host ratio analysis over time windows (the D3-PHDURA mechanism) is not implemented — the current model analyzes individual flows, not aggregated per-host ratios.

**D3-OTF — Outbound Traffic Filtering**  
*Definition: Filtering outbound network traffic to prevent unauthorized data transfer.*  
**Shadow313 Coverage: ❌ Absent**  
Outbound traffic filtering (DLP — Data Loss Prevention) would block large outbound transfers to non-approved destinations. Shadow313 has no outbound traffic filtering capability.

**Recommended next integration:** D3-PHDURA via a per-host ratio analyzer that aggregates upload/download bytes per host over 1-hour windows and flags hosts where the upload ratio exceeds 3× the baseline — the exfiltration signature.

---

## Technique 12: Exfiltration to Cloud Storage (T1567.002) — EF-002

### D3FEND Countermeasures Mapped

**D3-EBWSAM — Endpoint-based Web Server Access Mediation**  
*Definition: Controlling access to web servers from endpoints.*  
**Shadow313 Coverage: ❌ Absent**  
Endpoint-based web server access mediation would block connections from endpoints to unauthorized cloud storage domains (e.g., `mega.nz`, personal Dropbox accounts). Shadow313 detects connections to these domains in event data but does not enforce access mediation.

**D3-PBWSAM — Proxy-based Web Server Access Mediation**  
*Definition: Controlling access to web servers via a proxy.*  
**Shadow313 Coverage: ❌ Absent**  
A proxy-based solution (Zscaler, Netskope, Palo Alto Prisma) can inspect and block uploads to unauthorized cloud storage services. Shadow313 has no proxy integration.

**D3-UDTA — User Data Transfer Analysis**  
*Definition: Analyzing the amount of data transferred by a user.*  
**Shadow313 Coverage: ⚠️ Partial**  
The MITRE ATT&CK detection strategy DET0570 (October 2025) identifies the key signal: "unusual processes initiating HTTPS POST requests to domains associated with cloud storage services." Shadow313's EF-002 signature detects the destination domains in event data. D3-UDTA's full implementation correlates the destination domain with the transfer volume and the initiating process — Shadow313 detects the domain but not the full correlation.

**D3-DNSDL — DNS Denylisting**  
*Definition: Blocking DNS queries to known malicious or unauthorized domains.*  
**Shadow313 Coverage: ❌ Absent**  
DNS denylisting for unauthorized cloud storage domains (e.g., `mega.nz`, personal Dropbox) would prevent the initial DNS resolution required for exfiltration. Shadow313 has no DNS denylisting enforcement.

**Recommended next integration:** D3-UDTA via a cloud destination monitor that correlates outbound HTTPS POST requests to cloud storage domains with the initiating process and transfer volume, flagging uploads >10MB to non-approved cloud destinations.

---

## Technique 13: COM Object Hijacking (T1546.015) — FIN7-001

### D3FEND Countermeasures Mapped

**D3-SCP — System Configuration Permissions**  
*Definition: Restricting access to system configuration files and registry keys.*  
**Shadow313 Coverage: ❌ Absent**  
COM hijacking writes to `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32`. Restricting write access to CLSID registry keys in HKCU (via registry ACLs or AppLocker registry rules) would prevent COM hijacking. Shadow313 detects the registry key in event data but does not enforce registry ACL restrictions.

**D3-SFA — System File Analysis**  
*Definition: Monitoring system files such as authentication databases, configuration files, system logs, and system executables for modification or tampering.*  
**Shadow313 Coverage: ⚠️ Partial**  
The EvasionDetector fires on `clsid` and `inprocserver32` in event data — these are registry key paths that D3-SFA would monitor. Shadow313 detects these patterns in event descriptions but does not continuously monitor the CLSID registry hive for unauthorized modifications.

**D3-DO — Decoy Object**  
*Definition: A Decoy Object is created and deployed for the purposes of deceiving attackers.*  
**Shadow313 Coverage: ✅ Full (via Ghost-Watch)**  
Shadow313's `ghost_watch.py` implements AETHER decoys and WE-FORGE linguistic watermarking — a form of D3-DO. Specifically, deploying decoy CLSID registry entries that appear to be high-value COM objects (e.g., mimicking the NGEN CLSID used by Curly COMrades) would detect COM hijacking attempts when an attacker queries or modifies the decoy entry. The Ghost-Watch module's honeypot infrastructure is directly applicable here.

**D3-DUC — Decoy User Credential**  
*Definition: A Credential created for the purpose of deceiving an adversary.*  
**Shadow313 Coverage: ✅ Full (via Ghost-Watch)**  
Ghost-Watch's AETHER decoy system includes decoy credentials. Deploying decoy service account credentials with SPNs (to attract Kerberoasting) and decoy CLSID entries (to attract COM hijacking) provides early warning of both techniques.

**D3-PSA — Process Spawn Analysis**  
*Definition: Analyzing spawn arguments or attributes of a process to detect processes that are unauthorized.*  
**Shadow313 Coverage: ⚠️ Partial**  
COM hijacking causes a legitimate application to load a malicious DLL, which may then spawn child processes. D3-PSA would detect unexpected child processes spawned by the COM host application. Shadow313 detects the COM hijacking technique in event data but not the resulting process spawn.

**Recommended next integration:** D3-SCP via a registry integrity monitor that baselines all CLSID entries in `HKCU\Software\Classes\CLSID` and alerts on new entries or modifications — particularly entries pointing to DLLs in user-writable directories.

---

## Consolidated Coverage Matrix

| Evasion Technique | ATT&CK ID | Primary D3FEND Countermeasures | Full ✅ | Partial ⚠️ | Absent ❌ |
|---|---|---|---|---|---|
| Token Impersonation | T1134.001 | D3-SCF, D3-HBPI, D3-LAM, D3-ANET | 0 | 2 | 2 |
| UAC Bypass (fodhelper) | T1548.002 | D3-PSA, D3-PLA, D3-SCP, D3-ACH | 0 | 1 | 3 |
| Process Injection (svchost) | T1055.001 | D3-SCA, D3-SSC, D3-PSMD, D3-HBPI, D3-PCSV | 0 | 1 | 4 |
| Timestomping | T1070.006 | D3-FIM, D3-SFA, D3-FCA | 0 | 2 | 1 |
| DLL Side-Loading | T1574.002 | D3-DLIC, D3-EAL, D3-SBV, D3-SCF | 0 | 2 | 2 |
| Kerberoasting | T1558.003 | D3-SPP, D3-OTP, D3-ANET, D3-DAM, D3-CRO | 0 | 2 | 3 |
| Pass-the-Hash via WMI | T1550.002 | D3-ANCI, D3-HBPI, D3-ANET, D3-NI | 0 | 1 | 3 |
| Data Staging | T1074.001 | D3-FAPA, D3-UDTA, D3-FCA | 0 | 1 | 2 |
| Cobalt Strike HTTPS Beacon | T1071.001 | D3-NTA, D3-PHDURA, D3-CPSP, D3-DNSAL | 0 | 2 | 2 |
| Trusted Process C2 | T1071.001 | D3-PSA, D3-PLA, D3-RPTA | 0 | 1 | 2 |
| Exfiltration over C2 | T1041 | D3-UDTA, D3-PHDURA, D3-OTF | 0 | 2 | 1 |
| Cloud Storage Exfiltration | T1567.002 | D3-EBWSAM, D3-PBWSAM, D3-UDTA, D3-DNSDL | 0 | 1 | 3 |
| COM Object Hijacking | T1546.015 | D3-SCP, D3-SFA, D3-DO, D3-DUC, D3-PSA | **2** | 2 | 1 |

**Totals across all 13 techniques:**
- ✅ Full: **2** (both in COM Object Hijacking via Ghost-Watch D3-DO and D3-DUC)
- ⚠️ Partial: **20**
- ❌ Absent: **29**

---

## Gap Priority Ranking — Which D3FEND Primitives to Integrate Next

Ranked by: (attack surface breadth × implementation feasibility × coverage gap severity)

### Priority 1 — D3-PLA: Process Lineage Analysis
**Addresses:** UAC Bypass (PV-002), Trusted Process C2 (C2-003), COM Object Hijacking (FIN7-001)  
**Why first:** Process lineage analysis is the single D3FEND primitive that closes the most gaps simultaneously. UAC bypass, trusted process C2, and COM hijacking all produce anomalous parent-child process relationships that are invisible to flat event analysis but detectable via process tree traversal. Shadow313 already collects process data in the recon and network modules — adding a process tree builder and lineage analyzer is an incremental addition.  
**Implementation path:** Sysmon Event ID 1 (ProcessCreate) → build parent-child graph → flag: (auto-elevated binary → shell), (legitimate process → unexpected network connection), (COM host → unexpected child process).  
**Estimated effort:** 2-3 weeks.

### Priority 2 — D3-SCA: System Call Analysis (real-time)
**Addresses:** Process Injection (DE-001), Token Impersonation (PV-001)  
**Why second:** System call analysis at the kernel level converts Shadow313's post-hoc detection (fires on logged event data) into real-time prevention (intercepts the call before it completes). The EvasionDetector already identifies the correct system calls (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateToken`). Adding a kernel-level hook (eBPF on Linux, ETW on Windows) that intercepts these calls and blocks cross-process writes to protected processes would convert detection into prevention.  
**Implementation path:** eBPF program attached to `sys_enter_write` and `sys_enter_mmap` → check if target PID is a protected process → block and alert.  
**Estimated effort:** 3-4 weeks (requires kernel module or eBPF).

### Priority 3 — D3-ANET: Authentication Event Thresholding (statistical)
**Addresses:** Kerberoasting (CA-002), Pass-the-Hash (LM-001), Token Impersonation (PV-001)  
**Why third:** The existing `ml_anomaly.py` IsolationForest pipeline is the natural home for authentication event thresholding. Adding Kerberos TGS request rate analysis (flag: >10 TGS requests in 60 seconds from a single user) and NTLM authentication pattern analysis (flag: same account authenticating to >5 hosts in 60 seconds) extends the existing ML pipeline with two new feature sets.  
**Implementation path:** New feature extractor for Kerberos/NTLM events → feed into existing IsolationForest → add Kerberos-specific threshold rules as a hybrid statistical/ML detector.  
**Estimated effort:** 1-2 weeks (extends existing module).

### Priority 4 — D3-FIM: File Integrity Monitoring (with timestamp baseline)
**Addresses:** Timestomping (DE-002), DLL Side-Loading (DE-003)  
**Why fourth:** A file integrity monitor that records SHA3-256 hashes AND NTFS MACE timestamps for monitored directories would detect both timestomping (content hash unchanged, timestamp changed) and DLL side-loading (new DLL appears in application directory). Shadow313's `pe_analyzer.py` already computes file hashes — extending it to maintain a baseline database and detect timestamp-only changes is incremental.  
**Implementation path:** Extend `pe_analyzer.py` → add baseline snapshot (hash + MACE timestamps) → periodic comparison → alert on: (hash unchanged + timestamp changed) = timestomping; (new DLL in signed app directory) = side-loading candidate.  
**Estimated effort:** 1-2 weeks.

### Priority 5 — D3-FAPA: File Access Pattern Analysis
**Addresses:** Data Staging (CO-001), Cloud Storage Exfiltration (EF-002)  
**Why fifth:** File access pattern analysis closes the pre-exfiltration detection gap. Data staging involves accessing many files across sensitive directories before archiving — a pattern detectable by monitoring file access rates per process. This integrates with the existing `ghost_watch.py` event bus infrastructure.  
**Implementation path:** Monitor file access events (inotify on Linux, ReadDirectoryChangesW on Windows) → compute per-process file access rate → flag: >100 file accesses across >3 directories in <60 seconds.  
**Estimated effort:** 2 weeks.

### Priority 6 — D3-ANCI: Authentication Cache Invalidation (audit mode)
**Addresses:** Pass-the-Hash (LM-001), Kerberoasting (CA-002)  
**Why sixth:** Rather than implementing Credential Guard directly (a Windows kernel feature), Shadow313 can implement an audit module that checks whether Credential Guard is enabled on monitored hosts and flags hosts where NTLM hash extraction is possible. This is a configuration audit, not a runtime enforcement — implementable as a new health check in `health_check.py`.  
**Implementation path:** Add to `health_check.py` → check `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` registry key → flag hosts where `EnableVirtualizationBasedSecurity=0` or `RequirePlatformSecurityFeatures` does not include Credential Guard.  
**Estimated effort:** 1 week.

### Priority 7 — D3-PHDURA: Per Host Download-Upload Ratio Analysis
**Addresses:** Cobalt Strike Beacon (C2-001), Exfiltration over C2 (EF-001), Cloud Storage Exfiltration (EF-002)  
**Why seventh:** The existing `ml_anomaly.py` module already computes `byte_rate` per flow. Extending it to aggregate per-host upload/download ratios over time windows (1 hour, 24 hours) and flag hosts where the upload ratio exceeds 3× the baseline closes the exfiltration detection gap without requiring new infrastructure.  
**Implementation path:** Add time-windowed aggregation to `ml_anomaly.py` → compute per-host upload/download ratio → flag deviations >3σ from baseline.  
**Estimated effort:** 1 week.

### Priority 8 — D3-EAL: Executable Allowlisting (DLL path enforcement)
**Addresses:** DLL Side-Loading (DE-003), Trusted Process C2 (C2-003)  
**Why eighth:** DLL allowlisting enforcement (blocking DLL loads from user-writable directories by signed applications) is the most effective preventive control for DLL side-loading. This requires integration with the OS-level allowlisting mechanism (WDAC on Windows, AppArmor on Linux) — a deployment architecture decision rather than a code change.  
**Implementation path:** Shadow313 audit module → check WDAC/AppArmor policy → flag applications that load DLLs from user-writable directories → generate remediation recommendation.  
**Estimated effort:** 2 weeks (audit mode); 4-6 weeks (enforcement mode).

---

## D3FEND Primitives Already Fully Covered

Only two D3FEND primitives are fully covered in the current Shadow313 v4 architecture:

**D3-DO (Decoy Object) — via Ghost-Watch AETHER decoys**  
Ghost-Watch deploys AETHER decoy artifacts (files, credentials, network resources) that attract and detect attacker interaction. This directly implements D3-DO's mechanism of creating objects with no legitimate business purpose whose interaction indicates compromise.

**D3-DUC (Decoy User Credential) — via Ghost-Watch AETHER decoys**  
Ghost-Watch's decoy credential system deploys fake credentials that, when used, trigger alerts. This directly implements D3-DUC.

**Partial coverage that is closest to full:**

**D3-NTA (Network Traffic Analysis) — via JA3 fingerprinting**  
The `ja3_fingerprint.py` module implements JA3/JA3S TLS fingerprinting, which is a specific and effective form of network traffic analysis for C2 detection. This is the strongest partial coverage in the architecture — it catches default Cobalt Strike configurations but not custom malleable profiles.

**D3-SCA (System Call Analysis) — via EvasionDetector API call detection**  
The EvasionDetector's detection of `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` in event data is a post-hoc form of system call analysis. Converting this to real-time kernel-level interception (Priority 2 above) would make this coverage full.

---

## Summary: The Coverage Gap in One Sentence

Shadow313 v4 is a **detection-dominant architecture with minimal prevention and no hardening** relative to the D3FEND taxonomy. Of the 51 D3FEND primitive instances mapped across the 13 evasion techniques, 2 are fully covered (both in the Deceive tactic via Ghost-Watch), 20 are partially covered (detection of the artifact but not enforcement), and 29 are absent. The 8 priority integrations above would convert the most critical partial coverages to full and close the highest-impact absent gaps — moving Shadow313 from a pure detection tool toward a detect-and-prevent architecture aligned with D3FEND's full seven-tactic model (Model, Harden, Detect, Isolate, Deceive, Evict, Restore).

---

*Sources: MITRE D3FEND v1.5.0 (d3fend.mitre.org, August 2026); ATT&CK Mitigations to D3FEND Mappings (d3fend.mitre.org/mappings/attack-mitigations/); D3-PSA Process Spawn Analysis; D3-PLA Process Lineage Analysis; D3-SCA System Call Analysis; D3-SSC Shadow Stack Comparisons; D3-FIM File Integrity Monitoring; D3-SFA System File Analysis; D3-EAL Executable Allowlisting; D3-DLIC Driver Load Integrity Checking; D3-SCF System Call Filtering; D3-HBPI Hardware-based Process Isolation; D3-ANET Authentication Event Thresholding; D3-ANCI Authentication Cache Invalidation; D3-SPP Strong Password Policy; D3-OTP One-time Password; D3-CRO Credential Rotation; D3-UDTA User Data Transfer Analysis; D3-PHDURA Per Host Download-Upload Ratio Analysis; D3-FAPA File Access Pattern Analysis; D3-NTA Network Traffic Analysis; D3-CPSP Client-server Payload Profiling; D3-DNSAL DNS Allowlisting; D3-DNSDL DNS Denylisting; D3-DO Decoy Object; D3-DUC Decoy User Credential; D3-NI Network Isolation; D3-OTF Outbound Traffic Filtering; D3-EBWSAM Endpoint-based Web Server Access Mediation; D3-PBWSAM Proxy-based Web Server Access Mediation; D3-RPTA Relay Pattern Analysis; D3-PCSV Process Code Segment Verification; D3-PSMD Process Self-Modification Detection; D3-SCP System Configuration Permissions; D3-ACH Application Configuration Hardening; D3-SBV Service Binary Verification; D3-FCA File Creation Analysis; D3-DAM Domain Account Monitoring; D3-LAM Local Account Monitoring.*