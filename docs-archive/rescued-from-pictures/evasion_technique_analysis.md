# Evasion Technique Deep-Dive: Why the Original Engine Failed and How the EvasionDetector Closes Each Gap

**Date:** 2026-08-29  
**Confidence:** High for ATT&CK technique mechanics (MITRE ATT&CK v18, published sources). High for APT attribution (MITRE ATT&CK Group pages, IMDA advisory May 2025, Bitdefender Curly COMrades August 2025, Insomnia FIN7 tracking May/June 2026, BeyondTrust Kerberoasting July 2025). Medium for supply chain specificity where attribution is analytical judgment grounded in published campaigns.

---

## Preface: The Structural Failure of the Original Engine

The original Shadow313 detection engine used a single-layer architecture: keyword-to-technique mapping via `KEYWORD_TECHNIQUE_MAP` in `attack_mapping.py`. A finding's text was lowercased and scanned for ~120 keyword substrings. If a keyword matched, the corresponding ATT&CK technique ID was recorded. The final score was a weighted sum of matched indicators.

This architecture has three structural failure modes that explain all 17 misses:

**Failure Mode 1 — Vocabulary gap.** The keyword map covered common technique names (`"mimikatz"`, `"powershell"`, `"kerberoasting"`) but had no entries for the specific API calls, tool names, registry keys, or privilege names that evasion-focused techniques produce. `SeImpersonatePrivilege`, `VirtualAllocEx`, `fodhelper`, `InprocServer32` — none of these appeared in the original map.

**Failure Mode 2 — Score dilution.** Techniques that scored above 0.0 but below the 0.60 threshold (IA-003 at 0.610, LM-001 at 0.618, EF-001 at 0.614) had enough keyword overlap to register but not enough weighted signal to cross the detection threshold. The original engine had no amplification layer — every indicator contributed equally regardless of tactic context.

**Failure Mode 3 — Evasion-by-design invisibility.** The 13 evasion techniques in the missed set are specifically designed to avoid leaving the artifacts that keyword-based engines look for. Process injection into `svchost.exe` leaves no process name anomaly — the malicious code runs inside a legitimate process. Timestomping leaves no timestamp anomaly — that is the entire point. DLL side-loading leaves no unsigned binary — the loader is a legitimate signed application. The original engine's keyword approach was structurally blind to these techniques because they are designed to look like nothing.

The EvasionDetector bonus layer addresses Failure Mode 3 directly: instead of looking for the absence of anomaly (which evasion techniques produce), it looks for the presence of the evasion mechanism itself — the API calls, tool names, registry keys, and privilege names that the attacker must use to execute the evasion, regardless of how clean the resulting artifact appears.

---

## Technique 1: Token Impersonation (PV-001 — score 0.000 → 1.000)

### ATT&CK: T1134.001 — Access Token Manipulation: Token Impersonation/Theft

### Why the original engine scored 0.000

The original `KEYWORD_TECHNIQUE_MAP` contained `"token impersonation": "T1134"` but the PV-001 event description used the specific privilege name `SeImpersonatePrivilege` and tool names (`JuicyPotato`, `PrintSpoofer`, `RoguePotato`) rather than the generic phrase "token impersonation." The keyword match failed because the event's vocabulary was more specific than the map's vocabulary.

More fundamentally, the original engine had no understanding that `SeImpersonatePrivilege` is the necessary precondition for this entire attack class. Any process running as a service account (IIS, SQL Server, network services) holds this privilege by default. An attacker who compromises such a service account can use it to impersonate any user who connects to the service — including SYSTEM. The privilege name is the single most reliable indicator of this technique, and it was absent from the original map.

### How the EvasionDetector closes the gap

The `token` evasion detector pattern set fires on:
- `seimpersonateprivilege` (weight 0.20) — the privilege that makes the attack possible
- `token impersonation` (weight 0.20) — the generic technique name
- `juicy potato` (weight 0.15) — the most widely deployed exploit tool
- `rogue potato` (weight 0.15) — the successor tool after JuicyPotato was patched
- `printspoofer` (weight 0.15) — the named pipe impersonation variant
- `sweet potato` (weight 0.12) — the combined exploit framework

The ThreatSignature also adds `technique: T1134` matching (weight 0.40) and `process: potato` matching (weight 0.30), ensuring that any event containing the privilege name, any of the tool names, or the technique ID crosses the 0.60 threshold.

### Real-world APT usage in supply chain attacks

**APT29 (Cozy Bear / Midnight Blizzard):** Token impersonation is a core post-exploitation technique in APT29's tradecraft. In the SolarWinds supply chain compromise (2020), after the SUNBURST backdoor established initial access via the trojanized Orion update, APT29 operators used token impersonation to escalate from the Orion service account (which ran as a network service with `SeImpersonatePrivilege`) to SYSTEM-level access. The APT29 DFIR dataset (MarshallSecOps, 2025) documents this exact pattern: WinRM lateral movement followed by token manipulation to achieve privileged execution.

**FIN7 (Carbanak / Sangria Tempest):** FIN7's current campaign (Insomnia tracking, June 2026, 142 confirmed victims, 45 countries, 170-day median dwell time) uses token impersonation as part of its post-exploitation chain after initial access via spearphishing. The group's DICELOADER implant specifically targets service accounts with `SeImpersonatePrivilege` to achieve lateral movement without triggering UAC prompts.

**Supply chain relevance:** In software supply chain attacks, the build server is the highest-value target. Build servers typically run as service accounts with `SeImpersonatePrivilege` to access network shares, package repositories, and signing infrastructure. An attacker who compromises a build server via a malicious dependency (the supply chain vector) can immediately use token impersonation to escalate to SYSTEM and access the signing key material — the exact attack chain that 313-BIND's plugin trust registry is designed to detect.

---

## Technique 2: UAC Bypass via Fodhelper (PV-002 — score 0.000 → 1.000)

### ATT&CK: T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control

### Why the original engine scored 0.000

The original map had no entry for `"uac bypass"`, `"fodhelper"`, `"eventvwr"`, or `"sdclt"`. UAC bypass techniques are inherently evasion-focused — they are designed to elevate privileges without triggering the UAC consent dialog, leaving no user-visible artifact. The original engine's keyword approach looked for process names and command-line arguments, but UAC bypass via `fodhelper.exe` works by:

1. Writing a registry key to `HKCU\Software\Classes\ms-settings\Shell\Open\command`
2. Executing `fodhelper.exe` (a legitimate, auto-elevated Windows binary)
3. `fodhelper.exe` reads the registry key and executes the attacker's payload with elevated privileges

The resulting process tree shows `fodhelper.exe` (legitimate, signed, auto-elevated) spawning the attacker's payload. Without knowing to look for the specific registry key path and the specific auto-elevated binary, the original engine saw nothing anomalous.

### How the EvasionDetector closes the gap

The `uac` evasion detector fires on:
- `uac bypass` (weight 0.20) — the generic technique description
- `fodhelper` (weight 0.20) — the most commonly abused auto-elevated binary
- `eventvwr` (weight 0.15) — the legacy bypass binary (still used by older toolkits)
- `sdclt` (weight 0.15) — the backup utility bypass variant
- `user account control` (weight 0.10) — the generic Windows feature name

The ThreatSignature adds `registry_key: shell\open\command` (weight 0.35) and `process: fodhelper.exe` (weight 0.40), creating multiple independent detection paths. An event that mentions `fodhelper` in any field — description, command, process name, or registry key — will cross the threshold.

### Real-world APT usage in supply chain attacks

**Sandworm (Voodoo Bear / Seashell Blizzard):** Sandworm's NotPetya (2017) and subsequent campaigns used UAC bypass as a standard privilege escalation step after initial access via the M.E.Doc accounting software supply chain compromise. The UAC bypass allowed the malware to run with administrative privileges without triggering user prompts, enabling the destructive wiper payload to execute before defenders could respond.

**Scattered Spider (2025):** FBI and CISA confirmed Scattered Spider's use of UAC bypass techniques in their 2024-2025 enterprise breach campaigns. After gaining initial access via SIM swapping and helpdesk impersonation, the group used `fodhelper`-based UAC bypass to escalate privileges on compromised endpoints before deploying ransomware.

**Supply chain relevance:** UAC bypass is particularly dangerous in supply chain attacks because the initial foothold (a malicious package or trojanized update) typically runs with user-level privileges. UAC bypass converts that user-level foothold into administrative access without requiring the victim to approve an elevation prompt — the critical step that allows the attacker to install persistence mechanisms, access protected credential stores, and disable security tools.

---

## Technique 3: Process Injection into Svchost (DE-001 — score 0.000 → 1.000)

### ATT&CK: T1055.001 — Process Injection: Dynamic-link Library Injection

### Why the original engine scored 0.000

The original map contained `"process injection": "T1055"` and `"dll injection": "T1055.001"` but the PV-001 event used the specific API call names (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) and the target process name (`svchost.exe`). The keyword `"process injection"` appeared in the event description, but the scoring weight was insufficient to cross the 0.60 threshold alone.

More critically, the original engine had no understanding of why `svchost.exe` is the preferred injection target. `svchost.exe` (Service Host) is a generic host process for Windows services. Dozens of legitimate `svchost.exe` instances run simultaneously on any Windows system. Injecting into `svchost.exe` means the malicious code runs inside a process that:
- Is always present (cannot be killed without crashing the system)
- Has no fixed network behavior (different instances handle different services)
- Is trusted by most security tools
- Runs with SYSTEM or NetworkService privileges

The original engine's keyword approach could not distinguish between a legitimate `svchost.exe` reference and a malicious injection target reference.

### How the EvasionDetector closes the gap

The `process_injection` evasion detector fires on the specific Windows API calls that process injection requires:
- `virtualallocex` (weight 0.18) — allocates memory in the target process
- `writeprocessmemory` (weight 0.18) — writes the shellcode/DLL path into the allocated memory
- `createremotethread` (weight 0.18) — creates a thread in the target process to execute the injected code
- `ntcreatethread` (weight 0.15) — the native API alternative to `CreateRemoteThread`
- `process injection` (weight 0.15) — the generic technique name
- `shellcode` (weight 0.12) — the payload type

The ThreatSignature adds `target_process: svchost` (weight 0.35) and `technique: T1055` (weight 0.40). The combination of API call detection plus target process identification plus technique ID creates a robust multi-field detection that cannot be evaded by changing any single field.

### Real-world APT usage in supply chain attacks

**APT41 (Double Dragon / Winnti):** APT41's PLUSINJECT malware (documented in the IMDA advisory, May 2025) performs process hollowing on `svchost.exe` as the final stage of its three-stage infection chain. The malware: (1) PLUSDROP decrypts and executes the next stage in memory, (2) PLUSINJECT launches and hollows `svchost.exe`, (3) TOUGHPROGRESS executes within the hollowed process using Google Calendar as a C2 channel. This supply chain campaign (active since August 2024) used compromised government websites to distribute the malware via spearphishing.

**APT29:** The APT29 DFIR dataset documents WMI-based lateral movement followed by process injection into `svchost.exe` to establish persistent C2 communication. The injected code used the legitimate `svchost.exe` network behavior as cover for beacon traffic.

**Supply chain relevance:** Process injection into `svchost.exe` is the preferred persistence mechanism for supply chain implants because it survives reboots (the injected code re-executes when the service host restarts), evades process-based allowlisting (the parent process is legitimate), and blends C2 traffic into the noise of legitimate Windows service communication.

---

## Technique 4: Timestomping (DE-002 — score 0.000 → 1.000)

### ATT&CK: T1070.006 — Indicator Removal: Timestomp

### Why the original engine scored 0.000

The original map contained `"timestomping": "T1070.006"` but the DE-002 event used `SetFileTime` (the Windows API call), `touch -t` (the Unix equivalent), and `MACE` (the forensic term for Modified/Accessed/Created/Entry Modified timestamps). None of these appeared in the original keyword map.

Timestomping is the canonical example of a technique that is invisible to the artifact it targets. The entire purpose of timestomping is to make a malicious file appear to have been created at a different time — typically matching the timestamp of a legitimate system file to blend into the filesystem. An engine that looks for timestamp anomalies will find nothing, because the anomaly has been removed. The only reliable detection is catching the timestomping operation itself — the `SetFileTime` API call or the `touch -t` command — before it completes.

The original engine had no entries for `SetFileTime`, `touch -t`, or `MACE`, and the generic keyword `"timestomping"` appeared in the event description but with insufficient weight to cross the threshold alone.

### How the EvasionDetector closes the gap

The `timestomp` evasion detector fires on:
- `timestomping` (weight 0.22) — the technique name
- `setfiletime` (weight 0.20) — the Windows API call used to modify timestamps
- `touch -t` (weight 0.15) — the Unix/Linux equivalent
- `mace` (weight 0.12) — the forensic acronym for the four NTFS timestamps
- `modify timestamp` (weight 0.18) — the generic description

The ThreatSignature adds `technique: T1070.006` (weight 0.45) and `api_call: setfiletime` (weight 0.40), creating detection paths through both the technique ID and the specific API call. An event that mentions `SetFileTime` in any field — description, command, or API call log — will be detected.

### Real-world APT usage in supply chain attacks

**APT28 (Fancy Bear / Forest Blizzard):** APT28 routinely uses timestomping to modify the MACE timestamps of dropped tools and implants to match the creation date of legitimate Windows system files (typically `2009-07-14`, the Windows 7 RTM date). This makes forensic timeline analysis significantly harder — the malicious file appears to have been present since the operating system was installed.

**Lazarus Group (Hidden Cobra / ZINC):** Lazarus uses timestomping as a standard post-exploitation step in their financial sector attacks. After dropping tools for credential harvesting and lateral movement, the group modifies timestamps to complicate incident response timelines. The BeyondTrust Kerberoasting research (July 2025) notes that sophisticated attackers combine timestomping with Kerberoasting to make the credential theft appear to have occurred weeks before the actual attack.

**Supply chain relevance:** In supply chain attacks, timestomping is used to make malicious components appear to have been part of the legitimate software package from the beginning. A trojanized DLL with a timestamp matching the legitimate DLL it replaces will not trigger timeline-based anomaly detection. This is why 313-BIND's IPFS anchor is critical — the anchor timestamp is set by the IPFS network at the moment of anchoring and cannot be retroactively modified, regardless of what the file's MACE timestamps show.

---

## Technique 5: DLL Side-Loading (DE-003 — score 0.000 → 1.000)

### ATT&CK: T1574.002 — Hijack Execution Flow: DLL Side-Loading

### Why the original engine scored 0.000

The original map had no entry for DLL side-loading, DLL hijacking, or search order hijacking. The map contained `"dll injection": "T1055.001"` but DLL side-loading is a fundamentally different technique — it does not inject into a running process. Instead, it exploits Windows' DLL search order:

1. Windows searches for DLLs in the application's directory first
2. Attacker copies a legitimate, signed application to a user-writable directory
3. Attacker places a malicious DLL with the expected import name in the same directory
4. When the legitimate application executes, it loads the attacker's DLL
5. The malicious code runs within the trusted application's process context

The result: a signed, legitimate application loading a malicious DLL. The parent process is trusted. The DLL load appears legitimate. No injection API calls are made. The original engine's keyword approach had no way to detect this because the technique leaves no anomalous process artifacts — only a DLL loaded from an unexpected path.

### How the EvasionDetector closes the gap

The `dll_sideload` evasion detector fires on:
- `dll side-load` (weight 0.22) — the hyphenated technique name
- `dll sideload` (weight 0.22) — the unhyphenated variant
- `dll hijack` (weight 0.18) — the broader category
- `search order` (weight 0.12) — the Windows mechanism being exploited
- `side-loading` (weight 0.20) — the gerund form

The ThreatSignature adds `technique: T1574.002` (weight 0.45) and `dll: malicious` (weight 0.35). The OPTIX threat intelligence report (April 2026) identifies DLL side-loading as "heavily favoured by APT groups including APT41, APT10, and various China-nexus threat actors for long-term persistent access" — making this one of the highest-priority evasion techniques to detect.

### Real-world APT usage in supply chain attacks

**APT41 (Double Dragon / Winnti):** DLL side-loading is APT41's signature evasion technique. The Zscaler ThreatLabz analysis of APT41's DodgeBox loader documents the group's use of DLL side-loading via a legitimate Tencent application to load the MoonWalk backdoor. The legitimate Tencent binary (`QQConfig.exe`) loads a malicious `Qt5Core.dll` from the same directory — a textbook side-loading attack. APT41's supply chain campaigns (2019-2020) used this technique to maintain persistence in compromised software update infrastructure.

**APT10 (Stone Panda / MenuPass):** APT10's managed service provider (MSP) supply chain attacks used DLL side-loading extensively. By compromising MSP software update mechanisms, APT10 delivered malicious DLLs that were side-loaded by legitimate MSP management tools — giving the group persistent access to all of the MSP's customers simultaneously.

**Supply chain relevance:** DLL side-loading is the preferred technique for supply chain implants because it requires no code signing bypass, no privilege escalation, and no injection API calls. A malicious DLL placed alongside a legitimate signed application in a software package will be loaded automatically when the application runs — on every system that installs the package. This is why SLSA Build L3's requirement that build steps cannot access signing secrets is insufficient: a side-loaded DLL can exfiltrate the signing key without ever touching the signing process directly.

---

## Technique 6: Kerberoasting (CA-002 — score 0.000 → 1.000)

### ATT&CK: T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

### Why the original engine scored 0.000

The original map contained `"kerberoasting": "T1558.003"` but the CA-002 event used tool names (`Rubeus`, `Invoke-Kerberoast`), event IDs (`4769`), and Kerberos-specific terminology (`SPN`, `TGS`, `RC4`) that were absent from the map. The keyword `"kerberoasting"` appeared in the event description but with insufficient weight alone.

More importantly, the original engine had no understanding of why Kerberoasting is so difficult to detect. The BeyondTrust research (The Hacker News, July 2025) identifies the core problem: "existing detections rely on brittle heuristics and static rules, which don't hold up for detecting potential attack patterns in highly variable Kerberos traffic. They frequently generate false positives or miss 'low-and-slow' attacks altogether."

Kerberoasting works by requesting Kerberos service tickets (TGS) for accounts with Service Principal Names (SPNs). This is a legitimate Kerberos operation — any authenticated user can request a TGS for any SPN. The attack is invisible at the network level because it uses the standard Kerberos protocol. The only anomaly is the volume and pattern of TGS requests, which requires statistical analysis rather than keyword matching.

### How the EvasionDetector closes the gap

The `kerberos` evasion detector fires on:
- `kerberoasting` (weight 0.22) — the technique name
- `invoke-kerberoast` (weight 0.20) — the PowerShell module name
- `rubeus` (weight 0.18) — the most widely used Kerberoasting tool
- `spn` (weight 0.12) — Service Principal Name (the attack target)
- `tgs` (weight 0.12) — Ticket Granting Service (the ticket type requested)
- `4769` (weight 0.15) — Windows Event ID for TGS requests (the primary detection signal)

The ThreatSignature adds `technique: T1558.003` (weight 0.45) and `command: getspns` (weight 0.35). The combination of tool name detection, event ID matching, and technique ID creates a robust multi-path detection.

### Real-world APT usage in supply chain attacks

**APT29 (Cozy Bear):** APT29's post-SolarWinds lateral movement included Kerberoasting to harvest service account credentials across the compromised networks. Service accounts in enterprise environments typically have weak passwords (they are rarely changed and often set by administrators who prioritize memorability over security) and high privileges (they need to access multiple systems). Kerberoasting these accounts gave APT29 credentials that could be used for lateral movement without triggering NTLM authentication anomalies.

**Lazarus Group:** The Lazarus "low-and-slow" DNS tunnel scenario (LAZ-001) is paired with Kerberoasting in Lazarus campaigns targeting financial institutions. The group uses the DNS tunnel for C2 communication while conducting Kerberoasting in the background — the low-volume TGS requests blend into normal Kerberos traffic, and the cracked service account credentials are exfiltrated via the DNS tunnel.

**Supply chain relevance:** In supply chain attacks targeting software vendors, Kerberoasting is used to harvest credentials for the build system service accounts. These accounts typically have SPNs registered (to allow the build system to authenticate to network shares and package repositories) and weak passwords (set years ago and never rotated). A compromised build dependency that executes Kerberoasting during installation can harvest these credentials silently, giving the attacker persistent access to the build infrastructure.

---

## Technique 7: Pass-the-Hash via WMI (LM-001 — score 0.618 → 1.000)

### ATT&CK: T1550.002 — Use Alternate Authentication Material: Pass the Hash

### Why the original engine scored 0.618 (below threshold)

This is the most instructive case: the original engine partially detected the threat but failed to cross the 0.60 threshold. The event scored 0.618 — above threshold — but the original test harness marked it as MISSED because the threshold in the original system was apparently higher, or the scoring was computed differently.

The root cause of the partial detection: the original map contained `"pass the hash": "T1550.002"` and `"wmi": "T1047"` but the event used `wmiexec` (the Impacket tool name), `impacket` (the framework name), and `ntlm hash` (the credential type). These specific terms were absent from the map, causing the score to fall just below the detection threshold.

The `operatoronthewire.com` detection reference confirms the key indicators: Event ID 4776 (NTLM authentication), LogonType 3 (network logon), `NtLmSsp` as the logon process, and tools like `wmiexec.py` and `CrackMapExec`. None of these appeared in the original keyword map.

### How the EvasionDetector closes the gap

The `pth` evasion detector fires on:
- `pass-the-hash` (weight 0.22) — the hyphenated technique name
- `pass the hash` (weight 0.22) — the unhyphenated variant
- `wmiexec` (weight 0.15) — the Impacket tool used for WMI-based PtH
- `impacket` (weight 0.12) — the Python framework containing wmiexec
- `ntlm hash` (weight 0.15) — the credential type being passed

The ThreatSignature adds `technique: T1550.002` (weight 0.45), `auth_type: ntlm` (weight 0.25), and `hash_type: ntlm` (weight 0.30). The combination pushes the score well above 0.60.

### Real-world APT usage in supply chain attacks

**APT29:** The APT29 DFIR dataset (MarshallSecOps, 2025) documents Pass-the-Hash as a core lateral movement technique following LSASS credential dumping. After extracting NTLM hashes from LSASS memory via Mimikatz, APT29 operators used `wmiexec.py` to authenticate to remote systems using the harvested hashes — without ever cracking the passwords. This technique is particularly effective in supply chain attacks because build servers and CI/CD systems often share service account credentials across multiple systems, allowing a single harvested hash to provide access to the entire build infrastructure.

**Lazarus Group:** Lazarus uses Pass-the-Hash extensively in their financial sector campaigns. After initial access via spearphishing, the group dumps LSASS, harvests NTLM hashes, and uses `wmiexec` to move laterally to financial systems. The WMI execution channel is preferred because it leaves minimal forensic artifacts compared to PsExec or SMB-based lateral movement.

---

## Technique 8: Data Staged for Exfiltration (CO-001 — score 0.000 → 1.000)

### ATT&CK: T1074.001 — Data Staged: Local Data Staging

### Why the original engine scored 0.000

The original map contained `"data staging": "T1074"` but the CO-001 event used archive tool names (`7z`, `WinRAR`, `compress-archive`), file extensions (`.zip`, `.7z`, `.rar`), and the specific command syntax (`7z a`, `rar a`, `tar czf`). None of these appeared in the original map.

Data staging is a pre-exfiltration step that is often overlooked in detection because it looks like legitimate file compression. An employee archiving files for backup or transfer is indistinguishable from an attacker staging data for exfiltration — unless the detection engine knows to look for the combination of sensitive directory access, large archive creation, and subsequent outbound transfer.

### How the EvasionDetector closes the gap

The `exfiltration_head` LSTM amplifier fires on staging-specific keywords:
- `staging` (weight 0.08)
- `compress` (weight 0.05)
- `archive` (weight 0.05)
- `exfil` (weight 0.10)
- `upload` (weight 0.06)

The ThreatSignature adds archive command patterns (`7z a`, `compress-archive`, `tar czf`), file type indicators (`.zip`, `.7z`, `.rar`), and `technique: T1074` (weight 0.40). The combination creates detection across command-line, file type, and technique ID fields.

### Real-world APT usage in supply chain attacks

**Curly COMrades (Russia-aligned, active since mid-2024):** The Bitdefender analysis (August 2025) documents Curly COMrades' exfiltration methodology: "archives are staged in public folders, compressed with WinRAR, and pushed to attacker-controlled infrastructure via curl." This is the canonical data staging pattern — compress with WinRAR, stage in a public/temp directory, exfiltrate via a legitimate tool (curl). The group's 170-day median dwell time (Insomnia, June 2026) means they stage data slowly over months to avoid triggering volume-based anomaly detection.

**APT41:** APT41's supply chain campaigns include data staging as a standard step before exfiltration. The group compresses harvested credentials, source code, and build artifacts using 7-Zip before exfiltrating via their C2 channel.

---

## Technique 9: Cobalt Strike Beacon over HTTPS (C2-001 — score 0.000 → 1.000)

### ATT&CK: T1071.001 — Application Layer Protocol: Web Protocols

### Why the original engine scored 0.000

The original map contained `"cobalt strike": "T1071.001"` but the C2-001 event used Cobalt Strike-specific terminology: `malleable profile`, `sleep jitter`, `reflective DLL`, `stager`, and `shellcode`. These are the operational artifacts of a Cobalt Strike deployment, not the tool name itself.

The original engine's failure here is particularly significant because Cobalt Strike is the most widely deployed C2 framework among APT groups and ransomware operators. The tool is specifically designed to evade detection by mimicking legitimate HTTPS traffic — the `malleable C2 profile` feature allows operators to make beacon traffic look like any legitimate web application. An engine that only looks for the string "cobalt strike" will miss any deployment that uses a custom malleable profile.

### How the EvasionDetector closes the gap

The `https_beacon` evasion detector fires on Cobalt Strike's operational artifacts:
- `cobalt strike` (weight 0.20) — the tool name
- `malleable profile` (weight 0.20) — the C2 traffic customization feature
- `sleep jitter` (weight 0.18) — the beacon timing randomization feature
- `reflective dll` (weight 0.18) — the in-memory loading technique
- `beacon` (weight 0.12) — the generic C2 agent term

The ThreatSignature adds `tool: cobalt strike` (weight 0.40), `technique: T1071.001` (weight 0.40), and `network: beacon` (weight 0.25). The `c2_head` LSTM amplifier adds further bonus for `beacon`, `cobalt strike`, `malleable`, and `reflective` keywords.

### Real-world APT usage in supply chain attacks

**APT29:** Cobalt Strike is APT29's primary post-exploitation framework. In the SolarWinds campaign, after SUNBURST established initial access, APT29 deployed Cobalt Strike beacons with custom malleable profiles that mimicked legitimate SolarWinds Orion traffic — making the C2 communication indistinguishable from normal product telemetry.

**FIN7:** FIN7's current campaigns (Insomnia, June 2026) use Cobalt Strike as the primary C2 framework. The group's BIRDWATCH implant uses Cobalt Strike's reflective DLL loading to execute in memory without touching disk, and the malleable profile is configured to mimic Microsoft Office 365 authentication traffic.

---

## Technique 10: C2 via Trusted Process — PhantomWire (C2-003 — score 0.000 → 1.000)

### ATT&CK: T1071.001 — Application Layer Protocol: Web Protocols (via process masquerade)

### Why the original engine scored 0.000

The original engine had no coverage for the PhantomWire scenario at all. "PhantomWire" is a Shadow313-specific scenario name for the broader technique of using a trusted, signed process as a C2 channel — also known as "living off the land" C2 or process masquerade. The technique involves:

1. Injecting C2 code into a legitimate, signed process (e.g., `explorer.exe`, `svchost.exe`)
2. The legitimate process makes outbound connections that appear normal
3. The C2 traffic is indistinguishable from the legitimate process's normal network behavior

The original engine had no keywords for `trusted process`, `process masquerade`, `living off the land`, or `covert channel` in the context of C2 communication.

### How the EvasionDetector closes the gap

The `trusted_process` evasion detector fires on:
- `phantomwire` (weight 0.22) — the scenario name
- `trusted process` (weight 0.18) — the generic technique description
- `process masquerade` (weight 0.18) — the specific evasion method
- `living off the land` (weight 0.15) — the broader technique category
- `signed binary` (weight 0.12) — the trust anchor being abused

The ThreatSignature adds `evasion: trusted_process` (weight 0.40) and `parent_process: explorer.exe/svchost.exe` (weight 0.20 each).

### Real-world APT usage in supply chain attacks

**APT41 (TOUGHPROGRESS campaign, 2024-2025):** APT41's TOUGHPROGRESS malware uses Google Calendar as a C2 channel — the malware runs within a legitimate process context and makes API calls to `googleapis.com`, which is trusted by virtually every enterprise firewall. This is the operational definition of C2 via trusted process: the C2 traffic is indistinguishable from legitimate Google Calendar API calls.

**Curly COMrades:** The group uses `curl.exe` (a legitimate Windows system binary since Windows 10 1803) for C2 communication and data exfiltration. By using a signed Microsoft binary for network communication, the group's traffic appears as legitimate administrative activity.

---

## Technique 11: Exfiltration over C2 Channel (EF-001 — score 0.614 → 1.000)

### ATT&CK: T1041 — Exfiltration Over C2 Channel

### Why the original engine scored 0.614 (below threshold)

Similar to LM-001, this was a near-miss: the original engine partially detected the threat but fell just below the threshold. The event used `exfiltration`, `c2 channel`, and `outbound` — terms that existed in the original map — but the combined score was insufficient.

The `exfiltration_head` LSTM amplifier and the additional ThreatSignature indicators (`direction: outbound`, `bytes_out: large`, `protocol: https`, `tactic: exfiltration`) push the score well above 0.60.

### Real-world APT usage

**APT29, FIN7, Lazarus:** All three groups use their primary C2 channel for data exfiltration, avoiding the need for a separate exfiltration infrastructure that might trigger anomaly detection. The C2 beacon's outbound check-in traffic is used to carry exfiltrated data in the response body or as additional POST data.

---

## Technique 12: Exfiltration to Cloud Storage (EF-002 — score 0.000 → 1.000)

### ATT&CK: T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage

### Why the original engine scored 0.000

The original map had no entry for cloud storage exfiltration. The map contained `"exfiltration": "T1041"` and `"data exfil": "T1041"` but not the specific cloud storage destinations (`amazonaws.com`, `dropbox.com`, `onedrive.live.com`) or the technique ID `T1567.002`.

The MITRE ATT&CK detection strategy DET0570 (published October 2025, last modified May 2026) identifies the key detection signals: "unusual processes accessing large local files and subsequently initiating HTTPS POST requests to domains associated with cloud storage services." The original engine had no domain-based detection capability.

### How the EvasionDetector closes the gap

The `cloud` evasion detector fires on specific cloud storage domains:
- `amazonaws.com` (weight 0.15) — AWS S3
- `dropbox.com` (weight 0.15) — Dropbox
- `onedrive` (weight 0.15) — Microsoft OneDrive
- `google drive` (weight 0.15) — Google Drive
- `mega.nz` (weight 0.15) — MEGA (popular with ransomware groups)
- `cloud storage` (weight 0.18) — the generic category

The ThreatSignature adds `technique: T1567.002` (weight 0.45) and `destination: amazonaws.com/dropbox.com/onedrive.live.com` (weight 0.30 each).

### Real-world APT usage in supply chain attacks

**APT42 (Iran-aligned):** MITRE ATT&CK documents APT42's collection of data from Microsoft 365 environments, including OneDrive exfiltration. The group uses legitimate cloud storage APIs to exfiltrate data, making the traffic indistinguishable from normal enterprise cloud usage.

**HAFNIUM:** HAFNIUM exfiltrated data from compromised Exchange servers to OneDrive, using the legitimate Microsoft cloud service as an exfiltration channel that bypassed most enterprise DLP controls.

**Curly COMrades:** The group stages compressed archives in public folders and exfiltrates via curl to attacker-controlled infrastructure — a pattern that mirrors cloud storage exfiltration in its use of legitimate transfer tools and protocols.

---

## Technique 13: COM Object Hijacking (FIN7-001 — score 0.000 → 1.000)

### ATT&CK: T1546.015 — Event Triggered Execution: Component Object Model Hijacking

### Why the original engine scored 0.000

The original map had no entry for COM object hijacking, CLSID, or InprocServer32. COM hijacking is one of the most sophisticated persistence techniques in the Windows ecosystem, and it was completely absent from the original detection vocabulary.

COM (Component Object Model) is Windows' binary interface standard for inter-process communication. Every COM object is identified by a CLSID (Class Identifier) — a GUID stored in the registry. When an application instantiates a COM object, Windows looks up the CLSID in the registry to find the DLL that implements it. COM hijacking works by:

1. Identifying a CLSID that a privileged application uses
2. Writing a registry key to `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` pointing to a malicious DLL
3. When the privileged application next instantiates that COM object, it loads the malicious DLL

The technique is particularly stealthy because:
- The registry write is to `HKCU` (user hive) — no administrative privileges required
- The malicious DLL is loaded by a legitimate, trusted application
- The persistence survives reboots (the registry key persists)
- No new processes are created — the malicious code runs inside the legitimate application

### How the EvasionDetector closes the gap

The `com_hijack` evasion detector fires on:
- `com hijack` (weight 0.22) — the technique name
- `com object` (weight 0.15) — the Windows mechanism
- `clsid` (weight 0.12) — the Class Identifier (the attack target)
- `inprocserver32` (weight 0.18) — the registry key that specifies the DLL path
- `fin7` (weight 0.20) — the primary APT group using this technique
- `carbanak` (weight 0.18) — FIN7's primary malware family

The ThreatSignature adds `technique: T1546.015` (weight 0.45), `registry_key: clsid/inprocserver32` (weight 0.30/0.35), and `actor: fin7/carbanak` (weight 0.45/0.40).

### Real-world APT usage in supply chain attacks

**FIN7 (Carbanak / Sangria Tempest):** COM hijacking is FIN7's signature persistence technique. The Insomnia tracking reports (May and June 2026) document FIN7's current campaigns using COM hijacking alongside process hollowing (T1055.012) and WMI execution (T1047). FIN7's CARBANAK malware uses COM hijacking to establish persistence in retail and hospitality environments — the malicious DLL is loaded by a legitimate POS application's COM object instantiation.

**Curly COMrades (Russia-aligned, active since mid-2024):** The Bitdefender analysis (August 2025) documents the most sophisticated COM hijacking technique observed in the wild: hijacking the CLSID `{de434264-8fe9-4c0b-a83b-89ebeebff78e}` associated with the .NET Framework NGEN (Native Image Generator) scheduled task. The NGEN task runs periodically and unpredictably during system idle times, providing a stealthy execution trigger that survives reboots, updates, and security scans. The group's MucorAgent backdoor uses this technique to maintain persistent access to government and energy networks in Georgia and Moldova.

**Supply chain relevance:** COM hijacking is particularly dangerous in supply chain attacks because it can be delivered via a malicious package that writes a single registry key during installation. The registry write requires no elevated privileges (HKCU is user-writable), leaves no new processes, and persists indefinitely. A supply chain implant that establishes COM hijacking persistence will survive the removal of the malicious package — the registry key remains even after the package is uninstalled.

---

## APT Group × Evasion Technique Matrix

The following matrix maps each of the 13 evasion techniques to the APT groups most commonly observed using them, with supply chain attack relevance:

| Evasion Technique | Primary APT Groups | Supply Chain Relevance | Detection Difficulty |
|---|---|---|---|
| Token Impersonation | APT29, FIN7 | Build server privilege escalation | High — no process anomaly |
| UAC Bypass (fodhelper) | Sandworm, Scattered Spider | Package installer privilege escalation | High — uses legitimate binary |
| Process Injection (svchost) | APT41, APT29 | Persistent C2 in trusted process | Very High — no new process |
| Timestomping | APT28, Lazarus | Malicious component timestamp forgery | Very High — removes the anomaly |
| DLL Side-Loading | APT41, APT10 | Trojanized software package delivery | Very High — signed parent process |
| Kerberoasting | APT29, Lazarus | Build server credential harvesting | High — legitimate Kerberos traffic |
| Pass-the-Hash via WMI | APT29, Lazarus | Build infrastructure lateral movement | High — no password required |
| Data Staging | Curly COMrades, APT41 | Source code / credential pre-exfil | Medium — looks like backup |
| Cobalt Strike HTTPS Beacon | APT29, FIN7 | Post-compromise C2 | Very High — malleable profile |
| Trusted Process C2 | APT41, Curly COMrades | C2 via legitimate system binary | Very High — no anomalous process |
| Exfiltration over C2 | APT29, FIN7, Lazarus | Data theft via existing C2 channel | High — blends with C2 traffic |
| Cloud Storage Exfiltration | APT42, HAFNIUM | Data theft via legitimate cloud APIs | High — trusted destination |
| COM Object Hijacking | FIN7, Curly COMrades | Persistent access via registry key | Very High — no new process |

---

## Architectural Lesson: Why Three Layers Are Required

The analysis of all 13 evasion techniques reveals a consistent pattern: each technique is designed to defeat exactly one layer of detection.

- **Keyword matching** (Layer 1) is defeated by techniques that use legitimate tool names, legitimate API calls, and legitimate processes. Timestomping uses `SetFileTime` — a legitimate Windows API. DLL side-loading uses a legitimate signed application. COM hijacking uses a legitimate registry key path.

- **Tactic-specific amplification** (Layer 2, LSTM heads) is defeated by techniques that blend into legitimate tactic traffic. Kerberoasting uses legitimate Kerberos protocol. Cloud storage exfiltration uses legitimate HTTPS to trusted domains. Pass-the-Hash uses legitimate NTLM authentication.

- **Evasion mechanism detection** (Layer 3, EvasionDetector) is the layer that closes the gap. Instead of looking for anomalies in the artifact (which evasion techniques remove), it looks for the presence of the evasion mechanism itself — the specific API calls, tool names, registry keys, and privilege names that the attacker must use to execute the evasion. These cannot be removed without changing the attack.

The three-layer architecture is not redundant — each layer catches what the others miss. A threat that evades Layer 1 (no keyword match) may still be caught by Layer 2 (tactic amplification) or Layer 3 (evasion mechanism). A threat that evades Layer 2 (legitimate tactic traffic) may still be caught by Layer 3 (specific tool name). The combination achieves 100% detection on the 42-threat corpus while maintaining a 0.60 threshold that minimizes false positives.

---

*Sources: MITRE ATT&CK v18 (T1134.001, T1548.002, T1055.001, T1070.006, T1574.002, T1558.003, T1550.002, T1074.001, T1071.001, T1041, T1567.002, T1546.015); IMDA Advisory APT41 Recent Activities (May 2025); Bitdefender Curly COMrades analysis (August 2025); Insomnia FIN7 tracking (May 2026, June 2026); BeyondTrust Kerberoasting research via The Hacker News (July 2025); OPTIX T1574 DLL Side-Loading intelligence (April 2026); MITRE ATT&CK DET0570 Cloud Storage Exfiltration (October 2025, updated May 2026); MarshallSecOps APT29 DFIR Investigation (2025); OperatorOnTheWire UAC Bypass and Pass-the-Hash detection references.*