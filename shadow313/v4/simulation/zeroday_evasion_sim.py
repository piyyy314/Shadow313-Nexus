"""
shadow313.v4.simulation.zeroday_evasion_sim
────────────────────────────────────────────
Zero-Day & Unknown Threat Evasion Simulator

Tests FIX-12 through FIX-16 against novel attack variants using:
  - Mutation: slight parameter changes to stay below detection thresholds
  - Polymorphism: rotating TTPs / tool names / protocols each run
  - Living-off-the-Land (LOTL): abusing trusted OS binaries and protocols
  - Timing attacks: exploiting detection window boundaries
  - Hybrid chains: combining multiple low-signal techniques

Each bypass attempt is scored:
  BYPASSED   — detector returned detected=False (evasion succeeded)
  DETECTED   — detector returned detected=True  (evasion failed)
  PARTIAL    — detector flagged but below high-confidence threshold
"""
from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import Callable

from shadow313.v4.detection.threat_hardening import (
    ValidAccountsDetector,
    C2ProtocolAnalyzer,
    CredentialDumpingDetector,
    SessionHijackDetector,
    SpearphishingEnhancer,
)


# ── Result types ─────────────────────────────────────────────────────────────

@dataclass
class BypassAttempt:
    fix_id: str
    technique: str
    variant_name: str
    evasion_method: str
    result: dict
    bypassed: bool
    confidence: float
    notes: str = ""


@dataclass
class EvasionReport:
    fix_id: str
    detector_name: str
    total_variants: int
    bypassed: int
    detected: int
    partial: int
    bypass_rate: float
    attempts: list[BypassAttempt] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    countermeasures: list[str] = field(default_factory=list)


# ── FIX-12 Bypass Variants: ValidAccountsDetector (T1078) ────────────────────

def simulate_fix12_bypasses(rng: random.Random) -> EvasionReport:
    """
    Bypass attempts against ValidAccountsDetector.

    Known detection signals:
      - off_hours_login (hour 22-06)
      - new_source_ip
      - new_host
      - no_baseline

    Evasion strategies:
      V1: Business-hours login (avoid off_hours signal)
      V2: Gradual IP rotation — add new IPs to baseline before using them
      V3: VPN exit node cycling — attacker uses same ASN range as victim
      V4: Insider threat — attacker IS the legitimate user (no anomaly)
      V5: Slow-burn credential stuffing — one attempt per day, business hours
      V6: Cloud SSRF → metadata service → steal instance credentials (no login event)
      V7: Kerberos ticket reuse — no new login event generated at all
      V8: Pass-the-Hash — NTLM auth bypasses Kerberos, different event ID
    """
    attempts: list[BypassAttempt] = []

    # V1: Business-hours login from new IP (only 1 signal — below threshold)
    d = ValidAccountsDetector()
    d.record_baseline("alice", hour=10, src_ip="10.0.0.5", host="WS-01")
    r = d.evaluate("alice", hour=10, src_ip="185.220.101.5", host="WS-01")
    attempts.append(BypassAttempt(
        fix_id="FIX-12", technique="T1078",
        variant_name="V1_business_hours_new_ip",
        evasion_method="Timing: login during business hours to suppress off_hours signal",
        result=r, bypassed=not r["detected"], confidence=r["confidence"],
        notes="Only new_source_ip fires — 1 signal below 2-signal threshold. BYPASSED."
    ))

    # V2: Gradual IP poisoning — attacker adds their IP to baseline first
    d2 = ValidAccountsDetector()
    d2.record_baseline("bob", hour=10, src_ip="10.0.0.1", host="WS-02")
    # Attacker pre-seeds their IP into baseline (e.g., via SSRF or proxy)
    d2.record_baseline("bob", hour=10, src_ip="185.220.101.5", host="WS-02")
    r2 = d2.evaluate("bob", hour=10, src_ip="185.220.101.5", host="WS-02")
    attempts.append(BypassAttempt(
        fix_id="FIX-12", technique="T1078",
        variant_name="V2_baseline_poisoning",
        evasion_method="Mutation: pre-seed attacker IP into baseline via SSRF/proxy",
        result=r2, bypassed=not r2["detected"], confidence=r2["confidence"],
        notes="Attacker IP is now 'known' — zero signals fire. BYPASSED."
    ))

    # V3: Same-host lateral movement (new IP but known host)
    d3 = ValidAccountsDetector()
    d3.record_baseline("carol", hour=9, src_ip="10.0.0.3", host="DC-01")
    r3 = d3.evaluate("carol", hour=9, src_ip="10.0.0.99", host="DC-01")
    attempts.append(BypassAttempt(
        fix_id="FIX-12", technique="T1078",
        variant_name="V3_same_host_new_ip",
        evasion_method="LOTL: pivot to same known host from new internal IP",
        result=r3, bypassed=not r3["detected"], confidence=r3["confidence"],
        notes="new_source_ip fires but host is known — 1 signal. BYPASSED."
    ))

    # V4: Insider threat — perfect baseline match
    d4 = ValidAccountsDetector()
    for _ in range(10):
        d4.record_baseline("mallory", hour=10, src_ip="10.0.0.7", host="WS-05")
    r4 = d4.evaluate("mallory", hour=10, src_ip="10.0.0.7", host="WS-05")
    attempts.append(BypassAttempt(
        fix_id="FIX-12", technique="T1078",
        variant_name="V4_insider_threat",
        evasion_method="Polymorphism: attacker IS the legitimate user (insider)",
        result=r4, bypassed=not r4["detected"], confidence=r4["confidence"],
        notes="Zero signals — perfect baseline match. Fundamental blind spot. BYPASSED."
    ))

    # V5: Slow-burn — one login per day, business hours, rotating IPs slowly
    d5 = ValidAccountsDetector()
    # Build baseline with 3 known IPs
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
        d5.record_baseline("dave", hour=10, src_ip=ip, host="WS-01")
    # Attacker uses a 4th IP — only 1 new signal
    r5 = d5.evaluate("dave", hour=10, src_ip="10.0.0.4", host="WS-01")
    attempts.append(BypassAttempt(
        fix_id="FIX-12", technique="T1078",
        variant_name="V5_slow_burn_ip_rotation",
        evasion_method="Mutation: slow IP rotation within same /24 subnet",
        result=r5, bypassed=not r5["detected"], confidence=r5["confidence"],
        notes="Only new_source_ip fires — 1 signal. BYPASSED."
    ))

    # V6: Off-hours but known IP and host (only 1 signal)
    d6 = ValidAccountsDetector()
    d6.record_baseline("eve", hour=10, src_ip="10.0.0.8", host="WS-06")
    r6 = d6.evaluate("eve", hour=23, src_ip="10.0.0.8", host="WS-06")
    attempts.append(BypassAttempt(
        fix_id="FIX-12", technique="T1078",
        variant_name="V6_off_hours_known_ip_host",
        evasion_method="Timing: off-hours but from known IP/host (e.g., on-call engineer)",
        result=r6, bypassed=not r6["detected"], confidence=r6["confidence"],
        notes="Only off_hours_login fires — 1 signal. BYPASSED."
    ))

    bypassed = sum(1 for a in attempts if a.bypassed)
    detected = sum(1 for a in attempts if not a.bypassed)

    gaps = [
        "Single-signal evasion: attacker can suppress 2 of 3 signals by operating during business hours from a known host",
        "Baseline poisoning: if attacker can make 1 authenticated request (e.g., via SSRF), they can pre-seed their IP",
        "Insider threat: behavioural baseline is useless when attacker IS the legitimate user",
        "Subnet-local IP rotation: /24 changes don't trigger geo-anomaly detection",
        "No velocity check: 100 logins/minute from same IP/host = CLEAN",
        "No impossible travel: London login + Tokyo login 5 min apart = not detected",
    ]

    countermeasures = [
        "FIX-17a: Add impossible travel detection (geo-distance / time delta)",
        "FIX-17b: Add login velocity check (>5 logins/min = suspicious)",
        "FIX-17c: Subnet-aware IP comparison (flag /24 changes, not just exact IP)",
        "FIX-17d: Baseline integrity protection — require MFA to add new IP to baseline",
        "FIX-17e: Peer-group anomaly — flag if account behaviour diverges from peer group",
    ]

    return EvasionReport(
        fix_id="FIX-12", detector_name="ValidAccountsDetector",
        total_variants=len(attempts), bypassed=bypassed, detected=detected,
        partial=0, bypass_rate=bypassed / len(attempts),
        attempts=attempts, gaps=gaps, countermeasures=countermeasures,
    )


# ── FIX-13 Bypass Variants: C2ProtocolAnalyzer (T1071/T1041) ─────────────────

def simulate_fix13_bypasses(rng: random.Random) -> EvasionReport:
    """
    Bypass attempts against C2ProtocolAnalyzer.

    Known detection signals:
      - Beacon CV < 0.15 (regular intervals)
      - Domain entropy >= 3.8 (DGA)
      - Exfil volume ratio > 10x baseline

    Evasion strategies:
      V1: Jitter injection — add random ±30% noise to beacon intervals
      V2: Long-sleep beacon — 4-hour intervals (< MIN_BEACON_SAMPLES in window)
      V3: Domain fronting — use legitimate CDN domain (low entropy)
      V4: Slow exfil — drip data at 1KB/min over days
      V5: Protocol mimicry — beacon intervals match legitimate browser polling
      V6: Burst-then-sleep — 5 rapid connections then 2-hour silence
    """
    attempts: list[BypassAttempt] = []

    # V1: Jitter injection — CV pushed above 0.15
    a1 = C2ProtocolAnalyzer()
    base = 1_000_000.0
    # Add ±40% jitter to 60s interval
    for i in range(8):
        jitter = rng.uniform(-0.40, 0.40) * 60.0
        a1.record_connection("185.1.1.1", base + i * 60.0 + jitter)
    r1 = a1.analyze_beacon("185.1.1.1")
    attempts.append(BypassAttempt(
        fix_id="FIX-13", technique="T1071",
        variant_name="V1_jitter_injection",
        evasion_method="Mutation: ±40% random jitter pushes CV above 0.15 threshold",
        result=r1, bypassed=not r1["detected"], confidence=r1.get("confidence", 0.0),
        notes=f"CV={r1.get('interval_cv','N/A')} — jitter defeats fixed CV threshold."
    ))

    # V2: Long-sleep beacon — only 3 connections in observation window
    a2 = C2ProtocolAnalyzer()
    base2 = 1_000_000.0
    for i in range(3):  # Below MIN_BEACON_SAMPLES=5
        a2.record_connection("185.2.2.2", base2 + i * 14400.0)  # 4-hour intervals
    r2 = a2.analyze_beacon("185.2.2.2")
    attempts.append(BypassAttempt(
        fix_id="FIX-13", technique="T1071",
        variant_name="V2_long_sleep_beacon",
        evasion_method="Timing: 4-hour sleep intervals — fewer than MIN_BEACON_SAMPLES in window",
        result=r2, bypassed=not r2["detected"], confidence=0.0,
        notes="Insufficient samples — detector returns early. BYPASSED."
    ))

    # V3: Domain fronting — legitimate CDN domain (low entropy)
    a3 = C2ProtocolAnalyzer()
    r3 = a3.analyze_domain("cloudfront.net")
    attempts.append(BypassAttempt(
        fix_id="FIX-13", technique="T1071",
        variant_name="V3_domain_fronting",
        evasion_method="LOTL: route C2 through legitimate CDN (cloudfront.net, azureedge.net)",
        result=r3, bypassed=not r3["detected"], confidence=r3["confidence"],
        notes=f"Entropy={r3['entropy']:.3f} — legitimate domain, zero detection. BYPASSED."
    ))

    # V4: Slow exfil — below 10x volume threshold
    a4 = C2ProtocolAnalyzer()
    r4 = a4.analyze_exfil_volume("185.3.3.3", bytes_sent=50_000)  # 5x baseline
    attempts.append(BypassAttempt(
        fix_id="FIX-13", technique="T1041",
        variant_name="V4_slow_drip_exfil",
        evasion_method="Mutation: drip exfil at 50KB/session — below 10x volume threshold",
        result=r4, bypassed=not r4["detected"], confidence=r4["confidence"],
        notes=f"Ratio={r4['ratio_vs_baseline']:.1f}x — below threshold. BYPASSED."
    ))

    # V5: Protocol mimicry — beacon intervals match browser polling (30s)
    a5 = C2ProtocolAnalyzer()
    base5 = 1_000_000.0
    # Mimic browser auto-refresh: 30s ± 2s (CV ≈ 0.067 — WILL be detected)
    # Attacker adds more jitter: 30s ± 8s (CV ≈ 0.27 — evades)
    for i in range(8):
        jitter = rng.uniform(-8.0, 8.0)
        a5.record_connection("185.4.4.4", base5 + i * 30.0 + jitter)
    r5 = a5.analyze_beacon("185.4.4.4")
    attempts.append(BypassAttempt(
        fix_id="FIX-13", technique="T1071",
        variant_name="V5_browser_mimicry",
        evasion_method="Polymorphism: mimic browser polling intervals with added jitter",
        result=r5, bypassed=not r5["detected"], confidence=r5.get("confidence", 0.0),
        notes=f"CV={r5.get('interval_cv','N/A')} — mimics legitimate browser traffic."
    ))

    # V6: Low-entropy subdomain of DGA domain (attacker registers readable subdomain)
    a6 = C2ProtocolAnalyzer()
    r6 = a6.analyze_domain("api.update-service.com")  # Looks legitimate
    attempts.append(BypassAttempt(
        fix_id="FIX-13", technique="T1071",
        variant_name="V6_lookalike_domain",
        evasion_method="Polymorphism: register human-readable lookalike domain (low entropy)",
        result=r6, bypassed=not r6["detected"], confidence=r6["confidence"],
        notes=f"Entropy={r6['entropy']:.3f} — human-readable domain evades entropy check. BYPASSED."
    ))

    bypassed = sum(1 for a in attempts if a.bypassed)
    detected = sum(1 for a in attempts if not a.bypassed)

    gaps = [
        "Jitter injection: ±40% noise pushes CV above 0.15 — fixed threshold is gameable",
        "Long-sleep beacons: < MIN_BEACON_SAMPLES connections in observation window = no detection",
        "Domain fronting: legitimate CDN domains have low entropy — entropy check blind to fronting",
        "Slow drip exfil: splitting large exfil into many small sessions evades volume threshold",
        "Lookalike domains: human-readable typosquat domains have low entropy",
        "No cross-destination correlation: 10 different IPs each with 4 connections = undetected",
    ]

    countermeasures = [
        "FIX-18a: Adaptive CV threshold — use statistical process control (3-sigma) not fixed 0.15",
        "FIX-18b: Long-window beacon detection — track connections over 24h, not just recent window",
        "FIX-18c: Domain reputation + WHOIS age check — new domains < 30 days = suspicious",
        "FIX-18d: Cumulative exfil tracking — sum all sessions to same dest over 24h",
        "FIX-18e: TLS fingerprinting (JA3/JARM) — detect C2 frameworks by TLS handshake pattern",
        "FIX-18f: Cross-destination beacon correlation — detect distributed C2 infrastructure",
    ]

    return EvasionReport(
        fix_id="FIX-13", detector_name="C2ProtocolAnalyzer",
        total_variants=len(attempts), bypassed=bypassed, detected=detected,
        partial=0, bypass_rate=bypassed / len(attempts),
        attempts=attempts, gaps=gaps, countermeasures=countermeasures,
    )


# ── FIX-14 Bypass Variants: CredentialDumpingDetector (T1003) ────────────────

def simulate_fix14_bypasses(rng: random.Random) -> EvasionReport:
    """
    Bypass attempts against CredentialDumpingDetector.

    Known detection signals:
      - lsass_access_count (target contains 'lsass')
      - suspicious_access_mask (0x1010, 0x1410, 0x1fffff, 0x143a, 0x0010)
      - dump_tool keyword match
      - high_volume_lsass_access (>= 3 in 60s)

    Evasion strategies:
      V1: Novel access mask — use 0x0400 (PROCESS_QUERY_INFORMATION, not in known set)
      V2: Indirect LSASS dump — dump via comsvcs MiniDump without direct LSASS handle
      V3: LOTL — use Task Manager (taskmgr.exe) which is a trusted system binary
      V4: Shadow copy dump — dump SAM/SYSTEM/SECURITY hives (not LSASS process)
      V5: DCSync via legitimate replication — no LSASS access at all
      V6: Slow dump — one LSASS access per 90s (outside 60s window)
    """
    attempts: list[BypassAttempt] = []

    # V1: Novel access mask not in known set
    d1 = CredentialDumpingDetector()
    d1.record_event("powershell.exe", "lsass.exe", granted_access=0x0400)
    r1 = d1.evaluate()
    attempts.append(BypassAttempt(
        fix_id="FIX-14", technique="T1003",
        variant_name="V1_novel_access_mask",
        evasion_method="Mutation: use 0x0400 (PROCESS_QUERY_INFORMATION) — not in known mask set",
        result=r1, bypassed=not r1["detected"], confidence=r1["confidence"],
        notes="lsass_access fires but no mask match — only 1 signal. BYPASSED."
    ))

    # V2: Trusted binary — taskmgr.exe (not in DUMP_TOOL_KEYWORDS)
    d2 = CredentialDumpingDetector()
    d2.record_event("taskmgr.exe", "lsass.exe", granted_access=0x0400)
    r2 = d2.evaluate()
    attempts.append(BypassAttempt(
        fix_id="FIX-14", technique="T1003",
        variant_name="V2_taskmgr_lotl",
        evasion_method="LOTL: use Task Manager (taskmgr.exe) — trusted binary, not in keyword list",
        result=r2, bypassed=not r2["detected"], confidence=r2["confidence"],
        notes="taskmgr not in DUMP_TOOL_KEYWORDS, novel mask — 1 signal. BYPASSED."
    ))

    # V3: Shadow copy / registry hive dump (no LSASS target)
    d3 = CredentialDumpingDetector()
    d3.record_event("reg.exe", "HKLM\\SYSTEM", granted_access=0x0001)
    d3.record_event("reg.exe", "HKLM\\SAM", granted_access=0x0001)
    r3 = d3.evaluate()
    attempts.append(BypassAttempt(
        fix_id="FIX-14", technique="T1003",
        variant_name="V3_registry_hive_dump",
        evasion_method="Polymorphism: dump SAM/SYSTEM registry hives — no LSASS process access",
        result=r3, bypassed=not r3["detected"], confidence=r3["confidence"],
        notes="Target is registry key not 'lsass' — zero signals. BYPASSED."
    ))

    # V4: Slow dump — one access per 90s (outside 60s window)
    d4 = CredentialDumpingDetector()
    now = time.time()
    d4.record_event("powershell.exe", "lsass.exe", granted_access=0x1010,
                    timestamp=now - 200)
    d4.record_event("powershell.exe", "lsass.exe", granted_access=0x1010,
                    timestamp=now - 130)
    d4.record_event("powershell.exe", "lsass.exe", granted_access=0x1010,
                    timestamp=now - 90)
    # Only the most recent one is within 60s window
    d4.record_event("powershell.exe", "lsass.exe", granted_access=0x1010,
                    timestamp=now - 10)
    r4 = d4.evaluate()
    attempts.append(BypassAttempt(
        fix_id="FIX-14", technique="T1003",
        variant_name="V4_slow_dump_outside_window",
        evasion_method="Timing: space LSASS accesses > 60s apart — only 1 in detection window",
        result=r4, bypassed=not r4["detected"], confidence=r4["confidence"],
        notes=f"Only 1 event in 60s window — high_volume not triggered. Signals={r4['signals']}"
    ))

    # V5: Custom tool with renamed binary (not in keyword list)
    d5 = CredentialDumpingDetector()
    d5.record_event("svchost32.exe", "lsass.exe", granted_access=0x0400)
    r5 = d5.evaluate()
    attempts.append(BypassAttempt(
        fix_id="FIX-14", technique="T1003",
        variant_name="V5_renamed_tool",
        evasion_method="Polymorphism: rename mimikatz to svchost32.exe — evades keyword match",
        result=r5, bypassed=not r5["detected"], confidence=r5["confidence"],
        notes="Renamed binary not in keyword list, novel mask — 1 signal. BYPASSED."
    ))

    # V6: Single LSASS access with known mask (2 signals — DETECTED)
    d6 = CredentialDumpingDetector()
    d6.record_event("powershell.exe", "lsass.exe", granted_access=0x1010)
    r6 = d6.evaluate()
    attempts.append(BypassAttempt(
        fix_id="FIX-14", technique="T1003",
        variant_name="V6_single_known_mask",
        evasion_method="Baseline: single LSASS access with known mask (control — should detect)",
        result=r6, bypassed=not r6["detected"], confidence=r6["confidence"],
        notes="lsass_access + suspicious_mask = 2 signals. DETECTED (as expected)."
    ))

    bypassed = sum(1 for a in attempts if a.bypassed)
    detected = sum(1 for a in attempts if not a.bypassed)

    gaps = [
        "Novel access masks: only 5 masks in known set — 0x0400, 0x1000, 0x0010 variants evade",
        "Trusted binary LOTL: taskmgr.exe, werfault.exe, sqldumper.exe not in keyword list",
        "Registry hive dump: SAM/SYSTEM/SECURITY dump has no LSASS target — zero signals",
        "Slow dump: spacing accesses > 60s apart keeps count below high_volume threshold",
        "Renamed tools: any binary not in DUMP_TOOL_KEYWORDS evades keyword signal",
        "DCSync: replication-based credential theft generates no LSASS process access event",
    ]

    countermeasures = [
        "FIX-19a: Expand access mask set — add 0x0400, 0x1000, 0x0410, 0x1438 variants",
        "FIX-19b: Expand LOTL binary list — add taskmgr, werfault, sqldumper, rdrleakdiag",
        "FIX-19c: Registry hive access detection — flag SAM/SYSTEM/SECURITY reg exports",
        "FIX-19d: Extend detection window to 300s — catches slow-dump patterns",
        "FIX-19e: Parent process anomaly — flag any non-system process accessing LSASS",
        "FIX-19f: DCSync detection — monitor DS-Replication-Get-Changes-All privilege use",
    ]

    return EvasionReport(
        fix_id="FIX-14", detector_name="CredentialDumpingDetector",
        total_variants=len(attempts), bypassed=bypassed, detected=detected,
        partial=0, bypass_rate=bypassed / len(attempts),
        attempts=attempts, gaps=gaps, countermeasures=countermeasures,
    )


# ── FIX-15 Bypass Variants: SessionHijackDetector (T1539/T1557) ──────────────

def simulate_fix15_bypasses(rng: random.Random) -> EvasionReport:
    """
    Bypass attempts against SessionHijackDetector.

    Known detection signals:
      - ip_change within TOKEN_WINDOW_SECONDS (300s)
      - user_agent_change
      - post_logout_reuse
      - ARP table MAC change

    Evasion strategies:
      V1: Slow IP change — wait > 300s before switching IP
      V2: UA spoofing — copy victim's exact user-agent string
      V3: Token theft without logout — victim session still active
      V4: ARP cache poisoning with gradual MAC rotation
      V5: Cookie theft via XSS — attacker uses same IP (same network)
      V6: OAuth token theft — different token format, no session tracking
    """
    attempts: list[BypassAttempt] = []

    # V1: IP change after window expires
    d1 = SessionHijackDetector()
    now = time.time()
    d1.record_session("tok_slow", "10.0.0.1", "Mozilla/5.0", timestamp=now - 400)
    r1 = d1.record_session("tok_slow", "185.220.101.5", "Mozilla/5.0",
                            timestamp=now)  # 400s later — outside 300s window
    attempts.append(BypassAttempt(
        fix_id="FIX-15", technique="T1539",
        variant_name="V1_slow_ip_change",
        evasion_method="Timing: wait > TOKEN_WINDOW_SECONDS before switching IP",
        result=r1, bypassed=not r1["detected"], confidence=r1["confidence"],
        notes=f"IP change after 400s — outside 300s window. Signals={r1['signals']}. BYPASSED."
    ))

    # V2: UA spoofing — attacker copies victim's exact UA
    d2 = SessionHijackDetector()
    victim_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    d2.record_session("tok_ua", "10.0.0.1", victim_ua, timestamp=now)
    r2 = d2.record_session("tok_ua", "185.220.101.5", victim_ua,
                            timestamp=now + 30)
    attempts.append(BypassAttempt(
        fix_id="FIX-15", technique="T1539",
        variant_name="V2_ua_spoofing",
        evasion_method="Mutation: copy victim's exact User-Agent string — suppresses UA signal",
        result=r2, bypassed=not r2["detected"], confidence=r2["confidence"],
        notes=f"UA matches — only ip_change fires. Signals={r2['signals']}. DETECTED (1 signal)."
    ))

    # V3: Same-network attacker (same IP as victim — e.g., coffee shop MitM)
    d3 = SessionHijackDetector()
    d3.record_session("tok_samenet", "192.168.1.50", "Mozilla/5.0", timestamp=now)
    r3 = d3.record_session("tok_samenet", "192.168.1.50", "Mozilla/5.0",
                            timestamp=now + 10)
    attempts.append(BypassAttempt(
        fix_id="FIX-15", technique="T1539",
        variant_name="V3_same_network_mitm",
        evasion_method="LOTL: ARP poison on same LAN — attacker gets same source IP as victim",
        result=r3, bypassed=not r3["detected"], confidence=r3["confidence"],
        notes="Same IP, same UA — zero signals. BYPASSED."
    ))

    # V4: Gradual ARP rotation (change MAC in small steps — not tracked)
    d4 = SessionHijackDetector()
    d4.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    # Attacker changes MAC — this WILL be detected
    r4_detected = d4.record_arp("192.168.1.1", "11:22:33:44:55:66")
    # But if attacker first poisons to intermediate MAC, then to final:
    d4b = SessionHijackDetector()
    d4b.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    d4b.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:00")  # Step 1 — detected
    # After detection, defender updates baseline — attacker's MAC is now "known"
    # Simulate: defender ACKs the change (updates baseline)
    d4b._arp_table["192.168.1.1"] = "aa:bb:cc:dd:ee:00"
    r4 = d4b.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:00")  # Now "normal"
    attempts.append(BypassAttempt(
        fix_id="FIX-15", technique="T1557",
        variant_name="V4_arp_baseline_reset",
        evasion_method="Mutation: trigger detection once to force baseline update, then operate normally",
        result=r4, bypassed=not r4["detected"], confidence=r4.get("confidence", 0.0),
        notes="After baseline reset, attacker MAC is 'known'. BYPASSED."
    ))

    # V5: New token (attacker generates fresh OAuth token — no history)
    d5 = SessionHijackDetector()
    r5 = d5.record_session("tok_brand_new_oauth_xyz", "185.220.101.5", "curl/7.88",
                            timestamp=now)
    attempts.append(BypassAttempt(
        fix_id="FIX-15", technique="T1539",
        variant_name="V5_fresh_token_no_history",
        evasion_method="Polymorphism: steal OAuth refresh token — generate fresh access token with no history",
        result=r5, bypassed=not r5["detected"], confidence=r5.get("confidence", 0.0),
        notes="New token = NEW_SESSION verdict — no anomaly possible. BYPASSED."
    ))

    bypassed = sum(1 for a in attempts if a.bypassed)
    detected = sum(1 for a in attempts if not a.bypassed)

    gaps = [
        "Window boundary: IP change after 300s is invisible — no long-term session tracking",
        "Same-network MitM: ARP poison on LAN gives attacker same source IP as victim",
        "Fresh token theft: OAuth refresh token → new access token has no anomaly history",
        "ARP baseline reset: single detection event can be used to 'legitimise' attacker MAC",
        "No geolocation: IP change from 10.0.0.1 to 185.220.101.5 (different country) not flagged",
        "No concurrent session detection: victim + attacker both active simultaneously",
    ]

    countermeasures = [
        "FIX-20a: Extend session tracking window to 24h — catch slow IP changes",
        "FIX-20b: Geolocation anomaly — flag country-level IP changes within any window",
        "FIX-20c: Concurrent session detection — flag same token active from 2+ IPs simultaneously",
        "FIX-20d: ARP change rate limiting — >1 MAC change per hour for same IP = alert",
        "FIX-20e: Token binding — bind session tokens to TLS channel (RFC 8471)",
        "FIX-20f: Refresh token anomaly — flag refresh tokens used from new IP/device",
    ]

    return EvasionReport(
        fix_id="FIX-15", detector_name="SessionHijackDetector",
        total_variants=len(attempts), bypassed=bypassed, detected=detected,
        partial=0, bypass_rate=bypassed / len(attempts),
        attempts=attempts, gaps=gaps, countermeasures=countermeasures,
    )


# ── FIX-16 Bypass Variants: SpearphishingEnhancer (T1566.001) ────────────────

def simulate_fix16_bypasses(rng: random.Random) -> EvasionReport:
    """
    Bypass attempts against SpearphishingEnhancer.

    Known detection signals:
      - macro_extension (.docm, .xlsm, etc.)
      - macros_present flag
      - mime_mismatch
      - double_extension
      - office_parent + suspicious_child process

    Evasion strategies:
      V1: Clean extension + no macros (use DDE instead of VBA)
      V2: LNK file — not an Office document at all
      V3: ISO/IMG container — bypasses Mark-of-the-Web
      V4: HTML smuggling — JavaScript reconstructs payload in browser
      V5: Trusted child process — Office spawns legitimate binary first
      V6: Delayed execution — child process spawned > 60s after Office open
    """
    attempts: list[BypassAttempt] = []

    # V1: Clean .docx with DDE (no macros, correct MIME)
    e1 = SpearphishingEnhancer()
    r1 = e1.analyze_attachment(
        "invoice.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        has_macros=False,
    )
    attempts.append(BypassAttempt(
        fix_id="FIX-16", technique="T1566.001",
        variant_name="V1_dde_no_macros",
        evasion_method="Polymorphism: use DDE (Dynamic Data Exchange) instead of VBA macros",
        result=r1, bypassed=not r1["detected"], confidence=r1["confidence"],
        notes="Clean .docx, correct MIME, no macros — zero signals. BYPASSED."
    ))

    # V2: LNK shortcut file (not Office, not in extension list)
    e2 = SpearphishingEnhancer()
    r2 = e2.analyze_attachment("Q4_Report.pdf.lnk", "application/octet-stream")
    attempts.append(BypassAttempt(
        fix_id="FIX-16", technique="T1566.001",
        variant_name="V2_lnk_shortcut",
        evasion_method="Polymorphism: LNK shortcut file — not an Office document",
        result=r2, bypassed=not r2["detected"], confidence=r2["confidence"],
        notes=f"Signals={r2['signals']} — double_extension fires but only 1 signal. BYPASSED."
    ))

    # V3: ISO container (single extension, octet-stream — no signals)
    e3 = SpearphishingEnhancer()
    r3 = e3.analyze_attachment("invoice.iso", "application/octet-stream")
    attempts.append(BypassAttempt(
        fix_id="FIX-16", technique="T1566.001",
        variant_name="V3_iso_container",
        evasion_method="LOTL: ISO/IMG container bypasses MOTW — no Office extension",
        result=r3, bypassed=not r3["detected"], confidence=r3["confidence"],
        notes="No macro extension, no MIME mismatch for .iso — zero signals. BYPASSED."
    ))

    # V4: HTML smuggling (HTML file — not Office)
    e4 = SpearphishingEnhancer()
    r4 = e4.analyze_attachment("statement.html", "text/html")
    attempts.append(BypassAttempt(
        fix_id="FIX-16", technique="T1566.001",
        variant_name="V4_html_smuggling",
        evasion_method="Polymorphism: HTML smuggling — JS reconstructs payload in browser",
        result=r4, bypassed=not r4["detected"], confidence=r4["confidence"],
        notes="HTML file — no Office signals at all. BYPASSED."
    ))

    # V5: Delayed execution — child spawned > 60s after Office open
    e5 = SpearphishingEnhancer()
    now = time.time()
    e5.record_office_open("report.docm", timestamp=now - 120)  # 2 min ago
    r5 = e5.analyze_child_process("winword.exe", "powershell.exe", timestamp=now)
    attempts.append(BypassAttempt(
        fix_id="FIX-16", technique="T1566.001",
        variant_name="V5_delayed_execution",
        evasion_method="Timing: delay child process spawn > 60s after Office open",
        result=r5, bypassed=not r5["detected"], confidence=r5["confidence"],
        notes=f"Office open was 120s ago — recent_office_open=False. Detected={r5['detected']} "
              f"(office_parent+suspicious_child still fires regardless of timing)."
    ))

    # V6: Trusted child — Office spawns explorer.exe (not suspicious)
    e6 = SpearphishingEnhancer()
    e6.record_office_open("report.docm")
    r6 = e6.analyze_child_process("winword.exe", "explorer.exe")
    attempts.append(BypassAttempt(
        fix_id="FIX-16", technique="T1566.001",
        variant_name="V6_trusted_child_process",
        evasion_method="LOTL: Office spawns explorer.exe → explorer spawns powershell (indirect)",
        result=r6, bypassed=not r6["detected"], confidence=r6["confidence"],
        notes="explorer.exe not in SUSPICIOUS_CHILDREN — not detected. BYPASSED."
    ))

    bypassed = sum(1 for a in attempts if a.bypassed)
    detected = sum(1 for a in attempts if not a.bypassed)

    gaps = [
        "DDE/OLE: Dynamic Data Exchange executes commands without VBA macros — no macro signal",
        "LNK files: shortcut files execute arbitrary commands — not in Office extension list",
        "ISO/IMG containers: bypass Mark-of-the-Web and have no Office extension",
        "HTML smuggling: JavaScript-based payload delivery — no attachment analysis possible",
        "Indirect execution: Office → explorer.exe → powershell.exe breaks parent-child chain",
        "OneNote attachments: .one files can embed executables — not in MACRO_EXTENSIONS",
    ]

    countermeasures = [
        "FIX-21a: Add LNK/ISO/IMG/ONE to suspicious attachment extensions",
        "FIX-21b: DDE detection — scan .docx XML for DDE field codes",
        "FIX-21c: HTML smuggling detection — flag HTML attachments with base64 blobs > 10KB",
        "FIX-21d: Indirect execution chain — track grandchild processes (Office → any → suspicious)",
        "FIX-21e: MOTW bypass detection — flag files opened from ISO/IMG mount points",
        "FIX-21f: Extend SUSPICIOUS_CHILDREN to include explorer.exe when spawned by Office",
    ]

    return EvasionReport(
        fix_id="FIX-16", detector_name="SpearphishingEnhancer",
        total_variants=len(attempts), bypassed=bypassed, detected=detected,
        partial=0, bypass_rate=bypassed / len(attempts),
        attempts=attempts, gaps=gaps, countermeasures=countermeasures,
    )


# ── Master runner ─────────────────────────────────────────────────────────────

def run_zeroday_simulation(seed: int = 313) -> list[EvasionReport]:
    rng = random.Random(seed)
    return [
        simulate_fix12_bypasses(rng),
        simulate_fix13_bypasses(rng),
        simulate_fix14_bypasses(rng),
        simulate_fix15_bypasses(rng),
        simulate_fix16_bypasses(rng),
    ]


def print_report(reports: list[EvasionReport]) -> None:
    print("=" * 70)
    print("  SHADOW313 — ZERO-DAY EVASION SIMULATION REPORT")
    print("=" * 70)

    total_variants = sum(r.total_variants for r in reports)
    total_bypassed = sum(r.bypassed for r in reports)
    total_detected = sum(r.detected for r in reports)
    overall_bypass = total_bypassed / total_variants if total_variants else 0

    print(f"\n  Overall: {total_variants} variants tested | "
          f"{total_bypassed} bypassed ({overall_bypass:.0%}) | "
          f"{total_detected} detected ({total_detected/total_variants:.0%})\n")

    for report in reports:
        print(f"  {'─'*66}")
        print(f"  {report.fix_id}: {report.detector_name}")
        print(f"  Bypass rate: {report.bypass_rate:.0%} "
              f"({report.bypassed}/{report.total_variants} variants evaded)\n")

        for a in report.attempts:
            status = "BYPASSED ⚠" if a.bypassed else "DETECTED ✓"
            print(f"    [{status}] {a.variant_name}")
            print(f"             Method: {a.evasion_method}")
            print(f"             Notes:  {a.notes}")

        print(f"\n  Gaps identified ({len(report.gaps)}):")
        for g in report.gaps:
            print(f"    • {g}")

        print(f"\n  Next-gen countermeasures ({len(report.countermeasures)}):")
        for c in report.countermeasures:
            print(f"    → {c}")
        print()


if __name__ == "__main__":
    reports = run_zeroday_simulation()
    print_report(reports)