"""
tests/unit/v4/test_apt_hardening_fixes.py
──────────────────────────────────────────
Tests for FIX-12 through FIX-16 — the 5 targeted APT hardening detectors
that close the top evaded technique gaps identified in the 500-actor simulation.

Coverage:
  FIX-12: ValidAccountsDetector     (T1078 — 29x evaded)
  FIX-13: C2ProtocolAnalyzer        (T1071/T1041 — 26x evaded)
  FIX-14: CredentialDumpingDetector (T1003 — 14x evaded)
  FIX-15: SessionHijackDetector     (T1539/T1557 — 26x evaded)
  FIX-16: SpearphishingEnhancer     (T1566.001 — 11x evaded)
"""
from __future__ import annotations

import math
import time
import pytest

from shadow313.v4.detection.threat_hardening import (
    ValidAccountsDetector,
    C2ProtocolAnalyzer,
    CredentialDumpingDetector,
    SessionHijackDetector,
    SpearphishingEnhancer,
    HARDENING_FIXES,
)


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-12: ValidAccountsDetector (T1078)
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidAccountsDetector:

    def _detector_with_baseline(self) -> ValidAccountsDetector:
        d = ValidAccountsDetector()
        # Build baseline: account 'alice' logs in during business hours from known IP/host
        for _ in range(5):
            d.record_baseline("alice", hour=10, src_ip="10.0.0.5", host="WS-01")
        return d

    def test_clean_login_not_detected(self):
        d = self._detector_with_baseline()
        result = d.evaluate("alice", hour=10, src_ip="10.0.0.5", host="WS-01")
        assert result["detected"] is False
        assert result["verdict"] == "CLEAN"

    def test_off_hours_new_ip_new_host_detected(self):
        d = self._detector_with_baseline()
        # 3 signals: off-hours + new IP + new host
        result = d.evaluate("alice", hour=23, src_ip="185.220.101.5", host="DC-01")
        assert result["detected"] is True
        assert result["confidence"] >= 0.90
        assert "off_hours_login" in result["signals"]
        assert "new_source_ip" in result["signals"]
        assert "new_host" in result["signals"]

    def test_off_hours_only_not_detected(self):
        d = self._detector_with_baseline()
        # Only 1 signal — below threshold
        result = d.evaluate("alice", hour=23, src_ip="10.0.0.5", host="WS-01")
        assert result["detected"] is False
        assert result["confidence"] < 0.5

    def test_new_ip_and_new_host_detected(self):
        d = self._detector_with_baseline()
        result = d.evaluate("alice", hour=10, src_ip="192.168.99.1", host="ATTACKER-BOX")
        assert result["detected"] is True
        assert result["confidence"] >= 0.75

    def test_no_baseline_account_flagged(self):
        d = ValidAccountsDetector()
        result = d.evaluate("unknown_user", hour=10, src_ip="10.0.0.1", host="WS-01")
        # no_baseline + new_source_ip + new_host = 3 signals
        assert result["detected"] is True
        assert "no_baseline" in result["signals"]

    def test_technique_tag(self):
        d = ValidAccountsDetector()
        result = d.evaluate("bob", hour=10, src_ip="10.0.0.1", host="WS-01")
        assert result["technique"] == "T1078"

    def test_multiple_accounts_independent(self):
        d = ValidAccountsDetector()
        d.record_baseline("alice", hour=9, src_ip="10.0.0.1", host="WS-01")
        d.record_baseline("bob",   hour=9, src_ip="10.0.0.2", host="WS-02")
        r_alice = d.evaluate("alice", hour=9, src_ip="10.0.0.1", host="WS-01")
        r_bob   = d.evaluate("bob",   hour=9, src_ip="10.0.0.2", host="WS-02")
        assert r_alice["detected"] is False
        assert r_bob["detected"]   is False

    def test_early_morning_off_hours(self):
        d = self._detector_with_baseline()
        # Hour 3 is in off-hours window (22-06)
        result = d.evaluate("alice", hour=3, src_ip="10.0.0.5", host="WS-01")
        assert "off_hours_login" in result["signals"]

    def test_confidence_scales_with_signals(self):
        d = self._detector_with_baseline()
        r1 = d.evaluate("alice", hour=10, src_ip="10.0.0.5", host="WS-01")   # 0 signals
        r2 = d.evaluate("alice", hour=23, src_ip="10.0.0.5", host="WS-01")   # 1 signal
        r3 = d.evaluate("alice", hour=23, src_ip="1.2.3.4",  host="WS-01")   # 2 signals
        r4 = d.evaluate("alice", hour=23, src_ip="1.2.3.4",  host="DC-01")   # 3 signals
        assert r1["confidence"] < r2["confidence"] < r3["confidence"] < r4["confidence"]

    def test_fix12_registered_in_hardening_fixes(self):
        assert "FIX-12" in HARDENING_FIXES
        assert "ValidAccountsDetector" in HARDENING_FIXES["FIX-12"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-13: C2ProtocolAnalyzer (T1071 / T1041)
# ═══════════════════════════════════════════════════════════════════════════════

class TestC2ProtocolAnalyzer:

    def _analyzer_with_beacon(self, dest_ip: str = "185.220.101.5",
                               interval: float = 60.0, count: int = 8) -> C2ProtocolAnalyzer:
        a = C2ProtocolAnalyzer()
        base = 1_000_000.0
        for i in range(count):
            a.record_connection(dest_ip, base + i * interval)
        return a

    def test_regular_beacon_detected(self):
        a = self._analyzer_with_beacon(interval=60.0, count=8)
        result = a.analyze_beacon("185.220.101.5")
        assert result["detected"] is True
        assert result["verdict"] == "C2_BEACON"
        assert result["interval_cv"] < 0.15

    def test_irregular_traffic_not_detected(self):
        a = C2ProtocolAnalyzer()
        base = 1_000_000.0
        # Highly irregular intervals
        for offset in [0, 5, 120, 7, 300, 2, 90, 45]:
            a.record_connection("10.0.0.1", base + offset)
        result = a.analyze_beacon("10.0.0.1")
        assert result["detected"] is False

    def test_insufficient_samples(self):
        a = C2ProtocolAnalyzer()
        a.record_connection("1.2.3.4", 1000.0)
        a.record_connection("1.2.3.4", 1060.0)
        result = a.analyze_beacon("1.2.3.4")
        assert result["detected"] is False
        assert result["reason"] == "insufficient_samples"

    def test_high_entropy_domain_detected(self):
        a = C2ProtocolAnalyzer()
        # DGA-like domain: truly high entropy label (all unique chars → max entropy)
        # "abcdefghij" has 10 unique chars → entropy = log2(10) ≈ 3.32
        # "abcdefghijk" has 11 unique chars → entropy = log2(11) ≈ 3.46
        # Use a label with repeated random-looking chars that push past 3.8:
        # "a1b2c3d4e5f6" → 12 unique chars → log2(12) ≈ 3.58 — still not enough
        # Use a truly random-looking 16-char label with all unique chars:
        # entropy = log2(16) = 4.0 ✓
        result = a.analyze_domain("abcdefghijklmnop.evil.com")
        assert result["detected"] is True
        assert result["verdict"] == "DGA_SUSPECTED"
        assert result["entropy"] >= 3.8

    def test_low_entropy_domain_clean(self):
        a = C2ProtocolAnalyzer()
        result = a.analyze_domain("google.com")
        assert result["detected"] is False
        assert result["verdict"] == "NORMAL"

    def test_exfil_large_volume_detected(self):
        a = C2ProtocolAnalyzer()
        result = a.analyze_exfil_volume("185.220.101.5", bytes_sent=5_000_000)
        assert result["detected"] is True
        assert result["verdict"] == "EXFIL_SUSPECTED"
        assert result["technique"] == "T1041"

    def test_exfil_small_volume_clean(self):
        a = C2ProtocolAnalyzer()
        result = a.analyze_exfil_volume("10.0.0.1", bytes_sent=500)
        assert result["detected"] is False

    def test_domain_entropy_calculation(self):
        # Known entropy: "aaaa" → 0 bits, "abcd" → 2 bits
        assert C2ProtocolAnalyzer.domain_entropy("aaaa.com") == 0.0
        entropy_abcd = C2ProtocolAnalyzer.domain_entropy("abcd.com")
        assert abs(entropy_abcd - 2.0) < 0.01

    def test_beacon_confidence_high_for_very_regular(self):
        a = self._analyzer_with_beacon(interval=60.0, count=20)
        result = a.analyze_beacon("185.220.101.5")
        assert result["confidence"] >= 0.85

    def test_fix13_registered(self):
        assert "FIX-13" in HARDENING_FIXES
        assert "C2ProtocolAnalyzer" in HARDENING_FIXES["FIX-13"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-14: CredentialDumpingDetector (T1003)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCredentialDumpingDetector:

    def test_lsass_access_with_suspicious_mask_detected(self):
        d = CredentialDumpingDetector()
        d.record_event("powershell.exe", "lsass.exe", granted_access=0x1010)
        d.record_event("powershell.exe", "lsass.exe", granted_access=0x1010)
        result = d.evaluate()
        assert result["detected"] is True
        assert result["technique"] == "T1003"
        assert any("lsass" in s for s in result["signals"])

    def test_known_dump_tool_detected(self):
        d = CredentialDumpingDetector()
        d.record_event("mimikatz.exe", "lsass.exe", granted_access=0x1fffff)
        result = d.evaluate()
        assert result["detected"] is True
        assert any("dump_tool" in s for s in result["signals"])

    def test_procdump_detected(self):
        d = CredentialDumpingDetector()
        d.record_event("procdump.exe", "lsass.exe", granted_access=0x1010)
        result = d.evaluate()
        assert result["detected"] is True

    def test_high_volume_lsass_access(self):
        d = CredentialDumpingDetector()
        for _ in range(5):
            d.record_event("svchost.exe", "lsass.exe", granted_access=0x1010)
        result = d.evaluate()
        assert result["detected"] is True
        assert "high_volume_lsass_access" in result["signals"]
        assert result["verdict"] == "CRITICAL"

    def test_normal_process_access_not_detected(self):
        d = CredentialDumpingDetector()
        d.record_event("explorer.exe", "notepad.exe", granted_access=0x0001)
        result = d.evaluate()
        assert result["detected"] is False

    def test_no_events_clean(self):
        d = CredentialDumpingDetector()
        result = d.evaluate()
        assert result["detected"] is False
        assert result["verdict"] == "CLEAN"

    def test_confidence_critical_for_multiple_signals(self):
        d = CredentialDumpingDetector()
        d.record_event("mimikatz.exe", "lsass.exe", granted_access=0x1fffff)
        d.record_event("mimikatz.exe", "lsass.exe", granted_access=0x1fffff)
        d.record_event("mimikatz.exe", "lsass.exe", granted_access=0x1fffff)
        result = d.evaluate()
        assert result["confidence"] >= 0.90

    def test_comsvcs_dll_detected(self):
        d = CredentialDumpingDetector()
        d.record_event("comsvcs.exe", "lsass.exe", granted_access=0x1410)
        result = d.evaluate()
        assert result["detected"] is True

    def test_technique_tag(self):
        d = CredentialDumpingDetector()
        result = d.evaluate()
        assert result["technique"] == "T1003"

    def test_fix14_registered(self):
        assert "FIX-14" in HARDENING_FIXES
        assert "CredentialDumpingDetector" in HARDENING_FIXES["FIX-14"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-15: SessionHijackDetector (T1539 / T1557)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSessionHijackDetector:

    def test_new_session_not_detected(self):
        d = SessionHijackDetector()
        result = d.record_session("tok_abc123", "10.0.0.1", "Mozilla/5.0")
        assert result["detected"] is False
        assert result["verdict"] == "NEW_SESSION"

    def test_ip_change_within_window_detected(self):
        d = SessionHijackDetector()
        now = time.time()
        d.record_session("tok_abc123", "10.0.0.1", "Mozilla/5.0", timestamp=now)
        result = d.record_session("tok_abc123", "185.220.101.5", "Mozilla/5.0",
                                   timestamp=now + 30)
        assert result["detected"] is True
        assert any("ip_change" in s for s in result["signals"])

    def test_user_agent_change_detected(self):
        d = SessionHijackDetector()
        now = time.time()
        d.record_session("tok_xyz789", "10.0.0.1", "Mozilla/5.0", timestamp=now)
        result = d.record_session("tok_xyz789", "10.0.0.1", "curl/7.88",
                                   timestamp=now + 10)
        assert result["detected"] is True
        assert "user_agent_change" in result["signals"]

    def test_post_logout_reuse_detected(self):
        d = SessionHijackDetector()
        now = time.time()
        d.record_session("tok_logout1", "10.0.0.1", "Mozilla/5.0", timestamp=now)
        d.record_logout("tok_logout1")
        result = d.record_session("tok_logout1", "10.0.0.1", "Mozilla/5.0",
                                   timestamp=now + 5)
        assert result["detected"] is True
        assert "post_logout_reuse" in result["signals"]

    def test_same_ip_same_ua_normal(self):
        d = SessionHijackDetector()
        now = time.time()
        d.record_session("tok_normal", "10.0.0.1", "Mozilla/5.0", timestamp=now)
        result = d.record_session("tok_normal", "10.0.0.1", "Mozilla/5.0",
                                   timestamp=now + 60)
        assert result["detected"] is False
        assert result["verdict"] == "NORMAL"

    def test_arp_poisoning_detected(self):
        d = SessionHijackDetector()
        d.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        result = d.record_arp("192.168.1.1", "11:22:33:44:55:66")
        assert result["detected"] is True
        assert result["verdict"] == "ARP_POISONING_SUSPECTED"
        assert result["technique"] == "T1557"

    def test_arp_same_mac_normal(self):
        d = SessionHijackDetector()
        d.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        result = d.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        assert result["detected"] is False

    def test_new_arp_entry_not_detected(self):
        d = SessionHijackDetector()
        result = d.record_arp("192.168.1.100", "aa:bb:cc:dd:ee:ff")
        assert result["detected"] is False
        assert result["verdict"] == "NEW_ARP_ENTRY"

    def test_high_confidence_for_multiple_signals(self):
        d = SessionHijackDetector()
        now = time.time()
        d.record_session("tok_multi", "10.0.0.1", "Mozilla/5.0", timestamp=now)
        d.record_logout("tok_multi")
        result = d.record_session("tok_multi", "185.220.101.5", "curl/7.88",
                                   timestamp=now + 10)
        assert result["confidence"] >= 0.88

    def test_fix15_registered(self):
        assert "FIX-15" in HARDENING_FIXES
        assert "SessionHijackDetector" in HARDENING_FIXES["FIX-15"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-16: SpearphishingEnhancer (T1566.001)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSpearphishingEnhancer:

    def test_macro_extension_detected(self):
        e = SpearphishingEnhancer()
        # Two signals: macro_extension + macros_present → detected=True
        result = e.analyze_attachment("invoice.docm",
                                       "application/vnd.ms-word.document.macroEnabled.12",
                                       has_macros=True)
        assert result["detected"] is True
        assert any("macro_extension" in s for s in result["signals"])
        assert "macros_present" in result["signals"]

    def test_macros_present_flagged(self):
        e = SpearphishingEnhancer()
        result = e.analyze_attachment("report.docx",
                                       "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                       has_macros=True)
        # 1 signal only (macros_present) — below detection threshold
        assert "macros_present" in result["signals"]

    def test_mime_mismatch_detected(self):
        e = SpearphishingEnhancer()
        # .pdf extension but wrong MIME
        result = e.analyze_attachment("statement.pdf", "application/x-msdownload")
        assert "mime_mismatch" in " ".join(result["signals"])

    def test_double_extension_flagged(self):
        e = SpearphishingEnhancer()
        result = e.analyze_attachment("invoice.pdf.exe", "application/octet-stream")
        assert "double_extension" in result["signals"]

    def test_clean_attachment_not_detected(self):
        e = SpearphishingEnhancer()
        result = e.analyze_attachment(
            "report.pdf",
            "application/pdf",
            has_macros=False,
        )
        assert result["detected"] is False
        assert result["verdict"] == "CLEAN"

    def test_office_spawning_powershell_detected(self):
        e = SpearphishingEnhancer()
        e.record_office_open("Q4_Report.docm")
        result = e.analyze_child_process("winword.exe", "powershell.exe")
        assert result["detected"] is True
        assert result["verdict"] == "MACRO_EXECUTION"
        assert result["confidence"] >= 0.90

    def test_office_spawning_cmd_detected(self):
        e = SpearphishingEnhancer()
        e.record_office_open("invoice.xlsm")
        result = e.analyze_child_process("excel.exe", "cmd.exe")
        assert result["detected"] is True

    def test_normal_parent_child_not_detected(self):
        e = SpearphishingEnhancer()
        result = e.analyze_child_process("explorer.exe", "notepad.exe")
        assert result["detected"] is False

    def test_office_parent_non_suspicious_child_not_detected(self):
        e = SpearphishingEnhancer()
        result = e.analyze_child_process("winword.exe", "spellcheck.exe")
        assert result["detected"] is False

    def test_macro_extension_plus_macros_high_confidence(self):
        e = SpearphishingEnhancer()
        result = e.analyze_attachment("payload.xlsm",
                                       "application/vnd.ms-excel.sheet.macroEnabled.12",
                                       has_macros=True)
        assert result["detected"] is True
        assert result["confidence"] >= 0.70

    def test_technique_tag(self):
        e = SpearphishingEnhancer()
        result = e.analyze_attachment("test.docm", "application/octet-stream")
        assert result["technique"] == "T1566.001"

    def test_fix16_registered(self):
        assert "FIX-16" in HARDENING_FIXES
        assert "SpearphishingEnhancer" in HARDENING_FIXES["FIX-16"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: all 5 detectors fire on a realistic APT28-style kill chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestAPT28KillChainIntegration:
    """
    Simulate an APT28-style attack chain and verify all 5 new detectors fire.
    APT28 TTPs: T1566.001 → T1059.001 → T1078 → T1003 → T1071 → T1547
    """

    def test_full_apt28_chain_detected(self):
        # Stage 1: Spearphishing (T1566.001)
        spear = SpearphishingEnhancer()
        spear.record_office_open("Q4_Forecast.docm")
        r_spear = spear.analyze_child_process("winword.exe", "powershell.exe")
        assert r_spear["detected"] is True, "Stage 1 (T1566.001) not detected"

        # Stage 2: Valid accounts (T1078) — attacker uses stolen creds
        va = ValidAccountsDetector()
        va.record_baseline("jsmith", hour=9, src_ip="10.0.0.5", host="WS-07")
        r_va = va.evaluate("jsmith", hour=2, src_ip="185.220.101.5", host="DC-01")
        assert r_va["detected"] is True, "Stage 2 (T1078) not detected"

        # Stage 3: Credential dumping (T1003)
        cd = CredentialDumpingDetector()
        cd.record_event("powershell.exe", "lsass.exe", granted_access=0x1010)
        cd.record_event("powershell.exe", "lsass.exe", granted_access=0x1010)
        r_cd = cd.evaluate()
        assert r_cd["detected"] is True, "Stage 3 (T1003) not detected"

        # Stage 4: C2 beacon (T1071)
        c2 = C2ProtocolAnalyzer()
        base = 1_000_000.0
        for i in range(8):
            c2.record_connection("185.220.101.5", base + i * 60.0)
        r_c2 = c2.analyze_beacon("185.220.101.5")
        assert r_c2["detected"] is True, "Stage 4 (T1071) not detected"

        # Stage 5: Session hijack (T1539) — attacker reuses stolen token
        sh = SessionHijackDetector()
        now = time.time()
        sh.record_session("tok_jsmith", "10.0.0.5", "Mozilla/5.0", timestamp=now)
        r_sh = sh.record_session("tok_jsmith", "185.220.101.5", "curl/7.88",
                                  timestamp=now + 45)
        assert r_sh["detected"] is True, "Stage 5 (T1539) not detected"

        # All 5 stages detected
        detections = [r_spear, r_va, r_cd, r_c2, r_sh]
        assert all(r["detected"] for r in detections), \
            f"Not all stages detected: {[r['detected'] for r in detections]}"

    def test_all_detectors_return_technique_tag(self):
        spear = SpearphishingEnhancer()
        va    = ValidAccountsDetector()
        cd    = CredentialDumpingDetector()
        c2    = C2ProtocolAnalyzer()
        sh    = SessionHijackDetector()

        assert spear.analyze_attachment("x.docm", "app/octet")["technique"] == "T1566.001"
        assert va.evaluate("u", 10, "1.2.3.4", "h")["technique"] == "T1078"
        assert cd.evaluate()["technique"] == "T1003"
        assert c2.analyze_domain("xk3j9mq2p7.evil.com")["technique"] == "T1071"
        assert sh.record_arp("1.2.3.4", "aa:bb:cc:dd:ee:ff")["technique"] == "T1557"