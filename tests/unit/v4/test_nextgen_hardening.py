"""
tests/unit/v4/test_nextgen_hardening.py
────────────────────────────────────────
Tests for FIX-17 through FIX-21 — next-generation countermeasures
that close the gaps discovered by the zero-day evasion simulation.

Coverage:
  FIX-17: ImpossibleTravelDetector   (T1078)
  FIX-18: AdaptiveBeaconDetector     (T1071/T1041)
  FIX-19: HardenedCredDumpDetector   (T1003)
  FIX-20: AdvancedSessionGuard       (T1539/T1557)
  FIX-21: AttachmentDeepInspector    (T1566.001)
"""
from __future__ import annotations

import time
import pytest

from shadow313.v4.detection.nextgen_hardening import (
    ImpossibleTravelDetector,
    AdaptiveBeaconDetector,
    HardenedCredDumpDetector,
    AdvancedSessionGuard,
    AttachmentDeepInspector,
    NEXTGEN_FIXES,
)


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-17: ImpossibleTravelDetector
# ═══════════════════════════════════════════════════════════════════════════════

class TestImpossibleTravelDetector:

    def test_impossible_travel_detected(self):
        d = ImpossibleTravelDetector()
        now = time.time()
        # Login from EU, then 5 min later from APAC — impossible
        d.record_login("alice", "185.1.1.1", timestamp=now - 300)
        result = d.record_login("alice", "1.2.3.4", timestamp=now)
        assert result["detected"] is True
        assert any("impossible_travel" in s for s in result["signals"])

    def test_normal_login_not_detected(self):
        d = ImpossibleTravelDetector()
        now = time.time()
        d.record_login("bob", "10.0.0.1", timestamp=now - 3600)
        result = d.record_login("bob", "10.0.0.1", timestamp=now)
        assert result["detected"] is False

    def test_login_velocity_detected(self):
        d = ImpossibleTravelDetector()
        now = time.time()
        # 5 logins in 30 seconds
        for i in range(5):
            d.record_login("carol", "10.0.0.1", timestamp=now - 30 + i * 5)
        result = d.record_login("carol", "10.0.0.1", timestamp=now)
        assert result["detected"] is True
        assert any("login_velocity" in s for s in result["signals"])

    def test_subnet_change_detected(self):
        d = ImpossibleTravelDetector()
        now = time.time()
        d.record_login("dave", "185.1.1.1", timestamp=now - 60)
        result = d.record_login("dave", "185.2.2.2", timestamp=now)
        assert result["detected"] is True
        assert any("subnet_change" in s for s in result["signals"])

    def test_first_login_not_detected(self):
        d = ImpossibleTravelDetector()
        result = d.record_login("new_user", "10.0.0.1")
        assert result["detected"] is False

    def test_technique_tag(self):
        d = ImpossibleTravelDetector()
        result = d.record_login("u", "10.0.0.1")
        assert result["technique"] == "T1078"
        assert result["fix"] == "FIX-17"

    def test_internal_ip_no_geo_anomaly(self):
        d = ImpossibleTravelDetector()
        now = time.time()
        d.record_login("eve", "10.0.0.1", timestamp=now - 60)
        result = d.record_login("eve", "192.168.1.1", timestamp=now)
        # Both internal — no impossible travel
        assert not any("impossible_travel" in s for s in result["signals"])

    def test_fix17_registered(self):
        assert "FIX-17" in NEXTGEN_FIXES
        assert "ImpossibleTravelDetector" in NEXTGEN_FIXES["FIX-17"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-18: AdaptiveBeaconDetector
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdaptiveBeaconDetector:

    def test_long_window_beacon_detected(self):
        a = AdaptiveBeaconDetector()
        now = time.time()
        # 8 connections over 24h with regular 3-hour intervals
        for i in range(8):
            a.record_session("185.1.1.1", now - (7 - i) * 10800)
        result = a.analyze("185.1.1.1")
        assert result["detected"] is True
        assert any("beacon" in s for s in result["signals"])

    def test_cumulative_exfil_detected(self):
        a = AdaptiveBeaconDetector()
        now = time.time()
        # 60 MB total across 10 sessions
        for i in range(10):
            a.record_session("185.2.2.2", now - i * 3600,
                             bytes_sent=6 * 1024 * 1024)
        result = a.analyze("185.2.2.2")
        assert result["detected"] is True
        assert any("cumulative_exfil" in s for s in result["signals"])
        assert result["total_bytes_mb"] >= 50.0

    def test_known_bad_ja3_detected(self):
        a = AdaptiveBeaconDetector()
        now = time.time()
        a.record_session("185.3.3.3", now,
                         ja3="51c64c77e60f3980eea90869b68c58a8")
        result = a.analyze("185.3.3.3")
        assert result["detected"] is True
        assert any("known_bad_ja3" in s for s in result["signals"])

    def test_clean_traffic_not_detected(self):
        a = AdaptiveBeaconDetector()
        now = time.time()
        # 2 sessions, small volume, no bad JA3
        a.record_session("10.0.0.1", now - 3600, bytes_sent=1000)
        a.record_session("10.0.0.1", now, bytes_sent=1000)
        result = a.analyze("10.0.0.1")
        assert result["detected"] is False

    def test_new_domain_flagged(self):
        result = AdaptiveBeaconDetector.analyze_domain_reputation(
            "evil-update.com", domain_age_days=5
        )
        assert result["detected"] is True
        assert any("new_domain" in s for s in result["signals"])

    def test_lookalike_domain_flagged(self):
        result = AdaptiveBeaconDetector.analyze_domain_reputation(
            "login-verify.attacker.com", domain_age_days=365
        )
        assert result["detected"] is True
        assert any("lookalike" in s for s in result["signals"])

    def test_excessive_subdomains_flagged(self):
        result = AdaptiveBeaconDetector.analyze_domain_reputation(
            "a.b.c.d.e.evil.com", domain_age_days=365
        )
        assert result["detected"] is True
        assert any("excessive_subdomains" in s for s in result["signals"])

    def test_long_subdomain_label_flagged(self):
        long_label = "a" * 35
        result = AdaptiveBeaconDetector.analyze_domain_reputation(
            f"{long_label}.evil.com", domain_age_days=365
        )
        assert result["detected"] is True
        assert any("long_subdomain" in s for s in result["signals"])

    def test_legitimate_domain_clean(self):
        result = AdaptiveBeaconDetector.analyze_domain_reputation(
            "google.com", domain_age_days=9000
        )
        assert result["detected"] is False

    def test_fix18_registered(self):
        assert "FIX-18" in NEXTGEN_FIXES
        assert "AdaptiveBeaconDetector" in NEXTGEN_FIXES["FIX-18"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-19: HardenedCredDumpDetector
# ═══════════════════════════════════════════════════════════════════════════════

class TestHardenedCredDumpDetector:

    def test_novel_access_mask_now_detected(self):
        """FIX-19a: 0x0400 is now in the expanded mask set."""
        d = HardenedCredDumpDetector()
        d.record_event("powershell.exe", "lsass.exe", granted_access=0x0400)
        result = d.evaluate()
        assert result["detected"] is True
        assert any("suspicious_access_mask" in s for s in result["signals"])

    def test_taskmgr_lotl_now_detected(self):
        """FIX-19b: taskmgr.exe is now in the expanded LOTL list."""
        d = HardenedCredDumpDetector()
        d.record_event("taskmgr.exe", "lsass.exe", granted_access=0x0400)
        result = d.evaluate()
        assert result["detected"] is True
        assert any("dump_tool" in s for s in result["signals"])

    def test_registry_hive_dump_now_detected(self):
        """FIX-19c: SAM/SYSTEM registry hive dump now detected."""
        d = HardenedCredDumpDetector()
        d.record_event("reg.exe", "hklm\\sam", granted_access=0x0001)
        result = d.evaluate()
        assert result["detected"] is True
        assert any("registry_hive_dump" in s for s in result["signals"])

    def test_ntds_dit_detected(self):
        d = HardenedCredDumpDetector()
        d.record_event("ntdsutil.exe", "ntds.dit", granted_access=0x0001)
        result = d.evaluate()
        assert result["detected"] is True

    def test_slow_dump_now_detected(self):
        """FIX-19d: Extended 300s window catches slow dumps."""
        d = HardenedCredDumpDetector()
        now = time.time()
        # Events spaced 90s apart — within 300s window
        d.record_event("powershell.exe", "lsass.exe", granted_access=0x1010,
                       timestamp=now - 250)
        d.record_event("powershell.exe", "lsass.exe", granted_access=0x1010,
                       timestamp=now - 160)
        d.record_event("powershell.exe", "lsass.exe", granted_access=0x1010,
                       timestamp=now - 70)
        result = d.evaluate()
        assert result["detected"] is True
        assert any("high_volume" in s for s in result["signals"])

    def test_non_system_lsass_access_detected(self):
        """FIX-19e: Any non-system process accessing LSASS is flagged."""
        d = HardenedCredDumpDetector()
        d.record_event("svchost32.exe", "lsass.exe", granted_access=0x0400)
        result = d.evaluate()
        assert result["detected"] is True
        assert any("non_system_lsass" in s for s in result["signals"])

    def test_dcsync_detected(self):
        """FIX-19f: DCSync privilege use detected."""
        d = HardenedCredDumpDetector()
        d.record_dcsync("CORP\\attacker", "DS-Replication-Get-Changes-All")
        result = d.evaluate()
        assert result["detected"] is True
        assert any("dcsync" in s for s in result["signals"])

    def test_renamed_tool_now_detected(self):
        """FIX-19e: Renamed tool caught by non-system LSASS access signal."""
        d = HardenedCredDumpDetector()
        d.record_event("svchost32.exe", "lsass.exe", granted_access=0x1010)
        result = d.evaluate()
        assert result["detected"] is True

    def test_system_process_lsass_not_flagged(self):
        """Legitimate system processes accessing LSASS should not trigger non_system signal."""
        d = HardenedCredDumpDetector()
        d.record_event("lsass.exe", "lsass.exe", granted_access=0x0001)
        result = d.evaluate()
        # lsass.exe is in SYSTEM_LSASS_ACCESSORS — non_system signal should not fire
        assert not any("non_system_lsass" in s for s in result["signals"])

    def test_fix19_registered(self):
        assert "FIX-19" in NEXTGEN_FIXES
        assert "HardenedCredDumpDetector" in NEXTGEN_FIXES["FIX-19"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-20: AdvancedSessionGuard
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdvancedSessionGuard:

    def test_slow_ip_change_now_detected(self):
        """FIX-20a: 24h window catches IP changes after 300s."""
        d = AdvancedSessionGuard()
        now = time.time()
        d.record_session("tok_slow", "10.0.0.1", "Mozilla/5.0",
                         timestamp=now - 7200)  # 2 hours ago
        result = d.record_session("tok_slow", "185.220.101.5", "Mozilla/5.0",
                                   timestamp=now)
        assert result["detected"] is True
        assert any("ip_change_24h" in s for s in result["signals"])

    def test_geo_anomaly_detected(self):
        """FIX-20b: Country-level IP change detected."""
        d = AdvancedSessionGuard()
        now = time.time()
        d.record_session("tok_geo", "185.1.1.1", "Mozilla/5.0",
                         timestamp=now - 600)  # EU
        result = d.record_session("tok_geo", "91.1.1.1", "Mozilla/5.0",
                                   timestamp=now)  # RU
        assert result["detected"] is True
        assert any("geo_anomaly" in s for s in result["signals"])

    def test_concurrent_sessions_detected(self):
        """FIX-20c: Same token active from 2 IPs simultaneously."""
        d = AdvancedSessionGuard()
        now = time.time()
        d.record_session("tok_concurrent", "10.0.0.1", "Mozilla/5.0",
                         timestamp=now - 60)
        result = d.record_session("tok_concurrent", "185.220.101.5", "Mozilla/5.0",
                                   timestamp=now)
        assert result["detected"] is True
        assert any("concurrent" in s for s in result["signals"])

    def test_arp_rate_limit_detected(self):
        """FIX-20d: Multiple MAC changes in 1 hour flagged."""
        d = AdvancedSessionGuard()
        now = time.time()
        d.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff", timestamp=now - 1800)
        d.record_arp("192.168.1.1", "11:22:33:44:55:66", timestamp=now - 900)
        result = d.record_arp("192.168.1.1", "77:88:99:aa:bb:cc", timestamp=now)
        assert result["detected"] is True
        assert any("arp_rate" in s for s in result["signals"])

    def test_normal_session_not_detected(self):
        d = AdvancedSessionGuard()
        now = time.time()
        d.record_session("tok_normal", "10.0.0.1", "Mozilla/5.0",
                         timestamp=now - 3600)
        result = d.record_session("tok_normal", "10.0.0.1", "Mozilla/5.0",
                                   timestamp=now)
        assert result["detected"] is False

    def test_new_session_not_detected(self):
        d = AdvancedSessionGuard()
        result = d.record_session("tok_new", "10.0.0.1", "Mozilla/5.0")
        assert result["detected"] is False

    def test_arp_same_mac_not_detected(self):
        d = AdvancedSessionGuard()
        d.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        result = d.record_arp("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        assert result["detected"] is False

    def test_technique_tags(self):
        d = AdvancedSessionGuard()
        r1 = d.record_session("t", "10.0.0.1", "ua")
        r2 = d.record_arp("1.2.3.4", "aa:bb:cc:dd:ee:ff")
        assert r1["technique"] == "T1539"
        assert r2["technique"] == "T1557"

    def test_fix20_registered(self):
        assert "FIX-20" in NEXTGEN_FIXES
        assert "AdvancedSessionGuard" in NEXTGEN_FIXES["FIX-20"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# FIX-21: AttachmentDeepInspector
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttachmentDeepInspector:

    def test_lnk_file_detected(self):
        """FIX-21a: LNK shortcut now flagged."""
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("Q4_Report.pdf.lnk", "application/octet-stream")
        assert result["detected"] is True
        assert any("suspicious_extension" in s for s in result["signals"])

    def test_iso_container_detected(self):
        """FIX-21a: ISO container now flagged."""
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("invoice.iso", "application/octet-stream")
        assert result["detected"] is True
        assert any("suspicious_extension" in s for s in result["signals"])

    def test_one_file_detected(self):
        """FIX-21a: OneNote .one file now flagged."""
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("notes.one", "application/onenote")
        assert result["detected"] is True

    def test_dde_in_docx_detected(self):
        """FIX-21b: DDE field code in .docx XML content detected."""
        e = AttachmentDeepInspector()
        dde_content = '<w:instrText>DDE cmd.exe /c powershell</w:instrText>'
        result = e.analyze_attachment(
            "report.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            content_sample=dde_content,
        )
        assert result["detected"] is True
        assert any("dde_field" in s for s in result["signals"])

    def test_html_smuggling_detected(self):
        """FIX-21c: Large base64 blob in HTML attachment detected."""
        e = AttachmentDeepInspector()
        # Generate a large base64-like blob
        big_b64 = "A" * 15000
        html_content = f'<script>var x="{big_b64}";</script>'
        result = e.analyze_attachment("statement.html", "text/html",
                                       content_sample=html_content)
        assert result["detected"] is True
        assert any("html_smuggling" in s for s in result["signals"])

    def test_clean_pdf_not_detected(self):
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("report.pdf", "application/pdf")
        assert result["detected"] is False
        assert result["verdict"] == "CLEAN"

    def test_indirect_execution_chain_detected(self):
        """FIX-21d: Office → explorer → powershell indirect chain detected."""
        e = AttachmentDeepInspector()
        now = time.time()
        e.record_office_open("report.docm", timestamp=now - 30)
        # Build process tree: winword(1) → explorer(2) → powershell(3)
        e.record_process(1, 0, "winword.exe", timestamp=now - 30)
        e.record_process(2, 1, "explorer.exe", timestamp=now - 20)
        e.record_process(3, 2, "powershell.exe", timestamp=now - 10)
        result = e.analyze_process_chain(3, timestamp=now)
        assert result["detected"] is True
        assert any("indirect" in s for s in result["signals"])

    def test_hta_file_detected(self):
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("update.hta", "application/octet-stream")
        assert result["detected"] is True

    def test_ps1_file_detected(self):
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("setup.ps1", "text/plain")
        assert result["detected"] is True

    def test_technique_tag(self):
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("x.lnk", "application/octet-stream")
        assert result["technique"] == "T1566.001"
        assert result["fix"] == "FIX-21"

    def test_fix21_registered(self):
        assert "FIX-21" in NEXTGEN_FIXES
        assert "AttachmentDeepInspector" in NEXTGEN_FIXES["FIX-21"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: re-run zero-day bypass variants against next-gen detectors
# ═══════════════════════════════════════════════════════════════════════════════

class TestZeroDayBypassesClosed:
    """Verify that the specific bypass variants from the simulation are now caught."""

    def test_fix17_closes_business_hours_bypass(self):
        """V1 bypass: business hours + new IP — now caught by subnet_change."""
        d = ImpossibleTravelDetector()
        now = time.time()
        d.record_login("alice", "185.1.1.1", timestamp=now - 3600)
        result = d.record_login("alice", "185.2.2.2", timestamp=now)
        # Subnet change: 185.1.x → 185.2.x
        assert result["detected"] is True

    def test_fix19_closes_novel_mask_bypass(self):
        """V1 bypass: 0x0400 mask — now in expanded set."""
        d = HardenedCredDumpDetector()
        d.record_event("powershell.exe", "lsass.exe", granted_access=0x0400)
        result = d.evaluate()
        assert result["detected"] is True

    def test_fix19_closes_registry_hive_bypass(self):
        """V3 bypass: SAM registry dump — now detected."""
        d = HardenedCredDumpDetector()
        d.record_event("reg.exe", "hklm\\sam", granted_access=0x0001)
        result = d.evaluate()
        assert result["detected"] is True

    def test_fix19_closes_renamed_tool_bypass(self):
        """V5 bypass: renamed mimikatz — caught by non_system_lsass signal."""
        d = HardenedCredDumpDetector()
        d.record_event("svchost32.exe", "lsass.exe", granted_access=0x0400)
        result = d.evaluate()
        assert result["detected"] is True

    def test_fix20_closes_slow_ip_change_bypass(self):
        """V1 bypass: IP change after 400s — now caught by 24h window."""
        d = AdvancedSessionGuard()
        now = time.time()
        d.record_session("tok_slow", "10.0.0.1", "Mozilla/5.0",
                         timestamp=now - 7200)
        result = d.record_session("tok_slow", "185.220.101.5", "Mozilla/5.0",
                                   timestamp=now)
        assert result["detected"] is True

    def test_fix21_closes_lnk_bypass(self):
        """V2 bypass: LNK shortcut — now detected."""
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("Q4_Report.pdf.lnk", "application/octet-stream")
        assert result["detected"] is True

    def test_fix21_closes_iso_bypass(self):
        """V3 bypass: ISO container — now detected."""
        e = AttachmentDeepInspector()
        result = e.analyze_attachment("invoice.iso", "application/octet-stream")
        assert result["detected"] is True

    def test_fix21_closes_html_smuggling_bypass(self):
        """V4 bypass: HTML smuggling — now detected."""
        e = AttachmentDeepInspector()
        big_b64 = "B" * 15000
        html = f'<script>var payload="{big_b64}";</script>'
        result = e.analyze_attachment("statement.html", "text/html",
                                       content_sample=html)
        assert result["detected"] is True

    def test_fix21_closes_indirect_execution_bypass(self):
        """V6 bypass: Office → explorer → powershell — now detected."""
        e = AttachmentDeepInspector()
        now = time.time()
        e.record_office_open("report.docm", timestamp=now - 30)
        e.record_process(10, 0,  "winword.exe",   timestamp=now - 30)
        e.record_process(11, 10, "explorer.exe",  timestamp=now - 20)
        e.record_process(12, 11, "powershell.exe", timestamp=now - 10)
        result = e.analyze_process_chain(12, timestamp=now)
        assert result["detected"] is True

    def test_fix18_closes_cumulative_exfil_bypass(self):
        """V4 bypass: slow drip exfil — now caught by cumulative tracking."""
        a = AdaptiveBeaconDetector()
        now = time.time()
        # 10 sessions × 6MB = 60MB total (above 50MB threshold)
        for i in range(10):
            a.record_session("185.3.3.3", now - i * 3600,
                             bytes_sent=6 * 1024 * 1024)
        result = a.analyze("185.3.3.3")
        assert result["detected"] is True
        assert any("cumulative_exfil" in s for s in result["signals"])