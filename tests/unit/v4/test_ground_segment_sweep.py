"""
Tests for shadow313.v4.satellite.ground_segment_sweep

Covers all 5 sweep phases, finding classification, 313 binding,
scan profiles, and the full sweep pipeline.
"""
from __future__ import annotations

import pytest
from shadow313.v4.satellite.ground_segment_sweep import (
    GroundSegmentSweep, SweepFinding, SweepResult,
    run_ground_segment_sweep,
    SCAN_PROFILES, KNOWN_CVES,
    SNR_CRITICAL_THRESHOLD_DB, CLOCK_SKEW_CRITICAL_HZ,
    QBER_WARNING_THRESHOLD, QBER_ATTACK_THRESHOLD,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def default_result():
    """Run the default DEEP sweep (matches AEGIS NEXUS UI output)."""
    return run_ground_segment_sweep(verbose=False)


@pytest.fixture
def secure_result():
    """Run a sweep against a hardened station (all controls enabled)."""
    return run_ground_segment_sweep(
        firmware_signed=True,
        uart_authenticated=True,
        cwmp_mutual_tls=True,
        snr_db=25.0,
        clock_skew_hz=2.0,
        open_ports={
            "192.168.100.1":  [22, 443, 161],
            "192.168.100.15": [22, 443],
        },
        verbose=False,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Scan profiles
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanProfiles:

    def test_deep_profile_has_all_phases(self):
        assert SCAN_PROFILES["DEEP"]["phases"] == [0, 1, 2, 3, 4, 5]

    def test_quick_profile_has_fewer_phases(self):
        assert len(SCAN_PROFILES["QUICK"]["phases"]) < len(SCAN_PROFILES["DEEP"]["phases"])

    def test_standard_profile_excludes_hardware(self):
        assert 4 not in SCAN_PROFILES["STANDARD"]["phases"]

    def test_all_profiles_have_required_keys(self):
        for name, cfg in SCAN_PROFILES.items():
            assert "ports" in cfg
            assert "phases" in cfg
            assert "description" in cfg


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 0: Network Discovery
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase0Discovery:

    def test_two_hosts_discovered(self, default_result):
        assert len(default_result.hosts_found) == 2

    def test_host_ips_correct(self, default_result):
        ips = [h["ip"] for h in default_result.hosts_found]
        assert "192.168.100.1" in ips
        assert "192.168.100.15" in ips

    def test_host_descriptions_present(self, default_result):
        for h in default_result.hosts_found:
            assert "description" in h
            assert len(h["description"]) > 5

    def test_log_contains_discovery_phase(self, default_result):
        assert any("PHASE 0" in line for line in default_result.log_lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: Port Probing
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase1PortProbing:

    def test_ftp_finding_created(self, default_result):
        ftp_findings = [f for f in default_result.findings if "FTP" in f.finding]
        assert len(ftp_findings) >= 1

    def test_telnet_finding_created(self, default_result):
        telnet_findings = [f for f in default_result.findings if "Telnet" in f.finding]
        assert len(telnet_findings) >= 1

    def test_http_finding_created(self, default_result):
        http_findings = [f for f in default_result.findings if "HTTP Admin" in f.finding]
        assert len(http_findings) >= 1

    def test_ftp_is_critical(self, default_result):
        ftp = next(f for f in default_result.findings if "FTP" in f.finding)
        assert ftp.severity == "CRITICAL"

    def test_telnet_is_critical(self, default_result):
        telnet = next(f for f in default_result.findings if "Telnet" in f.finding)
        assert telnet.severity == "CRITICAL"

    def test_http_is_critical(self, default_result):
        http = next(f for f in default_result.findings if "HTTP Admin" in f.finding)
        assert http.severity == "CRITICAL"

    def test_ftp_remediation_mentions_sftp(self, default_result):
        ftp = next(f for f in default_result.findings if "FTP" in f.finding)
        assert "SFTP" in ftp.remediation or "sftp" in ftp.remediation.lower()

    def test_telnet_remediation_mentions_ssh(self, default_result):
        telnet = next(f for f in default_result.findings if "Telnet" in f.finding)
        assert "SSH" in telnet.remediation

    def test_snmp_not_a_finding_when_v3(self, default_result):
        snmp_findings = [f for f in default_result.findings if "SNMP" in f.finding]
        assert len(snmp_findings) == 0

    def test_log_contains_phase1(self, default_result):
        assert any("PHASE 1" in line for line in default_result.log_lines)

    def test_secure_station_no_port_findings(self, secure_result):
        port_findings = [f for f in secure_result.findings
                         if f.phase == 1]
        assert len(port_findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: TR-069 CWMP
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase2CWMP:

    def test_cwmp_finding_created(self, default_result):
        cwmp = [f for f in default_result.findings if "TR-069" in f.finding or "CWMP" in f.finding]
        assert len(cwmp) >= 1

    def test_cwmp_finding_is_critical(self, default_result):
        cwmp = next(f for f in default_result.findings if "CWMP" in f.finding)
        assert cwmp.severity == "CRITICAL"

    def test_cwmp_has_cve(self, default_result):
        cwmp = next(f for f in default_result.findings if "CWMP" in f.finding)
        assert cwmp.cve == "CVE-2026-3392"

    def test_cwmp_remediation_mentions_tls(self, default_result):
        cwmp = next(f for f in default_result.findings if "CWMP" in f.finding)
        assert "TLS" in cwmp.remediation or "tls" in cwmp.remediation.lower()

    def test_cwmp_secure_no_finding(self, secure_result):
        cwmp = [f for f in secure_result.findings if "CWMP" in f.finding]
        assert len(cwmp) == 0

    def test_log_contains_phase2(self, default_result):
        assert any("PHASE 2" in line for line in default_result.log_lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Firmware / Crypto Audit
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase3Firmware:

    def test_unsigned_firmware_finding(self, default_result):
        fw = [f for f in default_result.findings if "Firmware" in f.finding]
        assert len(fw) >= 1

    def test_firmware_finding_is_critical(self, default_result):
        fw = next(f for f in default_result.findings if "Firmware" in f.finding)
        assert fw.severity == "CRITICAL"

    def test_firmware_has_cve(self, default_result):
        fw = next(f for f in default_result.findings if "Firmware" in f.finding)
        assert fw.cve is not None

    def test_signed_firmware_no_finding(self, secure_result):
        fw = [f for f in secure_result.findings if "Firmware" in f.finding]
        assert len(fw) == 0

    def test_log_contains_device_hash(self, default_result):
        assert any("Device Hash" in line for line in default_result.log_lines)

    def test_log_contains_phase3(self, default_result):
        assert any("PHASE 3" in line for line in default_result.log_lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Hardware Debug (UART/JTAG)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase4Hardware:

    def test_uart_finding_created(self, default_result):
        uart = [f for f in default_result.findings if "UART" in f.finding]
        assert len(uart) >= 1

    def test_uart_finding_is_critical(self, default_result):
        uart = next(f for f in default_result.findings if "UART" in f.finding)
        assert uart.severity == "CRITICAL"

    def test_uart_remediation_mentions_physical(self, default_result):
        uart = next(f for f in default_result.findings if "UART" in f.finding)
        assert "secure" in uart.remediation.lower() or "physical" in uart.remediation.lower()

    def test_authenticated_uart_no_finding(self, secure_result):
        uart = [f for f in secure_result.findings if "UART" in f.finding]
        assert len(uart) == 0

    def test_log_contains_phase4(self, default_result):
        assert any("PHASE 4" in line for line in default_result.log_lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5: RF Telemetry
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase5RF:

    def test_rf_finding_created_when_snr_low(self, default_result):
        rf = [f for f in default_result.findings if "SNR" in f.finding]
        assert len(rf) >= 1

    def test_rf_finding_is_high(self, default_result):
        rf = next(f for f in default_result.findings if "SNR" in f.finding)
        assert rf.severity == "HIGH"

    def test_rf_finding_host_is_rf_link(self, default_result):
        rf = next(f for f in default_result.findings if "SNR" in f.finding)
        assert rf.host == "RF Link"

    def test_rf_remediation_mentions_gps(self, default_result):
        rf = next(f for f in default_result.findings if "SNR" in f.finding)
        assert "GPS" in rf.remediation or "NTP" in rf.remediation

    def test_good_snr_no_rf_finding(self, secure_result):
        rf = [f for f in secure_result.findings if "SNR" in f.finding]
        assert len(rf) == 0

    def test_snr_threshold_constant(self):
        assert SNR_CRITICAL_THRESHOLD_DB == 8.0

    def test_clock_skew_threshold_constant(self):
        assert CLOCK_SKEW_CRITICAL_HZ == 10.0

    def test_log_contains_phase5(self, default_result):
        assert any("PHASE 5" in line for line in default_result.log_lines)

    def test_snr_value_in_finding(self, default_result):
        rf = next(f for f in default_result.findings if "SNR" in f.finding)
        assert "5.9" in rf.finding

    def test_clock_skew_value_in_finding(self, default_result):
        rf = next(f for f in default_result.findings if "SNR" in f.finding)
        assert "55.1" in rf.finding


# ═══════════════════════════════════════════════════════════════════════════════
# 313 Temporal Binding
# ═══════════════════════════════════════════════════════════════════════════════

class TestTemporalBinding:

    def test_all_findings_have_bind_id(self, default_result):
        for f in default_result.findings:
            assert f.bind_id.startswith("313-GS-")

    def test_bind_ids_are_sequential(self, default_result):
        for i, f in enumerate(default_result.findings, 1):
            assert f.bind_id == f"313-GS-{i:08d}"

    def test_all_findings_have_chain_hash(self, default_result):
        for f in default_result.findings:
            assert len(f.chain_hash) == 64  # SHA3-256 hex

    def test_chain_hashes_are_unique(self, default_result):
        hashes = [f.chain_hash for f in default_result.findings]
        assert len(set(hashes)) == len(hashes)

    def test_bind_count_matches_findings(self, default_result):
        assert default_result.bind_count == len(default_result.findings)


# ═══════════════════════════════════════════════════════════════════════════════
# SweepResult properties
# ═══════════════════════════════════════════════════════════════════════════════

class TestSweepResult:

    def test_critical_count_correct(self, default_result):
        expected = sum(1 for f in default_result.findings if f.severity == "CRITICAL")
        assert default_result.critical_count == expected

    def test_high_count_correct(self, default_result):
        expected = sum(1 for f in default_result.findings if f.severity == "HIGH")
        assert default_result.high_count == expected

    def test_to_dict_has_required_keys(self, default_result):
        d = default_result.to_dict()
        for key in ("target_subnet", "profile", "scan_start", "scan_end",
                    "hosts_found", "open_ports", "findings",
                    "critical_count", "high_count", "bind_count", "chain_valid"):
            assert key in d

    def test_scan_end_is_set(self, default_result):
        assert default_result.scan_end != ""

    def test_target_subnet_preserved(self, default_result):
        assert default_result.target_subnet == "192.168.100.1/24"

    def test_profile_preserved(self, default_result):
        assert default_result.profile == "DEEP"

    def test_secure_station_has_zero_critical(self, secure_result):
        assert secure_result.critical_count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Findings table formatting
# ═══════════════════════════════════════════════════════════════════════════════

class TestFindingsTable:

    def test_table_contains_all_findings(self, default_result):
        sweep = GroundSegmentSweep()
        table = sweep.format_findings_table(default_result)
        for f in default_result.findings:
            assert f.severity in table

    def test_table_has_header(self, default_result):
        sweep = GroundSegmentSweep()
        table = sweep.format_findings_table(default_result)
        assert "Severity" in table
        assert "Finding" in table
        assert "Remediation" in table


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 6: QKD BB84 QBER
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase6QKD:

    def test_qber_attack_creates_critical_finding(self):
        result = run_ground_segment_sweep(qber_percent=40.0, verbose=False)
        qkd = [f for f in result.findings if "QKD" in f.finding]
        assert len(qkd) == 1
        assert qkd[0].severity == "CRITICAL"

    def test_qber_attack_finding_text(self):
        result = run_ground_segment_sweep(qber_percent=40.0, verbose=False)
        qkd = next(f for f in result.findings if "QKD" in f.finding)
        assert "eavesdropper" in qkd.finding.lower() or "key dropped" in qkd.finding.lower()

    def test_qber_warning_creates_high_finding(self):
        result = run_ground_segment_sweep(qber_percent=9.5, verbose=False)
        qkd = [f for f in result.findings if "QKD" in f.finding]
        assert len(qkd) == 1
        assert qkd[0].severity == "HIGH"

    def test_qber_secure_no_finding(self):
        result = run_ground_segment_sweep(qber_percent=2.0, verbose=False)
        qkd = [f for f in result.findings if "QKD" in f.finding]
        assert len(qkd) == 0

    def test_qber_none_no_finding(self, default_result):
        qkd = [f for f in default_result.findings if "QKD" in f.finding]
        assert len(qkd) == 0

    def test_qber_finding_host_is_qkd_channel(self):
        result = run_ground_segment_sweep(qber_percent=40.0, verbose=False)
        qkd = next(f for f in result.findings if "QKD" in f.finding)
        assert qkd.host == "QKD Channel"

    def test_qber_finding_remediation_mentions_terminate(self):
        result = run_ground_segment_sweep(qber_percent=40.0, verbose=False)
        qkd = next(f for f in result.findings if "QKD" in f.finding)
        assert "Terminate" in qkd.remediation or "terminate" in qkd.remediation.lower()

    def test_qber_finding_is_313_bound(self):
        result = run_ground_segment_sweep(qber_percent=40.0, verbose=False)
        qkd = next(f for f in result.findings if "QKD" in f.finding)
        assert qkd.bind_id.startswith("313-GS-")
        assert len(qkd.chain_hash) == 64

    def test_qber_threshold_constants(self):
        assert QBER_WARNING_THRESHOLD == 8.0
        assert QBER_ATTACK_THRESHOLD == 11.0

    def test_aegis_nexus_scenario_has_8_findings(self):
        """Reproduce the exact AEGIS NEXUS dashboard scenario."""
        result = run_ground_segment_sweep(
            qber_percent=40.0,
            snr_db=5.9,
            clock_skew_hz=55.1,
            verbose=False,
        )
        # 7 original findings + 1 QKD = 8+ findings
        assert len(result.findings) >= 8
        assert result.critical_count >= 7


# ═══════════════════════════════════════════════════════════════════════════════
# Known CVEs
# ═══════════════════════════════════════════════════════════════════════════════

class TestKnownCVEs:

    def test_cve_2026_3392_present(self):
        assert "CVE-2026-3392" in KNOWN_CVES

    def test_cve_has_required_fields(self):
        for cve_id, info in KNOWN_CVES.items():
            assert "description" in info
            assert "cvss" in info
            assert "fix" in info

    def test_cwmp_cve_cvss_is_critical(self):
        assert KNOWN_CVES["CVE-2026-3392"]["cvss"] >= 9.0


# ═══════════════════════════════════════════════════════════════════════════════
# Quick and Standard profiles
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanProfileVariants:

    def test_quick_profile_runs(self):
        result = run_ground_segment_sweep(profile="QUICK", verbose=False)
        assert isinstance(result, SweepResult)

    def test_standard_profile_runs(self):
        result = run_ground_segment_sweep(profile="STANDARD", verbose=False)
        assert isinstance(result, SweepResult)

    def test_quick_profile_no_hardware_phase(self):
        result = run_ground_segment_sweep(profile="QUICK", verbose=False)
        uart_findings = [f for f in result.findings if "UART" in f.finding]
        assert len(uart_findings) == 0

    def test_deep_profile_has_hardware_phase(self, default_result):
        uart_findings = [f for f in default_result.findings if "UART" in f.finding]
        assert len(uart_findings) >= 1