"""
Tests for shadow313.v4.satellite.cwmp_hardening

Covers CVE-2026-3392 mitigation: ACS allowlist, mutual TLS,
firmware signing, iptables rules, Sigma rules, and rogue ACS detection.
"""
from __future__ import annotations

import pytest
from shadow313.v4.satellite.cwmp_hardening import (
    CWMPHardener, CWMPConfig, CWMPHardeningResult,
    generate_iptables_rules, generate_sigma_rules,
    run_cwmp_hardening_assessment,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def vulnerable_config():
    return CWMPConfig(
        host_ip="192.168.100.1",
        cwmp_port=7547,
        acs_url="http://acs.provider.net:7547/",
        acs_allowed_ips=[],
        mutual_tls=False,
        cert_pinning=False,
        firmware_signed=False,
        firmware_algo="none",
        connection_request_auth=False,
        tr369_capable=False,
    )

@pytest.fixture
def hardened_config():
    return CWMPConfig(
        host_ip="192.168.100.1",
        cwmp_port=7547,
        acs_url="https://acs.provider.net:7547/",
        acs_allowed_ips=["10.0.0.1", "10.0.0.2"],
        mutual_tls=True,
        cert_pinning=True,
        firmware_signed=True,
        firmware_algo="SLH-DSA-SHA2-128f",
        connection_request_auth=True,
        tr369_capable=True,
    )

@pytest.fixture
def hardener():
    return CWMPHardener()


# ═══════════════════════════════════════════════════════════════════════════════
# ACS Allowlist
# ═══════════════════════════════════════════════════════════════════════════════

class TestACSAllowlist:

    def test_empty_allowlist_fails_critical(self, hardener, vulnerable_config):
        r = hardener.check_acs_allowlist(vulnerable_config)
        assert r.passed is False
        assert r.severity == "CRITICAL"

    def test_configured_allowlist_passes(self, hardener, hardened_config):
        r = hardener.check_acs_allowlist(hardened_config)
        assert r.passed is True

    def test_is_acs_allowed_exact_ip(self, hardener):
        assert hardener.is_acs_allowed("10.0.0.1", ["10.0.0.1"]) is True

    def test_is_acs_allowed_cidr(self, hardener):
        assert hardener.is_acs_allowed("10.0.0.50", ["10.0.0.0/24"]) is True

    def test_is_acs_allowed_rejects_unknown(self, hardener):
        assert hardener.is_acs_allowed("185.220.101.5", ["10.0.0.0/8"]) is False

    def test_is_acs_allowed_private_ranges(self, hardener):
        assert hardener.is_acs_allowed("192.168.1.100", ["192.168.0.0/16"]) is True

    def test_detect_rogue_acs_external_ip(self, hardener):
        result = hardener.detect_rogue_acs("185.220.101.5", ["10.0.0.0/8"])
        assert result["alert"] == "ROGUE_ACS_DETECTED"
        assert result["severity"] == "CRITICAL"
        assert result["action"] == "BLOCK"
        assert result["cve"] == "CVE-2026-3392"

    def test_detect_rogue_acs_known_ip(self, hardener):
        result = hardener.detect_rogue_acs("10.0.0.1", ["10.0.0.0/8"])
        assert result["alert"] == "NONE"
        assert result["action"] == "ALLOW"


# ═══════════════════════════════════════════════════════════════════════════════
# Mutual TLS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMutualTLS:

    def test_no_mtls_fails_critical(self, hardener, vulnerable_config):
        r = hardener.check_mutual_tls(vulnerable_config)
        assert r.passed is False
        assert r.severity == "CRITICAL"

    def test_mtls_without_pinning_fails_high(self, hardener):
        cfg = CWMPConfig(mutual_tls=True, cert_pinning=False)
        r = hardener.check_mutual_tls(cfg)
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_mtls_with_pinning_passes(self, hardener, hardened_config):
        r = hardener.check_mutual_tls(hardened_config)
        assert r.passed is True

    def test_mtls_remediation_mentions_tr369(self, hardener, vulnerable_config):
        r = hardener.check_mutual_tls(vulnerable_config)
        assert "TR-369" in r.remediation or "USP" in r.remediation


# ═══════════════════════════════════════════════════════════════════════════════
# Firmware Signing
# ═══════════════════════════════════════════════════════════════════════════════

class TestFirmwareSigning:

    def test_unsigned_firmware_fails_critical(self, hardener, vulnerable_config):
        r = hardener.check_firmware_signing(vulnerable_config)
        assert r.passed is False
        assert r.severity == "CRITICAL"

    def test_rsa2048_firmware_fails_high(self, hardener):
        cfg = CWMPConfig(firmware_signed=True, firmware_algo="RSA-2048")
        r = hardener.check_firmware_signing(cfg)
        assert r.passed is False
        assert r.severity == "HIGH"
        assert "HNDL" in r.detail or "Shor" in r.detail

    def test_slhdsa_firmware_passes(self, hardener, hardened_config):
        r = hardener.check_firmware_signing(hardened_config)
        assert r.passed is True

    def test_firmware_remediation_mentions_pqc(self, hardener, vulnerable_config):
        r = hardener.check_firmware_signing(vulnerable_config)
        assert "SLH-DSA" in r.remediation or "FIPS 205" in r.remediation

    def test_unsigned_firmware_has_cve(self, hardener, vulnerable_config):
        r = hardener.check_firmware_signing(vulnerable_config)
        assert r.cve is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Connection Request Auth
# ═══════════════════════════════════════════════════════════════════════════════

class TestConnectionRequestAuth:

    def test_no_auth_fails_high(self, hardener, vulnerable_config):
        r = hardener.check_connection_request_auth(vulnerable_config)
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_auth_enabled_passes(self, hardener, hardened_config):
        r = hardener.check_connection_request_auth(hardened_config)
        assert r.passed is True


# ═══════════════════════════════════════════════════════════════════════════════
# TR-369 Readiness
# ═══════════════════════════════════════════════════════════════════════════════

class TestTR369Readiness:

    def test_not_capable_fails_medium(self, hardener, vulnerable_config):
        r = hardener.check_tr369_readiness(vulnerable_config)
        assert r.passed is False
        assert r.severity == "MEDIUM"

    def test_capable_passes(self, hardener, hardened_config):
        r = hardener.check_tr369_readiness(hardened_config)
        assert r.passed is True


# ═══════════════════════════════════════════════════════════════════════════════
# Run all checks
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunAllChecks:

    def test_vulnerable_config_all_fail(self, hardener, vulnerable_config):
        checks = hardener.run_all_checks(vulnerable_config)
        assert len(checks) == 5
        failed = [c for c in checks if not c.passed]
        assert len(failed) >= 4  # at least 4 failures for fully vulnerable config

    def test_hardened_config_all_pass(self, hardener, hardened_config):
        checks = hardener.run_all_checks(hardened_config)
        passed = [c for c in checks if c.passed]
        assert len(passed) == 5

    def test_all_checks_have_remediation_when_failed(self, hardener, vulnerable_config):
        checks = hardener.run_all_checks(vulnerable_config)
        for c in checks:
            if not c.passed:
                assert len(c.remediation) > 10


# ═══════════════════════════════════════════════════════════════════════════════
# iptables rules
# ═══════════════════════════════════════════════════════════════════════════════

class TestIptablesRules:

    def test_rules_have_required_keys(self):
        rules = generate_iptables_rules("10.0.0.1")
        for key in ("immediate", "persistent", "verify", "rollback", "description"):
            assert key in rules

    def test_immediate_rules_contain_drop(self):
        rules = generate_iptables_rules("10.0.0.1")
        drop_rules = [r for r in rules["immediate"] if "DROP" in r]
        assert len(drop_rules) >= 2  # TCP and UDP

    def test_immediate_rules_contain_accept_for_acs(self):
        rules = generate_iptables_rules("10.0.0.1")
        accept_rules = [r for r in rules["immediate"] if "ACCEPT" in r and "10.0.0.1" in r]
        assert len(accept_rules) >= 1

    def test_custom_port_in_rules(self):
        rules = generate_iptables_rules("10.0.0.1", cwmp_port=8080)
        assert any("8080" in r for r in rules["immediate"])

    def test_rollback_rules_present(self):
        rules = generate_iptables_rules("10.0.0.1")
        assert len(rules["rollback"]) >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# Sigma rules
# ═══════════════════════════════════════════════════════════════════════════════

class TestSigmaRules:

    def test_four_sigma_rules_generated(self):
        rules = generate_sigma_rules()
        assert len(rules) >= 4

    def test_cwmp_rogue_acs_rule_present(self):
        rules = generate_sigma_rules()
        assert "cwmp_rogue_acs" in rules

    def test_cwmp_firmware_download_rule_present(self):
        rules = generate_sigma_rules()
        assert "cwmp_firmware_download" in rules

    def test_telnet_rule_present(self):
        rules = generate_sigma_rules()
        assert "telnet_cleartext" in rules

    def test_ftp_rule_present(self):
        rules = generate_sigma_rules()
        assert "ftp_anonymous" in rules

    def test_rules_contain_cve_reference(self):
        rules = generate_sigma_rules()
        assert "CVE-2026-3392" in rules["cwmp_rogue_acs"]

    def test_rules_contain_mitre_tags(self):
        rules = generate_sigma_rules()
        assert "attack.t1190" in rules["cwmp_rogue_acs"]

    def test_rules_are_valid_yaml_structure(self):
        rules = generate_sigma_rules()
        for name, rule in rules.items():
            assert "title:" in rule
            assert "detection:" in rule
            assert "level:" in rule


# ═══════════════════════════════════════════════════════════════════════════════
# Full assessment
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullAssessment:

    def test_assessment_runs_without_error(self):
        result = run_cwmp_hardening_assessment(verbose=False)
        assert "checks" in result
        assert "iptables_rules" in result
        assert "sigma_rules" in result

    def test_default_config_has_critical_failures(self):
        result = run_cwmp_hardening_assessment(verbose=False)
        assert result["critical"] >= 2

    def test_assessment_has_five_checks(self):
        result = run_cwmp_hardening_assessment(verbose=False)
        assert len(result["checks"]) == 5

    def test_hardened_config_passes_all(self):
        cfg = CWMPConfig(
            acs_allowed_ips=["10.0.0.1"],
            mutual_tls=True, cert_pinning=True,
            firmware_signed=True, firmware_algo="SLH-DSA-SHA2-128f",
            connection_request_auth=True, tr369_capable=True,
        )
        result = run_cwmp_hardening_assessment(config=cfg, verbose=False)
        assert result["failed"] == 0
        assert result["passed"] == 5