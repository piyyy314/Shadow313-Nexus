"""
Tests for shadow313.integrations.stia

Covers:
  - STIAParser: text, JSON, dict parsing
  - STIAScanResult: field mapping, derived fields, serialisation
  - STIABinder: bind_text, bind_json, bind_dict, summary
  - _SimulatedReceipt: timestamp ends in 313, hash fields present
  - report generation: HTML + JSON output
"""
from __future__ import annotations

import json
import os
import tempfile
import pytest

from shadow313.integrations.stia.parser import STIAParser, STIAScanResult
from shadow313.integrations.stia.binder import STIABinder, _SimulatedReceipt
from shadow313.integrations.stia.report import generate_stia_report


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_TEXT = """
STIA Scan Report
Target: SAT-TELSTAR-11N
Threat Profile: APT29 — Cozy Bear
Risk Level: CRITICAL
Severity: 9.2
Status: ACTIVE

CVEs Identified:
  CVE-2024-1234
  CVE-2023-5678

MITRE ATT&CK:
  Initial Access — T1190
  Lateral Movement — T1021.002
  Exfiltration — T1041

Signal Anomaly: GPS spoofing detected at 11700 MHz
SNR: 15.5 dB
Orbital Slot: 37.5W

Ghost Watch stream active
Watermark: WM-AABBCCDD1122
"""

SAMPLE_DICT = {
    "target_id":          "VSAT-GX-007",
    "target_name":        "Inmarsat GX VSAT Terminal",
    "target_type":        "vsat",
    "threat_profile":     "FIN7 — Carbanak",
    "risk_level":         "HIGH",
    "severity_score":     7.8,
    "status":             "MONITORING",
    "is_neutralized":     False,
    "cve_list":           ["CVE-2024-9999", "CVE-2023-1111"],
    "mitre_tactics":      ["Credential Access", "Lateral Movement"],
    "mitre_techniques":   ["T1003", "T1021"],
    "forensic_artifacts": [{"type": "process", "name": "mimikatz.exe"}],
    "mitigations":        [{"action": "isolate", "target": "VSAT-GX-007"}],
    "telemetry_events":   [{"event": "login_failure", "count": 47}],
    "ghost_stream":       True,
    "signal_anomaly":     False,
    "snr_db":             20.5,
    "frequency_mhz":      11700.0,
    "orbital_slot":       "98W",
}


# ═══════════════════════════════════════════════════════════════════════════════
# STIAParser — text parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIAParserText:

    def test_parse_text_target_id(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert "SAT-TELSTAR-11N" in r.target_id or "SAT-TELSTAR-11N" in r.target_name

    def test_parse_text_risk_level(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.risk_level == "CRITICAL"

    def test_parse_text_severity_score(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.severity_score == pytest.approx(9.2, abs=0.1)

    def test_parse_text_cves(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert "CVE-2024-1234" in r.cve_list
        assert "CVE-2023-5678" in r.cve_list

    def test_parse_text_mitre_tactics(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert any("Initial Access" in t for t in r.mitre_tactics)
        assert any("Lateral Movement" in t for t in r.mitre_tactics)
        assert any("Exfiltration" in t for t in r.mitre_tactics)

    def test_parse_text_mitre_techniques(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert "T1190" in r.mitre_techniques
        assert "T1041" in r.mitre_techniques

    def test_parse_text_signal_anomaly(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.signal_anomaly is True

    def test_parse_text_snr(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.snr_db == pytest.approx(15.5, abs=0.1)

    def test_parse_text_frequency(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.frequency_mhz == pytest.approx(11700.0, abs=1.0)

    def test_parse_text_ghost_stream(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.ghost_stream is True

    def test_parse_text_watermark(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert "WM-AABBCCDD1122" in r.watermark_ids

    def test_parse_text_orbital_slot(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.orbital_slot is not None
        assert "37.5" in r.orbital_slot or "W" in r.orbital_slot

    def test_parse_text_status_active(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert r.status == "ACTIVE"

    def test_parse_text_parsed_at_is_iso(self):
        p = STIAParser()
        r = p.parse_text(SAMPLE_TEXT)
        assert "T" in r.parsed_at  # ISO 8601 format


# ═══════════════════════════════════════════════════════════════════════════════
# STIAParser — dict parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIAParserDict:

    def test_parse_dict_target_id(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.target_id == "VSAT-GX-007"

    def test_parse_dict_target_name(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.target_name == "Inmarsat GX VSAT Terminal"

    def test_parse_dict_target_type(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.target_type == "vsat"

    def test_parse_dict_risk_level(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.risk_level == "HIGH"

    def test_parse_dict_severity_score(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.severity_score == pytest.approx(7.8, abs=0.01)

    def test_parse_dict_cves(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert "CVE-2024-9999" in r.cve_list
        assert "CVE-2023-1111" in r.cve_list

    def test_parse_dict_mitre_tactics(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert "Credential Access" in r.mitre_tactics
        assert "Lateral Movement" in r.mitre_tactics

    def test_parse_dict_mitre_techniques(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert "T1003" in r.mitre_techniques

    def test_parse_dict_forensic_artifacts(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert len(r.forensic_artifacts) == 1
        assert r.forensic_artifacts[0]["name"] == "mimikatz.exe"

    def test_parse_dict_mitigations(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert len(r.mitigations) == 1

    def test_parse_dict_telemetry_events(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert len(r.telemetry_events) == 1

    def test_parse_dict_ghost_stream(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.ghost_stream is True

    def test_parse_dict_snr(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.snr_db == pytest.approx(20.5, abs=0.01)

    def test_parse_dict_frequency(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.frequency_mhz == pytest.approx(11700.0, abs=0.01)

    def test_parse_dict_orbital_slot(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.orbital_slot == "98W"

    def test_parse_dict_not_neutralized(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        assert r.is_neutralized is False


# ═══════════════════════════════════════════════════════════════════════════════
# STIAParser — JSON parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIAParserJSON:

    def test_parse_json_valid(self):
        p = STIAParser()
        r = p.parse_json(json.dumps(SAMPLE_DICT))
        assert r.target_id == "VSAT-GX-007"
        assert r.risk_level == "HIGH"

    def test_parse_json_invalid_returns_result(self):
        p = STIAParser()
        r = p.parse_json("not valid json {{{")
        assert isinstance(r, STIAScanResult)
        assert len(r.parse_warnings) > 0

    def test_parse_json_roundtrip(self):
        p = STIAParser()
        r1 = p.parse_dict(SAMPLE_DICT)
        r2 = p.parse_json(json.dumps(r1.to_bind_payload()))
        assert r2.target_id == r1.target_id
        assert r2.risk_level == r1.risk_level


# ═══════════════════════════════════════════════════════════════════════════════
# STIAScanResult — derived fields and serialisation
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIAScanResult:

    def test_severity_label_critical(self):
        r = STIAScanResult(severity_score=9.5)
        assert r.severity_label() == "CRITICAL"

    def test_severity_label_high(self):
        r = STIAScanResult(severity_score=7.5)
        assert r.severity_label() == "HIGH"

    def test_severity_label_medium(self):
        r = STIAScanResult(severity_score=5.0)
        assert r.severity_label() == "MEDIUM"

    def test_severity_label_low(self):
        r = STIAScanResult(severity_score=2.5)
        assert r.severity_label() == "LOW"

    def test_severity_label_none(self):
        r = STIAScanResult(severity_score=0.0)
        assert r.severity_label() == "NONE"

    def test_to_nexus_findings_cves(self):
        r = STIAScanResult(
            target_id="T1",
            cve_list=["CVE-2024-1234"],
            risk_level="HIGH",
            severity_score=7.5,
        )
        findings = r.to_nexus_findings()
        cve_findings = [f for f in findings if f["type"] == "cve"]
        assert len(cve_findings) == 1
        assert cve_findings[0]["id"] == "CVE-2024-1234"

    def test_to_nexus_findings_tactics(self):
        r = STIAScanResult(
            target_id="T1",
            mitre_tactics=["Lateral Movement", "Exfiltration"],
        )
        findings = r.to_nexus_findings()
        tactic_findings = [f for f in findings if f["type"] == "mitre_tactic"]
        assert len(tactic_findings) == 2

    def test_to_nexus_findings_artifacts(self):
        r = STIAScanResult(
            target_id="T1",
            forensic_artifacts=[{"name": "evil.exe", "hash": "abc123"}],
        )
        findings = r.to_nexus_findings()
        artifact_findings = [f for f in findings if f["type"] == "forensic_artifact"]
        assert len(artifact_findings) == 1
        assert artifact_findings[0]["name"] == "evil.exe"

    def test_to_bind_payload_is_serialisable(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        payload = r.to_bind_payload()
        serialised = json.dumps(payload, default=str)
        parsed = json.loads(serialised)
        assert parsed["target_id"] == "VSAT-GX-007"

    def test_post_process_derives_risk_from_score(self):
        p = STIAParser()
        r = p.parse_dict({"target_id": "X", "severity_score": 8.5})
        assert r.risk_level == "HIGH"

    def test_post_process_derives_score_from_risk(self):
        p = STIAParser()
        r = p.parse_dict({"target_id": "X", "risk_level": "CRITICAL"})
        assert r.severity_score == pytest.approx(9.5, abs=0.1)

    def test_post_process_neutralized_from_status(self):
        p = STIAParser()
        r = p.parse_dict({"target_id": "X", "status": "NEUTRALIZED"})
        assert r.is_neutralized is True

    def test_empty_target_id_gets_generated(self):
        p = STIAParser()
        r = p.parse_dict({})
        assert r.target_id.startswith("STIA-")
        assert len(r.parse_warnings) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# STIABinder
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIABinder:

    def test_bind_dict_returns_result_and_receipt(self):
        b = STIABinder()
        result, receipt = b.bind_dict(SAMPLE_DICT)
        assert isinstance(result, STIAScanResult)
        assert receipt is not None

    def test_bind_text_returns_result_and_receipt(self):
        b = STIABinder()
        result, receipt = b.bind_text(SAMPLE_TEXT)
        assert isinstance(result, STIAScanResult)
        assert receipt is not None

    def test_bind_json_returns_result_and_receipt(self):
        b = STIABinder()
        result, receipt = b.bind_json(json.dumps(SAMPLE_DICT))
        assert isinstance(result, STIAScanResult)
        assert receipt is not None

    def test_summary_has_required_keys(self):
        b = STIABinder()
        result, receipt = b.bind_dict(SAMPLE_DICT)
        s = b.summary(result, receipt)
        for key in ("target", "threat_profile", "risk_level", "severity_score",
                    "status", "is_neutralized", "cves", "mitre_tactics",
                    "artifact_count", "mitigation_count", "telemetry_events",
                    "ghost_stream", "parsed_at"):
            assert key in s, f"Missing key: {key}"

    def test_summary_includes_receipt_fields(self):
        b = STIABinder()
        result, receipt = b.bind_dict(SAMPLE_DICT)
        s = b.summary(result, receipt)
        assert "bind_id" in s
        assert "timestamp_ns" in s

    def test_to_nexus_findings_delegates(self):
        b = STIABinder()
        result, _ = b.bind_dict(SAMPLE_DICT)
        findings = b.to_nexus_findings(result)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_bind_dict_risk_level_preserved(self):
        b = STIABinder()
        result, _ = b.bind_dict(SAMPLE_DICT)
        assert result.risk_level == "HIGH"

    def test_bind_dict_cves_preserved(self):
        b = STIABinder()
        result, _ = b.bind_dict(SAMPLE_DICT)
        assert "CVE-2024-9999" in result.cve_list


# ═══════════════════════════════════════════════════════════════════════════════
# _SimulatedReceipt
# ═══════════════════════════════════════════════════════════════════════════════

class TestSimulatedReceipt:

    def _make_receipt(self) -> _SimulatedReceipt:
        return _SimulatedReceipt({"target": "test", "risk": "HIGH"})

    def test_timestamp_ends_in_313(self):
        r = self._make_receipt()
        assert str(r.timestamp_ns).endswith("313")

    def test_bind_id_starts_with_313_stia(self):
        r = self._make_receipt()
        assert r.bind_id.startswith("313-STIA-")

    def test_payload_hash_is_sha3_256(self):
        r = self._make_receipt()
        assert r.payload_hash.startswith("sha3_256:")
        assert len(r.payload_hash) == len("sha3_256:") + 64

    def test_chain_hash_is_sha3_512(self):
        r = self._make_receipt()
        assert r.chain_hash.startswith("sha3_512:")
        assert len(r.chain_hash) == len("sha3_512:") + 128

    def test_to_dict_has_all_fields(self):
        r = self._make_receipt()
        d = r.to_dict()
        for key in ("bind_id", "timestamp_ns", "timestamp_iso", "payload_hash",
                    "chain_hash", "signature_algorithm", "ipfs_cid",
                    "ipfs_anchored", "app_id", "app_version"):
            assert key in d, f"Missing key: {key}"

    def test_app_id_is_aegis_nexus(self):
        r = self._make_receipt()
        assert r.app_id == "aegis-nexus-vsat"

    def test_ipfs_not_anchored_in_simulation(self):
        r = self._make_receipt()
        assert r.ipfs_anchored is False
        assert r.ipfs_cid is None

    def test_different_payloads_produce_different_hashes(self):
        r1 = _SimulatedReceipt({"target": "A"})
        r2 = _SimulatedReceipt({"target": "B"})
        assert r1.payload_hash != r2.payload_hash
        assert r1.chain_hash != r2.chain_hash


# ═══════════════════════════════════════════════════════════════════════════════
# Report generation
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportGeneration:

    def test_generate_report_creates_files(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        receipt = _SimulatedReceipt(r.to_bind_payload())
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path, json_path = generate_stia_report(r, receipt, output_dir=tmpdir)
            assert os.path.exists(html_path)
            assert os.path.exists(json_path)

    def test_json_report_is_valid(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        receipt = _SimulatedReceipt(r.to_bind_payload())
        with tempfile.TemporaryDirectory() as tmpdir:
            _, json_path = generate_stia_report(r, receipt, output_dir=tmpdir)
            with open(json_path) as fh:
                data = json.load(fh)
            assert data["report_type"] == "STIA_313_BOUND"
            assert "scan_result" in data
            assert "receipt" in data
            assert "nexus_findings" in data

    def test_html_report_contains_target(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        receipt = _SimulatedReceipt(r.to_bind_payload())
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path, _ = generate_stia_report(r, receipt, output_dir=tmpdir)
            html = open(html_path).read()
            assert "VSAT-GX-007" in html
            assert "313-STIA-" in html

    def test_html_report_contains_risk_level(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        receipt = _SimulatedReceipt(r.to_bind_payload())
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path, _ = generate_stia_report(r, receipt, output_dir=tmpdir)
            html = open(html_path).read()
            assert "HIGH" in html

    def test_report_with_none_receipt(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path, json_path = generate_stia_report(r, None, output_dir=tmpdir)
            assert os.path.exists(html_path)
            assert os.path.exists(json_path)

    def test_json_report_receipt_has_bind_id(self):
        p = STIAParser()
        r = p.parse_dict(SAMPLE_DICT)
        receipt = _SimulatedReceipt(r.to_bind_payload())
        with tempfile.TemporaryDirectory() as tmpdir:
            _, json_path = generate_stia_report(r, receipt, output_dir=tmpdir)
            data = json.load(open(json_path))
            assert data["receipt"]["bind_id"].startswith("313-STIA-")

    def test_binder_generate_report(self):
        b = STIABinder()
        result, receipt = b.bind_dict(SAMPLE_DICT)
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path, json_path = b.generate_report(result, receipt, output_dir=tmpdir)
            assert os.path.exists(html_path)
            assert os.path.exists(json_path)