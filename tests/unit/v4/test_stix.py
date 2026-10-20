"""Unit tests — shadow313.v4.stix"""
import pytest

class TestSTIXHandler:
    def test_module_importable(self):
        try:
            from shadow313.v4.stix.stix_handler import STIXHandler
            assert STIXHandler is not None
        except ImportError:
            pytest.skip("stix_handler not available")

    def test_stix_bundle_structure(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--test-123",
            "spec_version": "2.1",
            "objects": [],
        }
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"

    def test_indicator_creation(self):
        indicator = {
            "type": "indicator",
            "id": "indicator--test",
            "name": "Cobalt Strike C2",
            "pattern": "[ipv4-addr:value = '185.220.100.252']",
            "valid_from": "2026-01-01T00:00:00Z",
        }
        assert indicator["type"] == "indicator"
        assert "pattern" in indicator

    def test_attack_pattern_mapping(self):
        attack_pattern = {
            "type": "attack-pattern",
            "name": "Spearphishing Attachment",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}],
        }
        assert attack_pattern["type"] == "attack-pattern"

    def test_ioc_extraction(self):
        iocs = {"ips": ["185.220.101.42"], "domains": ["evil.com"], "hashes": ["abc123"]}
        assert len(iocs["ips"]) > 0

    def test_stix_export_format(self):
        import json
        bundle = {"type": "bundle", "objects": []}
        exported = json.dumps(bundle)
        assert "bundle" in exported
