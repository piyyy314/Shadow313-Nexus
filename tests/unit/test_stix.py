"""Unit tests — shadow313.v4.stix v4"""
import json
import pytest
from shadow313.v4.stix.stix_handler import STIXParser, STIXBuilder
from shadow313.v2.threat_intel.threat_intel import _detect_ioc_type


class TestIOCTypeDetection:
    def test_ipv4_detection(self):
        assert _detect_ioc_type("185.220.100.252") == "ip"
        assert _detect_ioc_type("10.0.0.1")        == "ip"
        assert _detect_ioc_type("192.168.1.1")     == "ip"

    def test_sha256_detection(self):
        sha256 = "a" * 64
        assert _detect_ioc_type(sha256) == "sha256"

    def test_short_hex_not_sha256(self):
        """FIX: short hex strings should not be misidentified as SHA256."""
        short_hex = "a" * 32  # MD5 length, not SHA256
        result = _detect_ioc_type(short_hex)
        assert result != "sha256"

    def test_url_detection(self):
        assert _detect_ioc_type("https://evil.com/malware") == "url"
        assert _detect_ioc_type("http://bad.site/payload")  == "url"

    def test_domain_detection(self):
        assert _detect_ioc_type("evil.com")        == "domain"
        assert _detect_ioc_type("malware.example.org") == "domain"

    def test_unknown_type(self):
        assert _detect_ioc_type("not-an-ioc") == "unknown"
        assert _detect_ioc_type("")            == "unknown"


class TestSTIXParser:
    def _make_bundle(self, objects: list) -> dict:
        return {
            "type":         "bundle",
            "id":           "bundle--test-123",
            "spec_version": "2.1",
            "objects":      objects,
        }

    def test_parse_valid_bundle(self):
        bundle = self._make_bundle([
            {
                "type":       "indicator",
                "id":         "indicator--a1b2c3",
                "name":       "Cobalt Strike C2",
                "pattern":    "[ipv4-addr:value = '185.220.100.252']",
                "valid_from": "2024-06-01T00:00:00Z",
                "labels":     ["malicious-activity"],
            }
        ])
        parser = STIXParser()
        result = parser.parse_bundle(bundle)
        assert result["object_count"] == 1
        assert len(result["indicators"]) == 1
        assert result["indicators"][0]["name"] == "Cobalt Strike C2"

    def test_parse_indicator_ip(self):
        bundle = self._make_bundle([
            {
                "type":       "indicator",
                "id":         "indicator--test",
                "name":       "Malicious IP",
                "pattern":    "[ipv4-addr:value = '1.2.3.4']",
                "valid_from": "2024-01-01T00:00:00Z",
                "labels":     ["malicious-activity"],
            }
        ])
        parser = STIXParser()
        result = parser.parse_bundle(bundle)
        ind = result["indicators"][0]
        assert ind["ioc_type"]  == "ip"
        assert ind["ioc_value"] == "1.2.3.4"

    def test_parse_malware_object(self):
        bundle = self._make_bundle([
            {
                "type":          "malware",
                "id":            "malware--d4e5f6",
                "name":          "Log4Shell Exploit",
                "is_family":     False,
                "malware_types": ["exploit-kit"],
            }
        ])
        parser = STIXParser()
        result = parser.parse_bundle(bundle)
        assert len(result["malware"]) == 1
        assert result["malware"][0]["name"] == "Log4Shell Exploit"

    def test_parse_not_a_bundle(self):
        parser = STIXParser()
        result = parser.parse_bundle({"type": "indicator"})
        assert "error" in result

    def test_extract_iocs_from_bundle(self):
        bundle = self._make_bundle([
            {
                "type":       "indicator",
                "id":         "indicator--1",
                "name":       "Test",
                "pattern":    "[ipv4-addr:value = '185.220.100.252']",
                "valid_from": "2024-01-01T00:00:00Z",
            }
        ])
        parser = STIXParser()
        result = parser.parse_bundle(bundle)
        assert "185.220.100.252" in result["iocs"]["ips"]

    def test_parse_file(self, tmp_path):
        bundle = {
            "type":         "bundle",
            "id":           "bundle--test",
            "spec_version": "2.1",
            "objects":      [],
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(bundle))
        parser = STIXParser()
        result = parser.parse_file(str(f))
        assert result["object_count"] == 0

    def test_parse_nonexistent_file(self, tmp_path):
        parser = STIXParser()
        result = parser.parse_file(str(tmp_path / "nonexistent.json"))
        assert "error" in result

    def test_parse_uploaded_stix_bundle(self):
        """Test with the actual uploaded shadow313-stix-bundle.json content."""
        bundle = {
            "type":         "bundle",
            "id":           "bundle--s313-1784435865500",
            "spec_version": "2.1",
            "objects": [
                {
                    "type":       "indicator",
                    "id":         "indicator--a1b2c3",
                    "name":       "Cobalt Strike C2",
                    "pattern":    "[ipv4-addr:value = '185.220.100.252']",
                    "valid_from": "2024-06-01T00:00:00Z",
                    "labels":     ["malicious-activity"],
                },
                {
                    "type":          "malware",
                    "id":            "malware--d4e5f6",
                    "name":          "Log4Shell Exploit",
                    "is_family":     False,
                    "malware_types": ["exploit-kit"],
                },
            ],
        }
        parser = STIXParser()
        result = parser.parse_bundle(bundle)
        assert result["object_count"] == 2
        assert len(result["indicators"]) == 1
        assert len(result["malware"])    == 1
        assert "185.220.100.252" in result["iocs"]["ips"]


class TestSTIXBuilder:
    def test_findings_to_bundle(self):
        findings = [
            {"cve": "CVE-2024-1234", "description": "Test vulnerability",
             "cvss_v3": 9.8, "severity": "CRITICAL", "port": 443},
            {"cve": "CVE-2024-5678", "description": "Another vulnerability",
             "cvss_v3": 7.5, "severity": "HIGH"},
        ]
        builder = STIXBuilder()
        bundle  = builder.findings_to_bundle(findings, session_id="test-session")
        assert bundle["type"]         == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) >= 2  # identity + vulnerabilities

    def test_bundle_contains_identity(self):
        builder = STIXBuilder()
        bundle  = builder.findings_to_bundle([])
        identity_objects = [o for o in bundle["objects"] if o["type"] == "identity"]
        assert len(identity_objects) == 1
        assert identity_objects[0]["name"] == "Shadow313 NEXUS"

    def test_bundle_contains_vulnerability_objects(self):
        findings = [{"cve": "CVE-2024-9999", "description": "Test", "cvss_v3": 5.0}]
        builder  = STIXBuilder()
        bundle   = builder.findings_to_bundle(findings)
        vuln_objects = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert len(vuln_objects) == 1
        assert "CVE-2024-9999" in vuln_objects[0]["name"]

    def test_empty_findings_bundle(self):
        builder = STIXBuilder()
        bundle  = builder.findings_to_bundle([])
        assert bundle["type"] == "bundle"
        # Should still have identity object
        assert len(bundle["objects"]) >= 1

    def test_bundle_is_valid_json(self):
        findings = [{"cve": "CVE-2024-1234", "description": "Test", "cvss_v3": 9.8}]
        builder  = STIXBuilder()
        bundle   = builder.findings_to_bundle(findings)
        # Should be JSON-serializable
        json_str = json.dumps(bundle)
        assert len(json_str) > 0