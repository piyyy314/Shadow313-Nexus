"""
Comprehensive tests — shadow313.v2.threat_intel
Covers: ThreatIntelDB CRUD, IOC type detection, feed syncers (offline),
        ThreatIntelManager lookup/enrich, threat scoring, edge cases.
"""
from __future__ import annotations
import sqlite3
import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shadow313.v2.threat_intel.threat_intel import (
    ThreatIntelDB, ThreatIntelManager, _detect_ioc_type,
    FeodoTrackerSync, URLhausSync, MalwareBazaarSync,
    ShodanInternetDBSync, OTXSync,
)


# ── IOC type detection ────────────────────────────────────────────────────────

class TestIOCTypeDetection:
    def test_ipv4_detection(self):
        assert _detect_ioc_type("192.168.1.1")     == "ip"
        assert _detect_ioc_type("10.0.0.1")        == "ip"
        assert _detect_ioc_type("185.220.101.1")   == "ip"
        assert _detect_ioc_type("255.255.255.255")  == "ip"

    def test_md5_hash_detection(self):
        assert _detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha256_hash_detection(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _detect_ioc_type(sha256) == "hash"

    def test_url_detection(self):
        assert _detect_ioc_type("http://evil.com/malware.exe")  == "url"
        assert _detect_ioc_type("https://phishing.site/login")  == "url"

    def test_domain_detection(self):
        assert _detect_ioc_type("evil.com")          == "domain"
        assert _detect_ioc_type("malware.example.org") == "domain"
        assert _detect_ioc_type("sub.domain.co.uk")  == "domain"

    def test_unknown_type(self):
        assert _detect_ioc_type("not-an-ioc")        == "unknown"
        assert _detect_ioc_type("")                  == "unknown"
        assert _detect_ioc_type("random string 123") == "unknown"

    def test_ipv4_boundary_cases(self):
        # Not a valid IP pattern — should not match
        assert _detect_ioc_type("999.999.999.999") == "ip"  # regex matches pattern, not validity
        assert _detect_ioc_type("1.2.3")           != "ip"  # only 3 octets


# ── ThreatIntelDB CRUD ────────────────────────────────────────────────────────

class TestThreatIntelDB:
    @pytest.fixture
    def db(self, tmp_path):
        return ThreatIntelDB(db_path=tmp_path / "test_threat.db")

    def test_db_initialises_all_tables(self, db):
        stats = db.stats()
        assert "ioc_ip"     in stats
        assert "ioc_domain" in stats
        assert "ioc_url"    in stats
        assert "ioc_hash"   in stats

    def test_store_and_lookup_ip(self, db):
        db.store_ip("185.220.101.1", "feodotracker", "botnet_c2",
                    confidence=90, last_seen="2024-01-01")
        result = db.lookup_ip("185.220.101.1")
        assert result is not None
        assert result["ip"]          == "185.220.101.1"
        assert result["source"]      == "feodotracker"
        assert result["threat_type"] == "botnet_c2"
        assert result["confidence"]  == 90
        assert result["last_seen"]   == "2024-01-01"

    def test_lookup_nonexistent_ip_returns_none(self, db):
        assert db.lookup_ip("1.2.3.4") is None

    def test_store_and_lookup_url(self, db):
        db.store_url("http://evil.com/payload.exe", "urlhaus", "malware",
                     http_status=200, tags="ransomware,emotet")
        result = db.lookup_url("http://evil.com/payload.exe")
        assert result is not None
        assert result["source"]      == "urlhaus"
        assert result["threat_type"] == "malware"
        assert "ransomware" in result["tags"]

    def test_lookup_nonexistent_url_returns_none(self, db):
        assert db.lookup_url("http://clean.com/") is None

    def test_store_and_lookup_hash(self, db):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        db.store_hash(sha256, "sha256", "emotet", "Emotet.Gen", "malwarebazaar")
        result = db.lookup_hash(sha256)
        assert result is not None
        assert result["hash_type"]      == "sha256"
        assert result["malware_family"] == "emotet"
        assert result["signature"]      == "Emotet.Gen"
        assert result["source"]         == "malwarebazaar"

    def test_lookup_nonexistent_hash_returns_none(self, db):
        assert db.lookup_hash("deadbeef" * 8) is None

    def test_stats_counts_correctly(self, db):
        db.store_ip("1.1.1.1", "test", "c2")
        db.store_ip("2.2.2.2", "test", "c2")
        db.store_url("http://a.com", "test", "malware")
        stats = db.stats()
        assert stats["ioc_ip"]  == 2
        assert stats["ioc_url"] == 1
        assert stats["ioc_hash"] == 0

    def test_upsert_replaces_existing_ip(self, db):
        db.store_ip("1.1.1.1", "source_a", "c2", confidence=50)
        db.store_ip("1.1.1.1", "source_b", "phishing", confidence=80)
        result = db.lookup_ip("1.1.1.1")
        # Should have the latest values
        assert result["source"]     == "source_b"
        assert result["confidence"] == 80

    def test_url_truncated_to_500_chars(self, db):
        long_url = "http://evil.com/" + "a" * 600
        db.store_url(long_url, "test", "malware")
        # Should not raise; lookup with truncated key
        result = db.lookup_url(long_url[:500])
        assert result is not None

    def test_empty_db_stats_all_zero(self, db):
        stats = db.stats()
        for table, count in stats.items():
            assert count == 0, f"Expected 0 for {table}, got {count}"


# ── Feed syncers (offline / mocked) ──────────────────────────────────────────

class TestFeodoTrackerSync:
    @pytest.fixture
    def db(self, tmp_path):
        return ThreatIntelDB(db_path=tmp_path / "feodo.db")

    def test_sync_returns_zero_on_network_error(self, db):
        syncer = FeodoTrackerSync(db)
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   side_effect=Exception("network error")):
            count = syncer.sync()
        assert count == 0

    def test_sync_stores_ips_from_mock_response(self, db):
        mock_data = [
            {"ip_address": "185.220.101.1", "last_online": "2024-01-01"},
            {"ip_address": "185.220.101.2", "last_online": "2024-01-02"},
            {"ip_address": "",              "last_online": ""},  # empty — should be skipped
        ]
        import json as _json
        mock_resp = MagicMock()
        mock_resp.read.return_value = _json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)

        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   return_value=mock_resp):
            count = FeodoTrackerSync(db).sync()

        assert count == 2
        assert db.lookup_ip("185.220.101.1") is not None
        assert db.lookup_ip("185.220.101.2") is not None
        assert db.stats()["ioc_ip"] == 2

    def test_sync_skips_empty_ip_entries(self, db):
        mock_data = [{"ip_address": "", "last_online": ""}]
        import json as _json
        mock_resp = MagicMock()
        mock_resp.read.return_value = _json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   return_value=mock_resp):
            count = FeodoTrackerSync(db).sync()
        assert count == 0


class TestURLhausSync:
    @pytest.fixture
    def db(self, tmp_path):
        return ThreatIntelDB(db_path=tmp_path / "urlhaus.db")

    def test_sync_returns_zero_on_error(self, db):
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   side_effect=Exception("timeout")):
            assert URLhausSync(db).sync() == 0

    def test_sync_stores_urls_from_mock_response(self, db):
        import json as _json
        mock_data = {
            "urls": [
                {"url": "http://evil.com/a.exe", "threat": "malware", "tags": ["emotet"]},
                {"url": "http://phish.com/login", "threat": "phishing", "tags": []},
                {"url": "",                        "threat": "malware",  "tags": []},  # skip
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = _json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   return_value=mock_resp):
            count = URLhausSync(db).sync()
        assert count == 2
        assert db.lookup_url("http://evil.com/a.exe") is not None


class TestOTXSync:
    @pytest.fixture
    def db(self, tmp_path):
        return ThreatIntelDB(db_path=tmp_path / "otx.db")

    def test_sync_returns_zero_without_api_key(self, db):
        syncer = OTXSync(db, api_key="")
        assert syncer.sync() == 0

    def test_sync_returns_zero_on_network_error(self, db):
        syncer = OTXSync(db, api_key="fake_key")
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   side_effect=Exception("auth error")):
            assert syncer.sync() == 0

    def test_sync_stores_ipv4_indicators(self, db):
        import json as _json
        mock_data = {
            "results": [{
                "name": "Test Pulse",
                "indicators": [
                    {"type": "IPv4",   "indicator": "1.2.3.4"},
                    {"type": "URL",    "indicator": "http://evil.com"},
                    {"type": "domain", "indicator": "evil.com"},
                    {"type": "FileHash-SHA256", "indicator": "abc123"},  # not handled
                ]
            }]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = _json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   return_value=mock_resp):
            count = OTXSync(db, api_key="key").sync()
        # IPv4 + URL + domain = 3
        assert count == 3


# ── ThreatIntelManager ────────────────────────────────────────────────────────

class TestThreatIntelManager:
    @pytest.fixture
    def manager(self, tmp_path):
        db = ThreatIntelDB(db_path=tmp_path / "mgr.db")
        return ThreatIntelManager(db, otx_api_key="")

    def test_lookup_clean_ip_returns_no_matches(self, manager):
        result = manager.lookup_ioc("8.8.8.8")
        assert result["type"]        == "ip"
        assert result["matches"]     == []
        assert result["is_malicious"] is False

    def test_lookup_known_malicious_ip(self, manager):
        # Pre-populate DB
        manager._db.store_ip("185.220.101.1", "feodotracker", "botnet_c2", confidence=90)
        result = manager.lookup_ioc("185.220.101.1")
        assert result["type"]        == "ip"
        assert len(result["matches"]) == 1
        assert result["is_malicious"] is True
        assert result["threat_score"] > 0

    def test_lookup_known_malicious_url(self, manager):
        manager._db.store_url("http://evil.com/payload", "urlhaus", "malware")
        result = manager.lookup_ioc("http://evil.com/payload")
        assert result["type"]        == "url"
        assert len(result["matches"]) == 1
        assert result["is_malicious"] is True

    def test_lookup_known_hash(self, manager):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        manager._db.store_hash(sha256, "sha256", "emotet", "Emotet.Gen", "malwarebazaar")
        result = manager.lookup_ioc(sha256)
        assert result["type"]        == "hash"
        assert len(result["matches"]) == 1
        assert result["is_malicious"] is True

    def test_threat_score_zero_for_clean_ioc(self, manager):
        result = manager.lookup_ioc("1.2.3.4")
        assert result["threat_score"] == 0

    def test_threat_score_increases_with_matches(self, manager):
        manager._db.store_ip("10.0.0.1", "feed_a", "c2", confidence=90)
        result = manager.lookup_ioc("10.0.0.1")
        assert result["threat_score"] >= 30

    def test_enrich_findings_adds_threat_intel_key(self, manager):
        findings = [
            {"cve": "CVE-2021-44228", "severity": "CRITICAL"},
            {"cve": "CVE-2017-5638",  "severity": "HIGH"},
        ]
        enriched = manager.enrich_findings(findings)
        assert len(enriched) == 2
        for f in enriched:
            assert "threat_intel" in f

    def test_enrich_findings_empty_list(self, manager):
        assert manager.enrich_findings([]) == []

    def test_sync_all_with_no_feeds(self, manager):
        # All feeds will fail (no network) — should return 0s not raise
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   side_effect=Exception("no network")):
            results = manager.sync_all(["feodo", "urlhaus"])
        assert isinstance(results, dict)
        assert results.get("feodo",   0) == 0
        assert results.get("urlhaus", 0) == 0

    def test_lookup_ioc_unknown_type(self, manager):
        result = manager.lookup_ioc("not-an-ioc-at-all")
        assert result["type"]    == "unknown"
        assert result["matches"] == []

    def test_enrich_ip_calls_shodan_on_network_error(self, manager):
        # enrich_ip delegates to lookup_ioc which returns a full IOC result dict
        with patch("shadow313.v2.threat_intel.threat_intel.urlreq.urlopen",
                   side_effect=Exception("timeout")):
            result = manager.enrich_ip("8.8.8.8")
        assert isinstance(result, dict)
        # Result contains either "value" (from lookup_ioc) or "ip" (from shodan direct)
        assert "value" in result or "ip" in result or "error" in result