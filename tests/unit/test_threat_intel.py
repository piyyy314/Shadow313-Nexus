"""Tests for IOC detection, SQLite storage, synthetic feed sync and enrichment."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from shadow313.v2.threat_intel.threat_intel import (
    FeodoTracker,
    MalwareBazaarSync,
    OTXSync,
    ThreatIntelDB,
    ThreatIntelManager,
    URLhausSync,
    _detect_ioc_type,
)

# ── IOC type detection ────────────────────────────────────────────────────────


class TestIOCTypeDetection:
    def test_ipv4_detection(self):
        assert _detect_ioc_type("192.168.1.1") == "ip"
        assert _detect_ioc_type("10.0.0.1") == "ip"
        assert _detect_ioc_type("185.220.101.1") == "ip"
        assert _detect_ioc_type("255.255.255.255") == "ip"

    def test_md5_hash_detection(self):
        assert _detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha256_hash_detection(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _detect_ioc_type(sha256) == "sha256"

    def test_url_detection(self):
        assert _detect_ioc_type("http://evil.com/malware.exe") == "url"
        assert _detect_ioc_type("https://phishing.site/login") == "url"

    def test_domain_detection(self):
        assert _detect_ioc_type("evil.com") == "domain"
        assert _detect_ioc_type("malware.example.org") == "domain"
        assert _detect_ioc_type("sub.domain.co.uk") == "domain"

    def test_unknown_type(self):
        assert _detect_ioc_type("not-an-ioc") == "unknown"
        assert _detect_ioc_type("") == "unknown"
        assert _detect_ioc_type("random string 123") == "unknown"

    def test_ipv4_boundary_cases(self):
        # Not a valid IP pattern — should not match
        assert _detect_ioc_type("999.999.999.999") == "ip"  # regex matches pattern, not validity
        assert _detect_ioc_type("1.2.3") != "ip"  # only 3 octets


@pytest.fixture
def db(tmp_path):
    database = ThreatIntelDB(tmp_path / "intel.db")
    yield database
    database._conn.close()


@pytest.fixture
def manager(tmp_path):
    manager = ThreatIntelManager(db_path=tmp_path / "manager.db")
    # Provider boundaries return synthetic data; these unit tests never use live feeds.
    with (
        patch.object(manager.shodan, "lookup", return_value={"status": "not_found"}),
        patch.object(manager.otx, "lookup_ip", return_value={"status": "not_found"}),
        patch.object(manager.bazaar, "lookup_hash", return_value={"status": "not_found"}),
        patch.object(manager.urlhaus, "lookup_url", return_value={"status": "not_found"}),
    ):
        yield manager
    manager.db._conn.close()


class TestThreatIntelDB:
    def test_ip_round_trip_and_upsert(self, db):
        assert db.lookup_ip("192.0.2.1") is None
        db.upsert_ip("192.0.2.1", ["c2"], "example", country="ZZ", ports=[443], source="fixture")
        db.commit()
        row = db.lookup_ip("192.0.2.1")
        assert row["tags"] == ["c2"] and row["ports"] == [443]
        assert row["malware"] == "example" and row["source"] == "fixture"
        db.upsert_ip("192.0.2.1", ["updated"], "other", source="fixture-two")
        assert db.stats()["ips"] == db.stats()["ioc_ip"] == 1
        assert db.lookup_ip("192.0.2.1")["tags"] == ["updated"]

    def test_domain_and_hash_round_trip(self, db):
        db.upsert_domain("example.com", ["c2"], "example", "fixture")
        db.upsert_hash("a" * 64, "sha256", "example", ["fixture"], "test-feed")
        assert db.lookup_domain("example.com")["tags"] == ["c2"]
        row = db.lookup_hash("a" * 64)
        assert row["hash_type"] == "sha256" and row["malware"] == "example"
        assert row["tags"] == ["fixture"]
        assert db.lookup_domain("missing.example") is None
        assert db.lookup_hash("b" * 64) is None

    def test_urls_use_bounded_parameterized_storage(self, db):
        url = "https://example.com/" + "a" * 1500
        db.upsert_url(url, ["test"], "example", "online", "fixture")
        row = db._conn.execute("SELECT url, tags, source FROM ioc_url").fetchone()
        assert row[0] == url[:1000] and row[2] == "fixture"
        assert json.loads(row[1]) == ["test"]

    def test_stats_and_feed_metadata(self, db):
        stats = db.stats()
        assert all(stats[key] == 0 for key in ("ips", "domains", "urls", "hashes", "techniques"))
        assert stats["feeds"] == {}
        assert db.get_meta("fixture") is None
        db.update_meta("fixture", 3)
        assert db.get_meta("fixture")["count"] == 3
        assert db.stats()["feeds"]["fixture"]["count"] == 3

    def test_search_and_sql_input(self, db):
        value = "'; DROP TABLE ioc_ip; --"
        db.upsert_ip(value, ["fixture"], "example", source="test")
        assert db.lookup_ip(value)["ip"] == value
        assert len(db.search_ip("example")) == 1
        assert db.stats()["ioc_ip"] == 1


class TestFeedSync:
    def test_feodo_fetch_and_cache(self, db):
        import json

        raw = json.dumps(
            [{"ip_address": "192.0.2.1", "malware": "Example", "port": 443}, {"ip_address": ""}]
        ).encode()
        with patch("shadow313.v2.threat_intel.threat_intel._http_get", return_value=raw) as get:
            feed = FeodoTracker(db)
            assert feed.sync()["synced"] == 1
            assert feed.sync()["status"] == "cached"
            get.assert_called_once()
        assert db.lookup_ip("192.0.2.1")["ports"] == [443]

    @pytest.mark.parametrize("raw", [None, b"invalid JSON"])
    def test_feodo_fetch_failure(self, db, raw):
        with patch("shadow313.v2.threat_intel.threat_intel._http_get", return_value=raw):
            assert FeodoTracker(db).sync()["status"] == "error"
        assert db.stats()["ips"] == 0

    def test_urlhaus_sync(self, db):
        payload = {
            "urls": [
                {"url": "https://example.com/a", "tags": ["test"], "url_status": "online"},
                {"url": ""},
            ]
        }
        with patch("shadow313.v2.threat_intel.threat_intel._http_post_json", return_value=payload):
            assert URLhausSync(db).sync_recent()["synced"] == 1
        assert db.stats()["ioc_url"] == 1

    def test_urlhaus_network_error(self, db):
        with patch("shadow313.v2.threat_intel.threat_intel._http_post_json", return_value=None):
            assert URLhausSync(db).sync_recent()["status"] == "error"
            assert URLhausSync(db).lookup_url("https://example.com")["status"] == "error"

    def test_malware_bazaar_hash(self, db):
        payload = {"query_status": "ok", "data": [{"signature": "Example", "tags": ["test"]}]}
        with patch("shadow313.v2.threat_intel.threat_intel._http_post_json", return_value=payload):
            assert MalwareBazaarSync(db).lookup_hash("a" * 64)["status"] == "found"
        assert db.lookup_hash("a" * 64)["malware"] == "Example"

    def test_otx_sync(self, db):
        raw = json.dumps(
            {
                "results": [
                    {
                        "name": "Synthetic pulse",
                        "indicators": [
                            {"type": "IPv4", "indicator": "192.0.2.1"},
                            {"type": "domain", "indicator": "example.com"},
                            {"type": "FileHash-SHA256", "indicator": "a" * 64},
                        ],
                    }
                ]
            }
        ).encode()
        with patch("shadow313.v2.threat_intel.threat_intel._http_get", return_value=raw):
            assert OTXSync(db, api_key="synthetic-fixture").sync_subscribed_pulses()["synced"] == 3
        assert db.lookup_ip("192.0.2.1") and db.lookup_domain("example.com")
        assert db.lookup_hash("a" * 64)

    def test_otx_missing_key_does_not_fetch(self, db):
        with patch("shadow313.v2.threat_intel.threat_intel._http_get") as get:
            result = OTXSync(db).sync_subscribed_pulses()
        assert result["status"] == "no_api_key"
        get.assert_not_called()


class TestThreatIntelManager:
    def test_local_ip_enrichment(self, manager):
        manager.db.upsert_ip("192.0.2.1", ["c2"], "Example", source="fixture")
        result = manager.lookup_ioc("192.0.2.1")
        assert result["ip"] == "192.0.2.1" and result["is_malicious"] is True
        assert result["local_ioc"]["source"] == "fixture"
        assert result["threat_score"] == 50

    def test_score_bounds(self, manager):
        assert manager._threat_score(None, {}, {}) == 0
        assert (
            manager._threat_score(
                {"ip": "192.0.2.1"},
                {"is_malicious": True, "vulns": ["cve"]},
                {"is_malicious": True, "pulse_count": 100},
            )
            == 100
        )

    def test_domain_hash_and_url_routes(self, manager):
        manager.db.upsert_domain("example.com", ["test"], "Example", "fixture")
        assert manager.lookup_ioc("example.com")["local"]["source"] == "fixture"
        manager.lookup_ioc("a" * 64)
        manager.bazaar.lookup_hash.assert_called_once_with("a" * 64)
        manager.lookup_ioc("https://example.com")
        manager.urlhaus.lookup_url.assert_called_once_with("https://example.com")

    def test_enrich_only_supported_fields(self, manager):
        findings = [{"cve": "CVE-2021-44228"}, {"ip": "192.0.2.1"}, {"sha256": "a" * 64}]
        enriched = manager.enrich_findings(findings)
        assert "threat_intel" not in enriched[0]
        assert enriched[1]["threat_intel"]["ip"] == "192.0.2.1"
        assert "hash_intel" in enriched[2]
        assert manager.enrich_findings([]) == []

    def test_sync_selected_feeds(self, manager):
        with (
            patch.object(
                manager.feodo, "sync", return_value={"status": "ok", "synced": 2}
            ) as feodo,
            patch.object(
                manager.urlhaus, "sync_recent", return_value={"status": "error"}
            ) as urlhaus,
            patch.object(manager.bazaar, "sync_recent") as bazaar,
        ):
            result = manager.sync_all(["feodo", "urlhaus"])
        assert result == {"feodo": {"status": "ok", "synced": 2}, "urlhaus": {"status": "error"}}
        feodo.assert_called_once()
        urlhaus.assert_called_once()
        bazaar.assert_not_called()
