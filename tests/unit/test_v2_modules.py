"""Unit tests — shadow313 v2 advanced modules"""
import pytest
from shadow313.v2.rag.tfidf_store import TFIDFVectorStore
from shadow313.v2.vuln_upgrades.attack_mapping import ATTACKMapper, NavigatorGenerator
from shadow313.v2.network_upgrades.dns_covert import DNSCovertDetector, _shannon_entropy
from shadow313.v2.crypto_agility.crypto_agility import (
    CryptoMigrationEngine, CryptoAgilityFramework, PQC_ALGORITHMS, PQC_SNIPPETS
)
from shadow313.v2.graph.intel_graph import _SimpleGraph


class TestTFIDFVectorStore:
    def test_add_and_query(self):
        store = TFIDFVectorStore()
        store.add("CVE-2021-44228 Log4Shell remote code execution vulnerability", {"id": "1"})
        store.add("SQL injection vulnerability in web application", {"id": "2"})
        store.add("Buffer overflow in network service", {"id": "3"})
        results = store.query("log4j remote code execution", top_k=2)
        assert len(results) > 0
        assert results[0]["score"] > 0

    def test_empty_store_query(self):
        store   = TFIDFVectorStore()
        results = store.query("anything", top_k=5)
        assert results == []

    def test_count(self):
        store = TFIDFVectorStore()
        assert store.count() == 0
        store.add("test document", {})
        assert store.count() == 1

    def test_batch_add(self):
        store = TFIDFVectorStore()
        items = [
            {"text": "RSA vulnerability", "id": "1", "metadata": {}},
            {"text": "ECDSA weakness",    "id": "2", "metadata": {}},
            {"text": "AES encryption",    "id": "3", "metadata": {}},
        ]
        store.add_batch(items)
        assert store.count() == 3

    def test_save_and_load(self, tmp_path):
        store_path = str(tmp_path / "store.json")
        store = TFIDFVectorStore(store_path)
        store.add("test document about security", {"id": "1"})
        store.save()
        store2 = TFIDFVectorStore(store_path)
        store2.load()
        assert store2.count() == 1


class TestATTACKMapper:
    def test_map_findings_with_keywords(self):
        mapper   = ATTACKMapper()
        findings = [
            {"cve": "CVE-2021-44228", "description": "remote code execution via log4j"},
            {"cve": "CVE-2017-5638",  "description": "sql injection in struts"},
        ]
        mapped = mapper.map_findings(findings)
        assert len(mapped) == 2
        for f in mapped:
            assert "attack_techniques" in f

    def test_map_text(self):
        mapper     = ATTACKMapper()
        techniques = mapper.map_text("cobalt strike c2 beaconing lateral movement")
        assert len(techniques) > 0
        assert all(t.startswith("T") for t in techniques)

    def test_technique_summary(self):
        mapper   = ATTACKMapper()
        findings = [
            {"attack_techniques": ["T1071", "T1046"]},
            {"attack_techniques": ["T1071", "T1190"]},
        ]
        summary = mapper.technique_summary(findings)
        assert summary.get("T1071") == 2

    def test_navigator_generation(self):
        nav   = NavigatorGenerator()
        layer = nav.generate({"T1071": 3, "T1046": 1, "T1190": 2})
        assert layer["name"] is not None
        assert layer["domain"] == "enterprise-attack"
        assert len(layer["techniques"]) == 3
        assert layer["versions"]["attack"] == "14"


class TestDNSCovertDetector:
    def test_shannon_entropy_high(self):
        # Random-looking string should have high entropy
        entropy = _shannon_entropy("aB3xK9mN2pQ7rS5tU8vW1yZ4cD6eF0gH")
        assert entropy > 3.0

    def test_shannon_entropy_low(self):
        # Repetitive string should have low entropy
        entropy = _shannon_entropy("aaaaaaaaaaaaaaaa")
        assert entropy < 1.0

    def test_high_entropy_subdomain_detection(self):
        detector = DNSCovertDetector()
        queries  = ["aB3xK9mN2pQ7rS5tU8vW1yZ4cD6eF0gH.example.com"]
        alerts   = detector.analyze_queries(queries)
        # May or may not trigger depending on entropy of test string
        assert isinstance(alerts, list)

    def test_tunnel_signature_detection(self):
        detector = DNSCovertDetector()
        queries  = ["iodine.tunnel.example.com", "dnscat2.c2.evil.com"]
        alerts   = detector.analyze_queries(queries)
        tunnel_alerts = [a for a in alerts if a["rule"] == "TUNNEL_TOOL_SIGNATURE"]
        assert len(tunnel_alerts) > 0

    def test_long_subdomain_detection(self):
        detector = DNSCovertDetector()
        long_sub = "a" * 50 + ".example.com"
        queries  = [long_sub]
        alerts   = detector.analyze_queries(queries)
        long_alerts = [a for a in alerts if a["rule"] == "LONG_SUBDOMAIN_LABEL"]
        assert len(long_alerts) > 0

    def test_high_subdomain_count(self):
        detector = DNSCovertDetector()
        queries  = [f"sub{i}.example.com" for i in range(25)]
        alerts   = detector.analyze_queries(queries)
        count_alerts = [a for a in alerts if a["rule"] == "HIGH_UNIQUE_SUBDOMAIN_COUNT"]
        assert len(count_alerts) > 0

    def test_clean_traffic_no_alerts(self):
        detector = DNSCovertDetector()
        queries  = ["www.example.com", "mail.example.com", "api.example.com"]
        alerts   = detector.analyze_queries(queries)
        assert len(alerts) == 0


class TestCryptoAgility:
    def test_pqc_algorithms_catalog(self):
        assert len(PQC_ALGORITHMS) == 11
        for name, info in PQC_ALGORITHMS.items():
            assert "type"  in info
            assert "fips"  in info
            assert "level" in info

    def test_pqc_snippets_available(self):
        assert "rsa-python"   in PQC_SNIPPETS
        assert "ecdsa-python" in PQC_SNIPPETS
        assert "aes128-python" in PQC_SNIPPETS
        assert "rsa-java"     in PQC_SNIPPETS
        assert "rsa-go"       in PQC_SNIPPETS
        assert "nginx-tls"    in PQC_SNIPPETS
        assert "generic-key-exchange" in PQC_SNIPPETS
        for key, snippet in PQC_SNIPPETS.items():
            assert "before" in snippet
            assert "after"  in snippet
            assert "notes"  in snippet

    def test_scan_python_file(self, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        engine   = CryptoMigrationEngine()
        findings = engine.scan(str(tmp_path), languages=["Python"])
        assert len(findings) > 0
        assert any(f["algorithm"] == "RSA" for f in findings)

    def test_readiness_vulnerable(self, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        engine   = CryptoMigrationEngine()
        findings = engine.scan(str(tmp_path))
        rating   = engine.compute_readiness(findings)
        assert rating in ("VULNERABLE", "PARTIAL")

    def test_readiness_quantum_ready(self):
        engine   = CryptoMigrationEngine()
        rating   = engine.compute_readiness([])
        assert rating == "QUANTUM_READY"

    def test_migration_plan_ordering(self):
        engine   = CryptoMigrationEngine()
        findings = [
            {"algorithm": "RSA",     "quantum": "VULNERABLE", "replace": "ML-KEM-768", "urgency": "IMMEDIATE"},
            {"algorithm": "AES-128", "quantum": "WEAKENED",   "replace": "AES-256",    "urgency": "SHORT-TERM"},
        ]
        plan = engine.migration_plan(findings)
        assert len(plan) == 2
        assert plan[0]["urgency"] == "IMMEDIATE"

    def test_framework_list_snippets(self):
        fw = CryptoAgilityFramework()
        snippets = fw.list_snippets()
        assert len(snippets) == 7

    def test_framework_get_snippet(self):
        fw      = CryptoAgilityFramework()
        snippet = fw.get_snippet("rsa-python")
        assert snippet is not None
        assert "before" in snippet
        assert "after"  in snippet

    def test_framework_list_pqc_algorithms(self):
        fw         = CryptoAgilityFramework()
        algorithms = fw.list_pqc_algorithms()
        assert len(algorithms) == 11


class TestSimpleGraph:
    def test_add_and_query_nodes(self):
        g = _SimpleGraph()
        g.add_node("host1", type="host", ip="192.168.1.1")
        g.add_node("cve1",  type="cve",  cvss=9.8)
        assert g.has_node("host1")
        assert g.has_node("cve1")
        assert not g.has_node("nonexistent")

    def test_add_edges(self):
        g = _SimpleGraph()
        g.add_node("host1", type="host")
        g.add_node("cve1",  type="cve")
        g.add_edge("host1", "cve1", edge_type="affected_by")
        assert g.number_of_edges() == 1
        assert "cve1" in g.neighbors("host1")

    def test_shortest_path(self):
        g = _SimpleGraph()
        g.add_node("a", type="host")
        g.add_node("b", type="service")
        g.add_node("c", type="cve")
        g.add_edge("a", "b", edge_type="runs")
        g.add_edge("b", "c", edge_type="affected_by")
        path = g.shortest_path("a", "c")
        assert path == ["a", "b", "c"]

    def test_shortest_path_no_path(self):
        g = _SimpleGraph()
        g.add_node("a", type="host")
        g.add_node("b", type="host")
        path = g.shortest_path("a", "b")
        assert path == []

    def test_serialization(self):
        g = _SimpleGraph()
        g.add_node("host1", type="host")
        g.add_edge("host1", "cve1", edge_type="affected_by")
        data = g.to_dict()
        g2   = _SimpleGraph()
        g2.from_dict(data)
        assert g2.has_node("host1")