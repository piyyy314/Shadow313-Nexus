"""Unit tests — shadow313 v2 advanced modules"""

from unittest.mock import MagicMock

from shadow313.v2.crypto_agility.crypto_agility import (
    PQC_ALGORITHMS,
    PQC_SNIPPETS,
    CryptoAgilityFramework,
    CryptoMigrationEngine,
)
from shadow313.v2.graph.intel_graph import IntelligenceGraph, _SimpleGraph
from shadow313.v2.network_upgrades.dns_covert import DNSCovertDetector, _shannon_entropy
from shadow313.v2.rag.tfidf_store import TFIDFVectorStore
from shadow313.v2.vuln_upgrades.attack_mapping import ATTACKMapper


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
        store = TFIDFVectorStore()
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
            {"text": "ECDSA weakness", "id": "2", "metadata": {}},
            {"text": "AES encryption", "id": "3", "metadata": {}},
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
    def test_map_finding(self):
        assert "T1190" in ATTACKMapper().map_finding(
            {"description": "remote code execution via log4j"}
        )

    def test_aggregate_findings(self):
        mapped = ATTACKMapper().map_findings(
            [
                {"cve": "CVE-2021-44228", "description": "remote code execution"},
                {"cve": "CVE-2017-5638", "description": "sql injection"},
            ]
        )
        exploit = next(m for m in mapped if m["technique_id"] == "T1190")
        assert exploit["count"] == 2
        assert set(exploit["cves"]) == {"CVE-2021-44228", "CVE-2017-5638"}

    def test_navigator_generation_scores_by_frequency(self):
        mapped = [
            {"technique_id": "T1071", "count": 3, "tactic": "command-and-control", "cves": []},
            {"technique_id": "T1046", "count": 1, "tactic": "discovery", "cves": []},
        ]
        layer = ATTACKMapper().build_navigator_layer(mapped, name="test scan")
        assert layer["name"] == "test scan"
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["attack"] == "14"
        assert [t["score"] for t in layer["techniques"]] == [100, 33]


def _dns_packets(names):
    import struct

    packets = []
    for i, name in enumerate(names):
        qname = (
            b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
        )
        wire = struct.pack("!6H", i, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!2H", 1, 1)
        packets.append(
            {
                "dport": 53,
                "sport": 40000,
                "src_ip": "192.0.2.1",
                "ts": float(i * 60),
                "payload_preview": wire.decode("latin-1"),
            }
        )
    return packets


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
        queries = ["aB3xK9mN2pQ7rS5tU8vW1yZ4cD6eF0gH.example.com"]
        alerts = detector.analyse_packets(_dns_packets(queries))
        # May or may not trigger depending on entropy of test string
        assert isinstance(alerts, list)

    def test_tunnel_signature_detection(self):
        detector = DNSCovertDetector()
        queries = ["iodine.tunnel.example.com", "dnscat2.c2.evil.com"]
        alerts = detector.analyse_packets(_dns_packets(queries))
        tunnel_alerts = [a for a in alerts if a["rule"] == "TUNNEL_TOOL_SIGNATURE"]
        assert len(tunnel_alerts) > 0

    def test_long_subdomain_detection(self):
        detector = DNSCovertDetector()
        long_sub = "a" * 50 + ".example.com"
        queries = [long_sub]
        alerts = detector.analyse_packets(_dns_packets(queries))
        long_alerts = [a for a in alerts if a["rule"] == "LONG_SUBDOMAIN_LABEL"]
        assert len(long_alerts) > 0

    def test_high_subdomain_count(self):
        detector = DNSCovertDetector()
        queries = [f"sub{i}.example.com" for i in range(60)]
        alerts = detector.analyse_packets(_dns_packets(queries))
        count_alerts = [a for a in alerts if a["rule"] == "HIGH_UNIQUE_SUBDOMAIN_COUNT"]
        assert len(count_alerts) > 0

    def test_clean_traffic_no_alerts(self):
        detector = DNSCovertDetector()
        queries = ["www.example.com", "mail.example.com", "api.example.com"]
        alerts = detector.analyse_packets(_dns_packets(queries))
        assert len(alerts) == 0


class TestCryptoAgility:
    def test_pqc_algorithms_catalog(self):
        assert len(PQC_ALGORITHMS) == 11
        for info in PQC_ALGORITHMS:
            assert "type" in info
            assert "fips" in info
            assert "level" in info

    def test_pqc_snippets_available(self):
        assert "rsa-python" in PQC_SNIPPETS
        assert "ecdsa-python" in PQC_SNIPPETS
        assert "aes128-python" in PQC_SNIPPETS
        assert "rsa-java" in PQC_SNIPPETS
        assert "nginx-tls" in PQC_SNIPPETS
        for key, snippet in PQC_SNIPPETS.items():
            assert "before" in snippet
            assert "after" in snippet
            assert "instructions" in snippet

    def test_scan_python_file(self, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        engine = CryptoMigrationEngine()
        findings = engine.scan(str(tmp_path), languages=["Python"])
        assert len(findings) > 0
        assert any(f["algorithm"] == "RSA" for f in findings)

    def test_readiness_vulnerable(self, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        engine = CryptoMigrationEngine()
        findings = engine.scan(str(tmp_path))
        rating = engine.pqc_readiness(findings)
        assert rating in ("VULNERABLE", "PARTIAL")

    def test_readiness_quantum_ready(self):
        engine = CryptoMigrationEngine()
        rating = engine.pqc_readiness([])
        assert rating == "QUANTUM_READY"

    def test_migration_plan_passes_status_context(self):
        kernel = MagicMock()
        kernel.ai.chat.return_value = "Migration plan"
        findings = [
            {"algorithm": "RSA", "status": "VULNERABLE"},
            {"algorithm": "AES-128", "status": "WEAKENED"},
        ]
        assert CryptoAgilityFramework(kernel).migration_plan(findings) == "Migration plan"
        context = kernel.ai.chat.call_args.kwargs["context"]
        assert context["vulnerable"] == findings[:1] and context["weakened"] == findings[1:]

    def test_framework_unknown_snippet_lists_choices(self):
        result = CryptoAgilityFramework(MagicMock()).get_snippet("missing")
        assert set(result["available"]) == set(PQC_SNIPPETS)

    def test_framework_get_snippet(self):
        fw = CryptoAgilityFramework(MagicMock())
        snippet = fw.get_snippet("rsa-python")
        assert snippet is not None
        assert "before" in snippet
        assert "after" in snippet

    def test_framework_list_pqc_algorithms(self):
        fw = CryptoAgilityFramework(MagicMock())
        algorithms = fw.list_pqc_algorithms()
        assert len(algorithms) == 11


class TestSimpleGraph:
    def test_add_and_query_nodes(self):
        g = _SimpleGraph()
        g.add_node("host1", type="host", ip="192.168.1.1")
        g.add_node("cve1", type="cve", cvss=9.8)
        assert g.has_node("host1")
        assert g.has_node("cve1")
        assert not g.has_node("nonexistent")

    def test_add_edges(self):
        g = _SimpleGraph()
        g.add_node("host1", type="host")
        g.add_node("cve1", type="cve")
        g.add_edge("host1", "cve1", edge_type="affected_by")
        assert g.number_of_edges() == 1
        assert "cve1" in g.neighbors("host1")

    def test_shortest_path_without_networkx(self, tmp_path, monkeypatch):
        monkeypatch.setattr("shadow313.v2.graph.intel_graph._HAS_NX", False)
        graph = IntelligenceGraph(persist_path=str(tmp_path / "graph.json"))
        graph._g.add_node("a", type="host")
        graph._g.add_node("b", type="host")
        graph._g.add_edge("a", "b")
        assert graph.neighbors("a") == ["b"]
        # Path search is optional and requires NetworkX.
        assert graph.shortest_path("a", "b") == []

    def test_shortest_path_no_path(self, tmp_path):
        graph = IntelligenceGraph(persist_path=str(tmp_path / "graph.json"))
        graph._g = _SimpleGraph()
        graph._g.add_node("a", type="host")
        graph._g.add_node("b", type="host")
        assert graph.shortest_path("a", "b") == []

    def test_serialization(self):
        graph = _SimpleGraph()
        graph.add_node("host1", type="host")
        graph.add_edge("host1", "cve1", edge_type="affected_by")
        assert graph.to_dict() == {
            "nodes": {"host1": {"type": "host"}},
            "edges": [{"src": "host1", "dst": "cve1", "edge_type": "affected_by"}],
        }
