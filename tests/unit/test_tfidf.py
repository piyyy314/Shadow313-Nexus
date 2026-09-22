"""Unit tests — shadow313.v2.rag TF-IDF vector store v4"""
import pytest
from shadow313.v2.rag.rag_engine import RAGEngine, TFIDFVectorStore, SecurityKnowledgeBase


class TestTFIDFVectorStore:
    def test_upsert_and_query(self):
        store = TFIDFVectorStore()
        store.upsert("doc1", "OpenSSH remote code execution vulnerability CVE-2024-1234",
                     {"source": "nvd"}, namespace="cve")
        results = store.query("OpenSSH vulnerability", top_k=5, namespace="cve")
        assert len(results) >= 1
        assert results[0]["id"] == "doc1"

    def test_query_empty_store(self):
        store = TFIDFVectorStore()
        results = store.query("anything", top_k=5)
        assert results == []

    def test_upsert_replaces_existing(self):
        store = TFIDFVectorStore()
        store.upsert("doc1", "original content", {}, namespace="general")
        store.upsert("doc1", "updated content",  {}, namespace="general")
        assert store.count("general") == 1

    def test_count_by_namespace(self):
        store = TFIDFVectorStore()
        store.upsert("cve1", "CVE content",  {}, namespace="cve")
        store.upsert("cve2", "CVE content2", {}, namespace="cve")
        store.upsert("gen1", "General content", {}, namespace="general")
        assert store.count("cve")     == 2
        assert store.count("general") == 1
        assert store.count()          == 3

    def test_query_namespace_filter(self):
        store = TFIDFVectorStore()
        store.upsert("cve1", "SQL injection vulnerability", {}, namespace="cve")
        store.upsert("gen1", "SQL injection general info",  {}, namespace="general")
        results = store.query("SQL injection", top_k=5, namespace="cve")
        assert all(r["id"].startswith("cve") for r in results)

    def test_top_k_limit(self):
        store = TFIDFVectorStore()
        for i in range(10):
            store.upsert(f"doc{i}", f"security vulnerability number {i}", {})
        results = store.query("security vulnerability", top_k=3)
        assert len(results) <= 3

    def test_deduplication_in_results(self):
        """FIX: results should not contain duplicate doc IDs."""
        store = TFIDFVectorStore()
        store.upsert("doc1", "test content security", {})
        results = store.query("test content security", top_k=10)
        ids = [r["id"] for r in results]
        assert len(ids) == len(set(ids))

    def test_score_is_float(self):
        store = TFIDFVectorStore()
        store.upsert("doc1", "test content", {})
        results = store.query("test", top_k=1)
        if results:
            assert isinstance(results[0]["score"], float)

    def test_shannon_entropy_calculation(self):
        """Verify TF-IDF tokenization handles various inputs."""
        store = TFIDFVectorStore()
        tokens = store._tokenize("Hello World! CVE-2024-1234 test123")
        assert "hello" in tokens
        assert "world" in tokens
        assert "cve" in tokens
        assert "2024" in tokens

    def test_multiple_queries_consistent(self):
        store = TFIDFVectorStore()
        store.upsert("doc1", "Apache HTTP Server vulnerability", {})
        store.upsert("doc2", "Nginx web server security issue", {})
        r1 = store.query("Apache vulnerability", top_k=2)
        r2 = store.query("Apache vulnerability", top_k=2)
        assert [r["id"] for r in r1] == [r["id"] for r in r2]


class TestSecurityKnowledgeBase:
    def test_init_uses_tfidf_fallback(self, tmp_path):
        """When ChromaDB is not installed, should use TF-IDF fallback."""
        kb = SecurityKnowledgeBase(chroma_path=str(tmp_path / "chroma"))
        # Should not raise
        kb.upsert("test1", "test content", {}, namespace="general")

    def test_upsert_and_query(self, tmp_path):
        kb = SecurityKnowledgeBase(chroma_path=str(tmp_path / "chroma"))
        kb.upsert("cve1", "Log4Shell remote code execution CVE-2021-44228",
                  {"cvss": 10.0}, namespace="cve")
        results = kb.query("Log4Shell", top_k=5, namespace="cve")
        assert len(results) >= 1

    def test_stats_returns_dict(self, tmp_path):
        kb = SecurityKnowledgeBase(chroma_path=str(tmp_path / "chroma"))
        stats = kb.stats()
        assert "backend" in stats
        assert "namespaces" in stats
        assert stats["backend"] in ("chromadb", "tfidf")

    def test_all_namespaces_in_stats(self, tmp_path):
        kb = SecurityKnowledgeBase(chroma_path=str(tmp_path / "chroma"))
        stats = kb.stats()
        for ns in ("cve", "mitre", "owasp", "session", "general"):
            assert ns in stats["namespaces"]


class _FakeAI:
    def __init__(self):
        self.prompts = []

    def chat(self, user_prompt, system_prompt=None):
        self.prompts.append((user_prompt, system_prompt))
        return "stub response"


class _FakeKB:
    def query(self, query, namespace="cve", top_k=5):
        return [{
            "id": "doc1",
            "text": "Apache HTTP Server vulnerability context",
            "namespace": namespace,
            "score": 0.75,
        }]

    def query_all(self, query, top_k=5):
        return []


class TestRAGEngine:
    def test_chat_with_context_includes_history(self):
        ai = _FakeAI()
        rag = RAGEngine(ai)
        rag.kb = _FakeKB()
        rag._hist = [
            {"role": "user", "content": "Earlier question"},
            {"role": "assistant", "content": "Earlier answer"},
        ]

        answer = rag.chat_with_context("What CVEs affect Apache?")

        assert answer == "stub response"
        prompt, system_prompt = ai.prompts[0]
        assert "RETRIEVED CONTEXT:" in prompt
        assert "CONVERSATION HISTORY:\nUser: Earlier question\nAssistant: Earlier answer\n\n" in prompt
        assert "QUESTION: What CVEs affect Apache?" in prompt
        assert system_prompt is not None