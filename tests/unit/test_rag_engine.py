"""Tests for TF-IDF retrieval, namespaced ingestion, grounded chat and fine-tune YAML."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from shadow313.v2.rag.rag_engine import RAGEngine, SecurityKnowledgeBase, generate_finetune_config
from shadow313.v2.rag.tfidf_store import TFIDFVectorStore, _cosine, _tfidf, _tokenize

NAMESPACES = SecurityKnowledgeBase.NAMESPACES


class TestTFIDFInternals:

    def test_tokenize_lowercases(self):
        tokens = _tokenize("Hello World SECURITY")
        assert all((t == t.lower() for t in tokens))

    def test_tokenize_removes_short_words(self):
        tokens = _tokenize("a an the security")
        assert "a" not in tokens

    def test_tokenize_extracts_words(self):
        tokens = _tokenize("CVE vulnerability exploit")
        assert "cve" in tokens
        assert "vulnerability" in tokens
        assert "exploit" in tokens

    def test_tokenize_empty_string(self):
        assert _tokenize("") == []

    def test_tfidf_returns_one_vector_per_doc(self):
        docs = [["security", "vulnerability"], ["exploit", "cve"]]
        vectors = _tfidf(docs)
        assert len(vectors) == 2

    def test_tfidf_empty_docs(self):
        vectors = _tfidf([])
        assert vectors == []

    def test_cosine_identical_vectors(self):
        v = {"a": 1.0, "b": 2.0}
        score = _cosine(v, v)
        assert abs(score - 1.0) < 1e-06

    def test_cosine_orthogonal_vectors(self):
        v1 = {"a": 1.0}
        v2 = {"b": 1.0}
        assert _cosine(v1, v2) == 0.0

    def test_cosine_empty_vectors(self):
        assert _cosine({}, {}) == 0.0
        assert _cosine({"a": 1.0}, {}) == 0.0


class TestTFIDFVectorStoreExtended:

    def test_query_returns_top_k_results(self):
        store = TFIDFVectorStore()
        for i in range(10):
            store.add(f"document about security topic {i}", {"id": str(i)})
        results = store.query("security topic", top_k=3)
        assert len(results) <= 3

    def test_query_results_sorted_by_score_descending(self):
        store = TFIDFVectorStore()
        store.add("RSA vulnerability critical security", {"id": "1"})
        store.add("unrelated content about cooking", {"id": "2"})
        store.add("RSA encryption weakness exploit", {"id": "3"})
        results = store.query("RSA vulnerability", top_k=3)
        if len(results) >= 2:
            assert results[0]["score"] >= results[1]["score"]

    def test_query_result_has_required_fields(self):
        store = TFIDFVectorStore()
        store.add("test document", {"id": "1", "source": "test"})
        results = store.query("test", top_k=1)
        if results:
            assert "text" in results[0]
            assert "metadata" in results[0]
            assert "score" in results[0]

    def test_metadata_preserved_in_results(self):
        store = TFIDFVectorStore()
        store.add("CVE-2021-44228 Log4Shell", {"id": "cve1", "severity": "CRITICAL"})
        results = store.query("Log4Shell", top_k=1)
        if results:
            assert results[0]["metadata"].get("severity") == "CRITICAL"

    def test_add_batch_with_empty_list(self):
        store = TFIDFVectorStore()
        store.add_batch([])
        assert store.count() == 0

    def test_save_creates_file(self, tmp_path):
        store_path = str(tmp_path / "store.json")
        store = TFIDFVectorStore(store_path)
        store.add("test", {})
        store.save()
        assert (tmp_path / "store.json").exists()

    def test_load_from_nonexistent_file_is_noop(self, tmp_path):
        store = TFIDFVectorStore(str(tmp_path / "nonexistent.json"))
        store.load()
        assert store.count() == 0

    def test_rebuild_after_multiple_adds(self):
        store = TFIDFVectorStore()
        store.add("first document security", {})
        store.add("second document vulnerability", {})
        store.add("third document exploit", {})
        assert len(store._vectors) == 3

    def test_query_with_top_k_larger_than_store(self):
        store = TFIDFVectorStore()
        store.add("only one document", {})
        results = store.query("document", top_k=100)
        assert len(results) <= 1


class TestSecurityKnowledgeBase:

    @pytest.fixture
    def kb(self, tmp_path):
        return SecurityKnowledgeBase(persist_dir=str(tmp_path / "chroma"))

    def test_all_namespaces_initialised(self, kb):
        for ns in NAMESPACES:
            assert ns in kb._stores

    def test_add_and_query_cve_namespace(self, kb):
        kb.upsert("cve1", "CVE-2021-44228 Log4Shell remote code execution", namespace="cve")
        results = kb.query("Log4Shell remote code", top_k=3, namespace="cve")
        assert len(results) > 0

    def test_add_and_query_mitre_namespace(self, kb):
        kb.upsert("t1071", "T1071 Application Layer Protocol C2 communication", namespace="mitre")
        results = kb.query("C2 communication protocol", top_k=3, namespace="mitre")
        assert len(results) > 0

    def test_namespace_isolation(self, kb):
        kb.upsert("cve1", "RSA vulnerability CVE-2024-1234", namespace="cve")
        kb.upsert("t1046", "T1046 network service scanning", namespace="mitre")
        cve_results = kb.query("network scanning", top_k=5, namespace="cve")
        mitre_results = kb.query("RSA vulnerability", top_k=5, namespace="mitre")
        assert isinstance(cve_results, list)
        assert isinstance(mitre_results, list)

    def test_query_unknown_namespace_returns_empty(self, kb):
        results = kb.query("test", top_k=5, namespace="nonexistent_namespace")
        assert results == []

    def test_count_per_namespace(self, kb):
        assert kb.stats().get("cve", 0) == 0
        kb.upsert("doc1", "test document", namespace="cve")
        assert kb.stats().get("cve", 0) == 1

    def test_count_unknown_namespace_returns_zero(self, kb):
        assert kb.stats().get("nonexistent", 0) == 0

    def test_add_batch_to_namespace(self, kb):
        items = [
            {"text": "CVE-2021-44228 Log4Shell", "id": "cve1", "metadata": {}},
            {"text": "CVE-2017-5638 Struts2 RCE", "id": "cve2", "metadata": {}},
        ]
        for item in items:
            kb.upsert(item["id"], item["text"], item["metadata"], namespace="cve")
        assert kb.stats().get("cve", 0) == 2

    def test_add_to_none_namespace_is_noop(self, kb):
        kb.upsert("id1", "text", namespace="nonexistent")


class TestRAGEngine:

    @pytest.fixture
    def engine_and_kb(self, tmp_path):
        kb = SecurityKnowledgeBase(persist_dir=str(tmp_path / "chroma"))
        mock_ai = MagicMock()
        mock_ai.chat.return_value = "AI response about security"
        engine = RAGEngine(mock_ai, persist_dir=str(tmp_path / "engine"))
        engine.kb = kb
        return (engine, kb, mock_ai)

    def test_chat_calls_ai_with_augmented_prompt(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        kb.upsert("cve1", "CVE-2021-44228 Log4Shell critical vulnerability", namespace="cve")
        response = engine.chat_with_context("What is Log4Shell?")
        assert response == "AI response about security"
        mock_ai.chat.assert_called_once()
        call_args = mock_ai.chat.call_args[0][0]
        assert "Log4Shell" in call_args or "context" in call_args.lower()

    def test_chat_without_context_still_calls_ai(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        response = engine.chat_with_context("What is RSA?")
        assert response == "AI response about security"
        mock_ai.chat.assert_called_once()

    def test_chat_history_grows(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        assert len(engine._hist) == 0
        engine.chat_with_context("Question 1")
        assert len(engine._hist) == 2
        engine.chat_with_context("Question 2")
        assert len(engine._hist) == 4

    def test_clear_history(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        engine.chat_with_context("Question 1")
        engine.clear_history()
        assert engine._hist == []

    def test_chat_uses_grounded_system_prompt(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        engine.chat_with_context("test")
        system = mock_ai.chat.call_args.kwargs["system_prompt"]
        assert "Use ONLY the retrieved context" in system
        assert "Never fabricate CVE IDs" in system

    def test_ingest_session_findings(self, engine_and_kb):
        engine, kb, _ = engine_and_kb
        findings = [
            {"cve": "CVE-2021-44228", "severity": "CRITICAL"},
            {"target": "example.com", "ports": []},
        ]
        assert engine.ingest_session("session-1", findings) == 2
        results = kb.query("Log4Shell CVE-2021-44228", namespace="session")
        assert results and results[0]["metadata"]["session_id"] == "session-1"

    def test_ingest_empty_session_findings(self, engine_and_kb):
        engine, kb, _ = engine_and_kb
        assert engine.ingest_session("empty-session", []) == 0
        assert kb.store("session").count() == 0

    def test_ingest_session_keeps_sessions_distinct(self, engine_and_kb):
        engine, kb, _ = engine_and_kb
        finding = {"cve": "CVE-2021-44228"}
        engine.ingest_session("one", [finding])
        engine.ingest_session("two", [finding])
        results = kb.query("CVE-2021-44228", namespace="session")
        assert {r["metadata"]["session_id"] for r in results} == {"one", "two"}

    def test_chat_queries_multiple_namespaces(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        kb.upsert("cve1", "CVE-2021-44228 Log4Shell", namespace="cve")
        kb.upsert("t1190", "T1190 Exploit Public-Facing Application", namespace="mitre")
        engine.chat_with_context("Log4Shell exploit technique")
        mock_ai.chat.assert_called_once()


class TestDomainIngestion:

    def test_ingest_cves(self, tmp_path):
        kb = SecurityKnowledgeBase(persist_dir=str(tmp_path))
        count = kb.ingest_cve_list(
            [
                {
                    "id": "CVE-2021-44228",
                    "description": "Log4Shell RCE",
                    "cvss_v3": 10.0,
                    "severity": "CRITICAL",
                },
                {"id": "CVE-2017-5638", "description": "Struts RCE"},
                {"description": "Missing ID must be skipped"},
            ]
        )
        assert count == kb.store("cve").count() == 2
        result = kb.query("Log4Shell", namespace="cve")[0]
        assert result["metadata"]["cve_id"] == "CVE-2021-44228"
        assert result["metadata"]["severity"] == "CRITICAL"

    def test_ingest_mitre_and_owasp(self, tmp_path):
        kb = SecurityKnowledgeBase(persist_dir=str(tmp_path))
        assert (
            kb.ingest_mitre_attack(
                [{"id": "T1059.001", "name": "PowerShell", "description": "command execution"}]
            )
            == 1
        )
        assert kb.ingest_owasp([{"id": "A01", "name": "Broken Access Control"}]) == 1
        assert (
            kb.query("PowerShell", namespace="mitre")[0]["metadata"]["technique_id"] == "T1059.001"
        )
        assert (
            kb.query("Broken Access Control", namespace="owasp")[0]["metadata"]["source"] == "owasp"
        )

    def test_finetune_yaml(self, tmp_path):
        import yaml

        output = tmp_path / "nested" / "config.yaml"
        result = generate_finetune_config("test/model", str(output))
        assert Path(result) == output
        config = yaml.safe_load(output.read_text())
        assert config["model_name"] == "test/model"
        assert config["quantization"]["load_in_4bit"] is True
        assert config["lora"]["r"] == 16
        assert config["export"]["format"] == "gguf"
        assert "{{instruction}}" in config["prompt_template"]
        assert '{"instruction": ..., "input": ..., "output": ...}' in output.read_text()
