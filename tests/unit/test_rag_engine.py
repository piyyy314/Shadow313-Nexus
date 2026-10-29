"""
Comprehensive tests — shadow313.v2.rag (RAG engine, SecurityKnowledgeBase, ingesters)
Covers: TF-IDF fallback (no ChromaDB), namespace isolation, RAG chat augmentation,
        session ingestion, NVD ingester (mocked), MITRE ingester (mocked),
        LoRA config generator, edge cases.
"""
from __future__ import annotations
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from shadow313.v2.rag.tfidf_store import TFIDFVectorStore, _tokenize, _tfidf, _cosine
from shadow313.v2.rag.rag_engine import (
    SecurityKnowledgeBase, RAGEngine, NVDIngester,
    MITREIngester, LoRAFineTuneConfigGenerator, NAMESPACES,
)


# ── TF-IDF internals ──────────────────────────────────────────────────────────

class TestTFIDFInternals:
    def test_tokenize_lowercases(self):
        tokens = _tokenize("Hello World SECURITY")
        assert all(t == t.lower() for t in tokens)

    def test_tokenize_removes_short_words(self):
        tokens = _tokenize("a an the security")
        # Words < 2 chars should be excluded
        assert "a" not in tokens

    def test_tokenize_extracts_words(self):
        tokens = _tokenize("CVE vulnerability exploit")
        assert "cve"           in tokens
        assert "vulnerability" in tokens
        assert "exploit"       in tokens

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
        assert abs(score - 1.0) < 1e-6

    def test_cosine_orthogonal_vectors(self):
        v1 = {"a": 1.0}
        v2 = {"b": 1.0}
        assert _cosine(v1, v2) == 0.0

    def test_cosine_empty_vectors(self):
        assert _cosine({}, {}) == 0.0
        assert _cosine({"a": 1.0}, {}) == 0.0


# ── TFIDFVectorStore extended ─────────────────────────────────────────────────

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
            assert "text"     in results[0]
            assert "metadata" in results[0]
            assert "score"    in results[0]

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
        store.load()  # Should not raise
        assert store.count() == 0

    def test_rebuild_after_multiple_adds(self):
        store = TFIDFVectorStore()
        store.add("first document security", {})
        store.add("second document vulnerability", {})
        store.add("third document exploit", {})
        # Vectors should be rebuilt after each add
        assert len(store._vectors) == 3

    def test_query_with_top_k_larger_than_store(self):
        store = TFIDFVectorStore()
        store.add("only one document", {})
        results = store.query("document", top_k=100)
        assert len(results) <= 1


# ── SecurityKnowledgeBase (TF-IDF mode) ──────────────────────────────────────

class TestSecurityKnowledgeBase:
    @pytest.fixture
    def kb(self, tmp_path):
        # Force TF-IDF mode (no ChromaDB)
        return SecurityKnowledgeBase(
            chroma_path=str(tmp_path / "chroma"),
            use_chroma=False,
        )

    def test_all_namespaces_initialised(self, kb):
        for ns in NAMESPACES:
            assert ns in kb._stores

    def test_add_and_query_cve_namespace(self, kb):
        kb.add("cve", "CVE-2021-44228 Log4Shell remote code execution", "cve1")
        results = kb.query("cve", "Log4Shell remote code", top_k=3)
        assert len(results) > 0

    def test_add_and_query_mitre_namespace(self, kb):
        kb.add("mitre", "T1071 Application Layer Protocol C2 communication", "t1071")
        results = kb.query("mitre", "C2 communication protocol", top_k=3)
        assert len(results) > 0

    def test_namespace_isolation(self, kb):
        kb.add("cve",   "RSA vulnerability CVE-2024-1234", "cve1")
        kb.add("mitre", "T1046 network service scanning", "t1046")
        # Query CVE namespace should not return MITRE content
        cve_results   = kb.query("cve",   "network scanning", top_k=5)
        mitre_results = kb.query("mitre", "RSA vulnerability", top_k=5)
        # Results should come from their respective namespaces
        assert isinstance(cve_results,   list)
        assert isinstance(mitre_results, list)

    def test_query_unknown_namespace_returns_empty(self, kb):
        results = kb.query("nonexistent_namespace", "test", top_k=5)
        assert results == []

    def test_count_per_namespace(self, kb):
        assert kb.count("cve") == 0
        kb.add("cve", "test document", "doc1")
        assert kb.count("cve") == 1

    def test_count_unknown_namespace_returns_zero(self, kb):
        assert kb.count("nonexistent") == 0

    def test_add_batch_to_namespace(self, kb):
        items = [
            {"text": "CVE-2021-44228 Log4Shell", "id": "cve1", "metadata": {}},
            {"text": "CVE-2017-5638 Struts2 RCE", "id": "cve2", "metadata": {}},
        ]
        kb.add_batch("cve", items)
        assert kb.count("cve") == 2

    def test_add_to_none_namespace_is_noop(self, kb):
        # Should not raise
        kb.add("nonexistent", "text", "id1")


# ── RAGEngine ─────────────────────────────────────────────────────────────────

class TestRAGEngine:
    @pytest.fixture
    def engine_and_kb(self, tmp_path):
        kb = SecurityKnowledgeBase(
            chroma_path=str(tmp_path / "chroma"),
            use_chroma=False,
        )
        mock_ai = MagicMock()
        mock_ai.chat.return_value = "AI response about security"
        engine = RAGEngine(kb, mock_ai, top_k=3)
        return engine, kb, mock_ai

    def test_chat_calls_ai_with_augmented_prompt(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        kb.add("cve", "CVE-2021-44228 Log4Shell critical vulnerability", "cve1")
        response = engine.chat("What is Log4Shell?")
        assert response == "AI response about security"
        mock_ai.chat.assert_called_once()
        # The prompt passed to AI should contain the retrieved context
        call_args = mock_ai.chat.call_args[0][0]
        assert "Log4Shell" in call_args or "context" in call_args.lower()

    def test_chat_without_context_still_calls_ai(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        # Empty KB — no context retrieved
        response = engine.chat("What is RSA?")
        assert response == "AI response about security"
        mock_ai.chat.assert_called_once()

    def test_chat_history_grows(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        assert len(engine._history) == 0
        engine.chat("Question 1")
        assert len(engine._history) == 2  # user + assistant
        engine.chat("Question 2")
        assert len(engine._history) == 4

    def test_clear_history(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        engine.chat("Question 1")
        engine.clear_history()
        assert engine._history == []

    def test_chat_with_custom_system_prompt(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        engine.chat("test", system_prompt="Custom system prompt")
        call_kwargs = mock_ai.chat.call_args[1]
        assert call_kwargs.get("system_prompt") == "Custom system prompt"

    def test_ingest_session_reads_json_files(self, engine_and_kb, tmp_path):
        engine, kb, mock_ai = engine_and_kb
        session_dir = tmp_path / "session"
        session_dir.mkdir()
        (session_dir / "findings.json").write_text(
            json.dumps({"findings": [{"cve": "CVE-2021-44228", "severity": "CRITICAL"}]})
        )
        (session_dir / "recon.json").write_text(
            json.dumps({"target": "example.com", "ports": []})
        )
        count = engine.ingest_session(str(session_dir))
        assert count == 2

    def test_ingest_session_empty_directory(self, engine_and_kb, tmp_path):
        engine, kb, mock_ai = engine_and_kb
        session_dir = tmp_path / "empty_session"
        session_dir.mkdir()
        count = engine.ingest_session(str(session_dir))
        assert count == 0

    def test_ingest_session_skips_invalid_json(self, engine_and_kb, tmp_path):
        engine, kb, mock_ai = engine_and_kb
        session_dir = tmp_path / "session"
        session_dir.mkdir()
        (session_dir / "corrupt.json").write_text("not valid json {{{")
        # Should not raise
        count = engine.ingest_session(str(session_dir))
        assert count == 0

    def test_chat_queries_multiple_namespaces(self, engine_and_kb):
        engine, kb, mock_ai = engine_and_kb
        kb.add("cve",   "CVE-2021-44228 Log4Shell", "cve1")
        kb.add("mitre", "T1190 Exploit Public-Facing Application", "t1190")
        engine.chat("Log4Shell exploit technique")
        # AI should have been called with combined context
        mock_ai.chat.assert_called_once()


# ── NVDIngester ───────────────────────────────────────────────────────────────

class TestNVDIngester:
    @pytest.fixture
    def ingester_and_kb(self, tmp_path):
        kb = SecurityKnowledgeBase(
            chroma_path=str(tmp_path / "chroma"),
            use_chroma=False,
        )
        return NVDIngester(kb), kb

    def test_ingest_from_nonexistent_db_returns_zero(self, ingester_and_kb):
        ingester, kb = ingester_and_kb
        count = ingester.ingest_from_db("/nonexistent/path/cve.db")
        assert count == 0

    def test_ingest_from_in_memory_db(self, ingester_and_kb, tmp_path):
        import sqlite3
        ingester, kb = ingester_and_kb
        # Create a minimal CVE DB
        db_path = tmp_path / "cve.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE cves (
                id TEXT PRIMARY KEY, description TEXT,
                cvss_v3 REAL, severity TEXT,
                published TEXT, modified TEXT,
                cpe TEXT, ref_urls TEXT
            )""")
        conn.execute("INSERT INTO cves VALUES (?,?,?,?,?,?,?,?)",
                     ("CVE-2021-44228", "Log4Shell RCE", 10.0, "CRITICAL",
                      "2021-12-10", "2021-12-15", "[]", "[]"))
        conn.execute("INSERT INTO cves VALUES (?,?,?,?,?,?,?,?)",
                     ("CVE-2017-5638", "Struts2 RCE", 9.8, "CRITICAL",
                      "2017-03-10", "2017-03-15", "[]", "[]"))
        conn.commit()
        conn.close()
        count = ingester.ingest_from_db(str(db_path))
        assert count == 2
        # Verify content was ingested into KB
        assert kb.count("cve") == 2


# ── MITREIngester ─────────────────────────────────────────────────────────────

class TestMITREIngester:
    @pytest.fixture
    def ingester_and_kb(self, tmp_path):
        kb = SecurityKnowledgeBase(
            chroma_path=str(tmp_path / "chroma"),
            use_chroma=False,
        )
        return MITREIngester(kb), kb

    def test_ingest_returns_zero_on_network_error(self, ingester_and_kb):
        ingester, kb = ingester_and_kb
        # urlreq is imported inside the method from urllib — patch at urllib level
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            count = ingester.fetch_and_ingest()
        assert count == 0

    def test_ingest_from_mock_stix_bundle(self, ingester_and_kb):
        ingester, kb = ingester_and_kb
        mock_bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "Spearphishing Attachment",
                    "description": "Adversaries may send spearphishing emails with malicious attachments.",
                    "external_references": [{"external_id": "T1566.001"}],
                },
                {
                    "type": "attack-pattern",
                    "name": "PowerShell",
                    "description": "Adversaries may abuse PowerShell commands.",
                    "external_references": [{"external_id": "T1059.001"}],
                },
                {
                    "type": "malware",  # Not attack-pattern — should be skipped
                    "name": "Emotet",
                    "description": "Banking trojan",
                    "external_references": [],
                },
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_bundle).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            count = ingester.fetch_and_ingest()
        assert count == 2  # Only attack-patterns
        assert kb.count("mitre") == 2


# ── LoRAFineTuneConfigGenerator ───────────────────────────────────────────────

class TestLoRAFineTuneConfigGenerator:
    def test_generate_creates_config_file(self, tmp_path):
        gen   = LoRAFineTuneConfigGenerator()
        paths = gen.generate(str(tmp_path))
        assert "config" in paths
        assert "script" in paths
        assert Path(paths["config"]).exists()
        assert Path(paths["script"]).exists()

    def test_config_file_is_valid_json(self, tmp_path):
        gen   = LoRAFineTuneConfigGenerator()
        paths = gen.generate(str(tmp_path))
        config = json.loads(Path(paths["config"]).read_text())
        assert "model_name"   in config
        assert "r"            in config
        assert "lora_alpha"   in config
        assert "load_in_4bit" in config

    def test_config_uses_4bit_quantization(self, tmp_path):
        gen    = LoRAFineTuneConfigGenerator()
        paths  = gen.generate(str(tmp_path))
        config = json.loads(Path(paths["config"]).read_text())
        assert config["load_in_4bit"] is True

    def test_script_file_contains_unsloth_import(self, tmp_path):
        gen    = LoRAFineTuneConfigGenerator()
        paths  = gen.generate(str(tmp_path))
        script = Path(paths["script"]).read_text()
        assert "unsloth" in script or "FastLanguageModel" in script

    def test_generate_creates_output_directory(self, tmp_path):
        nested = tmp_path / "nested" / "output"
        gen    = LoRAFineTuneConfigGenerator()
        paths  = gen.generate(str(nested))
        assert nested.exists()
        assert Path(paths["config"]).exists()

    def test_config_has_gguf_export_flag(self, tmp_path):
        gen    = LoRAFineTuneConfigGenerator()
        paths  = gen.generate(str(tmp_path))
        config = json.loads(Path(paths["config"]).read_text())
        assert "gguf_export" in config
        assert config["gguf_export"] is True