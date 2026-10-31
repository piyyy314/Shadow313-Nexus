"""Unit tests — shadow313.core (v2)"""

import pytest

from shadow313.core.ai_engine import AIEngine
from shadow313.core.config import Config
from shadow313.core.output import OutputFormatter
from shadow313.core.session import Session


@pytest.fixture(autouse=True)
def isolate_ai_environment(monkeypatch):
    for key in ("SHADOW313_AI_BACKEND", "SHADOW313_AI_MODEL", "SHADOW313_AI_ENDPOINT"):
        monkeypatch.delenv(key, raising=False)


class TestConfig:
    def test_defaults_loaded(self, tmp_path):
        cfg = Config(config_path=str(tmp_path / "config.yaml"))
        assert cfg.get("ai", "backend") == "ollama"
        assert cfg.get("ai", "model") == "mistral:7b"
        assert cfg.get("output", "format") == "rich"

    def test_deep_merge(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("shadow313:\n  ai:\n    model: llama3:8b\n    backend: ollama\n")
        cfg = Config(config_path=str(config_file))
        assert cfg.get("ai", "model") == "llama3:8b"
        assert cfg.get("ai", "backend") == "ollama"
        assert cfg.get("ai", "context_window") == 8192

    def test_env_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SHADOW313_AI_MODEL", "phi3:mini")
        cfg = Config(config_path=str(tmp_path / "config.yaml"))
        assert cfg.get("ai", "model") == "phi3:mini"

    def test_set_and_get(self, tmp_path):
        cfg = Config(config_path=str(tmp_path / "config.yaml"))
        cfg.set("ai", "model", "gpt-4o")
        assert cfg.get("ai", "model") == "gpt-4o"

    def test_get_default(self, tmp_path):
        cfg = Config(config_path=str(tmp_path / "config.yaml"))
        assert cfg.get("nonexistent", "key", default="fallback") == "fallback"

    def test_v2_sections_present(self, tmp_path):
        cfg = Config(config_path=str(tmp_path / "config.yaml"))
        assert cfg.get("rag", "top_k") == 5
        assert cfg.get("agent", "default_approval") == "gate_high"
        assert cfg.get("dashboard", "port") == 7313


class TestSession:
    def test_creates_session_dir(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        assert s.session_dir.exists()

    def test_unique_ids(self, tmp_path):
        s1 = Session(sessions_dir=str(tmp_path))
        s2 = Session(sessions_dir=str(tmp_path))
        assert s1.id != s2.id

    def test_resume_session(self, tmp_path):
        s1 = Session(sessions_dir=str(tmp_path))
        sid = s1.id
        s2 = Session.resume(sid, sessions_dir=str(tmp_path))
        assert s2.id == sid

    def test_write_and_read_json(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        data = {"test": True, "value": 42, "list": [1, 2, 3]}
        s.write("test.json", data)
        loaded = s.read("test.json")
        assert loaded == data

    def test_audit_log(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        s.audit("recon", "start", "example.com")
        s.audit("recon", "complete", "/path/to/file")
        log = s.get_audit_log()
        assert len(log) == 2
        assert log[0]["module"] == "recon"
        assert log[0]["action"] == "start"

    def test_set_target(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        s.set_target("example.com")
        assert s.target == "example.com"

    def test_summary(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        s.write("recon.json", {"test": True})
        summary = s.summary()
        assert summary["session_id"] == s.id
        assert "recon.json" in summary["files"]

    def test_list_sessions(self, tmp_path):
        s1 = Session(sessions_dir=str(tmp_path))
        s2 = Session(sessions_dir=str(tmp_path))
        sessions = Session.list_sessions(sessions_dir=str(tmp_path))
        ids = [s.get("session_id") for s in sessions]
        assert s1.id in ids
        assert s2.id in ids


class TestOutputFormatter:
    def test_instantiation(self):
        out = OutputFormatter(fmt="json", color=False)
        assert out.fmt == "json"

    def test_json_mode_suppresses_info(self, capsys):
        out = OutputFormatter(fmt="json", color=False)
        out.info("should not print")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_error_always_prints(self, capsys):
        out = OutputFormatter(fmt="json", color=False)
        out.error("this should print")
        captured = capsys.readouterr()
        assert "this should print" in captured.err


class TestAIEngine:
    def test_disabled_backend(self):
        ai = AIEngine({"backend": "disabled"})
        assert not ai.is_available()
        response = ai.chat("test prompt")
        assert "disabled" in response.lower()

    def test_unknown_backend(self):
        ai = AIEngine({"backend": "unknown_backend"})
        response = ai.chat("test")
        assert "Unknown" in response

    def test_list_models_non_ollama(self):
        ai = AIEngine({"backend": "openai"})
        assert ai.list_models() == []
