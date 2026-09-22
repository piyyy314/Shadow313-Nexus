"""Unit tests — shadow313.core.ai_engine v4"""
import pytest
from shadow313.core.ai_engine import AIEngine


class TestAIEngineDisabled:
    """Tests that work without any AI backend (disabled mode)."""

    def _make_engine(self, backend="disabled"):
        return AIEngine({"backend": backend, "model": "test", "endpoint": "http://localhost:11434"})

    def test_disabled_chat_returns_stub(self):
        engine = self._make_engine("disabled")
        result = engine.chat("hello")
        assert "disabled" in result.lower() or "AI" in result

    def test_disabled_is_not_available(self):
        engine = self._make_engine("disabled")
        assert engine.is_available() is False

    def test_disabled_list_models_empty(self):
        engine = self._make_engine("disabled")
        assert engine.list_models() == []

    def test_disabled_stream_yields_stub(self):
        engine = self._make_engine("disabled")
        tokens = list(engine.stream("hello"))
        assert len(tokens) > 0
        assert any("disabled" in t.lower() or "AI" in t for t in tokens)

    def test_context_truncation(self):
        """FIX: context should be truncated to avoid exceeding context window."""
        engine = self._make_engine("disabled")
        large_context = {"data": "x" * 20000}
        # Should not raise even with very large context
        result = engine.chat("test", context=large_context)
        assert isinstance(result, str)

    def test_truncate_context_method(self):
        engine = self._make_engine("disabled")
        large = {"key": "v" * 15000}
        truncated = engine._truncate_context(large)
        assert len(truncated) <= engine._MAX_CTX_CHARS + 50  # allow for truncation marker

    def test_unknown_backend_returns_message(self):
        engine = AIEngine({"backend": "unknown_backend"})
        result = engine.chat("hello")
        assert "Unknown" in result or "backend" in result.lower()

    def test_stream_non_ollama_falls_back_to_chat(self):
        """FIX: stream() for non-ollama backends should pass system_prompt correctly."""
        engine = self._make_engine("disabled")
        tokens = list(engine.stream("hello", system_prompt="You are a test assistant."))
        assert len(tokens) > 0

    def test_openai_missing_key_returns_error(self):
        """FIX: OpenAI backend without API key should return error message."""
        import os
        # Ensure no key is set
        old_key = os.environ.pop("OPENAI_API_KEY", None)
        try:
            engine = AIEngine({"backend": "openai", "model": "gpt-4o",
                               "endpoint": "https://api.openai.com", "openai_api_key": ""})
            result = engine.chat("hello")
            assert "error" in result.lower() or "OPENAI_API_KEY" in result
        finally:
            if old_key:
                os.environ["OPENAI_API_KEY"] = old_key


class TestAIEngineConfig:
    def test_config_parsing(self):
        engine = AIEngine({
            "backend":        "ollama",
            "model":          "llama3:8b",
            "endpoint":       "http://localhost:11434",
            "timeout":        60,
            "context_window": 4096,
        })
        assert engine.backend  == "ollama"
        assert engine.model    == "llama3:8b"
        assert engine.timeout  == 60
        assert engine.ctx_win  == 4096

    def test_default_config(self):
        engine = AIEngine({})
        assert engine.backend  == "ollama"
        assert engine.model    == "mistral:7b"
        assert engine.timeout  == 120
        assert engine.ctx_win  == 8192

    def test_endpoint_trailing_slash_stripped(self):
        engine = AIEngine({"endpoint": "http://localhost:11434/"})
        assert not engine.endpoint.endswith("/")