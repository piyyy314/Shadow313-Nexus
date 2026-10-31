"""AI request/response protocol tests for the new core engine, fully offline."""

import json
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock
from urllib.error import URLError

import pytest

# Exercise the implementation used by normal runtime imports, not a shadowed file.
import shadow313.core.ai_engine as _MODULE
AIEngine = _MODULE.AIEngine


@pytest.mark.parametrize(
    "endpoint",
    [
        "file:///etc/passwd",
        "ftp://example.invalid",
        "http://169.254.169.254/latest",
        "http://169.254.170.2/credentials",
        "http://metadata.google.internal",
        "http://100.100.100.200",
        "http://169.254.20.30",
        "http://[fd00::1]",
    ],
)
def test_reserved_endpoints_and_non_http_schemes_are_rejected(endpoint):
    with pytest.raises(ValueError):
        AIEngine({"endpoint": endpoint})


def test_ollama_chat_serializes_system_context_and_options(monkeypatch):
    fetch = Mock(return_value=BytesIO(b'{"message":{"content":"  answer  "}}'))
    monkeypatch.setattr(_MODULE.request, "urlopen", fetch)
    engine = AIEngine(
        {
            "endpoint": "http://localhost:11434/",
            "model": "test-model",
            "timeout": "7",
            "context_window": "1024",
        }
    )
    assert engine.chat("question", system_prompt="custom", context={"count": 2}) == "answer"
    request = fetch.call_args.args[0]
    payload = json.loads(request.data)
    assert request.full_url == "http://localhost:11434/api/chat"
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert payload["model"] == "test-model"
    assert payload["stream"] is False
    assert payload["options"] == {"num_ctx": 1024}
    assert payload["messages"][0] == {"role": "system", "content": "custom"}
    assert payload["messages"][1]["content"] == 'Context:\n{\n  "count": 2\n}\n\nquestion'
    assert fetch.call_args.kwargs == {"timeout": 7}


@pytest.mark.parametrize("error", [URLError("offline"), ValueError("bad JSON")])
def test_ollama_errors_return_messages(monkeypatch, error):
    monkeypatch.setattr(_MODULE.request, "urlopen", Mock(side_effect=error))
    assert "AI error" in AIEngine({}).chat("question")


def test_stream_ignores_blank_and_malformed_chunks_and_stops_at_done(monkeypatch):
    chunks = (
        b'\nnot-json\n{"message":{"content":"hello "}}\n'
        b'{"message":{"content":"world"},"done":true}\n'
        b'{"message":{"content":"must not appear"}}\n'
    )
    fetch = Mock(return_value=BytesIO(chunks))
    monkeypatch.setattr(_MODULE.request, "urlopen", fetch)
    assert list(AIEngine({}).stream("question", "system")) == ["hello ", "world"]
    payload = json.loads(fetch.call_args.args[0].data)
    assert payload["stream"] is True
    assert payload["messages"][0]["content"] == "system"


def test_stream_connection_error_yields_error_token(monkeypatch):
    monkeypatch.setattr(_MODULE.request, "urlopen", Mock(side_effect=OSError("offline")))
    assert list(AIEngine({}).stream("question")) == ["[AI stream error: offline]"]


def test_openai_compatible_payload_and_nonollama_stream_fallback(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-local-key")
    fetch = Mock(return_value=BytesIO(b'{"choices":[{"message":{"content":" result "}}]}'))
    monkeypatch.setattr(_MODULE.request, "urlopen", fetch)
    engine = AIEngine(
        {"backend": "openai", "endpoint": "https://example.invalid", "context_window": 512}
    )
    assert list(engine.stream("question", "system")) == ["result"]
    request = fetch.call_args.args[0]
    assert request.full_url == "https://example.invalid/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer synthetic-local-key"
    payload = json.loads(request.data)
    assert payload["max_tokens"] == 512
    assert payload["messages"] == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "question"},
    ]


def test_disabled_and_missing_api_key_never_make_requests(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    fetch = Mock(side_effect=AssertionError("unexpected request"))
    monkeypatch.setattr(_MODULE.request, "urlopen", fetch)
    disabled = AIEngine({"backend": "disabled"})
    assert "disabled" in disabled.chat("question")
    assert disabled.is_available() is False
    assert disabled.list_models() == []
    assert "configure the selected provider API key" in AIEngine({"backend": "openai"}).chat("question")
    fetch.assert_not_called()


def test_model_listing_and_availability_have_bounded_probe_timeouts(monkeypatch):
    fetch = Mock(
        side_effect=[
            BytesIO(b""),
            BytesIO(b'{"models":[{"name":"one"},{"name":"two"}]}'),
            OSError("offline"),
            OSError("offline"),
        ]
    )
    monkeypatch.setattr(_MODULE.request, "urlopen", fetch)
    engine = AIEngine({})
    assert engine.is_available() is True
    assert engine.list_models() == ["one", "two"]
    assert engine.is_available() is False
    assert engine.list_models() == []
    assert [call.kwargs["timeout"] for call in fetch.call_args_list] == [5, 10, 5, 10]
