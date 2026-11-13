"""Production API startup rejects known placeholder and weak keys."""

import pytest

from shadow313.api.server import create_app


@pytest.mark.parametrize(
    "api_key",
    [
        None,
        "",
        "replace-with-a-random-api-key",
        "change-me",
        "short-key",
        " " * 48,
    ],
)
def test_production_rejects_missing_placeholder_or_short_api_key(monkeypatch, api_key):
    monkeypatch.setenv("SHADOW313_ENV", "production")
    if api_key is None:
        monkeypatch.delenv("SHADOW313_API_KEY", raising=False)
    else:
        monkeypatch.setenv("SHADOW313_API_KEY", api_key)

    with pytest.raises(RuntimeError, match="non-placeholder value"):
        create_app()


def test_production_accepts_randomized_api_key(monkeypatch):
    monkeypatch.setenv("SHADOW313_ENV", "production")
    monkeypatch.setenv("SHADOW313_API_KEY", "a" * 48)

    app = create_app()

    assert app.title == "Shadow313 NEXUS API"


def test_development_keeps_short_test_keys_usable(monkeypatch):
    monkeypatch.setenv("SHADOW313_ENV", "development")
    monkeypatch.delenv("SHADOW313_API_KEY", raising=False)

    app = create_app(api_key="test-key")

    assert app.title == "Shadow313 NEXUS API"

def test_chat_endpoint_runs_ai_in_threadpool_and_returns_configured_response(monkeypatch):
    from fastapi.testclient import TestClient
    from starlette import concurrency

    from shadow313.core import ai_engine
    from shadow313.core.config import Config

    calls = []

    class FakeAIEngine:
        backend = "gateway"
        model = "provider/model"

        def __init__(self, config):
            assert config["backend"] == "gateway"

        def is_available(self):
            return True

        def chat(self, prompt, system_prompt=None, context=None):
            return f"response to {prompt}"

    original_run_in_threadpool = concurrency.run_in_threadpool

    async def track_threadpool(func, *args, **kwargs):
        calls.append(func)
        return await original_run_in_threadpool(func, *args, **kwargs)

    monkeypatch.setattr(ai_engine, "AIEngine", FakeAIEngine)
    monkeypatch.setattr(
        Config,
        "get",
        lambda self, *keys, default=None: {"backend": "gateway"} if keys == ("ai",) else default,
    )
    monkeypatch.setattr(concurrency, "run_in_threadpool", track_threadpool)

    client = TestClient(create_app(api_key="test-api-key"))
    response = client.post(
        "/api/chat",
        headers={"X-API-Key": "test-api-key"},
        json={"prompt": "check this event"},
    )

    assert response.status_code == 200
    assert response.json()["response"] == "response to check this event"
    assert response.json()["backend"] == "gateway"
    assert len(calls) == 1

