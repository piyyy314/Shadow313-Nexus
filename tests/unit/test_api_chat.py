"""Authenticated AI chat API tests; provider calls stay mocked and offline."""

from fastapi.testclient import TestClient

from shadow313.api.server import create_app


def test_chat_endpoint_authenticates_and_uses_configured_gateway(monkeypatch):
    from shadow313.core import ai_engine

    captured = {}

    class FakeAIEngine:
        def __init__(self, config):
            captured["config"] = config
            self.backend = config["backend"]
            self.model = config["model"]

        def is_available(self):
            return True

        def chat(self, prompt, system_prompt=None, context=None):
            captured["request"] = (prompt, system_prompt, context)
            return "Mocked defensive analysis"

    monkeypatch.setattr(ai_engine, "AIEngine", FakeAIEngine)
    monkeypatch.setenv("SHADOW313_AI_BACKEND", "gateway")
    monkeypatch.setenv("SHADOW313_AI_MODEL", "provider/model-name")
    monkeypatch.setenv("SHADOW313_AI_ENDPOINT", "https://ai-gateway.vercel.sh/v1")

    client = TestClient(create_app(api_key="chat-test-key"))
    payload = {
        "prompt": "Summarize these defensive alerts",
        "system_prompt": "Be concise",
        "context": {"alert_count": 2},
    }

    denied = client.post("/api/chat", json=payload)
    assert denied.status_code == 401

    response = client.post(
        "/api/chat",
        headers={"X-API-Key": "chat-test-key"},
        json=payload,
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "backend": "gateway",
        "model": "provider/model-name",
        "response": "Mocked defensive analysis",
    }
    assert captured["config"]["endpoint"] == "https://ai-gateway.vercel.sh/v1"
    assert captured["request"] == (
        payload["prompt"],
        payload["system_prompt"],
        payload["context"],
    )


def test_chat_endpoint_returns_service_unavailable_when_ai_is_disabled(monkeypatch):
    monkeypatch.setenv("SHADOW313_AI_BACKEND", "disabled")
    client = TestClient(create_app(api_key="chat-test-key"))

    response = client.post(
        "/api/chat",
        headers={"X-API-Key": "chat-test-key"},
        json={"prompt": "Analyze this alert"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "AI backend is disabled"
