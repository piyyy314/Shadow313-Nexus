"""Telegram bot integration tests for ShiatoAli alerts and shared AI backends."""

import json
from datetime import datetime, timezone

from shadow313.integrations.telegram import bot


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return json.dumps(self.payload).encode()


def test_fetch_events_reads_authenticated_shiatoali_alerts(monkeypatch):
    created_at = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(bot, "API_URL", "http://shadow313-api:8313")
    monkeypatch.setattr(bot, "EVENT_PROVIDER_WARNED", False)
    monkeypatch.setattr(bot, "PROCESSED_ALERT_IDS", set())
    monkeypatch.setenv("SHADOW313_API_KEY", "test-api-key")
    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["headers"] = {key.lower(): value for key, value in request.headers.items()}
        seen["timeout"] = timeout
        return FakeResponse({
            "items": [{
                "alert_id": "alert-123",
                "title": "Repeated authentication failures",
                "severity": "high",
                "risk_score": 80,
                "technique": "T1110",
                "created_at": created_at,
                "host": "server-01",
            }]
        })

    monkeypatch.setattr(bot.urllib.request, "urlopen", fake_urlopen)
    events = bot._fetch_events(0)

    assert seen["url"] == "http://shadow313-api:8313/api/shiatoali/alerts?limit=500&offset=0&since=1970-01-01T00%3A00%3A00%2B00%3A00&order=asc"
    assert seen["headers"]["x-api-key"] == "test-api-key"
    assert seen["timeout"] == 8
    assert len(events) == 1
    assert events[0]["alert_id"] == "alert-123"
    assert events[0]["source"] == "ShiatoAli SOC"
    assert events[0]["host"] == "server-01"
    assert events[0]["technique"] == "T1110"


def test_fetch_events_skips_processed_and_old_alerts(monkeypatch):
    monkeypatch.setattr(bot, "API_URL", "http://shadow313-api:8313")
    monkeypatch.setattr(bot, "PROCESSED_ALERT_IDS", {"already-sent"})
    monkeypatch.setenv("SHADOW313_API_KEY", "test-api-key")
    created_at = datetime.now(timezone.utc).isoformat()

    monkeypatch.setattr(
        bot.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse({
            "items": [
                {"alert_id": "already-sent", "created_at": created_at},
                {"alert_id": "too-old", "created_at": "2020-01-01T00:00:00+00:00"},
            ]
        }),
    )

    cutoff = datetime(2021, 1, 1, tzinfo=timezone.utc).timestamp()
    assert bot._fetch_events(cutoff) == []


def test_telegram_ai_uses_the_configured_gateway(monkeypatch):
    from shadow313.core import ai_engine

    captured = {}

    class FakeAIEngine:
        def __init__(self, config):
            captured["config"] = config
            self.backend = config["backend"]

        def is_available(self):
            return True

        def chat(self, prompt, system_prompt=None):
            captured["prompt"] = prompt
            captured["system_prompt"] = system_prompt
            return "Gateway response"

    monkeypatch.setattr(ai_engine, "AIEngine", FakeAIEngine)
    monkeypatch.setattr(bot, "AI_BACKEND", "gateway")
    monkeypatch.setattr(bot, "AI_ENDPOINT", "https://ai-gateway.vercel.sh/v1")
    monkeypatch.setattr(bot, "AI_MODEL", "provider/model")

    assert bot._ai_generate("Analyze this alert") == "Gateway response"
    assert captured["config"]["backend"] == "gateway"
    assert captured["config"]["model"] == "provider/model"
    assert captured["prompt"] == "Analyze this alert"


def test_send_alert_reports_delivery_result(monkeypatch):
    monkeypatch.setattr(bot, "CHAT_ID", "test-chat")
    monkeypatch.setattr(bot, "send_message", lambda *args, **kwargs: {"ok": True})
    assert bot.send_alert({"severity": "HIGH", "message": "test alert"}) is True

    monkeypatch.setattr(bot, "send_message", lambda *args, **kwargs: None)
    assert bot.send_alert({"severity": "HIGH", "message": "test alert"}) is False


def test_fetch_events_paginates_backlog_and_orders_alerts(monkeypatch):
    from urllib.parse import parse_qs, urlsplit

    monkeypatch.setattr(bot, "API_URL", "http://shadow313-api:8313")
    monkeypatch.setattr(bot, "PROCESSED_ALERT_IDS", set())
    monkeypatch.setenv("SHADOW313_API_KEY", "test-api-key")
    created_at = datetime.now(timezone.utc).isoformat()
    offsets = []

    def fake_urlopen(request, timeout):
        offset = int(parse_qs(urlsplit(request.full_url).query)["offset"][0])
        offsets.append(offset)
        if offset == 0:
            alerts = [
                {"alert_id": f"alert-{index:03}", "created_at": created_at}
                for index in range(500)
            ]
        else:
            alerts = [{"alert_id": "alert-500", "created_at": created_at}]
        return FakeResponse({"items": alerts})

    monkeypatch.setattr(bot.urllib.request, "urlopen", fake_urlopen)
    events = bot._fetch_events(0)

    assert offsets == [0, 500]
    assert len(events) == 501
    assert events[0]["alert_id"] == "alert-000"
    assert events[-1]["alert_id"] == "alert-500"


def test_alert_cursor_keeps_newer_successes_after_older_delivery_retry(monkeypatch):
    monkeypatch.setattr(bot, "PROCESSED_ALERT_IDS", {"older-retry", "newer-success"})
    monkeypatch.setattr(
        bot,
        "PROCESSED_ALERT_TIMESTAMPS",
        {"older-retry": 100.0, "newer-success": 200.0},
    )

    cursor = bot._advance_alert_cursor(50.0)

    assert cursor == 200.0
    assert bot.PROCESSED_ALERT_IDS == {"newer-success"}
    assert bot.PROCESSED_ALERT_TIMESTAMPS == {"newer-success": 200.0}
