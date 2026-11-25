"""Regression tests for SSRF-resistant workflow webhook delivery."""

import socket

from shadow313.v4.workflow import webhook_security


def _dns_record(address: str):
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, 443),
    )


def test_webhook_without_hmac_secret_fails_closed():
    delivery = webhook_security.HTTPWebhookDelivery(
        allowed_hosts={"hooks.example.com"}
    )

    result = delivery.deliver(
        "https://hooks.example.com/events",
        {"event": "test"},
        "execution-1",
    )

    assert result["status"] == "not_configured"
    assert result["success"] is False


def test_unallowlisted_host_is_rejected_before_dns(monkeypatch):
    delivery = webhook_security.HTTPWebhookDelivery(
        hmac_secret=b"s" * 32,
        allowed_hosts={"hooks.example.com"},
    )

    def unexpected_dns(*args, **kwargs):
        raise AssertionError("DNS must not run for an unallowlisted host")

    monkeypatch.setattr(webhook_security.socket, "getaddrinfo", unexpected_dns)
    result = delivery.deliver(
        "https://attacker.example/events",
        {"event": "test"},
        "execution-2",
    )

    assert result["status"] == "rejected"
    assert "not in" in result["error"]


def test_private_ip_target_is_rejected_even_when_allowlisted():
    delivery = webhook_security.HTTPWebhookDelivery(
        hmac_secret=b"s" * 32,
        allowed_hosts={"127.0.0.1"},
    )

    result = delivery.deliver(
        "https://127.0.0.1/internal",
        {"event": "test"},
        "execution-3",
    )

    assert result["status"] == "rejected"
    assert "non-public" in result["error"]


def test_plain_http_target_is_rejected():
    delivery = webhook_security.HTTPWebhookDelivery(
        hmac_secret=b"s" * 32,
        allowed_hosts={"hooks.example.com"},
    )

    result = delivery.deliver(
        "http://hooks.example.com/events",
        {"event": "test"},
        "execution-4",
    )

    assert result["status"] == "rejected"
    assert "HTTPS" in result["error"]


def test_private_dns_answer_is_rejected(monkeypatch):
    delivery = webhook_security.HTTPWebhookDelivery(
        hmac_secret=b"s" * 32,
        allowed_hosts={"hooks.example.com"},
    )
    monkeypatch.setattr(
        webhook_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_dns_record("10.0.0.10")],
    )

    result = delivery.deliver(
        "https://hooks.example.com/events",
        {"event": "test"},
        "execution-5",
    )

    assert result["status"] == "rejected"
    assert "non-public" in result["error"]


def test_webhook_uses_pinned_public_ip_and_does_not_follow_redirects(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 302

    class FakeConnection:
        def __init__(self, host, port, pinned_ip, **kwargs):
            captured["host"] = host
            captured["port"] = port
            captured["pinned_ip"] = pinned_ip

        def request(self, method, path, body, headers):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body
            captured["headers"] = headers

        def getresponse(self):
            return FakeResponse()

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(
        webhook_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_dns_record("93.184.216.34")],
    )
    monkeypatch.setattr(
        webhook_security,
        "_PinnedHTTPSConnection",
        FakeConnection,
    )
    delivery = webhook_security.HTTPWebhookDelivery(
        hmac_secret=b"s" * 32,
        allowed_hosts={"hooks.example.com"},
    )

    result = delivery.deliver(
        "https://hooks.example.com/events?source=nexus",
        {"event": "test"},
        "execution-6",
    )

    assert captured["pinned_ip"] == "93.184.216.34"
    assert captured["host"] == "hooks.example.com"
    assert captured["path"] == "/events?source=nexus"
    assert captured["method"] == "POST"
    assert captured["closed"] is True
    assert result["status_code"] == 302
    assert result["success"] is False
    assert "not followed" in result["error"]


def test_reserved_webhook_headers_cannot_be_overridden():
    delivery = webhook_security.HTTPWebhookDelivery(
        hmac_secret=b"s" * 32,
        allowed_hosts={"93.184.216.34"},
    )

    result = delivery.deliver(
        "https://93.184.216.34/events",
        {"event": "test"},
        "execution-7",
        headers={"X-Nexus-Signature": "attacker-value"},
    )

    assert result["status"] == "rejected"
    assert "reserved" in result["error"]
