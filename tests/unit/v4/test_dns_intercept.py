"""Regression tests for DNS intercept result status."""

from shadow313.v4.aegis.dns_intercept import DNSInterceptor


def test_unresolved_dns_target_is_marked_failed(monkeypatch):
    interceptor = DNSInterceptor()
    monkeypatch.setattr(interceptor, "_resolve", lambda target: "UNRESOLVED")

    entry = interceptor.intercept("missing-host.invalid")

    assert entry.resolved_ip == "UNRESOLVED"
    assert entry.status == "FAILED"


def test_resolved_dns_target_is_marked_success(monkeypatch):
    interceptor = DNSInterceptor()
    monkeypatch.setattr(interceptor, "_resolve", lambda target: "192.0.2.10")

    entry = interceptor.intercept("sensor.example")

    assert entry.resolved_ip == "192.0.2.10"
    assert entry.status == "SUCCESS"
