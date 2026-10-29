"""Deterministic recon tests; no sockets, providers or timers run live."""

import asyncio
import json
import socket
import sys
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from shadow313.modules.recon.dns_enum import DNSEnumerator
from shadow313.modules.recon.fingerprint import WebFingerprinter
from shadow313.modules.recon.geoip import GeoIPEnricher
from shadow313.modules.recon.port_scan import AsyncPortScanner
from shadow313.modules.recon.subdomain import SubdomainDiscoverer
from shadow313.modules.recon.whois_lookup import WHOISLookup


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("80, 443,8000-8002", [80, 443, 8000, 8001, 8002]),
        ("22-22", [22]),
        ("443", [443]),
        ("", AsyncPortScanner.COMMON_PORTS),
    ],
)
def test_parse_ports_expands_inclusive_ranges(text, expected):
    assert AsyncPortScanner.parse_ports(text) == expected


@pytest.mark.parametrize("text", ["http", "80-https", "80,,443"])
def test_parse_ports_rejects_nonnumeric_input(text):
    with pytest.raises(ValueError):
        AsyncPortScanner.parse_ports(text)


@pytest.mark.asyncio
async def test_probe_truncates_banner_and_closes_connection(monkeypatch):
    reader = SimpleNamespace(read=AsyncMock(return_value=b"x" * 300 + b"\xff"))
    writer = SimpleNamespace(close=Mock(), wait_closed=AsyncMock())
    connect = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr("shadow313.modules.recon.port_scan.asyncio.open_connection", connect)
    scanner = AsyncPortScanner("example.invalid", [22], timeout=0.5)
    result = await scanner._probe(22)
    assert result == {"port": 22, "state": "open", "banner": "x" * 200}
    connect.assert_awaited_once_with("example.invalid", 22)
    reader.read.assert_awaited_once_with(1024)
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


@pytest.mark.asyncio
async def test_probe_retains_open_port_when_banner_and_close_fail(monkeypatch):
    writer = SimpleNamespace(close=Mock(), wait_closed=AsyncMock(side_effect=OSError))
    connect = AsyncMock(
        return_value=(SimpleNamespace(read=AsyncMock(side_effect=TimeoutError)), writer)
    )
    monkeypatch.setattr("shadow313.modules.recon.port_scan.asyncio.open_connection", connect)
    assert await AsyncPortScanner("example.invalid")._probe(443) == {
        "port": 443,
        "state": "open",
        "banner": "",
    }
    writer.close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [ConnectionRefusedError, TimeoutError, OSError])
async def test_probe_closed_unreachable_or_timeout_returns_none(monkeypatch, error):
    monkeypatch.setattr(
        "shadow313.modules.recon.port_scan.asyncio.open_connection", AsyncMock(side_effect=error)
    )
    assert await AsyncPortScanner("example.invalid")._probe(443) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("stealth", [False, True])
async def test_scan_filters_failed_probes_and_stealth_delays(monkeypatch, stealth):
    scanner = AsyncPortScanner("example.invalid", [80, 443], stealth=stealth)
    probe = AsyncMock(side_effect=[None, {"port": 443, "state": "open"}])
    sleep = AsyncMock()
    monkeypatch.setattr(scanner, "_probe", probe)
    monkeypatch.setattr("shadow313.modules.recon.port_scan.asyncio.sleep", sleep)
    assert await scanner.scan_async() == [{"port": 443, "state": "open"}]
    assert [call.args for call in probe.await_args_list] == [(80,), (443,)]
    assert sleep.await_count == (2 if stealth else 0)


def test_scan_sync_wrapper_runs_without_existing_event_loop(monkeypatch):
    scanner = AsyncPortScanner("example.invalid", [443])
    monkeypatch.setattr(scanner, "scan_async", AsyncMock(return_value=[{"port": 443}]))
    monkeypatch.setattr(asyncio, "get_event_loop", Mock(side_effect=RuntimeError))
    assert scanner.scan() == [{"port": 443}]


@pytest.mark.parametrize(("rtype", "family"), [("A", socket.AF_INET), ("AAAA", socket.AF_INET6)])
def test_dns_address_records_deduplicate_and_handle_resolution_errors(monkeypatch, rtype, family):
    resolve = Mock(return_value=[(family, 1, 6, "", ("address", 0))] * 2)
    monkeypatch.setattr("shadow313.modules.recon.dns_enum.socket.getaddrinfo", resolve)
    enumerator = DNSEnumerator("example.invalid")
    assert enumerator._query(rtype) == ["address"]
    resolve.assert_called_once_with("example.invalid", None, family)
    resolve.side_effect = socket.gaierror("not found")
    assert enumerator._query(rtype) == []


def test_dns_resolve_omits_empty_results_and_optional_dependency_fallback(monkeypatch):
    enumerator = DNSEnumerator("example.invalid")
    query = Mock(side_effect=lambda rtype: ["mail.invalid"] if rtype == "MX" else [])
    monkeypatch.setattr(enumerator, "_query", query)
    assert enumerator.resolve() == {"MX": ["mail.invalid"]}
    assert query.call_count == 7
    monkeypatch.setitem(sys.modules, "dns.resolver", None)
    assert DNSEnumerator("example.invalid")._query("TXT") == ["[dnspython not installed]"]


def test_ct_logs_filter_apex_and_unrelated_domains_deduplicate_wildcards(monkeypatch):
    payload = [
        {"name_value": "*.api.example.invalid\napi.example.invalid\nexample.invalid"},
        {"name_value": "other.invalid\nwww.example.invalid"},
        {},
    ]
    fetch = Mock(return_value=BytesIO(json.dumps(payload).encode()))
    monkeypatch.setattr("shadow313.modules.recon.subdomain.urlreq.urlopen", fetch)
    discoverer = SubdomainDiscoverer("example.invalid")
    assert set(discoverer.from_ct_logs()) == {"api.example.invalid", "www.example.invalid"}
    assert set(discoverer.found) == {"api.example.invalid", "www.example.invalid"}
    assert fetch.call_args.kwargs["timeout"] == 15


def test_ct_failure_and_wordlist_rate_limit_do_not_stop_discovery(monkeypatch):
    monkeypatch.setattr(
        "shadow313.modules.recon.subdomain.urlreq.urlopen", Mock(side_effect=OSError)
    )
    resolve = Mock(side_effect=[socket.gaierror(), [("resolved",)]])
    sleep = Mock()
    monkeypatch.setattr("shadow313.modules.recon.subdomain.socket.getaddrinfo", resolve)
    monkeypatch.setattr("shadow313.modules.recon.subdomain.time.sleep", sleep)
    discoverer = SubdomainDiscoverer("example.invalid", ["missing", "www"], True, 4)
    assert discoverer.scan() == ["www.example.invalid"]
    assert [call.args for call in sleep.call_args_list] == [(0.25,), (0.25,)]


def test_geoip_bulk_caps_requests_and_reuses_cache(monkeypatch):
    fetch = Mock(side_effect=lambda ip: {"query": ip})
    sleep = Mock()
    enricher = GeoIPEnricher()
    monkeypatch.setattr(enricher, "_fetch", fetch)
    monkeypatch.setattr("shadow313.modules.recon.geoip.time.sleep", sleep)
    ips = [f"192.0.2.{i}" for i in range(25)]
    assert enricher.lookup_bulk(ips, delay=0.2) == [{"query": ip} for ip in ips[:20]]
    assert fetch.call_count == 20
    assert sleep.call_count == 20
    assert enricher.lookup(ips[0]) == {"query": ips[0]}
    assert fetch.call_count == 20


def test_geoip_failed_fetch_is_cached(monkeypatch):
    fetch = Mock(side_effect=OSError("offline"))
    monkeypatch.setattr("shadow313.modules.recon.geoip.urlreq.urlopen", fetch)
    enricher = GeoIPEnricher()
    assert enricher.lookup("192.0.2.1") == {"query": "192.0.2.1", "error": "GeoIP lookup failed"}
    assert enricher.lookup("192.0.2.1")["error"] == "GeoIP lookup failed"
    fetch.assert_called_once()


def test_fingerprint_uses_body_and_headers_and_reports_missing_security_headers(monkeypatch):
    response = {
        "status": 200,
        "body": "WP-CONTENT /wp-includes/",
        "headers": {"Server": "nginx", "X-Frame-Options": "DENY"},
    }
    fetch = Mock(return_value=response)
    monkeypatch.setattr("shadow313.modules.recon.fingerprint._http_get", fetch)
    fingerprinter = WebFingerprinter("example.invalid")
    result = fingerprinter.fingerprint()
    assert result["url"] == "https://example.invalid"
    assert set(result["tech"]) == {"WordPress", "Nginx"}
    headers = fingerprinter.check_security_headers()
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Content-Security-Policy"] == "MISSING"
    assert len(headers) == 6
    fetch.return_value = {"body": "", "headers": {}, "error": "offline"}
    assert fingerprinter.fingerprint() == {
        "url": "https://example.invalid",
        "error": "offline",
        "tech": [],
    }


def test_whois_normalizes_missing_fields_without_network(monkeypatch):
    whois = SimpleNamespace(
        whois=Mock(
            return_value=SimpleNamespace(
                registrar="Registry",
                creation_date=None,
                expiration_date=None,
                updated_date=None,
                name_servers=None,
                status=None,
                emails=None,
                org=None,
            )
        )
    )
    monkeypatch.setitem(sys.modules, "whois", whois)
    result = WHOISLookup("example.invalid").lookup()
    assert result["registrar"] == "Registry"
    assert result["created"] == ""
    assert result["name_servers"] == []
    whois.whois.assert_called_once_with("example.invalid")
    whois.whois.side_effect = ValueError("invalid response")
    assert WHOISLookup("example.invalid").lookup()["error"] == "invalid response"


def test_whois_missing_optional_library_uses_raw_protocol(monkeypatch):
    monkeypatch.setitem(sys.modules, "whois", None)
    connection = Mock()
    connection.recv.side_effect = [b"registrar: test\n", b""]
    sock = Mock()
    sock.__enter__ = Mock(return_value=connection)
    sock.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(
        "shadow313.modules.recon.whois_lookup.socket.socket", Mock(return_value=sock)
    )
    assert WHOISLookup("example.invalid").lookup() == {
        "domain": "example.invalid",
        "raw": "registrar: test\n",
    }
    connection.connect.assert_called_once_with(("whois.iana.org", 43))
    connection.send.assert_called_once_with(b"example.invalid\r\n")
