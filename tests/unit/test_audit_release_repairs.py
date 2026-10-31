"""Behavioral regressions for the reproduced audit release blockers."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from shadow313.core.binding_sdk.binder import AppIdentity, Binder313, BindReceipt


def binder():
    return Binder313(AppIdentity(app_id="fixture", app_name="Fixture"))


def test_receipts_round_trip_metadata_sequence_and_full_signature():
    b = binder()
    for i in range(3):
        r = b.bind({"x": i}, {"source": "test", "nested": [i]})
        exported = r.to_dict()
        assert exported["signature"] == r.signature
        assert b.verify(BindReceipt(**exported), {"x": i})["valid"]
        assert not binder().verify(r, {"x": i})["valid"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("signature", "00"),
        ("chain_hash", "tampered"),
        ("prev_chain_hash", "fake"),
        ("sequence", 9),
        ("metadata", {"x": 1}),
        ("timestamp_ns", 313),
        ("signature_algorithm", "bogus"),
        ("public_key", "fake"),
        ("app_id", "other"),
        ("app_version", "fake"),
        ("bind_id", "fake"),
        ("receipt_format", 1),
    ],
)
def test_receipt_tampering_is_rejected(field, value):
    b = binder()
    r = b.bind({"fixture": True})
    setattr(r, field, value)
    assert not b.verify(r, {"fixture": True})["valid"]


def test_signing_failure_never_downgrades_or_advances_chain():
    b = binder()
    b._pyspx = SimpleNamespace(sign=lambda *_: (_ for _ in ()).throw(RuntimeError("fixture")))
    b._pyspx_sk = b"test"
    b._pyspx_pk = b"public"
    b._signing_algo = "SPHINCS+-SHAKE-128f"
    with pytest.raises(RuntimeError, match="fixture"):
        b.bind({"x": 1})
    assert b._sequence == 0 and b._prev_chain_hash == ""


def test_main_api_auth_unavailable_routes_and_lolbin():
    from shadow313.api.server import create_app

    c = TestClient(create_app(api_key="test-fixture"))
    for path in ("/api/mobile/scan", "/api/scan/recon", "/api/scan/vuln"):
        assert c.post(path, json={}).status_code == 401
        r = c.post(path, json={}, headers={"X-API-Key": "test-fixture"})
        assert r.status_code == 503 and "queued" not in r.text
    for path in ("/api/audit/chain", "/api/events"):
        assert c.get(path).status_code == 401
        assert c.get(path, headers={"X-API-Key": "test-fixture"}).status_code == 503
    r = c.post(
        "/api/detect",
        json={
            "event": {"process_name": "mshta.exe", "command_line": "mshta.exe javascript:alert(1)"}
        },
        headers={"X-API-Key": "test-fixture"},
    )
    assert r.status_code == 200 and "error" not in r.json()["results"]["lolbin"]
    r = c.post(
        "/api/detect",
        content=b"x" * 1_048_577,
        headers={"X-API-Key": "test-fixture", "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_mobile_api_token_applies_to_every_route():
    from shadow313.v4.mobile_api.mobile_api import MobileAPIModule

    m = MobileAPIModule.__new__(MobileAPIModule)
    m.out = SimpleNamespace(success=lambda *_: None)
    m.kernel = SimpleNamespace(
        session=SimpleNamespace(id="fixture", read=lambda _: {}), get_module=lambda _: None
    )
    with patch("uvicorn.run") as run:
        m._start("127.0.0.1", 7314, "fixture-token")
    c = TestClient(run.call_args.args[0])
    for path in ("/api/v1/status", "/api/v1/findings", "/api/v1/receipts"):
        assert c.get(path).status_code == 401
        assert c.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert c.get(path, headers={"Authorization": "Bearer fixture-token"}).status_code == 200


def test_audit_numeric_validation_and_remote_auth():
    from shadow313.api.audit_server import create_app

    c = TestClient(create_app(), client=("127.0.0.1", 123))
    for body in ({"distance_km": 0}, {"frequency_ghz": -1}, {"bandwidth_mhz": 0}):
        assert c.post("/api/link-budget", json=body).status_code == 422
    assert c.post("/api/link-budget", json={}).status_code == 200
    remote = TestClient(create_app(), client=("198.51.100.1", 123))
    assert remote.get("/api/audit/chain").status_code in (401, 503)


@pytest.mark.parametrize(
    "endpoint", ["https://ai-gateway.vercel.sh", "https://ai-gateway.vercel.sh/v1"]
)
def test_gateway_url_and_key_without_network(monkeypatch, endpoint):
    from shadow313.core.ai_engine import AIEngine

    monkeypatch.setenv("AI_GATEWAY_API_KEY", "fixture")
    engine = AIEngine({"backend": "gateway", "endpoint": endpoint})
    with patch(
        "shadow313.core.ai_engine.request.urlopen", side_effect=OSError("intercepted")
    ) as send:
        engine.chat("test")
    req = send.call_args.args[0]
    assert req.full_url == "https://ai-gateway.vercel.sh/v1/chat/completions"
    assert req.headers["Authorization"] == "Bearer fixture"


def test_default_simulation_no_undefined_logger():
    from shadow313.v4.temporal_binding.attack_simulation import run_simulation

    assert isinstance(run_simulation(), dict)
