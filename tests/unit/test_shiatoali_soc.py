from __future__ import annotations

from shadow313.v4.shiatoali.service import EventInput, ShiatoAliStore


def make_store(tmp_path):
    return ShiatoAliStore(tmp_path / "shiatoali-test.sqlite3")


def test_ingest_persists_event_and_detects_encoded_powershell(tmp_path):
    store = make_store(tmp_path)
    result = store.ingest(EventInput(
        source="windows",
        host="workstation-01",
        event_type="process_creation",
        message="powershell.exe -EncodedCommand SQBFAFgA",
        event_id="evt-powershell-1",
    ))

    assert result["status"] == "accepted"
    assert len(result["alerts_created"]) == 1
    assert result["alerts_created"][0]["rule_id"] == "SHIA-EXEC-001"
    assert store.health()["events"] == 1
    assert store.health()["alerts"] == 1


def test_in_memory_store_keeps_state_across_connections():
    store = ShiatoAliStore(":memory:")
    result = store.ingest(EventInput(
        source="linux",
        host="memory-host",
        event_type="system",
        message="service started",
        event_id="memory-event",
    ))

    assert result["status"] == "accepted"
    assert store.health()["events"] == 1
    assert store.list_events()[0]["event_id"] == "memory-event"


def test_duplicate_event_is_idempotent(tmp_path):
    store = make_store(tmp_path)
    event = EventInput(
        source="linux",
        host="server-01",
        event_type="system",
        message="service started",
        event_id="same-event",
    )

    first = store.ingest(event)
    second = store.ingest(event)

    assert first["status"] == "accepted"
    assert second["status"] == "duplicate"
    assert store.health()["events"] == 1


def test_five_failed_authentications_raise_brute_force_alert(tmp_path):
    store = make_store(tmp_path)
    for index in range(5):
        result = store.ingest(EventInput(
            source="linux",
            host="auth-01",
            event_type="authentication_failure",
            message="authentication failed",
            username="analyst",
            event_id=f"failed-{index}",
        ))

    assert any(
        alert["rule_id"] == "SHIA-ID-001"
        for alert in result["alerts_created"]
    )



def test_authenticated_api_ingestion_and_alert_query(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from shadow313.api.server import create_app

    monkeypatch.setenv("SHIAATOALI_DB_PATH", str(tmp_path / "api.sqlite3"))
    client = TestClient(create_app(api_key="shiatoali-test-key"))
    headers = {"x-api-key": "shiatoali-test-key"}
    response = client.post(
        "/api/shiatoali/events",
        headers=headers,
        json={
            "source": "windows",
            "host": "endpoint-02",
            "event_type": "process_creation",
            "message": "powershell.exe -EncodedCommand <redacted>",
            "event_id": "api-event-1",
        },
    )

    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    alerts = client.get("/api/shiatoali/alerts", headers=headers)
    assert alerts.status_code == 200
    assert alerts.json()["items"][0]["rule_id"] == "SHIA-EXEC-001"

    denied = client.get("/api/shiatoali/alerts")
    assert denied.status_code == 401


def test_case_lifecycle_links_alert_and_records_audit_activity(tmp_path):
    store = make_store(tmp_path)
    event_result = store.ingest(EventInput(
        source="windows",
        host="endpoint-03",
        event_type="process_creation",
        message="powershell.exe -EncodedCommand AAAA",
        event_id="case-alert-event",
    ))
    alert_id = event_result["alerts_created"][0]["alert_id"]
    case = store.create_case(
        title="Investigate suspicious PowerShell",
        description="Review endpoint telemetry and user activity.",
        priority="high",
        created_by="soc-analyst",
        alert_id=alert_id,
    )

    updated = store.update_case(
        case["case_id"],
        actor="soc-analyst",
        status="investigating",
        assignee="tier-2",
        note="Endpoint owner contacted; preserve evidence.",
    )
    detail = store.get_case(case["case_id"])

    assert updated["status"] == "investigating"
    assert updated["assignee"] == "tier-2"
    assert len(detail["alerts"]) == 1
    assert [item["action"] for item in detail["activity"]] == [
        "created", "status_changed", "assigned", "note"
    ]


def test_case_rejects_invalid_status_and_unknown_alert(tmp_path):
    store = make_store(tmp_path)
    try:
        store.create_case("Bad link", alert_id="missing-alert")
        raise AssertionError("expected missing alert validation")
    except ValueError as exc:
        assert "alert not found" in str(exc)

    case = store.create_case("Valid case")
    try:
        store.update_case(case["case_id"], status="magic")
        raise AssertionError("expected invalid status validation")
    except ValueError as exc:
        assert "invalid case status" in str(exc)
