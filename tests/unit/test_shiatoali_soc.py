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
