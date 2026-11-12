"""Real PostgreSQL integration tests for the ShiatoAli persistence adapter.

The CI workflow provisions an ephemeral PostgreSQL service and applies the
Alembic schema before running this module. These tests are intentionally kept
out of the SQLite-only unit-test matrix.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from shadow313.v4.shiatoali.service import EventInput, ShiatoAliStore


@pytest.fixture(scope="module")
def store() -> ShiatoAliStore:
    if not os.getenv("SHIAATOALI_DATABASE_URL"):
        pytest.skip("real PostgreSQL integration database is not configured")
    return ShiatoAliStore()


def test_postgresql_event_alert_case_and_note_workflow(store: ShiatoAliStore):
    event_id = f"pg-workflow-{uuid4().hex}"
    event = store.ingest(EventInput(
        source="windows",
        host="pg-integration-endpoint",
        event_type="process_creation",
        message="powershell.exe -EncodedCommand AAAA; nmap -sV 192.0.2.10",
        event_id=event_id,
    ))

    assert event["status"] == "accepted"
    assert {item["rule_id"] for item in event["alerts_created"]} == {
        "SHIA-EXEC-001", "SHIA-DISC-001"
    }
    alerts = store.list_alerts(limit=500)
    linked_alert = next(item for item in alerts if item["event_id"] == event_id)
    assert linked_alert["host"] == "pg-integration-endpoint"

    case = store.create_case(
        title="PostgreSQL integration case",
        created_by="ci",
        alert_id=linked_alert["alert_id"],
    )
    updated = store.update_case(
        case["case_id"], actor="ci", note="Integration note only"
    )
    detail = store.get_case(case["case_id"])

    assert updated["updated_at"] == detail["activity"][-1]["created_at"]
    assert detail["alerts"][0]["alert_id"] == linked_alert["alert_id"]
    assert detail["activity"][-1]["details"] == "Integration note only"


def test_postgresql_concurrent_duplicate_ingestion_is_idempotent(store: ShiatoAliStore):
    event_id = f"pg-concurrent-{uuid4().hex}"
    event = EventInput(
        source="linux",
        host="pg-concurrent-host",
        event_type="system",
        message="service started",
        event_id=event_id,
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store.ingest(event), range(8)))

    assert sum(result["status"] == "accepted" for result in results) == 1
    assert sum(result["status"] == "duplicate" for result in results) == 7
    persisted = [
        item for item in store.list_events(limit=500)
        if item["event_id"] == event_id
    ]
    assert len(persisted) == 1
