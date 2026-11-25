"""Safety regressions for the SOAR action execution contract."""

from nexus_toolkit.soar.playbook_engine import PlaybookAction, SOAREngine


def test_soar_defaults_to_dry_run_and_never_claims_containment():
    engine = SOAREngine()
    result = engine.trigger({"severity": "critical", "src_ip": "192.0.2.10"})

    assert result["status"] == "simulated"
    assert result["dry_run"] is True
    assert result["actions"]
    assert {action["status"] for action in result["actions"]} == {"simulated"}


def test_live_action_without_adapter_is_not_configured():
    engine = SOAREngine(dry_run=False)
    result = engine.trigger({"severity": "high", "src_ip": "192.0.2.10"})

    assert result["status"] == "not_configured"
    assert all(action["status"] == "not_configured" for action in result["actions"])
    assert all("blocked" not in str(action).lower() for action in result["actions"])


def test_live_action_is_completed_only_after_adapter_confirmation():
    calls = []
    engine = SOAREngine(
        dry_run=False,
        adapters={
            PlaybookAction.BLOCK_IP: lambda alert: (
                calls.append(alert) or {"status": "completed", "provider_id": "fw-123"}
            ),
        },
    )

    result = engine._handlers[PlaybookAction.BLOCK_IP]({"src_ip": "192.0.2.10"})

    assert calls == [{"src_ip": "192.0.2.10"}]
    assert result == {
        "status": "completed",
        "provider_id": "fw-123",
        "action": "block_ip",
    }


def test_adapter_cannot_claim_completion_with_legacy_success_words():
    engine = SOAREngine(
        dry_run=False,
        adapters={PlaybookAction.BLOCK_IP: lambda _: {"status": "blocked"}},
    )

    result = engine._handlers[PlaybookAction.BLOCK_IP]({"src_ip": "192.0.2.10"})

    assert result["status"] == "failed"
    assert "did not explicitly confirm completed" in result["reason"]


def test_missing_action_handlers_are_reported_not_silently_omitted():
    engine = SOAREngine(dry_run=False)
    engine._handlers.pop(PlaybookAction.GENERATE_RECEIPT)

    result = engine.trigger({"severity": "critical"})

    receipt = next(
        action for action in result["actions"]
        if action["action"] == PlaybookAction.GENERATE_RECEIPT.value
    )
    assert receipt["status"] == "not_configured"


def test_unknown_alert_does_not_create_an_execution_log():
    engine = SOAREngine()

    result = engine.trigger({"severity": "low"})

    assert result["triggered"] is False
    assert result["status"] == "not_matched"
    assert engine.get_log() == []
