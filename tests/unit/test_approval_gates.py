"""Approval gate boundary and interruption regressions for PR #86."""

from unittest.mock import Mock

import pytest

from shadow313.v2.agent.approval import (
    CallbackApprovalGate,
    FullHumanApprovalGate,
    GateHighApprovalGate,
    make_gate,
)


@pytest.mark.parametrize("gate", [GateHighApprovalGate, FullHumanApprovalGate])
@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (" Y ", True),
        ("YES", True),
        ("n", False),
        ("", False),
        ("maybe", False),
    ],
)
def test_interactive_gates_accept_only_explicit_yes(monkeypatch, gate, answer, expected):
    prompt = Mock(return_value=answer)
    monkeypatch.setattr("builtins.input", prompt)
    assert gate().approve("sensitive step", "cRiTiCaL") is expected
    assert "sensitive step" in prompt.call_args.args[0]
    prompt.assert_called_once()


@pytest.mark.parametrize("gate", [GateHighApprovalGate, FullHumanApprovalGate])
@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_interactive_gates_deny_when_input_is_interrupted(monkeypatch, gate, error):
    monkeypatch.setattr("builtins.input", Mock(side_effect=error))
    assert gate().approve("sensitive step", "HIGH") is False


@pytest.mark.parametrize("risk", ["LOW", "medium", "INFO"])
def test_high_risk_gate_does_not_prompt_for_lower_risks(monkeypatch, risk):
    prompt = Mock(side_effect=AssertionError("unexpected prompt"))
    monkeypatch.setattr("builtins.input", prompt)
    assert GateHighApprovalGate().approve("read-only step", risk) is True
    prompt.assert_not_called()


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("AUTO", "AutoApprovalGate"),
        ("FULL-HUMAN", "FullHumanApprovalGate"),
        ("gate-high", "GateHighApprovalGate"),
        ("unknown", "GateHighApprovalGate"),
    ],
)
def test_policy_factory_normalizes_case_and_hyphens(policy, expected):
    assert type(make_gate(policy)).__name__ == expected


@pytest.mark.parametrize(
    ("value", "expected"), [(None, False), ([], False), ([1], True), (1, True)]
)
def test_callback_gate_coerces_result_and_passes_original_arguments(value, expected):
    callback = Mock(return_value=value)
    assert CallbackApprovalGate(callback).approve("step", "HIGH") is expected
    callback.assert_called_once_with("step", "HIGH")
