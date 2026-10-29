"""Tests for agent plans, executor policies, approval gates, persistence and rollback."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from shadow313.v2.agent.agent import (
    CHAIN_TEMPLATES,
    AgentExecutor,
    AgentPlan,
    AgentStep,
    ApprovalPolicy,
    StepStatus,
)
from shadow313.v2.agent.agent import (
    CallbackApprovalGate as ExecutorCallbackGate,
)
from shadow313.v2.agent.approval import (
    ApprovalGate,
    AutoApprovalGate,
    CallbackApprovalGate,
    FullHumanApprovalGate,
    GateHighApprovalGate,
    make_gate,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


# ── ApprovalGate tests ────────────────────────────────────────────────────────


class TestApprovalGates:
    def test_auto_gate_always_approves(self):
        gate = AutoApprovalGate()
        assert gate.approve("any_step", "CRITICAL") is True
        assert gate.approve("any_step", "LOW") is True
        assert gate.approve("any_step", "HIGH") is True

    def test_base_gate_always_approves(self):
        gate = ApprovalGate()
        assert gate.approve("step", "HIGH") is True

    def test_callback_gate_approves_when_callback_returns_true(self):
        gate = CallbackApprovalGate(callback=lambda name, risk: True)
        assert gate.approve("step", "HIGH") is True

    def test_callback_gate_rejects_when_callback_returns_false(self):
        gate = CallbackApprovalGate(callback=lambda name, risk: False)
        assert gate.approve("step", "HIGH") is False

    def test_callback_gate_passes_correct_args(self):
        received = []

        def cb(name, risk):
            received.append((name, risk))
            return True

        gate = CallbackApprovalGate(callback=cb)
        gate.approve("recon", "MEDIUM")
        assert received == [("recon", "MEDIUM")]

    def test_make_gate_auto(self):
        gate = make_gate("auto")
        assert isinstance(gate, AutoApprovalGate)

    def test_make_gate_full_human(self):
        gate = make_gate("full_human")
        assert isinstance(gate, FullHumanApprovalGate)

    def test_make_gate_gate_high(self):
        gate = make_gate("gate_high")
        assert isinstance(gate, GateHighApprovalGate)

    def test_make_gate_default_is_gate_high(self):
        gate = make_gate("unknown_policy")
        assert isinstance(gate, GateHighApprovalGate)

    def test_make_gate_hyphen_variant(self):
        gate = make_gate("full-human")
        assert isinstance(gate, FullHumanApprovalGate)

    def test_gate_high_approves_low_risk(self):
        gate = GateHighApprovalGate()
        # LOW risk should not prompt — auto-approve
        assert gate.approve("step", "LOW") is True
        assert gate.approve("step", "MEDIUM") is True

    def test_gate_high_rejects_high_risk_on_no_input(self, monkeypatch):
        gate = GateHighApprovalGate()
        # Simulate user typing 'n'
        monkeypatch.setattr("builtins.input", lambda _: "n")
        assert gate.approve("step", "HIGH") is False
        assert gate.approve("step", "CRITICAL") is False

    def test_gate_high_approves_high_risk_on_yes(self, monkeypatch):
        gate = GateHighApprovalGate()
        monkeypatch.setattr("builtins.input", lambda _: "y")
        assert gate.approve("step", "HIGH") is True

    def test_full_human_approves_on_yes(self, monkeypatch):
        gate = FullHumanApprovalGate()
        monkeypatch.setattr("builtins.input", lambda _: "yes")
        assert gate.approve("step", "LOW") is True

    def test_full_human_rejects_on_no(self, monkeypatch):
        gate = FullHumanApprovalGate()
        monkeypatch.setattr("builtins.input", lambda _: "no")
        assert gate.approve("step", "LOW") is False

    def test_full_human_rejects_on_eof(self, monkeypatch):
        gate = FullHumanApprovalGate()
        monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))
        assert gate.approve("step", "LOW") is False


# The executor uses AgentStep.params, lowercase risk levels and run(plan).
# Its approval gate receives (step, plan); approval.py exposes a separate UI API.


@pytest.fixture
def executor(tmp_path):
    kernel = MagicMock()
    kernel.get_module.return_value.run.return_value = {"findings": ["example"]}
    kernel.get_module.return_value.scan.return_value = {"scanned": True}
    return AgentExecutor(kernel, policy=ApprovalPolicy.AUTO, log_dir=str(tmp_path))


def test_step_serialization():
    step = AgentStep("step1", "Recon", "recon", "run", {"mode": "passive"})
    assert step.status == StepStatus.PENDING
    assert step.risk_level == "low"
    assert step.to_dict()["params"] == {"mode": "passive"}
    assert step.to_dict()["status"] == "pending"


def test_plan_serialization():
    plan = AgentPlan(target="example.com", policy=ApprovalPolicy.FULL_HUMAN)
    data = plan.to_dict()
    assert data["target"] == "example.com"
    assert data["policy"] == "full_human"
    assert data["steps"] == []
    assert data["id"] and data["created_at"]


@pytest.mark.parametrize(
    "template,count",
    [
        ("full_pentest", 8),
        ("quick_vuln", 3),
        ("defense_audit", 3),
        ("crypto_audit", 4),
    ],
)
def test_builtin_plan_creation(executor, template, count):
    plan = executor.create_plan("example.com", template, {"extra": True})
    assert len(plan.steps) == count
    assert plan.policy == ApprovalPolicy.AUTO
    for step in plan.steps:
        assert step.params["target"] == "example.com"
        assert step.params["extra"] is True
        assert step.risk_level in {"low", "medium", "high", "critical"}
    assert len({s.id for s in plan.steps}) == count
    saved = json.loads((executor.log_dir / f"plan_{plan.id}.json").read_text())
    assert saved == plan.to_dict()


def test_unknown_template_uses_quick_vuln(executor):
    plan = executor.create_plan("example.com", "unknown")
    assert [s.module for s in plan.steps] == [s["module"] for s in CHAIN_TEMPLATES["quick_vuln"]]


def test_create_plan_keeps_template_params_independent(executor):
    first = executor.create_plan("one.example", "quick_vuln")
    first.steps[0].params["mode"] = "changed"
    second = executor.create_plan("two.example", "quick_vuln")
    assert second.steps[0].params == {"mode": "passive", "target": "two.example"}


def test_run_forwards_results_and_persists(executor):
    plan = executor.create_custom_plan(
        "example.com",
        [
            {"name": "one", "module": "recon", "params": {"mode": "passive"}},
            {"name": "two", "module": "vuln", "action": "scan"},
        ],
    )
    summary = executor.run(plan)
    assert summary["success"] is True
    assert summary["steps_ok"] == 2
    module = executor.kernel.get_module.return_value
    module.run.assert_called_once_with(mode="passive", target="example.com")
    module.scan.assert_called_once_with(
        target="example.com", _prev_result={"findings": ["example"]}
    )
    assert all(s.status == StepStatus.COMPLETED for s in plan.steps)
    assert all(s.started_at <= s.ended_at and s.duration_s >= 0 for s in plan.steps)
    saved = json.loads((executor.log_dir / f"run_{summary['run_id']}.json").read_text())
    assert saved == summary


@pytest.mark.parametrize(
    "resume,expected", [(False, ["failed", "pending"]), (True, ["failed", "completed"])]
)
def test_run_failure_policy(executor, resume, expected):
    executor.kernel.get_module.return_value.run.side_effect = [RuntimeError("scan failed"), {}]
    plan = executor.create_custom_plan("example.com", [{"module": "recon"}, {"module": "vuln"}])
    summary = executor.run(plan, resume_on_error=resume)
    assert summary["success"] is False
    assert summary["steps_failed"] == 1
    assert [s.status.value for s in plan.steps] == expected
    assert plan.steps[0].error == "scan failed"


@pytest.mark.parametrize(
    "policy,risk,explicit,expected_calls",
    [
        (ApprovalPolicy.AUTO, "critical", True, 0),
        (ApprovalPolicy.GATE_HIGH, "low", False, 0),
        (ApprovalPolicy.GATE_HIGH, "high", False, 1),
        (ApprovalPolicy.GATE_HIGH, "low", True, 1),
        (ApprovalPolicy.FULL_HUMAN, "low", False, 1),
    ],
)
def test_approval_policy(executor, policy, risk, explicit, expected_calls):
    approve = MagicMock(return_value=True)
    executor.gate = ExecutorCallbackGate(approve)
    executor.policy = policy
    plan = executor.create_custom_plan(
        "example.com",
        [
            {"module": "recon", "risk_level": risk, "requires_approval": explicit},
        ],
    )
    assert executor.run(plan)["steps_ok"] == 1
    assert approve.call_count == expected_calls
    if expected_calls:
        approve.assert_called_once_with(plan.steps[0], plan)


def test_rejection_skips_step_and_continues(executor):
    executor.policy = ApprovalPolicy.GATE_HIGH
    executor.gate = ExecutorCallbackGate(lambda step, plan: False)
    plan = executor.create_custom_plan(
        "example.com",
        [
            {"module": "recon", "risk_level": "high"},
            {"module": "vuln"},
        ],
    )
    result = executor.run(plan)
    assert result["steps_skipped"] == 1 and result["steps_ok"] == 1
    assert plan.steps[0].status == StepStatus.SKIPPED
    executor.kernel.get_module.assert_called_once_with("vuln")


def test_rollback_resets_from_named_step(executor):
    plan = executor.create_custom_plan(
        "example.com", [{"name": "one", "module": "recon"}, {"name": "two", "module": "vuln"}]
    )
    executor.run(plan)
    executor.rollback(plan, "two")
    assert plan.steps[0].status == StepStatus.COMPLETED
    step = plan.steps[1]
    assert step.status == StepStatus.PENDING
    assert step.result is None and step.error == ""
    assert step.started_at == step.ended_at == ""
    assert step.duration_s == 0
    assert json.loads((executor.log_dir / f"plan_{plan.id}.json").read_text()) == plan.to_dict()


def test_missing_module_and_action(executor):
    plan = executor.create_custom_plan("example.com", [{"module": "missing"}])
    executor.kernel.get_module.return_value = None
    assert executor.run(plan)["results"][0]["result"]["status"] == "stub"
    executor.kernel.get_module.return_value = object()
    assert executor.run(plan)["results"][0]["result"]["status"] == "no_action"


def test_no_plan_raises(executor):
    with pytest.raises(ValueError, match="No plan"):
        executor.run()


def test_empty_plan(executor):
    summary = executor.run(AgentPlan())
    assert summary["steps_total"] == 0 and summary["success"] is True
    executor.kernel.get_module.assert_not_called()


def test_ai_planning(executor):
    executor.kernel.ai.chat.return_value = 'Suggested: [{"module": "recon", "action": "run"}]'
    assert executor.ai_suggest_plan("example.com", "audit") == [
        {"module": "recon", "action": "run"}
    ]
    executor.kernel.ai.chat.return_value = "not JSON"
    assert executor.ai_suggest_plan("example.com", "audit") == []
    executor.kernel.ai = None
    assert executor.ai_suggest_plan("example.com", "audit") == []
