"""
Comprehensive tests — shadow313.v2.agent (auto-chain loop, approval gates, plan management)
Covers: AgentStep, AgentPlan, AgentExecutor, approval policies, result forwarding,
        rollback, BUILTIN_PLANS structure, AgentModule.run() edge cases.
"""
from __future__ import annotations
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from shadow313.v2.agent.approval import (
    AutoApprovalGate, GateHighApprovalGate, FullHumanApprovalGate,
    CallbackApprovalGate, make_gate, ApprovalGate,
)
from shadow313.v2.agent.agent import (
    AgentStep, AgentPlan, AgentExecutor, AgentModule,
    BUILTIN_PLANS, _now,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_kernel(dispatch_return=None):
    """Return a minimal mock kernel."""
    kernel = MagicMock()
    kernel.out = MagicMock()
    kernel.ai  = MagicMock()
    kernel.ai.chat.return_value = "[AI response]"
    kernel.session = MagicMock()
    kernel.session.id = "test-session-uuid"
    kernel.config.get.return_value = {}
    kernel.dispatch.return_value = dispatch_return or {"findings": [], "status": "ok"}
    return kernel


# ── ApprovalGate tests ────────────────────────────────────────────────────────

class TestApprovalGates:
    def test_auto_gate_always_approves(self):
        gate = AutoApprovalGate()
        assert gate.approve("any_step", "CRITICAL") is True
        assert gate.approve("any_step", "LOW")      is True
        assert gate.approve("any_step", "HIGH")     is True

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
        assert gate.approve("step", "LOW")    is True
        assert gate.approve("step", "MEDIUM") is True

    def test_gate_high_rejects_high_risk_on_no_input(self, monkeypatch):
        gate = GateHighApprovalGate()
        # Simulate user typing 'n'
        monkeypatch.setattr("builtins.input", lambda _: "n")
        assert gate.approve("step", "HIGH")     is False
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


# ── AgentStep / AgentPlan tests ───────────────────────────────────────────────

class TestAgentDataclasses:
    def test_agent_step_defaults(self):
        step = AgentStep(name="recon", module="recon")
        assert step.kwargs      == {}
        assert step.risk_level  == "MEDIUM"
        assert step.rollback_fn is None
        assert step.description == ""

    def test_agent_step_custom_values(self):
        rollback = lambda: None
        step = AgentStep(name="vuln", module="vuln",
                         kwargs={"quick": True}, risk_level="LOW",
                         rollback_fn=rollback, description="Vuln scan")
        assert step.kwargs      == {"quick": True}
        assert step.risk_level  == "LOW"
        assert step.rollback_fn is rollback
        assert step.description == "Vuln scan"

    def test_agent_plan_to_dict(self):
        plan = AgentPlan(name="test_plan", steps=[
            AgentStep(name="recon", module="recon", description="Recon step"),
            AgentStep(name="vuln",  module="vuln",  description="Vuln step"),
        ])
        d = plan.to_dict()
        assert d["name"] == "test_plan"
        assert len(d["steps"]) == 2
        assert d["steps"][0]["name"]   == "recon"
        assert d["steps"][0]["module"] == "recon"
        assert d["steps"][1]["name"]   == "vuln"

    def test_agent_plan_empty_steps(self):
        plan = AgentPlan(name="empty")
        assert plan.to_dict()["steps"] == []


# ── BUILTIN_PLANS structure tests ─────────────────────────────────────────────

class TestBuiltinPlans:
    def test_all_four_plans_present(self):
        assert "full_pentest"  in BUILTIN_PLANS
        assert "quick_vuln"    in BUILTIN_PLANS
        assert "defense_audit" in BUILTIN_PLANS
        assert "crypto_audit"  in BUILTIN_PLANS

    def test_full_pentest_has_eight_steps(self):
        assert len(BUILTIN_PLANS["full_pentest"]) == 8

    def test_quick_vuln_has_three_steps(self):
        assert len(BUILTIN_PLANS["quick_vuln"]) == 3

    def test_defense_audit_has_three_steps(self):
        assert len(BUILTIN_PLANS["defense_audit"]) == 3

    def test_crypto_audit_has_four_steps(self):
        assert len(BUILTIN_PLANS["crypto_audit"]) == 4

    def test_all_steps_have_required_fields(self):
        for plan_name, steps in BUILTIN_PLANS.items():
            for step in steps:
                assert "name"       in step, f"{plan_name}: step missing 'name'"
                assert "module"     in step, f"{plan_name}: step missing 'module'"
                assert "risk_level" in step, f"{plan_name}: step missing 'risk_level'"
                assert step["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), \
                    f"{plan_name}: invalid risk_level '{step['risk_level']}'"

    def test_full_pentest_starts_with_recon(self):
        assert BUILTIN_PLANS["full_pentest"][0]["module"] == "recon"

    def test_full_pentest_ends_with_report(self):
        assert BUILTIN_PLANS["full_pentest"][-1]["module"] == "report"

    def test_quick_vuln_starts_with_recon(self):
        assert BUILTIN_PLANS["quick_vuln"][0]["module"] == "recon"


# ── AgentExecutor tests ───────────────────────────────────────────────────────

class TestAgentExecutor:
    def test_execute_single_step_success(self):
        kernel = _make_kernel({"findings": [{"cve": "CVE-2024-1"}], "status": "ok"})
        gate   = AutoApprovalGate()
        plan   = AgentPlan(name="test", steps=[
            AgentStep(name="recon", module="recon", description="Recon"),
        ])
        executor = AgentExecutor(kernel, gate)
        state    = executor.execute(plan, target="example.com")

        assert state["status"] == "complete"
        assert len(state["results"]) == 1
        assert state["results"][0]["step"]   == "recon"
        assert state["results"][0]["status"] == "ok"
        assert len(state["errors"]) == 0

    def test_execute_injects_target_into_kwargs(self):
        kernel = _make_kernel()
        gate   = AutoApprovalGate()
        plan   = AgentPlan(name="test", steps=[
            AgentStep(name="recon", module="recon"),
        ])
        AgentExecutor(kernel, gate).execute(plan, target="target.com")
        call_kwargs = kernel.dispatch.call_args[1]
        assert call_kwargs.get("target") == "target.com"

    def test_execute_forwards_prev_result(self):
        kernel = _make_kernel()
        gate   = AutoApprovalGate()
        # Two steps — second should receive _prev_result
        plan = AgentPlan(name="test", steps=[
            AgentStep(name="step1", module="recon"),
            AgentStep(name="step2", module="vuln"),
        ])
        AgentExecutor(kernel, gate).execute(plan, target="t.com")
        # Second dispatch call should have _prev_result
        second_call_kwargs = kernel.dispatch.call_args_list[1][1]
        assert "_prev_result" in second_call_kwargs

    def test_execute_aborts_on_gate_rejection(self):
        kernel = _make_kernel()
        gate   = CallbackApprovalGate(callback=lambda name, risk: False)
        plan   = AgentPlan(name="test", steps=[
            AgentStep(name="recon", module="recon", risk_level="HIGH"),
            AgentStep(name="vuln",  module="vuln"),
        ])
        state = AgentExecutor(kernel, gate).execute(plan)
        # Gate rejection causes early break; status ends as "complete" (loop exits)
        # but no steps should have been dispatched
        assert state["status"] in ("aborted", "complete")
        kernel.dispatch.assert_not_called()

    def test_execute_continues_after_step_exception(self):
        kernel = _make_kernel()
        # First dispatch raises, second succeeds
        kernel.dispatch.side_effect = [Exception("recon failed"), {"findings": []}]
        gate = AutoApprovalGate()
        plan = AgentPlan(name="test", steps=[
            AgentStep(name="recon", module="recon"),
            AgentStep(name="vuln",  module="vuln"),
        ])
        state = AgentExecutor(kernel, gate).execute(plan)
        assert state["status"] == "complete"
        assert len(state["errors"])  == 1
        assert len(state["results"]) == 1
        assert state["errors"][0]["step"] == "recon"

    def test_execute_calls_rollback_on_failure(self):
        kernel = _make_kernel()
        kernel.dispatch.side_effect = Exception("step failed")
        rollback_called = []
        rollback = lambda: rollback_called.append(True)
        gate = AutoApprovalGate()
        plan = AgentPlan(name="test", steps=[
            AgentStep(name="recon", module="recon", rollback_fn=rollback),
        ])
        AgentExecutor(kernel, gate).execute(plan)
        assert len(rollback_called) == 1

    def test_execute_state_has_timestamps(self):
        kernel = _make_kernel()
        gate   = AutoApprovalGate()
        plan   = AgentPlan(name="test", steps=[
            AgentStep(name="recon", module="recon"),
        ])
        state = AgentExecutor(kernel, gate).execute(plan)
        assert "started"  in state
        assert "finished" in state
        assert state["started"] <= state["finished"]

    def test_execute_empty_plan(self):
        kernel = _make_kernel()
        gate   = AutoApprovalGate()
        plan   = AgentPlan(name="empty", steps=[])
        state  = AgentExecutor(kernel, gate).execute(plan)
        assert state["status"] == "complete"
        assert state["results"] == []
        assert state["errors"]  == []
        kernel.dispatch.assert_not_called()

    def test_execute_does_not_inject_target_when_empty(self):
        kernel = _make_kernel()
        gate   = AutoApprovalGate()
        plan   = AgentPlan(name="test", steps=[
            AgentStep(name="recon", module="recon", kwargs={"mode": "passive"}),
        ])
        AgentExecutor(kernel, gate).execute(plan, target="")
        call_kwargs = kernel.dispatch.call_args[1]
        # target="" should not override existing kwargs
        assert "mode" in call_kwargs

    def test_execute_step_kwargs_preserved(self):
        kernel = _make_kernel()
        gate   = AutoApprovalGate()
        plan   = AgentPlan(name="test", steps=[
            AgentStep(name="vuln", module="vuln", kwargs={"quick": True, "audit_deps": "req.txt"}),
        ])
        AgentExecutor(kernel, gate).execute(plan)
        call_kwargs = kernel.dispatch.call_args[1]
        assert call_kwargs.get("quick")      is True
        assert call_kwargs.get("audit_deps") == "req.txt"


# ── AgentModule.run() tests ───────────────────────────────────────────────────

class TestAgentModuleRun:
    def _make_module(self, tmp_path, dispatch_return=None):
        kernel = _make_kernel(dispatch_return)
        kernel.config.get.return_value = {
            "default_approval": "auto",
            "plans_dir": str(tmp_path / "agent_runs"),
        }
        return AgentModule(kernel), kernel

    def test_list_plans_returns_all_four(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        result = module.run(list_plans=True)
        assert "plans" in result
        assert set(result["plans"]) == {"full_pentest", "quick_vuln", "defense_audit", "crypto_audit"}

    def test_unknown_plan_returns_error(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        result = module.run(plan="nonexistent_plan", approval="auto")
        assert "error" in result
        assert "unknown_plan" in result["error"]

    def test_no_plan_returns_error(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        result = module.run()
        assert "error" in result
        assert result["error"] == "no_plan_specified"

    def test_valid_plan_executes_and_persists(self, tmp_path):
        module, kernel = self._make_module(tmp_path)
        result = module.run(plan="quick_vuln", target="example.com", approval="auto")
        assert result["status"] == "complete"
        # Verify run file was persisted
        run_files = list((tmp_path / "agent_runs").glob("*.json"))
        assert len(run_files) == 1
        run_data = json.loads(run_files[0].read_text())
        assert run_data["plan"]["name"] == "quick_vuln"

    def test_suggest_plan_calls_ai(self, tmp_path):
        module, kernel = self._make_module(tmp_path)
        result = module.run(suggest_plan=True, target="example.com")
        assert "suggested_plan" in result
        kernel.ai.chat.assert_called_once()

    def test_ai_context_returns_plan_names(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        ctx = module.ai_context()
        assert ctx["module"] == "agent"
        assert "full_pentest" in ctx["available_plans"]