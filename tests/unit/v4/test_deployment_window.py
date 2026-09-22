"""
Tests for shadow313.v4.deployment.deployment_window

Covers deployment window definitions, 313-BIND receipt chain,
step execution, rollback checkpoints, and full plan simulation.
"""
from __future__ import annotations

import pytest
import shadow313.v4.deployment.deployment_window as dw_mod
from shadow313.v4.deployment.deployment_window import (
    DeploymentWindow, DeploymentStep, DeploymentWindowExecutor,
    _bind_step, verify_deployment_chain,
    run_deployment_plan,
    DW1, DW2, DW3, DW4, ALL_WINDOWS,
)


@pytest.fixture(autouse=True)
def reset_chain():
    dw_mod._DEPLOY_COUNTER = 0
    dw_mod._DEPLOY_CHAIN   = []
    yield
    dw_mod._DEPLOY_COUNTER = 0
    dw_mod._DEPLOY_CHAIN   = []


# ═══════════════════════════════════════════════════════════════════════════════
# Window definitions
# ═══════════════════════════════════════════════════════════════════════════════

class TestWindowDefinitions:

    def test_four_windows_defined(self):
        assert len(ALL_WINDOWS) == 4

    def test_window_ids_unique(self):
        ids = [w.window_id for w in ALL_WINDOWS]
        assert len(set(ids)) == 4

    def test_dw1_targets_crqc001_003(self):
        assert any("CRQC-001" in c for c in DW1.crqc_items)
        assert any("CRQC-003" in c for c in DW1.crqc_items)

    def test_dw2_targets_hsm(self):
        assert "HSM" in DW2.title

    def test_dw3_targets_x509(self):
        assert "X.509" in DW3.title or "Certificate" in DW3.title

    def test_dw4_targets_ipfs(self):
        assert "IPFS" in DW4.title

    def test_all_windows_have_steps(self):
        for w in ALL_WINDOWS:
            assert len(w.steps) >= 2, f"{w.window_id} needs at least 2 steps"

    def test_all_windows_have_pre_checks(self):
        for w in ALL_WINDOWS:
            assert len(w.pre_checks) >= 3

    def test_all_windows_have_post_checks(self):
        for w in ALL_WINDOWS:
            assert len(w.post_checks) >= 3

    def test_all_windows_have_rollback_window(self):
        for w in ALL_WINDOWS:
            assert len(w.rollback_window) > 0

    def test_dw1_has_five_steps(self):
        assert len(DW1.steps) == 5

    def test_dw1_last_step_is_313bind_verification(self):
        last = DW1.steps[-1]
        assert "313" in last.name or "BIND" in last.name or "verification" in last.name.lower()

    def test_all_steps_have_rollback_cmd(self):
        for w in ALL_WINDOWS:
            for s in w.steps:
                assert len(s.rollback_cmd) > 0, f"{s.step_id} missing rollback_cmd"

    def test_all_steps_have_verify_cmd(self):
        for w in ALL_WINDOWS:
            for s in w.steps:
                assert len(s.verify_cmd) > 0, f"{s.step_id} missing verify_cmd"

    def test_all_steps_have_go_criteria(self):
        for w in ALL_WINDOWS:
            for s in w.steps:
                assert len(s.go_criteria) >= 2, f"{s.step_id} needs >= 2 go criteria"

    def test_all_steps_have_no_go_criteria(self):
        for w in ALL_WINDOWS:
            for s in w.steps:
                assert len(s.no_go_criteria) >= 1, f"{s.step_id} needs >= 1 no-go criteria"

    def test_dw1_target_date_is_2026(self):
        assert "2026" in DW1.target_date

    def test_dw2_target_date_is_2027(self):
        assert "2027" in DW2.target_date

    def test_offline_systems_defined_for_critical_steps(self):
        # Steps that modify signing infrastructure must declare offline systems
        for w in ALL_WINDOWS:
            for s in w.steps:
                if "migrate" in s.name.lower() or "deploy" in s.name.lower():
                    # These steps should declare what goes offline
                    assert s.offline_systems is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 313-BIND receipt chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestBindReceiptChain:

    def test_bind_step_creates_receipt(self):
        r = _bind_step("DW-TEST", "S1", "Test step", "STARTED", {"key": "val"})
        assert r["bind_id"] == "313-DW-00000001"
        assert r["window_id"] == "DW-TEST"
        assert r["step_id"] == "S1"
        assert r["status"] == "STARTED"

    def test_bind_id_increments(self):
        r1 = _bind_step("DW-TEST", "S1", "Step 1", "STARTED", {})
        r2 = _bind_step("DW-TEST", "S2", "Step 2", "COMPLETED", {})
        assert r1["bind_id"] == "313-DW-00000001"
        assert r2["bind_id"] == "313-DW-00000002"

    def test_timestamp_ends_in_313(self):
        r = _bind_step("DW-TEST", "S1", "Test", "STARTED", {})
        assert r["timestamp_ns"] % 1000 == 313

    def test_chain_hash_is_sha3_256(self):
        r = _bind_step("DW-TEST", "S1", "Test", "STARTED", {})
        assert len(r["chain_hash"]) == 64

    def test_chain_hashes_are_unique(self):
        r1 = _bind_step("DW-TEST", "S1", "Step 1", "STARTED", {})
        r2 = _bind_step("DW-TEST", "S2", "Step 2", "COMPLETED", {})
        assert r1["chain_hash"] != r2["chain_hash"]

    def test_empty_chain_is_valid(self):
        result = verify_deployment_chain()
        assert result["valid"] is True
        assert result["total"] == 0

    def test_chain_valid_after_multiple_steps(self):
        for i in range(5):
            _bind_step("DW-TEST", f"S{i}", f"Step {i}", "COMPLETED", {"i": i})
        result = verify_deployment_chain()
        assert result["valid"] is True
        assert result["total"] == 5

    def test_chain_message_contains_count(self):
        for i in range(3):
            _bind_step("DW-TEST", f"S{i}", f"Step {i}", "COMPLETED", {})
        result = verify_deployment_chain()
        assert "3" in result["message"]

    def test_all_statuses_accepted(self):
        for status in ("STARTED", "COMPLETED", "ROLLED_BACK", "VERIFIED"):
            _bind_step("DW-TEST", f"S-{status}", "Test", status, {})
        assert len(dw_mod._DEPLOY_CHAIN) == 4


# ═══════════════════════════════════════════════════════════════════════════════
# DeploymentWindowExecutor
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeploymentWindowExecutor:

    def test_executor_runs_pre_checks(self):
        executor = DeploymentWindowExecutor(DW1, verbose=False)
        receipt = executor.run_pre_checks()
        assert receipt["status"] == "STARTED"
        assert receipt["window_id"] == "DW-1"
        assert receipt["step_id"] == "DW-1-PRE"

    def test_executor_runs_step(self):
        executor = DeploymentWindowExecutor(DW1, verbose=False)
        receipt = executor.run_step(DW1.steps[0], simulate=True)
        assert receipt["status"] == "COMPLETED"
        assert receipt["step_id"] == "DW-1-S1"

    def test_executor_runs_post_checks(self):
        executor = DeploymentWindowExecutor(DW1, verbose=False)
        executor.run_pre_checks()
        receipt = executor.run_post_checks()
        assert receipt["status"] == "VERIFIED"
        assert receipt["step_id"] == "DW-1-POST"

    def test_executor_full_window_dw1(self):
        executor = DeploymentWindowExecutor(DW1, verbose=False)
        result = executor.run_full_window(simulate=True)
        assert result["window_id"] == "DW-1"
        assert result["chain_status"]["valid"] is True
        assert len(result["step_receipts"]) == len(DW1.steps)

    def test_executor_full_window_all_steps_completed(self):
        executor = DeploymentWindowExecutor(DW1, verbose=False)
        result = executor.run_full_window(simulate=True)
        for r in result["step_receipts"]:
            assert r["status"] == "COMPLETED"

    def test_executor_receipts_accumulate(self):
        executor = DeploymentWindowExecutor(DW1, verbose=False)
        result = executor.run_full_window(simulate=True)
        # pre + steps + post
        expected = 1 + len(DW1.steps) + 1
        assert result["total_receipts"] == expected

    def test_step_receipt_stored_on_step(self):
        executor = DeploymentWindowExecutor(DW1, verbose=False)
        executor.run_step(DW1.steps[0], simulate=True)
        assert DW1.steps[0].receipt is not None
        assert DW1.steps[0].receipt["bind_id"].startswith("313-DW-")


# ═══════════════════════════════════════════════════════════════════════════════
# Full deployment plan
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullDeploymentPlan:

    def test_plan_runs_without_error(self):
        result = run_deployment_plan(verbose=False)
        assert "windows" in result
        assert "chain_status" in result

    def test_plan_has_four_windows(self):
        result = run_deployment_plan(verbose=False)
        assert len(result["windows"]) == 4

    def test_plan_chain_is_valid(self):
        result = run_deployment_plan(verbose=False)
        assert result["chain_status"]["valid"] is True

    def test_plan_total_receipts_correct(self):
        result = run_deployment_plan(verbose=False)
        # Each window: 1 pre + N steps + 1 post
        expected = sum(1 + len(w.steps) + 1 for w in ALL_WINDOWS)
        assert result["total_receipts"] == expected

    def test_plan_all_windows_have_valid_chain(self):
        result = run_deployment_plan(verbose=False)
        for w in result["windows"]:
            assert w["chain_status"]["valid"] is True

    def test_plan_dw1_has_correct_crqc_items(self):
        result = run_deployment_plan(verbose=False)
        dw1 = result["windows"][0]
        pre_payload = dw1["pre_receipt"]["payload"]
        assert any("CRQC-001" in c for c in pre_payload["crqc_items"])

    def test_plan_receipts_are_sequential(self):
        result = run_deployment_plan(verbose=False)
        # Collect all bind IDs across all windows
        all_ids = []
        for w in result["windows"]:
            all_ids.append(w["pre_receipt"]["bind_id"])
            for r in w["step_receipts"]:
                all_ids.append(r["bind_id"])
            all_ids.append(w["post_receipt"]["bind_id"])
        # Extract numbers and verify sequential
        nums = [int(bid.split("-")[-1]) for bid in all_ids]
        assert nums == list(range(1, len(nums) + 1))

    def test_plan_chain_covers_all_windows(self):
        result = run_deployment_plan(verbose=False)
        window_ids_in_chain = set(r["window_id"] for r in dw_mod._DEPLOY_CHAIN)
        for w in ALL_WINDOWS:
            assert w.window_id in window_ids_in_chain


# ═══════════════════════════════════════════════════════════════════════════════
# Rollback checkpoint coverage
# ═══════════════════════════════════════════════════════════════════════════════

class TestRollbackCheckpoints:

    def test_dw1_s2_rollback_uses_git_checkout(self):
        assert "git checkout" in DW1.steps[1].rollback_cmd

    def test_dw1_s3_rollback_restores_backup(self):
        assert "backup" in DW1.steps[2].rollback_cmd.lower()

    def test_dw1_s4_rollback_restores_ledger(self):
        assert "restore" in DW1.steps[3].rollback_cmd.lower()

    def test_dw2_s2_rollback_uses_git_checkout(self):
        assert "git checkout" in DW2.steps[1].rollback_cmd

    def test_dw3_s2_rollback_restores_classical_cert(self):
        assert "backup" in DW3.steps[1].rollback_cmd.lower() or "restore" in DW3.steps[1].rollback_cmd.lower()

    def test_no_go_criteria_cover_key_failure_modes(self):
        # DW-1-S1: must catch ImportError
        assert any("ImportError" in c or "import" in c.lower() for c in DW1.steps[0].no_go_criteria)

    def test_dw1_s5_receipt_is_immutable(self):
        # The 313-BIND verification step must note receipts are immutable
        last_step = DW1.steps[-1]
        assert "immutable" in last_step.rollback_cmd.lower() or "N/A" in last_step.rollback_cmd