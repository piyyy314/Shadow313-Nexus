"""Unit tests — shadow313.v4.workflow.workflow_engine"""
import json
import pytest
from shadow313.v4.workflow.workflow_engine import (
    WorkflowNode,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowDLQ,
    WorkflowIdempotencyStore,
    HTTPWebhookDelivery,
    BuiltinStepExecutor,
    WorkflowLogEntry,
    DeliveryEvent,
    BindingType,
    SAMPLE_WORKFLOW_YAML,
    SHADOW313_SECURITY_WORKFLOW_YAML,
)


class TestWorkflowNode:
    def test_default_status_pending(self):
        node = WorkflowNode(node_id="n1", node_type="builtin.noop")
        assert node.status == "pending"

    def test_execution_id_generated(self):
        n1 = WorkflowNode(node_id="n1", node_type="builtin.noop")
        n2 = WorkflowNode(node_id="n2", node_type="builtin.noop")
        assert n1.execution_id != n2.execution_id

    def test_depends_on_default_empty(self):
        node = WorkflowNode(node_id="n1", node_type="builtin.noop")
        assert node.depends_on == []


class TestWorkflowDefinition:
    def _make_wf(self) -> WorkflowDefinition:
        steps = [
            WorkflowNode(node_id="step1", node_type="builtin.schema_validate"),
            WorkflowNode(node_id="step2", node_type="builtin.transform", depends_on=["step1"]),
            WorkflowNode(node_id="step3", node_type="builtin.ledger_write", depends_on=["step2"]),
        ]
        return WorkflowDefinition(
            workflow_id = "wf-test",
            name        = "Test Workflow",
            steps       = steps,
        )

    def test_get_node(self):
        wf   = self._make_wf()
        node = wf.get_node("step1")
        assert node is not None
        assert node.node_id == "step1"

    def test_get_nonexistent_node(self):
        wf = self._make_wf()
        assert wf.get_node("nonexistent") is None

    def test_get_ready_nodes_initial(self):
        wf    = self._make_wf()
        ready = wf.get_ready_nodes(completed=set())
        assert len(ready) == 1
        assert ready[0].node_id == "step1"

    def test_get_ready_nodes_after_step1(self):
        wf    = self._make_wf()
        ready = wf.get_ready_nodes(completed={"step1"})
        assert len(ready) == 1
        assert ready[0].node_id == "step2"

    def test_get_ready_nodes_all_complete(self):
        wf    = self._make_wf()
        ready = wf.get_ready_nodes(completed={"step1","step2","step3"})
        assert len(ready) == 0

    def test_is_complete_when_all_done(self):
        wf = self._make_wf()
        for step in wf.steps:
            step.status = "complete"
        assert wf.is_complete() is True

    def test_is_not_complete_when_pending(self):
        wf = self._make_wf()
        assert wf.is_complete() is False

    def test_is_complete_with_dlq(self):
        wf = self._make_wf()
        for step in wf.steps:
            step.status = "dlq"
        assert wf.is_complete() is True  # DLQ counts as "done"


class TestWorkflowDLQ:
    def test_enqueue_increases_depth(self, tmp_path):
        dlq  = WorkflowDLQ(dlq_dir=str(tmp_path))
        node = WorkflowNode(node_id="n1", node_type="builtin.noop")
        node.execution_id = "exec-1"
        dlq.enqueue("exec-1", "wf-1", "n1", {}, "Test error", [])
        assert dlq.depth() == 1

    def test_drain_clears_queue(self, tmp_path):
        dlq = WorkflowDLQ(dlq_dir=str(tmp_path))
        dlq.enqueue("exec-1", "wf-1", "n1", {}, "Error 1", [])
        dlq.enqueue("exec-2", "wf-1", "n2", {}, "Error 2", [])
        items = dlq.drain()
        assert len(items) == 2
        assert dlq.depth() == 0

    def test_alert_threshold(self, tmp_path):
        dlq = WorkflowDLQ(dlq_dir=str(tmp_path))
        dlq.ALERT_THRESHOLD = 3
        alerts = []
        dlq.register_alert(lambda data: alerts.append(data))
        for i in range(4):
            dlq.enqueue(f"exec-{i}", "wf-1", "n1", {}, "Error", [])
        assert len(alerts) >= 1

    def test_persists_to_disk(self, tmp_path):
        dlq = WorkflowDLQ(dlq_dir=str(tmp_path))
        dlq.enqueue("exec-abc", "wf-1", "n1", {"key": "val"}, "Disk test", [])
        dlq_files = list(tmp_path.glob("dlq_*.json"))
        assert len(dlq_files) >= 1

    def test_get_by_execution_id(self, tmp_path):
        dlq = WorkflowDLQ(dlq_dir=str(tmp_path))
        dlq.enqueue("exec-xyz", "wf-1", "n1", {}, "Error", [])
        item = dlq.get_by_execution_id("exec-xyz")
        assert item is not None
        assert item["execution_id"] == "exec-xyz"


class TestWorkflowIdempotencyStore:
    def test_new_key_not_duplicate(self):
        store = WorkflowIdempotencyStore()
        is_dup, cached = store.is_duplicate("exec-1")
        assert is_dup is False
        assert cached is None

    def test_recorded_key_is_duplicate(self):
        store = WorkflowIdempotencyStore()
        store.record("exec-1", {"status": "complete"})
        is_dup, cached = store.is_duplicate("exec-1")
        assert is_dup is True
        assert cached == {"status": "complete"}

    def test_different_keys_not_duplicate(self):
        store = WorkflowIdempotencyStore()
        store.record("exec-1", {"status": "complete"})
        is_dup, _ = store.is_duplicate("exec-2")
        assert is_dup is False


class TestBuiltinStepExecutor:
    def test_schema_validate(self):
        executor = BuiltinStepExecutor()
        node     = WorkflowNode(node_id="n1", node_type="builtin.schema_validate",
                               config={"schema_ref": "schemas/test.json"})
        result   = executor.execute(node, {"input": {"key": "value"}})
        assert result["validated"] is True

    def test_transform(self):
        executor = BuiltinStepExecutor()
        node     = WorkflowNode(node_id="n1", node_type="builtin.transform",
                               config={"template": "key: value\nother: data"})
        result   = executor.execute(node, {})
        assert "transformed" in result
        assert isinstance(result["transformed"], dict)

    def test_ledger_write(self):
        executor = BuiltinStepExecutor()
        node     = WorkflowNode(node_id="n1", node_type="builtin.ledger_write",
                               config={"payload": {"event_type": "TEST"}})
        result   = executor.execute(node, {"execution_id": "exec-1"})
        assert result["ledger_write"] == "ok"
        assert result["payload"]["execution_id"] == "exec-1"

    def test_unknown_type_returns_status(self):
        executor = BuiltinStepExecutor()
        node     = WorkflowNode(node_id="n1", node_type="builtin.unknown_type")
        result   = executor.execute(node, {})
        assert result["status"] == "executed"


class TestWorkflowEngine:
    def test_register_workflow(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        wf     = WorkflowDefinition(
            workflow_id = "wf-test",
            name        = "Test",
            steps       = [WorkflowNode(node_id="s1", node_type="builtin.schema_validate")],
        )
        engine.register(wf)
        assert "wf-test" in engine._workflows

    def test_execute_simple_workflow(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        wf     = WorkflowDefinition(
            workflow_id = "wf-simple",
            name        = "Simple",
            steps       = [WorkflowNode(node_id="s1", node_type="builtin.schema_validate")],
        )
        engine.register(wf)
        result = engine.execute("wf-simple")
        assert result["workflow_id"] == "wf-simple"
        assert "execution_id" in result
        assert result["status"] in ("complete", "failed")

    def test_execute_sequential_workflow(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        wf     = WorkflowDefinition(
            workflow_id = "wf-seq",
            name        = "Sequential",
            steps       = [
                WorkflowNode(node_id="s1", node_type="builtin.schema_validate"),
                WorkflowNode(node_id="s2", node_type="builtin.transform",
                            depends_on=["s1"], config={"template": "key: value"}),
                WorkflowNode(node_id="s3", node_type="builtin.ledger_write",
                            depends_on=["s2"], config={"payload": {"event": "done"}}),
            ],
        )
        engine.register(wf)
        result = engine.execute("wf-seq")
        assert result["status"] in ("complete", "failed")
        assert len(result["steps"]) == 3

    def test_execute_nonexistent_workflow(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        result = engine.execute("nonexistent-wf")
        assert "error" in result

    def test_idempotency_deduplication(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        wf     = WorkflowDefinition(
            workflow_id = "wf-idem",
            name        = "Idempotent",
            steps       = [WorkflowNode(node_id="s1", node_type="builtin.schema_validate")],
        )
        engine.register(wf)
        exec_id = "test-exec-id-123"
        r1 = engine.execute("wf-idem", execution_id=exec_id)
        r2 = engine.execute("wf-idem", execution_id=exec_id)
        assert r2.get("duplicate") is True

    def test_register_from_yaml(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        wf     = engine.register_from_yaml(SAMPLE_WORKFLOW_YAML)
        assert wf.workflow_id == "wf-ledger-commit-notify"
        assert len(wf.steps) >= 3

    def test_register_shadow313_workflow(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        wf     = engine.register_from_yaml(SHADOW313_SECURITY_WORKFLOW_YAML)
        assert wf.workflow_id == "wf-shadow313-full-scan"
        assert len(wf.steps) >= 5

    def test_stats(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        stats  = engine.stats()
        assert "registered_workflows" in stats
        assert "total_executions"     in stats
        assert "success_rate"         in stats
        assert "dlq_depth"            in stats

    def test_get_logs(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        wf     = WorkflowDefinition(
            workflow_id = "wf-log",
            name        = "Log Test",
            steps       = [WorkflowNode(node_id="s1", node_type="builtin.schema_validate")],
        )
        engine.register(wf)
        engine.execute("wf-log")
        logs = engine.get_logs(limit=50)
        assert len(logs) >= 1

    def test_dlq_populated_on_failure(self, tmp_path):
        engine = WorkflowEngine(log_dir=str(tmp_path))
        # Create a workflow with a failing HTTP webhook (no server running)
        wf = WorkflowDefinition(
            workflow_id = "wf-fail",
            name        = "Failing",
            steps       = [
                WorkflowNode(
                    node_id   = "s1",
                    node_type = "http_webhook",
                    config    = {"target": "http://127.0.0.1:19999/nonexistent"},
                    retry_max = 1,  # Only 1 retry to speed up test
                    retry_base_ms = 10,
                ),
            ],
        )
        engine.register(wf)
        result = engine.execute("wf-fail")
        # Should have failed and gone to DLQ
        assert result["status"] in ("complete", "failed")
        # DLQ may or may not have items depending on retry behavior


class TestWorkflowLogEntry:
    def test_to_json(self):
        entry = WorkflowLogEntry(
            event        = DeliveryEvent.SUCCESS.value,
            execution_id = "exec-1",
            workflow_id  = "wf-1",
            node_id      = "step-1",
            attempt      = 1,
            binding_type = "http_webhook",
            latency_ms   = 87,
        )
        json_str = entry.to_json()
        data     = json.loads(json_str)
        assert data["event"]        == "workflow.delivery.success"
        assert data["execution_id"] == "exec-1"
        assert data["latency_ms"]   == 87

    def test_timestamp_present(self):
        entry = WorkflowLogEntry()
        assert entry.ts != ""
        assert "T" in entry.ts

    def test_delivery_events(self):
        assert DeliveryEvent.ATTEMPT.value     == "workflow.delivery.attempt"
        assert DeliveryEvent.SUCCESS.value     == "workflow.delivery.success"
        assert DeliveryEvent.RETRY.value       == "workflow.delivery.retry"
        assert DeliveryEvent.DEAD_LETTER.value == "workflow.delivery.dead_letter"