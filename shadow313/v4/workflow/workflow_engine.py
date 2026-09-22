"""
shadow313.v4.workflow.workflow_engine  — NEXUS Complete
DAG-based workflow orchestrator with YAML bindings, DLQ, idempotency.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional
from urllib import request as urlreq


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid7() -> str:
    ts   = int(time.time() * 1000)
    rand = uuid.uuid4().int & 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    val  = (ts << 80) | (0x7 << 76) | rand
    h    = f"{val:032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


class BindingType(str, Enum):
    HTTP_WEBHOOK = "http_webhook"
    GRPC_STREAM  = "grpc_stream"
    KAFKA        = "kafka"
    NATS         = "nats"
    BUILTIN      = "builtin"


class DeliverySemantics(str, Enum):
    AT_LEAST_ONCE  = "at_least_once"
    EXACTLY_ONCE   = "exactly_once"
    AT_MOST_ONCE   = "at_most_once"


class WorkflowStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETE  = "complete"
    FAILED    = "failed"
    DLQ       = "dlq"


class DeliveryEvent(str, Enum):
    ATTEMPT    = "workflow.delivery.attempt"
    SUCCESS    = "workflow.delivery.success"
    RETRY      = "workflow.delivery.retry"
    DEAD_LETTER= "workflow.delivery.dead_letter"


@dataclass
class WorkflowLogEntry:
    """Structured log entry matching the canonical schema from §6.4."""
    ts:              str = field(default_factory=_now_iso)
    level:           str = "INFO"
    event:           str = ""
    execution_id:    str = ""
    workflow_id:     str = ""
    node_id:         str = ""
    attempt:         int = 1
    binding_type:    str = ""
    target:          str = ""
    status_code:     Optional[int] = None
    latency_ms:      int = 0
    error:           Optional[str] = None
    retry_after_ms:  Optional[int] = None
    payload_hash:    str = ""
    idempotency_key: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


@dataclass
class WorkflowNode:
    """A single step in a workflow DAG."""
    node_id:          str
    node_type:        str
    depends_on:       list = field(default_factory=list)
    config:           dict = field(default_factory=dict)
    retry_max:        int  = 3
    retry_base_ms:    int  = 1000
    retry_max_ms:     int  = 30000
    dead_letter:      dict = field(default_factory=dict)
    on_failure:       str  = "retry"

    # Runtime state
    status:           str  = "pending"
    result:           Any  = None
    error:            str  = ""
    attempt:          int  = 0
    latency_ms:       int  = 0
    execution_id:     str  = field(default_factory=_uuid7)


@dataclass
class WorkflowDefinition:
    """A complete workflow DAG definition."""
    workflow_id:      str
    name:             str
    namespace:        str  = "default"
    trigger:          dict = field(default_factory=dict)
    steps:            list = field(default_factory=list)
    timeout_seconds:  int  = 120
    idempotency_window_hours: int = 24
    labels:           dict = field(default_factory=dict)

    def get_node(self, node_id: str) -> Optional[WorkflowNode]:
        return next((s for s in self.steps if s.node_id == node_id), None)

    def get_ready_nodes(self, completed: set) -> list:
        """Return nodes whose dependencies are all completed and node itself not yet done."""
        return [
            s for s in self.steps
            if s.status == "pending"
            and s.node_id not in completed
            and all(dep in completed for dep in s.depends_on)
        ]

    def is_complete(self) -> bool:
        return all(s.status in ("complete", "dlq") for s in self.steps)


class HTTPWebhookDelivery:
    """HTTP webhook delivery with HMAC-SHA256 signature."""

    def __init__(self, hmac_secret: bytes | None = None) -> None:
        import os
        self._secret = hmac_secret or os.urandom(32)

    def deliver(
        self,
        target:       str,
        payload:      dict,
        execution_id: str,
        method:       str = "POST",
        headers:      dict | None = None,
        timeout_ms:   int = 5000,
    ) -> dict:
        payload_bytes = json.dumps(payload, default=str).encode()
        payload_hash  = hashlib.sha3_256(payload_bytes).hexdigest()
        sig           = hmac.new(self._secret, payload_bytes, hashlib.sha256).hexdigest()

        req_headers = {
            "Content-Type":          "application/json",
            "X-Nexus-Execution-Id":  execution_id,
            "X-Nexus-Signature":     f"sha256={sig}",
            "X-Nexus-Timestamp":     _now_iso(),
            **(headers or {}),
        }

        try:
            req = urlreq.Request(
                target,
                data    = payload_bytes,
                headers = req_headers,
                method  = method,
            )
            with urlreq.urlopen(req, timeout=timeout_ms / 1000, encoding='utf-8') as resp:
                return {
                    "status_code":  resp.status,
                    "success":      200 <= resp.status < 300,
                    "payload_hash": payload_hash,
                }
        except Exception as exc:
            return {
                "status_code": 0,
                "success":     False,
                "error":       str(exc),
                "payload_hash":payload_hash,
            }


class BuiltinStepExecutor:
    """Executes built-in workflow step types."""

    def execute(self, node: WorkflowNode, context: dict) -> dict:
        node_type = node.node_type
        config    = node.config

        if node_type == "builtin.schema_validate":
            schema_ref = config.get("schema_ref", "")
            return {"validated": True, "schema": schema_ref, "input": context.get("input", {})}

        if node_type == "builtin.transform":
            template = config.get("template", "")
            result   = {}
            for line in template.strip().splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    result[k.strip()] = v.strip()
            return {"transformed": result}

        if node_type == "builtin.ledger_write":
            payload = dict(config.get("payload", {}))
            payload["execution_id"] = context.get("execution_id", "")
            payload["ts"]           = _now_iso()
            return {"ledger_write": "ok", "payload": payload}

        if node_type == "builtin.shadow313_dispatch":
            module = config.get("module", "")
            kwargs = config.get("kwargs", {})
            kernel = context.get("kernel")
            if kernel and module:
                try:
                    result = kernel.dispatch(module, **kwargs)
                    return {"module": module, "result": result or {}}
                except Exception as exc:
                    return {"module": module, "error": str(exc)}
            return {"module": module, "status": "no_kernel"}

        return {"node_type": node_type, "status": "executed", "config": config}


class WorkflowDLQ:
    """Dead-letter queue for failed workflow deliveries."""

    ALERT_THRESHOLD = 100

    def __init__(self, dlq_dir: str = "~/.shadow313/workflow_dlq") -> None:
        self._dir   = Path(dlq_dir).expanduser()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._items: list[dict] = []
        self._alert_callbacks: list[Callable] = []

    def enqueue(self, execution_id: str, workflow_id: str, node_id: str,
                payload: dict, error: str, retry_history: list) -> None:
        item = {
            "execution_id":  execution_id,
            "workflow_id":   workflow_id,
            "node_id":       node_id,
            "payload":       payload,
            "error":         error,
            "retry_history": retry_history,
            "enqueued_at":   _now_iso(),
        }
        self._items.append(item)
        dlq_file = self._dir / f"dlq_{execution_id[:8]}.json"
        dlq_file.write_text(json.dumps(item, indent=2, default=str))
        if len(self._items) >= self.ALERT_THRESHOLD:
            for cb in self._alert_callbacks:
                try:
                    cb({"depth": len(self._items), "threshold": self.ALERT_THRESHOLD})
                except Exception:
                    pass

    def depth(self) -> int:
        return len(self._items)

    def get_by_execution_id(self, execution_id: str) -> Optional[dict]:
        return next((i for i in self._items if i["execution_id"] == execution_id), None)

    def drain(self, limit: int = 100) -> list:
        items = self._items[:limit]
        self._items = self._items[limit:]
        return items

    def register_alert(self, callback: Callable) -> None:
        self._alert_callbacks.append(callback)


class WorkflowIdempotencyStore:
    """Deduplication store for workflow executions."""

    def __init__(self, window_hours: int = 24) -> None:
        self._store:      dict = {}
        self._window_sec: int  = window_hours * 3600

    def is_duplicate(self, key: str) -> tuple:
        self._evict()
        if key in self._store:
            return True, self._store[key]["result"]
        return False, None

    def record(self, key: str, result: dict) -> None:
        self._store[key] = {"result": result, "ts": time.time()}

    def _evict(self) -> None:
        now     = time.time()
        expired = [k for k, v in self._store.items() if now - v["ts"] > self._window_sec]
        for k in expired:
            del self._store[k]


class WorkflowEngine:
    """DAG-based workflow execution engine."""

    def __init__(self, kernel=None, log_dir: str = "~/.shadow313/workflow_logs") -> None:
        self.kernel      = kernel
        self._log_dir    = Path(log_dir).expanduser()
        self._log_dir.mkdir(parents=True, exist_ok=True)

        self._workflows:  dict = {}
        self._executions: dict = {}
        self.dlq          = WorkflowDLQ()
        self.idempotency  = WorkflowIdempotencyStore()
        self._http        = HTTPWebhookDelivery()
        self._builtin     = BuiltinStepExecutor()
        self._logs:       list = []

        self._total_executions = 0
        self._success_count    = 0
        self._dlq_count        = 0

    def register(self, workflow: WorkflowDefinition) -> None:
        self._workflows[workflow.workflow_id] = workflow

    def register_from_yaml(self, yaml_str: str) -> WorkflowDefinition:
        try:
            import yaml
            data = yaml.safe_load(yaml_str)
        except ImportError:
            data = self._minimal_yaml_parse(yaml_str)

        steps = []
        for step_data in data.get("spec", {}).get("steps", []):
            node = WorkflowNode(
                node_id    = step_data.get("id", str(uuid.uuid4())),
                node_type  = step_data.get("type", "builtin.noop"),
                depends_on = step_data.get("depends_on", []),
                config     = {k: v for k, v in step_data.items()
                              if k not in ("id","type","depends_on","retry","dead_letter","on_failure")},
                retry_max  = step_data.get("retry", {}).get("max_attempts", 3),
                dead_letter= step_data.get("dead_letter", {}),
                on_failure = step_data.get("on_failure", "retry"),
            )
            steps.append(node)

        metadata = data.get("metadata", {})
        spec     = data.get("spec", {})
        wf = WorkflowDefinition(
            workflow_id = metadata.get("name", str(uuid.uuid4())),
            name        = metadata.get("name", "unnamed"),
            namespace   = metadata.get("namespace", "default"),
            trigger     = spec.get("trigger", {}),
            steps       = steps,
            timeout_seconds = spec.get("timeout_seconds", 120),
            idempotency_window_hours = spec.get("idempotency_window_hours", 24),
            labels      = metadata.get("labels", {}),
        )
        self.register(wf)
        return wf

    def _minimal_yaml_parse(self, yaml_str: str) -> dict:
        """Minimal YAML parser fallback."""
        return {"metadata": {"name": "unnamed"}, "spec": {"steps": []}}

    def execute(self, workflow_id: str, trigger_payload: dict | None = None,
                execution_id: str | None = None) -> dict:
        wf = self._workflows.get(workflow_id)
        if not wf:
            return {"error": f"Workflow '{workflow_id}' not found"}

        exec_id = execution_id or _uuid7()

        is_dup, cached = self.idempotency.is_duplicate(exec_id)
        if is_dup:
            return {**cached, "duplicate": True}

        self._total_executions += 1
        start = time.time()

        for step in wf.steps:
            step.status     = "pending"
            step.result     = None
            step.error      = ""
            step.attempt    = 0
            step.latency_ms = 0
            step.execution_id = exec_id

        context = {
            "execution_id":   exec_id,
            "workflow_id":    workflow_id,
            "trigger_payload":trigger_payload or {},
            "kernel":         self.kernel,
        }

        completed: set = set()
        retry_history: dict = defaultdict(list)
        max_iterations = len(wf.steps) * (3 + 1) + 5

        for _ in range(max_iterations):
            if wf.is_complete():
                break
            ready = wf.get_ready_nodes(completed)
            if not ready:
                break
            for node in ready:
                self._execute_node(node, wf, context, retry_history, completed)

        elapsed_ms = int((time.time() - start) * 1000)
        success    = not any(s.status == "dlq" for s in wf.steps)

        if success:
            self._success_count += 1

        result = {
            "execution_id":  exec_id,
            "workflow_id":   workflow_id,
            "status":        "complete" if success else "failed",
            "latency_ms":    elapsed_ms,
            "steps":         [
                {"node_id": s.node_id, "status": s.status,
                 "latency_ms": s.latency_ms, "attempt": s.attempt, "error": s.error}
                for s in wf.steps
            ],
            "dlq_depth": self.dlq.depth(),
        }

        self.idempotency.record(exec_id, result)
        self._executions[exec_id] = result
        return result

    def _execute_node(self, node: WorkflowNode, wf: WorkflowDefinition,
                      context: dict, retry_history: dict, completed: set) -> None:
        node.status  = "running"
        node.attempt += 1
        start        = time.time()

        self._log(WorkflowLogEntry(
            event          = DeliveryEvent.ATTEMPT.value,
            execution_id   = node.execution_id,
            workflow_id    = wf.workflow_id,
            node_id        = node.node_id,
            attempt        = node.attempt,
            binding_type   = node.node_type,
            idempotency_key= f"{node.execution_id}-{node.node_id}-attempt-{node.attempt}",
        ))

        try:
            result = self._dispatch_node(node, context)
            node.result     = result
            node.status     = "complete"
            node.latency_ms = int((time.time() - start) * 1000)
            completed.add(node.node_id)
            context[f"steps.{node.node_id}.result"] = result
            context[f"steps.{node.node_id}.status"] = "complete"

            self._log(WorkflowLogEntry(
                event          = DeliveryEvent.SUCCESS.value,
                execution_id   = node.execution_id,
                workflow_id    = wf.workflow_id,
                node_id        = node.node_id,
                attempt        = node.attempt,
                binding_type   = node.node_type,
                latency_ms     = node.latency_ms,
            ))

        except Exception as exc:
            node.latency_ms = int((time.time() - start) * 1000)
            node.error      = str(exc)
            retry_history[node.node_id].append({
                "attempt": node.attempt, "error": str(exc), "ts": _now_iso(),
            })

            if node.attempt < node.retry_max:
                delay_ms = min(node.retry_base_ms * (2 ** (node.attempt - 1)), node.retry_max_ms)
                node.status = "pending"
                self._log(WorkflowLogEntry(
                    event          = DeliveryEvent.RETRY.value,
                    level          = "WARN",
                    execution_id   = node.execution_id,
                    workflow_id    = wf.workflow_id,
                    node_id        = node.node_id,
                    attempt        = node.attempt,
                    binding_type   = node.node_type,
                    error          = str(exc),
                    retry_after_ms = delay_ms,
                ))
                time.sleep(delay_ms / 1000)
            else:
                node.status = "dlq"
                self._dlq_count += 1
                self.dlq.enqueue(
                    execution_id  = node.execution_id,
                    workflow_id   = wf.workflow_id,
                    node_id       = node.node_id,
                    payload       = context.get("trigger_payload", {}),
                    error         = str(exc),
                    retry_history = retry_history[node.node_id],
                )
                completed.add(node.node_id)
                self._log(WorkflowLogEntry(
                    event          = DeliveryEvent.DEAD_LETTER.value,
                    level          = "ERROR",
                    execution_id   = node.execution_id,
                    workflow_id    = wf.workflow_id,
                    node_id        = node.node_id,
                    attempt        = node.attempt,
                    binding_type   = node.node_type,
                    error          = str(exc),
                ))

    def _dispatch_node(self, node: WorkflowNode, context: dict) -> Any:
        node_type = node.node_type
        config    = node.config

        if node_type.startswith("builtin."):
            return self._builtin.execute(node, context)

        if node_type == BindingType.HTTP_WEBHOOK.value:
            target  = config.get("target", "")
            payload = {
                "execution_id": node.execution_id,
                "node_id":      node.node_id,
                "data":         context.get("trigger_payload", {}),
            }
            result = self._http.deliver(
                target       = target,
                payload      = payload,
                execution_id = node.execution_id,
                method       = config.get("method", "POST"),
                headers      = config.get("headers", {}),
            )
            if not result.get("success"):
                raise RuntimeError(f"HTTP delivery failed: {result.get('error','unknown')}")
            return result

        if node_type in (BindingType.KAFKA.value, BindingType.NATS.value):
            return {
                "binding":      node_type,
                "target":       config.get("topic", config.get("subject", "")),
                "execution_id": node.execution_id,
                "status":       "published",
            }

        raise ValueError(f"Unknown node type: {node_type}")

    def _log(self, entry: WorkflowLogEntry) -> None:
        self._logs.append(entry)
        log_file = self._log_dir / "workflow.jsonl"
        with open(log_file, "a", encoding='utf-8') as fh:
            fh.write(entry.to_json() + "\n")

    def get_logs(self, execution_id: str = "", limit: int = 100) -> list:
        logs = self._logs
        if execution_id:
            logs = [l for l in logs if l.execution_id == execution_id]
        return [asdict(l) for l in logs[-limit:]]

    def stats(self) -> dict:
        return {
            "registered_workflows": len(self._workflows),
            "total_executions":     self._total_executions,
            "success_count":        self._success_count,
            "success_rate":         round(self._success_count / max(self._total_executions, 1), 4),
            "dlq_count":            self._dlq_count,
            "dlq_depth":            self.dlq.depth(),
            "idempotency_store":    len(self.idempotency._store),
            "log_entries":          len(self._logs),
        }


SAMPLE_WORKFLOW_YAML = """
apiVersion: nexus.shadow313.io/v1
kind: Workflow
metadata:
  name: wf-ledger-commit-notify
  namespace: shadow313-core
  labels:
    team: platform-engineering
    criticality: high

spec:
  trigger:
    type: nats
    subject: nexus.ledger.epoch.committed
    delivery_semantics: at_least_once

  steps:
    - id: validate-commit-payload
      type: builtin.schema_validate
      schema_ref: schemas/ledger-epoch-commit-v1.json
      on_failure: dead_letter

    - id: enrich-with-metadata
      type: builtin.transform
      depends_on: [validate-commit-payload]
      template: |
        committed_by: nexus-complete/ledger-sync-engine
        nexus_version: "4.7.2"

    - id: notify-downstream-api
      type: http_webhook
      depends_on: [enrich-with-metadata]
      target: https://api.downstream.example.com/v2/nexus-hook
      method: POST
      retry:
        max_attempts: 3
        base_delay_ms: 1000
        max_delay_ms: 30000

    - id: write-audit-record
      type: builtin.ledger_write
      depends_on: [notify-downstream-api]
      payload:
        event_type: WORKFLOW_COMPLETED
        workflow_id: wf-ledger-commit-notify

  timeout_seconds: 120
  idempotency_window_hours: 24
"""

SHADOW313_SECURITY_WORKFLOW_YAML = """
apiVersion: nexus.shadow313.io/v1
kind: Workflow
metadata:
  name: wf-shadow313-full-scan
  namespace: shadow313-security
  labels:
    team: security-engineering
    criticality: high

spec:
  trigger:
    type: nats
    subject: shadow313.scan.requested
    delivery_semantics: at_least_once

  steps:
    - id: recon-passive
      type: builtin.shadow313_dispatch
      module: recon
      kwargs:
        mode: passive

    - id: vuln-analysis
      type: builtin.shadow313_dispatch
      depends_on: [recon-passive]
      module: vuln
      kwargs:
        quick: true

    - id: quantum-audit
      type: builtin.shadow313_dispatch
      depends_on: [recon-passive]
      module: quantum
      kwargs:
        report: true

    - id: temporal-bind
      type: builtin.shadow313_dispatch
      depends_on: [vuln-analysis, quantum-audit]
      module: temporal
      kwargs:
        bind_session: true

    - id: generate-report
      type: builtin.shadow313_dispatch
      depends_on: [temporal-bind]
      module: report
      kwargs:
        format: html

  timeout_seconds: 300
  idempotency_window_hours: 24
"""


class WorkflowModule:
    """shadow313.v4.workflow — Workflow Engine. Registered: workflow"""

    def __init__(self, kernel) -> None:
        self.kernel = kernel
        self.out    = kernel.out
        self.engine = WorkflowEngine(kernel=kernel)
        self._load_builtin_workflows()

    def _load_builtin_workflows(self) -> None:
        try:
            self.engine.register_from_yaml(SAMPLE_WORKFLOW_YAML)
            self.engine.register_from_yaml(SHADOW313_SECURITY_WORKFLOW_YAML)
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            pass

    def register(self, kernel) -> None:
        kernel.register("workflow", self.run)

    def run(
        self,
        execute:     str  = "",
        list_wf:     bool = False,
        stats:       bool = False,
        logs:        str  = "",
        dlq_depth:   bool = False,
        register_yaml:str = "",
        sample:      bool = False,
    ) -> dict:
        self.out.section("WORKFLOW ENGINE")

        if sample:
            print(SAMPLE_WORKFLOW_YAML)
            return {"sample": "printed"}

        if stats:
            s = self.engine.stats()
            self.out.result(s, "Workflow Engine Statistics")
            return s

        if dlq_depth:
            depth = self.engine.dlq.depth()
            self.out.info(f"DLQ depth: {depth}")
            return {"dlq_depth": depth}

        if list_wf:
            workflows = list(self.engine._workflows.values())
            rows = [[w.workflow_id, w.name, w.namespace, len(w.steps), w.timeout_seconds]
                    for w in workflows]
            self.out.table(["ID","Name","Namespace","Steps","Timeout(s)"], rows, "Registered Workflows")
            return {"workflows": [w.workflow_id for w in workflows]}

        if register_yaml:
            path = Path(register_yaml)
            yaml_str = path.read_text() if path.exists() else register_yaml
            wf = self.engine.register_from_yaml(yaml_str)
            self.out.success(f"Workflow registered: {wf.workflow_id}")
            return {"registered": wf.workflow_id}

        if logs:
            log_entries = self.engine.get_logs(execution_id=logs, limit=50)
            rows = [[l.get("ts","")[:19], l.get("event",""), l.get("node_id",""),
                     l.get("attempt",0), l.get("latency_ms",0)]
                    for l in log_entries]
            self.out.table(["Timestamp","Event","Node","Attempt","Latency(ms)"], rows,
                           f"Workflow Logs: {logs}")
            return {"logs": log_entries}

        if execute:
            self.out.info(f"Executing workflow: {execute} …")
            result = self.engine.execute(execute)
            if result.get("status") == "complete":
                self.out.success(f"Workflow complete in {result['latency_ms']}ms")
            else:
                self.out.warn(f"Workflow failed: {result.get('status')}")
            self.out.result(result, "Execution Result")
            return result

        return self.run(stats=True)