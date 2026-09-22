"""
shadow313.v2.agent.agent
Feature #3 — Agentic Auto-Chain Loop
State machine that chains modules autonomously (recon → vuln → exploit-check → report)
with human-in-the-loop approval gates, step logging, and rollback capability.
"""
from __future__ import annotations
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable


# ---------------------------------------------------------------------------
# State & Step definitions
# ---------------------------------------------------------------------------

class StepStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"
    AWAITING  = "awaiting_approval"


class ApprovalPolicy(str, Enum):
    AUTO       = "auto"         # Never pause for approval
    GATE_HIGH  = "gate_high"    # Pause before high-risk steps
    FULL_HUMAN = "full_human"   # Pause before every step


@dataclass
class AgentStep:
    id:          str
    name:        str
    module:      str
    action:      str
    params:      dict[str, Any]
    risk_level:  str            = "low"   # low | medium | high | critical
    status:      StepStatus     = StepStatus.PENDING
    result:      Any            = None
    error:       str            = ""
    started_at:  str            = ""
    ended_at:    str            = ""
    duration_s:  float          = 0.0
    requires_approval: bool     = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class AgentPlan:
    id:          str             = field(default_factory=lambda: str(uuid.uuid4()))
    target:      str             = ""
    description: str             = ""
    steps:       list[AgentStep] = field(default_factory=list)
    created_at:  str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy:      ApprovalPolicy  = ApprovalPolicy.GATE_HIGH

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "target":      self.target,
            "description": self.description,
            "policy":      self.policy.value,
            "created_at":  self.created_at,
            "steps":       [s.to_dict() for s in self.steps],
        }


# ---------------------------------------------------------------------------
# Built-in chain templates
# ---------------------------------------------------------------------------

CHAIN_TEMPLATES: dict[str, list[dict]] = {
    "full_pentest": [
        {"name": "Passive Recon",       "module": "recon",   "action": "run",
         "params": {"mode": "passive"}, "risk_level": "low"},
        {"name": "Active Recon",        "module": "recon",   "action": "run",
         "params": {"mode": "active"},  "risk_level": "medium", "requires_approval": True},
        {"name": "Vulnerability Scan",  "module": "vuln",    "action": "scan",
         "params": {},                  "risk_level": "medium"},
        {"name": "EPSS Scoring",        "module": "vuln",    "action": "epss",
         "params": {},                  "risk_level": "low"},
        {"name": "KEV Check",           "module": "vuln",    "action": "kev",
         "params": {},                  "risk_level": "low"},
        {"name": "ATT&CK Mapping",      "module": "vuln",    "action": "attack_map",
         "params": {},                  "risk_level": "low"},
        {"name": "Network Capture",     "module": "network", "action": "analyze",
         "params": {},                  "risk_level": "medium"},
        {"name": "Generate Report",     "module": "reports", "action": "pdf",
         "params": {},                  "risk_level": "low"},
    ],
    "quick_vuln": [
        {"name": "Passive Recon",       "module": "recon",  "action": "run",
         "params": {"mode": "passive"}, "risk_level": "low"},
        {"name": "Vulnerability Scan",  "module": "vuln",   "action": "scan",
         "params": {},                  "risk_level": "medium"},
        {"name": "EPSS + KEV",          "module": "vuln",   "action": "epss_kev",
         "params": {},                  "risk_level": "low"},
    ],
    "defense_audit": [
        {"name": "CIS Benchmark",       "module": "defense", "action": "audit",
         "params": {},                  "risk_level": "low"},
        {"name": "Firewall Analysis",   "module": "defense", "action": "firewall",
         "params": {},                  "risk_level": "low"},
        {"name": "AI Remediation",      "module": "defense", "action": "remediate",
         "params": {},                  "risk_level": "low"},
    ],
    "crypto_audit": [
        {"name": "TLS Scan",            "module": "quantum", "action": "tls",
         "params": {},                  "risk_level": "low"},
        {"name": "Cert Audit",          "module": "quantum", "action": "cert",
         "params": {},                  "risk_level": "low"},
        {"name": "Code Crypto Scan",    "module": "quantum", "action": "codescan",
         "params": {},                  "risk_level": "low"},
        {"name": "PQC Migration Plan",  "module": "quantum", "action": "roadmap",
         "params": {},                  "risk_level": "low"},
    ],
}


# ---------------------------------------------------------------------------
# ApprovalGate — pluggable UI hook
# ---------------------------------------------------------------------------

class ApprovalGate:
    """
    Synchronous approval gate. Override `request_approval` for custom UI.
    Default implementation uses stdin (terminal prompt).
    """

    def request_approval(self, step: AgentStep, plan: AgentPlan) -> bool:
        """Returns True = approved, False = skip this step."""
        print(f"\n[AGENT GATE] Step '{step.name}' requires approval.")
        print(f"  Module:     {step.module}")
        print(f"  Action:     {step.action}")
        print(f"  Risk:       {step.risk_level.upper()}")
        print(f"  Params:     {json.dumps(step.params)}")
        try:
            ans = input("  Approve? [y/N/abort]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans == "abort":
            raise SystemExit("Agent run aborted by user.")
        return ans == "y"


class AutoApprovalGate(ApprovalGate):
    """Always approves — for automated / CI runs."""
    def request_approval(self, step: AgentStep, plan: AgentPlan) -> bool:
        return True


class CallbackApprovalGate(ApprovalGate):
    """Delegates to a user-supplied callback(step, plan) → bool."""
    def __init__(self, callback: Callable[[AgentStep, AgentPlan], bool]) -> None:
        self._cb = callback

    def request_approval(self, step: AgentStep, plan: AgentPlan) -> bool:
        return self._cb(step, plan)


# ---------------------------------------------------------------------------
# AgentExecutor — core state machine
# ---------------------------------------------------------------------------

class AgentExecutor:
    """
    Feature #3 — Agentic execution state machine.
    Chains Shadow313 modules sequentially, persists progress, supports rollback.
    """

    HIGH_RISK = {"high", "critical"}

    def __init__(self, kernel: Any,
                 approval_gate: ApprovalGate | None = None,
                 policy: ApprovalPolicy = ApprovalPolicy.GATE_HIGH,
                 log_dir: str = "~/.shadow313/agent_runs") -> None:
        self.kernel   = kernel
        self.gate     = approval_gate or ApprovalGate()
        self.policy   = policy
        self.log_dir  = Path(log_dir).expanduser()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._current_plan: AgentPlan | None = None
        self._step_results: list[dict]       = []

    # ── Plan creation ─────────────────────────────────────────────────────
    def create_plan(self, target: str, template: str = "full_pentest",
                    extra_params: dict | None = None) -> AgentPlan:
        steps_raw = CHAIN_TEMPLATES.get(template, CHAIN_TEMPLATES["quick_vuln"])
        steps = []
        for raw in steps_raw:
            params = {**raw.get("params", {}), **(extra_params or {}), "target": target}
            steps.append(AgentStep(
                id=str(uuid.uuid4())[:8],
                name=raw["name"],
                module=raw["module"],
                action=raw["action"],
                params=params,
                risk_level=raw.get("risk_level", "low"),
                requires_approval=raw.get("requires_approval", False),
            ))
        plan = AgentPlan(
            target=target,
            description=f"Auto-chain: {template} against {target}",
            steps=steps,
            policy=self.policy,
        )
        self._current_plan = plan
        self._save_plan(plan)
        return plan

    def create_custom_plan(self, target: str,
                           steps: list[dict]) -> AgentPlan:
        """Create a plan from a list of step dicts."""
        agent_steps = []
        for raw in steps:
            params = {**raw.get("params", {}), "target": target}
            agent_steps.append(AgentStep(
                id=str(uuid.uuid4())[:8],
                name=raw.get("name", raw.get("module", "step")),
                module=raw["module"],
                action=raw.get("action", "run"),
                params=params,
                risk_level=raw.get("risk_level", "low"),
                requires_approval=raw.get("requires_approval", False),
            ))
        plan = AgentPlan(target=target, steps=agent_steps, policy=self.policy)
        self._current_plan = plan
        self._save_plan(plan)
        return plan

    # ── Execution ─────────────────────────────────────────────────────────
    def run(self, plan: AgentPlan | None = None,
            resume_on_error: bool = False) -> dict:
        plan = plan or self._current_plan
        if not plan:
            raise ValueError("No plan to execute. Call create_plan() first.")

        self._step_results = []
        run_id = str(uuid.uuid4())[:8]
        started = time.time()

        print(f"\n[AGENT] Starting run {run_id} — {plan.description}")
        print(f"[AGENT] Target: {plan.target} | Steps: {len(plan.steps)} | Policy: {plan.policy.value}\n")

        for step in plan.steps:
            # Approval gate
            needs_gate = (
                self.policy == ApprovalPolicy.FULL_HUMAN
                or (self.policy == ApprovalPolicy.GATE_HIGH
                    and step.risk_level in self.HIGH_RISK)
                or step.requires_approval
            )
            if needs_gate and self.policy != ApprovalPolicy.AUTO:
                step.status = StepStatus.AWAITING
                self._save_plan(plan)
                approved = self.gate.request_approval(step, plan)
                if not approved:
                    step.status = StepStatus.SKIPPED
                    step.error  = "Skipped by user at approval gate"
                    self._step_results.append(step.to_dict())
                    print(f"[AGENT] ⏭  SKIPPED — {step.name}")
                    self._save_plan(plan)
                    continue

            # Execute
            step.status     = StepStatus.RUNNING
            step.started_at = datetime.now(timezone.utc).isoformat()
            self._save_plan(plan)

            print(f"[AGENT] ▶  Running — {step.name} ({step.module}.{step.action})")
            t0 = time.time()
            try:
                result = self._dispatch_step(step)
                step.result    = result
                step.status    = StepStatus.COMPLETED
                print(f"[AGENT] ✓  Done — {step.name} ({time.time()-t0:.1f}s)")
            except Exception as exc:
                step.status = StepStatus.FAILED
                step.error  = str(exc)
                print(f"[AGENT] ✗  FAILED — {step.name}: {exc}")
                if not resume_on_error:
                    step.ended_at   = datetime.now(timezone.utc).isoformat()
                    step.duration_s = time.time() - t0
                    self._step_results.append(step.to_dict())
                    self._save_plan(plan)
                    break

            step.ended_at   = datetime.now(timezone.utc).isoformat()
            step.duration_s = time.time() - t0
            self._step_results.append(step.to_dict())
            self._save_plan(plan)

            # Feed outputs to AI context
            self._update_context(step)

        total_time = time.time() - started
        summary = self._build_summary(plan, run_id, total_time)
        self._save_run_log(plan, summary)
        return summary

    # ── Dispatch ──────────────────────────────────────────────────────────
    def _dispatch_step(self, step: AgentStep) -> Any:
        """Route step to the appropriate kernel module."""
        module = self.kernel.get_module(step.module)
        if module is None:
            # Graceful degradation — return stub
            return {"status": "stub", "module": step.module,
                    "note": f"Module '{step.module}' not loaded in kernel"}

        action_map: dict[str, str] = {
            # Recon
            "run":       "run",
            # Vuln
            "scan":      "scan",
            "epss":      "epss_score",
            "kev":       "kev_check",
            "epss_kev":  "epss_kev_check",
            "attack_map":"attack_map",
            # Network
            "analyze":   "analyze",
            # Defense
            "audit":     "audit",
            "firewall":  "check_firewall",
            "remediate": "remediate",
            # Quantum
            "tls":       "scan_tls",
            "cert":      "audit_cert",
            "codescan":  "scan_code",
            "roadmap":   "migration_roadmap",
            # Reports
            "pdf":       "generate_pdf",
        }
        method_name = action_map.get(step.action, step.action)
        method = getattr(module, method_name, None)
        if method is None:
            return {"status": "no_action", "module": step.module,
                    "action": step.action}
        return method(**step.params)

    # ── Context accumulation ──────────────────────────────────────────────
    def _update_context(self, step: AgentStep) -> None:
        """Pass completed step outputs as context to the next steps."""
        if step.result and isinstance(step.result, dict):
            # Enrich next steps' params with outputs
            if self._current_plan:
                for s in self._current_plan.steps:
                    if s.status == StepStatus.PENDING:
                        s.params["_prev_result"] = step.result
                        break   # Only first pending step gets direct feed

    # ── Persistence ───────────────────────────────────────────────────────
    def _save_plan(self, plan: AgentPlan) -> None:
        path = self.log_dir / f"plan_{plan.id}.json"
        path.write_text(json.dumps(plan.to_dict(), indent=2))

    def _save_run_log(self, plan: AgentPlan, summary: dict) -> None:
        path = self.log_dir / f"run_{summary['run_id']}.json"
        path.write_text(json.dumps(summary, indent=2))

    def _build_summary(self, plan: AgentPlan,
                       run_id: str, elapsed: float) -> dict:
        completed = [s for s in plan.steps if s.status == StepStatus.COMPLETED]
        failed    = [s for s in plan.steps if s.status == StepStatus.FAILED]
        skipped   = [s for s in plan.steps if s.status == StepStatus.SKIPPED]
        return {
            "run_id":       run_id,
            "plan_id":      plan.id,
            "target":       plan.target,
            "elapsed_s":    round(elapsed, 2),
            "steps_total":  len(plan.steps),
            "steps_ok":     len(completed),
            "steps_failed": len(failed),
            "steps_skipped":len(skipped),
            "success":      len(failed) == 0,
            "results":      self._step_results,
        }

    # ── Rollback ──────────────────────────────────────────────────────────
    def rollback(self, plan: AgentPlan, to_step_name: str) -> None:
        """Reset steps from a given step onwards (allows re-run)."""
        found = False
        for step in plan.steps:
            if step.name == to_step_name:
                found = True
            if found:
                step.status    = StepStatus.PENDING
                step.result    = None
                step.error     = ""
                step.started_at = ""
                step.ended_at   = ""
                step.duration_s = 0.0
        if found:
            self._save_plan(plan)
            print(f"[AGENT] Rolled back to step '{to_step_name}'")
        else:
            print(f"[AGENT] Step '{to_step_name}' not found in plan")

    # ── AI-assisted planning ──────────────────────────────────────────────
    def ai_suggest_plan(self, target: str, objective: str) -> list[dict]:
        """Use AI to suggest a custom chain for the given objective."""
        if not self.kernel.ai:
            return []
        prompt = (
            f"Target: {target}\nObjective: {objective}\n\n"
            "Suggest an ordered list of Shadow313 modules to chain. "
            "Available modules: recon, vuln, network, defense, quantum, reports. "
            "Return JSON array: [{\"module\": ..., \"action\": ..., "
            "\"risk_level\": low|medium|high, \"name\": ...}]"
        )
        raw = self.kernel.ai.chat(prompt)
        try:
            import re
            m = re.search(r'\[.*?\]', raw, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        return []

    # ── List saved plans ──────────────────────────────────────────────────
    def list_plans(self) -> list[dict]:
        plans = []
        for f in self.log_dir.glob("plan_*.json"):
            try:
                data = json.loads(f.read_text())
                plans.append({
                    "id":         data.get("id"),
                    "target":     data.get("target"),
                    "description":data.get("description"),
                    "created_at": data.get("created_at"),
                    "steps":      len(data.get("steps", [])),
                })
            except Exception:
                pass
        return sorted(plans, key=lambda x: x.get("created_at",""), reverse=True)
