"""shadow313.v2.agent.approval — Approval gate implementations."""
from __future__ import annotations


class ApprovalGate:
    """Base approval gate."""
    def approve(self, step_name: str, risk_level: str) -> bool:
        return True


class AutoApprovalGate(ApprovalGate):
    """Fully automated — no pauses."""
    def approve(self, step_name: str, risk_level: str) -> bool:
        return True


class GateHighApprovalGate(ApprovalGate):
    """Pause on high-risk steps."""
    def approve(self, step_name: str, risk_level: str) -> bool:
        if risk_level.upper() in ("HIGH", "CRITICAL"):
            try:
                ans = input(f"\n[APPROVAL REQUIRED] Step '{step_name}' (risk: {risk_level}). Proceed? [y/N] ").strip().lower()
                return ans in ("y", "yes")
            except (EOFError, KeyboardInterrupt):
                return False
        return True


class FullHumanApprovalGate(ApprovalGate):
    """Pause before every step."""
    def approve(self, step_name: str, risk_level: str) -> bool:
        try:
            ans = input(f"\n[APPROVAL] Step '{step_name}'. Proceed? [y/N] ").strip().lower()
            return ans in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False


class CallbackApprovalGate(ApprovalGate):
    """Custom callback-based approval."""
    def __init__(self, callback) -> None:
        self._callback = callback

    def approve(self, step_name: str, risk_level: str) -> bool:
        return bool(self._callback(step_name, risk_level))


def make_gate(policy: str) -> ApprovalGate:
    policy = policy.lower().replace("-", "_")
    if policy == "auto":
        return AutoApprovalGate()
    if policy == "full_human":
        return FullHumanApprovalGate()
    return GateHighApprovalGate()  # default: gate_high