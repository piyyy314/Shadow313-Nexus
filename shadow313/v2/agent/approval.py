"""shadow313.v2.agent.approval — Approval gate implementations."""
from __future__ import annotations


class ApprovalGate:
    """Base approval gate."""
    def approve(self, step_name: str, risk_level: str) -> bool:
        """Approve every step regardless of its name or risk level."""
        return True


class AutoApprovalGate(ApprovalGate):
    """Fully automated — no pauses."""
    def approve(self, step_name: str, risk_level: str) -> bool:
        """Approve every step without prompting."""
        return True


class GateHighApprovalGate(ApprovalGate):
    """Pause on high-risk steps."""
    def approve(self, step_name: str, risk_level: str) -> bool:
        """Prompt only for HIGH or CRITICAL risk, ignoring case.

        Accept only y/yes, ignoring case and surrounding whitespace; reject on
        EOF or interruption. Other risk levels are approved without prompting.
        """
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
        """Prompt for every step, accepting only y/yes regardless of case.

        Surrounding whitespace is ignored. EOF or interruption rejects the step.
        """
        try:
            ans = input(f"\n[APPROVAL] Step '{step_name}'. Proceed? [y/N] ").strip().lower()
            return ans in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False


class CallbackApprovalGate(ApprovalGate):
    """Custom callback-based approval."""
    def __init__(self, callback) -> None:
        """Store a callback accepting the step name and risk level."""
        self._callback = callback

    def approve(self, step_name: str, risk_level: str) -> bool:
        """Return the callback result as a bool; callback exceptions propagate."""
        return bool(self._callback(step_name, risk_level))


def make_gate(policy: str) -> ApprovalGate:
    """Choose an approval gate, ignoring case and treating hyphens as underscores.

    Unknown policies use the gate that prompts for high and critical risks.
    """
    policy = policy.lower().replace("-", "_")
    if policy == "auto":
        return AutoApprovalGate()
    if policy == "full_human":
        return FullHumanApprovalGate()
    return GateHighApprovalGate()  # default: gate_high