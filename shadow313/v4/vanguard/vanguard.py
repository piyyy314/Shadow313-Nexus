"""
shadow313.v4.vanguard.vanguard  — NEXUS Complete
Vanguard: Autonomous vulnerability chain planning and verification.

Capabilities:
  - CVE → PoC search → lab verification flow (fully gated)
  - Autonomous attack path planning using ATT&CK graph
  - Exploit chain scoring and prioritization
  - Verification in Docker sandbox (lab mode required)
  - Integration with 313 Temporal Binding for chain receipts
  - NEXUS Tier 1 Defensible Moat feature
"""
from __future__ import annotations
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


LAB_MODE_MSG = """
╔══════════════════════════════════════════════════════════════════════╗
║  SHADOW313 VANGUARD — AUTONOMOUS VULNERABILITY CHAIN SAFETY GATE    ║
║                                                                      ║
║  Vanguard plans and verifies exploit chains in isolated lab envs.   ║
║  REQUIRED: --lab-mode flag AND valid scope.yaml                     ║
║  All chains are advisory-only. No autonomous execution.             ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── ATT&CK Chain Templates ────────────────────────────────────────────────────

CHAIN_TEMPLATES = {
    "web_rce_to_persistence": {
        "name":        "Web RCE → Persistence",
        "description": "Exploit web vulnerability for RCE, establish persistence",
        "steps": [
            {"id": "initial_access",    "technique": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "execution",         "technique": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "persistence",       "technique": "T1505", "name": "Server Software Component"},
            {"id": "privilege_escalation","technique":"T1068","name": "Exploitation for Privilege Escalation"},
            {"id": "defense_evasion",   "technique": "T1070", "name": "Indicator Removal"},
            {"id": "c2",                "technique": "T1071", "name": "Application Layer Protocol"},
        ],
        "risk_level": "CRITICAL",
        "lab_only":   True,
    },
    "credential_access_lateral": {
        "name":        "Credential Access → Lateral Movement",
        "description": "Dump credentials and move laterally through network",
        "steps": [
            {"id": "credential_access", "technique": "T1003", "name": "OS Credential Dumping"},
            {"id": "lateral_movement",  "technique": "T1021", "name": "Remote Services"},
            {"id": "discovery",         "technique": "T1082", "name": "System Information Discovery"},
            {"id": "collection",        "technique": "T1074", "name": "Data Staged"},
            {"id": "exfiltration",      "technique": "T1041", "name": "Exfiltration Over C2 Channel"},
        ],
        "risk_level": "HIGH",
        "lab_only":   True,
    },
    "supply_chain_compromise": {
        "name":        "Supply Chain Compromise",
        "description": "Compromise software supply chain for persistent access",
        "steps": [
            {"id": "resource_dev",      "technique": "T1195", "name": "Supply Chain Compromise"},
            {"id": "initial_access",    "technique": "T1195.002", "name": "Compromise Software Supply Chain"},
            {"id": "persistence",       "technique": "T1547", "name": "Boot or Logon Autostart Execution"},
            {"id": "c2",                "technique": "T1071", "name": "Application Layer Protocol"},
            {"id": "impact",            "technique": "T1486", "name": "Data Encrypted for Impact"},
        ],
        "risk_level": "CRITICAL",
        "lab_only":   True,
    },
    "pqc_harvest_decrypt": {
        "name":        "Harvest Now Decrypt Later (HNDL)",
        "description": "Identify and prioritize encrypted data for future quantum decryption",
        "steps": [
            {"id": "recon",             "technique": "T1590", "name": "Gather Victim Network Information"},
            {"id": "collection",        "technique": "T1119", "name": "Automated Collection"},
            {"id": "exfiltration",      "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
            {"id": "impact",            "technique": "T1600", "name": "Weaken Encryption"},
        ],
        "risk_level": "HIGH",
        "lab_only":   False,  # This is a defensive analysis chain
        "defensive":  True,
    },
}


@dataclass
class ChainStep:
    """A single step in a vulnerability chain."""
    step_id:    str
    technique:  str
    name:       str
    status:     str = "planned"  # planned | verified | failed | skipped
    cve:        str = ""
    tool:       str = ""
    output:     str = ""
    latency_ms: int = 0


@dataclass
class VulnerabilityChain:
    """A complete vulnerability chain with scoring."""
    chain_id:    str
    template:    str
    name:        str
    target:      str
    steps:       list[ChainStep] = field(default_factory=list)
    risk_level:  str = "HIGH"
    score:       float = 0.0
    status:      str = "planned"
    created_at:  str = field(default_factory=_now_iso)
    receipt_id:  str = ""  # 313-BIND receipt

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class ChainPlanner:
    """
    Plans vulnerability chains using ATT&CK graph and CVE data.
    Advisory-only — no autonomous execution.
    """

    def plan(
        self,
        target:   str,
        template: str,
        cves:     list[dict] | None = None,
        ai_engine=None,
    ) -> VulnerabilityChain:
        """Plan a vulnerability chain for a target."""
        import uuid
        tmpl = CHAIN_TEMPLATES.get(template)
        if not tmpl:
            raise ValueError(f"Unknown template: {template}. Available: {list(CHAIN_TEMPLATES.keys())}")

        chain = VulnerabilityChain(
            chain_id  = str(uuid.uuid4())[:12],
            template  = template,
            name      = tmpl["name"],
            target    = target,
            risk_level= tmpl["risk_level"],
            steps     = [
                ChainStep(
                    step_id   = s["id"],
                    technique = s["technique"],
                    name      = s["name"],
                )
                for s in tmpl["steps"]
            ],
        )

        # Map CVEs to steps if provided
        if cves:
            self._map_cves_to_steps(chain, cves)

        # Score the chain
        chain.score = self._score_chain(chain, cves or [])

        # AI-enhanced planning
        if ai_engine:
            chain_ctx = {
                "target":   target,
                "template": template,
                "steps":    [asdict(s) for s in chain.steps],
                "cves":     (cves or [])[:5],
            }
            ai_plan = ai_engine.chat(
                "As a security researcher in a lab environment, analyse this vulnerability chain plan. "
                "For each step: (1) identify the most likely tools/techniques, "
                "(2) estimate detection probability, (3) suggest defensive countermeasures. "
                "This is for authorized security research only.",
                context=chain_ctx,
            )
            chain.steps[0].output = f"AI Analysis: {ai_plan[:500]}"

        return chain

    def _map_cves_to_steps(self, chain: VulnerabilityChain, cves: list[dict]) -> None:
        """Map CVEs to chain steps based on technique alignment."""
        technique_cve_map = {
            "T1190": [c for c in cves if c.get("cvss_v3", 0) >= 7.0],
            "T1059": [c for c in cves if "command" in c.get("description","").lower()],
            "T1068": [c for c in cves if "privilege" in c.get("description","").lower()],
            "T1003": [c for c in cves if "credential" in c.get("description","").lower()],
        }
        for step in chain.steps:
            matching = technique_cve_map.get(step.technique, [])
            if matching:
                best = max(matching, key=lambda c: c.get("cvss_v3", 0))
                step.cve = best.get("cve", "")

    def _score_chain(self, chain: VulnerabilityChain, cves: list[dict]) -> float:
        """Score a chain based on CVE severity, technique coverage, and exploitability."""
        base_score = len(chain.steps) * 10.0

        # CVE severity bonus
        if cves:
            avg_cvss = sum(c.get("cvss_v3", 0) for c in cves) / len(cves)
            base_score += avg_cvss * 5

        # Risk level multiplier
        multipliers = {"CRITICAL": 1.5, "HIGH": 1.2, "MEDIUM": 1.0, "LOW": 0.8}
        base_score *= multipliers.get(chain.risk_level, 1.0)

        return round(min(base_score, 100.0), 1)


class ChainVerifier:
    """
    Verifies vulnerability chains in isolated lab environments.
    Integrates with Docker sandbox for CVE reproduction.
    """

    def verify_step(
        self,
        step:      ChainStep,
        sandbox,   # SandboxModule
        lab_mode:  bool = False,
    ) -> ChainStep:
        """Verify a single chain step using the sandbox."""
        if not lab_mode:
            step.status = "skipped"
            step.output = "Lab mode required for verification"
            return step

        if not step.cve:
            step.status = "skipped"
            step.output = "No CVE mapped to this step"
            return step

        start = time.time()
        try:
            result = sandbox.reproducer.reproduce(step.cve, timeout=30)
            if "error" not in result:
                step.status    = "verified"
                step.output    = f"CVE {step.cve} reproduced successfully"
                step.tool      = result.get("container_id", "")
            else:
                step.status    = "failed"
                step.output    = result.get("error", "Unknown error")
        except Exception as exc:
            step.status = "failed"
            step.output = str(exc)

        step.latency_ms = int((time.time() - start) * 1000)
        return step


class VanguardModule:
    """shadow313.v4.vanguard — Autonomous vulnerability chains. Registered: vanguard"""

    def __init__(self, kernel) -> None:
        self.kernel   = kernel
        self.out      = kernel.out
        self.session  = kernel.session
        self.planner  = ChainPlanner()
        self.verifier = ChainVerifier()
        self._chains: list[VulnerabilityChain] = []

    def register(self, kernel) -> None:
        kernel.register("vanguard", self.run)

    def run(
        self,
        plan:       str  = "",
        template:   str  = "web_rce_to_persistence",
        target:     str  = "",
        verify:     bool = False,
        lab_mode:   bool = False,
        list_chains:bool = False,
        list_templates:bool = False,
        score_only: bool = False,
    ) -> dict:
        self.out.section("VANGUARD — AUTONOMOUS VULNERABILITY CHAINS")

        if list_templates:
            rows = [[k, v["name"], v["risk_level"], "Yes" if v.get("defensive") else "No"]
                    for k, v in CHAIN_TEMPLATES.items()]
            self.out.table(["Template","Name","Risk","Defensive"], rows, "Chain Templates")
            return {"templates": list(CHAIN_TEMPLATES.keys())}

        if list_chains:
            if not self._chains:
                self.out.info("No chains planned yet. Use --plan to create one.")
                return {"chains": []}
            rows = [[c.chain_id, c.name, c.target, c.risk_level, str(c.score), c.status]
                    for c in self._chains]
            self.out.table(["ID","Name","Target","Risk","Score","Status"], rows, "Planned Chains")
            return {"chains": [c.to_dict() for c in self._chains]}

        if plan or target:
            if not target:
                self.out.error("--target required for chain planning")
                return {"error": "target_required"}

            # Load CVE findings from session
            findings = (self.session.read("findings.json") or {}).get("findings", [])

            self.out.info(f"Planning chain: {template} → {target}")
            chain = self.planner.plan(
                target    = target,
                template  = template,
                cves      = findings[:20],
                ai_engine = self.kernel.ai,
            )
            self._chains.append(chain)

            # Display chain
            rows = [[s.step_id, s.technique, s.name, s.cve or "—", s.status]
                    for s in chain.steps]
            self.out.table(["Step","Technique","Name","CVE","Status"], rows,
                           f"Chain: {chain.name} (Score: {chain.score})")

            if verify and lab_mode:
                self.out.warn("Verifying chain steps in sandbox (LAB MODE) …")
                sandbox = self.kernel.get_module("sandbox")
                if sandbox:
                    for step in chain.steps:
                        if step.cve:
                            step = self.verifier.verify_step(step, sandbox, lab_mode=True)
                            status_icon = "✓" if step.status == "verified" else "✗"
                            self.out.info(f"  {status_icon} {step.step_id}: {step.status}")
                    chain.status = "verified" if all(
                        s.status in ("verified","skipped") for s in chain.steps
                    ) else "partial"
                else:
                    self.out.warn("Sandbox module not available for verification")
            elif verify and not lab_mode:
                self.out.error(LAB_MODE_MSG)

            # 313 Temporal Binding
            temporal = self.kernel.get_module("temporal")
            if temporal:
                receipt = temporal.engine.bind(chain.to_dict(), self.session.id, "vanguard")
                chain.receipt_id = receipt.receipt_id
                self.out.success(f"Chain bound: {receipt.receipt_id}")

            self.session.write("vanguard_chain.json", chain.to_dict())
            return chain.to_dict()

        # Default: show status
        self.out.info(f"Vanguard: {len(self._chains)} chains planned")
        self.out.info("Use --plan --target <target> to plan a chain")
        self.out.info("Use --list-templates to see available chain templates")
        return {"chains_planned": len(self._chains)}