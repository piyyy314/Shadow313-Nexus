from __future__ import annotations
"""
shadow313.v4.simulation.swift_cascade_sim
SWIFT Cascade Failure Simulator — models FASTCash multi-institution attack propagation.
"""
import time, random
from typing import Optional

INSTITUTION_ARCHETYPES = {
    "A": {"name": "Bangladesh Bank", "csp_score": 8, "vendor": "T24", "daily_volume_usd": 1_200_000_000, "fed_connected": True},
    "B": {"name": "Finacle Consortium", "csp_score": 22, "vendor": "Finacle", "daily_volume_usd": 800_000_000, "fed_connected": False},
    "C": {"name": "Custom SWIFT", "csp_score": 35, "vendor": "Custom", "daily_volume_usd": 500_000_000, "fed_connected": False},
    "D": {"name": "RCBC Philippines", "csp_score": 12, "vendor": "T24", "daily_volume_usd": 950_000_000, "fed_connected": True},
    "E": {"name": "Credential Reuse Target", "csp_score": 5, "vendor": "T24", "daily_volume_usd": 1_100_000_000, "fed_connected": True},
}

class SWIFTCascadeSimulator:
    """Simulates FASTCash-style cascade failures across SWIFT network."""

    LOSS_RATE_PER_SECOND = 10_938  # $10,938/second at peak

    def __init__(self, num_institutions: int = 50):
        self.num_institutions = num_institutions
        self.compromised: list = []
        self.timeline: list = []
        self.total_loss_usd: float = 0.0

    def run_simulation(self, pivot_archetype: str = "D", hours: int = 22) -> dict:
        """Run full cascade simulation from initial pivot."""
        self.compromised = []
        self.timeline = []
        self.total_loss_usd = 0.0

        pivot = INSTITUTION_ARCHETYPES.get(pivot_archetype, INSTITUTION_ARCHETYPES["D"])
        self._log_event(0, "INITIAL_COMPROMISE", pivot["name"], pivot["daily_volume_usd"] * 0.1)

        # Phase 1: T+2h — Initial access
        self._simulate_phase(2, 5, "LOW_CSP_TARGETING", 120)
        # Phase 2: T+4h — Vendor fingerprint exploitation
        self._simulate_phase(4, 10, "VENDOR_FINGERPRINT", 45)
        # Phase 3: T+8h — Credential reuse
        self._simulate_phase(8, 20, "CREDENTIAL_REUSE", 15)
        # Phase 4: T+16h — Automated FASTCash 2.0
        self._simulate_phase(16, 40, "FASTCASH_AUTOMATED", 5)
        # Phase 5: T+22h — Full network compromise
        self._simulate_phase(22, min(50, self.num_institutions), "FULL_COMPROMISE", 1)

        return {
            "pivot_archetype": pivot_archetype,
            "pivot_institution": pivot["name"],
            "total_institutions_compromised": len(self.compromised),
            "total_loss_usd": round(self.total_loss_usd, 2),
            "loss_rate_per_second": self.LOSS_RATE_PER_SECOND,
            "timeline": self.timeline,
            "simulation_hours": hours,
        }

    def _simulate_phase(self, hour: int, target_count: int, phase_name: str, injection_time_min: int) -> None:
        new_targets = target_count - len(self.compromised)
        for i in range(max(0, new_targets)):
            loss = random.uniform(50_000_000, 200_000_000)
            self.total_loss_usd += loss
            inst_name = f"Institution-{len(self.compromised)+1}"
            self.compromised.append(inst_name)
            self._log_event(hour, phase_name, inst_name, loss, injection_time_min)

    def _log_event(self, hour: int, phase: str, institution: str, loss: float, injection_min: int = 0) -> None:
        self.timeline.append({
            "hour": hour,
            "phase": phase,
            "institution": institution,
            "loss_usd": round(loss, 2),
            "injection_time_min": injection_min,
            "cumulative_compromised": len(self.compromised),
            "cumulative_loss_usd": round(self.total_loss_usd, 2),
        })

    def status(self) -> dict:
        return {
            "institutions_compromised": len(self.compromised),
            "total_loss_usd": round(self.total_loss_usd, 2),
            "timeline_events": len(self.timeline),
        }
