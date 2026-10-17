from __future__ import annotations
"""
shadow313.v4.simulation.choke_point_sim
Choke Point Hardening Simulator — models strategic hardening of SWIFT network nodes.
"""
import time

HARDENING_SCENARIOS = [
    {"name": "Surgical Top-5 (Arch-D)", "nodes": 5, "cost_usd": 800_000, "deploy_hours": 6,
     "institutions_saved": 50, "loss_prevented_usd": 8_550_000_000},
    {"name": "Full T24 Reset (24 nodes)", "nodes": 24, "cost_usd": 6_800_000, "deploy_hours": 96,
     "institutions_saved": 50, "loss_prevented_usd": 8_550_000_000},
    {"name": "Arch-B Bridge Only", "nodes": 8, "cost_usd": 2_100_000, "deploy_hours": 24,
     "institutions_saved": 12, "loss_prevented_usd": 1_130_000_000},
    {"name": "Hybrid ZTA + D3FEND", "nodes": 50, "cost_usd": 31_500_000, "deploy_hours": 1008,
     "institutions_saved": 48, "loss_prevented_usd": 7_545_000_000},
    {"name": "Isolation-First (0-15% CSP)", "nodes": 15, "cost_usd": 4_200_000, "deploy_hours": 72,
     "institutions_saved": 35, "loss_prevented_usd": 5_200_000_000},
]

class ChokePointSimulator:
    """Models strategic choke point hardening scenarios."""

    def __init__(self, baseline_loss_usd: float = 8_550_000_000):
        self.baseline_loss = baseline_loss_usd
        self.scenario_results: list = []

    def run_all_scenarios(self) -> list:
        results = []
        for scenario in HARDENING_SCENARIOS:
            result = self.evaluate_scenario(scenario)
            results.append(result)
            self.scenario_results.append(result)
        return sorted(results, key=lambda x: x["roi"], reverse=True)

    def evaluate_scenario(self, scenario: dict) -> dict:
        roi = scenario["loss_prevented_usd"] / max(scenario["cost_usd"], 1)
        residual = self.baseline_loss - scenario["loss_prevented_usd"]
        return {
            **scenario,
            "roi": round(roi, 1),
            "residual_loss_usd": max(0, residual),
            "cost_effectiveness": round(scenario["loss_prevented_usd"] / scenario["nodes"] / 1e6, 2),
            "timestamp": time.time(),
        }

    def recommend_optimal(self) -> dict:
        if not self.scenario_results:
            self.run_all_scenarios()
        return max(self.scenario_results, key=lambda x: x["roi"])

    def status(self) -> dict:
        return {"scenarios_evaluated": len(self.scenario_results)}
