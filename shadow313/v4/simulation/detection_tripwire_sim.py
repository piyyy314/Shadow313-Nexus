from __future__ import annotations
"""
shadow313.v4.simulation.detection_tripwire_sim
Detection Tripwire Simulator — models 16 strategic tripwires for SWIFT attack detection.
"""
import time

TRIPWIRES = [
    {"id": "TW-01", "name": "Simultaneous Multi-Institution Login Alert", "cost_usd": 500, "deploy_min": 30, "leverage": 96, "escape_reduction": 0.85},
    {"id": "TW-02", "name": "Off-Hours SWIFT Admin Access", "cost_usd": 200, "deploy_min": 15, "leverage": 88, "escape_reduction": 0.72},
    {"id": "TW-03", "name": "MT103 Amount Threshold Alert", "cost_usd": 300, "deploy_min": 20, "leverage": 82, "escape_reduction": 0.68},
    {"id": "TW-04", "name": "New Beneficiary Account Alert", "cost_usd": 400, "deploy_min": 25, "leverage": 79, "escape_reduction": 0.65},
    {"id": "TW-05", "name": "Credential Reuse Cross-Institution", "cost_usd": 800, "deploy_min": 45, "leverage": 94, "escape_reduction": 0.88},
    {"id": "TW-06", "name": "SWIFT Gateway Config Change", "cost_usd": 600, "deploy_min": 35, "leverage": 85, "escape_reduction": 0.71},
    {"id": "TW-07", "name": "JAR File Injection Detection", "cost_usd": 1200, "deploy_min": 60, "leverage": 91, "escape_reduction": 0.82},
    {"id": "TW-08", "name": "Mule Account Velocity Alert", "cost_usd": 350, "deploy_min": 20, "leverage": 77, "escape_reduction": 0.63},
    {"id": "TW-09", "name": "DNS Tunneling from SWIFT Host", "cost_usd": 700, "deploy_min": 40, "leverage": 83, "escape_reduction": 0.69},
    {"id": "TW-10", "name": "Unusual MT202 COV Pattern", "cost_usd": 450, "deploy_min": 25, "leverage": 80, "escape_reduction": 0.66},
    {"id": "TW-11", "name": "SWIFT Operator Privilege Escalation", "cost_usd": 900, "deploy_min": 50, "leverage": 89, "escape_reduction": 0.75},
    {"id": "TW-12", "name": "Simultaneous Multi-Institution Login Alert", "cost_usd": 500, "deploy_min": 30, "leverage": 96, "escape_reduction": 0.85},
    {"id": "TW-13", "name": "Honeypot SWIFT Credentials Accessed", "cost_usd": 1500, "deploy_min": 90, "leverage": 98, "escape_reduction": 0.95},
    {"id": "TW-14", "name": "Abnormal Transaction Volume Spike", "cost_usd": 250, "deploy_min": 15, "leverage": 75, "escape_reduction": 0.60},
    {"id": "TW-15", "name": "Cross-Border Transfer Pattern", "cost_usd": 600, "deploy_min": 35, "leverage": 81, "escape_reduction": 0.67},
    {"id": "TW-16", "name": "SWIFT Message Replay Detection", "cost_usd": 1100, "deploy_min": 55, "leverage": 87, "escape_reduction": 0.73},
]

class DetectionTripwireSimulator:
    """Models strategic tripwire deployment for SWIFT attack detection."""

    BASELINE_ESCAPE_PROB = 0.182  # 18.2% baseline escape probability

    def __init__(self):
        self.deployed_tripwires: list = []
        self.simulation_results: list = []

    def deploy_wave(self, wave: int) -> dict:
        """Deploy tripwires in waves."""
        waves = {
            1: ["TW-01", "TW-02", "TW-05", "TW-12", "TW-13"],
            2: ["TW-03", "TW-04", "TW-06", "TW-07", "TW-11"],
            3: ["TW-08", "TW-09", "TW-10", "TW-14", "TW-15", "TW-16"],
        }
        wave_ids = waves.get(wave, [])
        deployed = [t for t in TRIPWIRES if t["id"] in wave_ids]
        self.deployed_tripwires.extend(deployed)
        return self._calculate_effectiveness()

    def _calculate_effectiveness(self) -> dict:
        if not self.deployed_tripwires:
            return {"escape_probability": self.BASELINE_ESCAPE_PROB, "tripwires_active": 0}

        combined_reduction = 1.0
        for tw in self.deployed_tripwires:
            combined_reduction *= (1 - tw["escape_reduction"])

        escape_prob = self.BASELINE_ESCAPE_PROB * combined_reduction
        total_cost = sum(t["cost_usd"] for t in self.deployed_tripwires)
        roi = (self.BASELINE_ESCAPE_PROB - escape_prob) * 8_550_000_000 / max(total_cost, 1)

        return {
            "tripwires_active": len(self.deployed_tripwires),
            "escape_probability": round(escape_prob, 4),
            "baseline_escape_prob": self.BASELINE_ESCAPE_PROB,
            "reduction_pct": round((1 - escape_prob / self.BASELINE_ESCAPE_PROB) * 100, 1),
            "total_cost_usd": total_cost,
            "roi": round(roi, 0),
        }

    def get_top_tripwires(self, n: int = 5) -> list:
        return sorted(TRIPWIRES, key=lambda x: x["leverage"], reverse=True)[:n]

    def status(self) -> dict:
        return {"tripwires_deployed": len(self.deployed_tripwires), "total_available": len(TRIPWIRES)}
