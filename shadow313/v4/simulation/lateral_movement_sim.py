from __future__ import annotations
"""
shadow313.v4.simulation.lateral_movement_sim
Lateral Movement Simulator — models attacker pivot strategies across network segments.
"""
import time, random

PIVOT_TECHNIQUES = {
    "pass_the_hash": {"technique": "T1550.002", "detection_prob": 0.35, "speed_min": 2},
    "pass_the_ticket": {"technique": "T1550.003", "detection_prob": 0.40, "speed_min": 3},
    "psexec": {"technique": "T1021.002", "detection_prob": 0.55, "speed_min": 1},
    "wmi": {"technique": "T1047", "detection_prob": 0.45, "speed_min": 2},
    "rdp": {"technique": "T1021.001", "detection_prob": 0.60, "speed_min": 5},
    "ssh": {"technique": "T1021.004", "detection_prob": 0.30, "speed_min": 1},
    "dcsync": {"technique": "T1003.006", "detection_prob": 0.70, "speed_min": 10},
}

class LateralMovementSimulator:
    """Simulates attacker lateral movement across network segments."""

    def __init__(self):
        self.movement_log: list = []
        self.compromised_hosts: list = []

    def simulate_pivot(self, source: str, target: str, technique: str = "pass_the_hash",
                       detection_active: bool = True) -> dict:
        tech_data = PIVOT_TECHNIQUES.get(technique, PIVOT_TECHNIQUES["pass_the_hash"])
        detection_prob = tech_data["detection_prob"] * (1.5 if detection_active else 0.5)
        detected = random.random() < detection_prob

        event = {
            "source": source,
            "target": target,
            "technique": technique,
            "mitre_id": tech_data["technique"],
            "detected": detected,
            "detection_prob": round(detection_prob, 2),
            "time_min": tech_data["speed_min"],
            "timestamp": time.time(),
        }
        self.movement_log.append(event)
        if not detected:
            self.compromised_hosts.append(target)
        return event

    def simulate_campaign(self, entry_point: str, targets: list, technique: str = "pass_the_hash") -> dict:
        results = []
        current = entry_point
        for target in targets:
            result = self.simulate_pivot(current, target, technique)
            results.append(result)
            if not result["detected"]:
                current = target
            else:
                break

        return {
            "entry_point": entry_point,
            "targets_attempted": len(targets),
            "hosts_compromised": len(self.compromised_hosts),
            "campaign_stopped": any(r["detected"] for r in results),
            "results": results,
            "total_time_min": sum(r["time_min"] for r in results),
        }

    def status(self) -> dict:
        return {
            "pivots_simulated": len(self.movement_log),
            "hosts_compromised": len(self.compromised_hosts),
            "detection_rate": round(sum(1 for e in self.movement_log if e["detected"]) / max(len(self.movement_log), 1), 2),
        }
