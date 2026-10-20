from __future__ import annotations
"""
shadow313.v4.simulation.arch_e_sim
Arch-E Credential Reuse Simulator — models the most dangerous unguarded SWIFT attack pathway.
"""
import time

ARCH_E_KILL_CHAIN = [
    {"phase": 1, "name": "Shared swiftadm Discovery", "time_s": 30, "detection_prob": 0.05, "technique": "T1078.002"},
    {"phase": 2, "name": "Consortium Password Sync Exploit", "time_s": 45, "detection_prob": 0.03, "technique": "T1078"},
    {"phase": 3, "name": "Lateral Movement via Shared Creds", "time_s": 60, "detection_prob": 0.08, "technique": "T1550.002"},
    {"phase": 4, "name": "SWIFT Admin Privilege Escalation", "time_s": 20, "detection_prob": 0.04, "technique": "T1068"},
    {"phase": 5, "name": "No-MFA Exploitation", "time_s": 10, "detection_prob": 0.02, "technique": "T1556"},
    {"phase": 6, "name": "MT103 Injection", "time_s": 15, "detection_prob": 0.06, "technique": "T1565.001"},
    {"phase": 7, "name": "Mule Account Transfer", "time_s": 30, "detection_prob": 0.07, "technique": "T1041"},
    {"phase": 8, "name": "Evidence Destruction", "time_s": 20, "detection_prob": 0.05, "technique": "T1070"},
    {"phase": 9, "name": "Repeat Across Institutions", "time_s": 180, "detection_prob": 0.10, "technique": "T1021"},
]

class ArchESimulator:
    """Simulates the Arch-E credential reuse attack pathway."""

    def __init__(self):
        self.simulation_results: list = []

    def run_kill_chain(self, d3fend_active: bool = False) -> dict:
        total_time_s = 0
        phases_completed = []
        detected = False
        detection_phase = None

        for phase in ARCH_E_KILL_CHAIN:
            total_time_s += phase["time_s"]
            detection_prob = phase["detection_prob"] * (2.0 if d3fend_active else 1.0)
            phase_detected = detection_prob > 0.5  # Simplified detection model

            phases_completed.append({
                **phase,
                "detected": phase_detected,
                "cumulative_time_s": total_time_s,
            })

            if phase_detected and not detected:
                detected = True
                detection_phase = phase["phase"]

        total_loss = 7_790_000_000 if not detected else 7_790_000_000 * (detection_phase / len(ARCH_E_KILL_CHAIN))
        result = {
            "d3fend_active": d3fend_active,
            "total_time_s": total_time_s,
            "total_time_min": round(total_time_s / 60, 1),
            "detected": detected,
            "detection_phase": detection_phase,
            "phases_completed": phases_completed,
            "estimated_loss_usd": round(total_loss, 2),
            "overall_detection_prob": 0.0 if not d3fend_active else 0.14,
            "timestamp": time.time(),
        }
        self.simulation_results.append(result)
        return result

    def compare_with_without_d3fend(self) -> dict:
        without = self.run_kill_chain(d3fend_active=False)
        with_d3fend = self.run_kill_chain(d3fend_active=True)
        return {
            "without_d3fend": without,
            "with_d3fend": with_d3fend,
            "loss_reduction_usd": without["estimated_loss_usd"] - with_d3fend["estimated_loss_usd"],
            "detection_improvement": with_d3fend["overall_detection_prob"] - without["overall_detection_prob"],
        }

    def status(self) -> dict:
        return {"simulations_run": len(self.simulation_results)}
