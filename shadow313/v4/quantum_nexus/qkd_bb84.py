from __future__ import annotations
"""
shadow313.v4.quantum_nexus.qkd_bb84
QKD BB84 Simulator — Quantum Key Distribution with APD blinding attack simulation.
"""
import random, time
import numpy as np

class BB84Simulator:
    """BB84 Quantum Key Distribution protocol simulator."""

    def __init__(self, key_length: int = 1024, qber_threshold: float = 0.11):
        self.key_length = key_length
        self.qber_threshold = qber_threshold
        self.session_log: list = []

    def simulate_protocol(self, under_attack: bool = False) -> dict:
        alice_bits = np.random.randint(2, size=self.key_length)
        alice_bases = np.random.randint(2, size=self.key_length)
        bob_bases = np.random.randint(2, size=self.key_length)

        if not under_attack:
            bob_bits = np.where(alice_bases == bob_bases, alice_bits,
                                np.random.randint(2, size=self.key_length))
            qber = 0.0
            eve_key_rate = 0.0
            attack_type = None
        else:
            # APD Blinding Attack (Project SCYTHE)
            eve_bases = np.random.randint(2, size=self.key_length)
            eve_bits = np.where(alice_bases == eve_bases, alice_bits,
                                np.random.randint(2, size=self.key_length))
            detected_by_bob = (eve_bases == bob_bases)
            bob_bits = np.zeros(self.key_length, dtype=int)
            bob_bits[detected_by_bob] = eve_bits[detected_by_bob]
            valid = (alice_bases == bob_bases) & detected_by_bob
            errors = np.sum(alice_bits[valid] != bob_bits[valid])
            qber = float(errors / np.sum(valid)) if np.sum(valid) > 0 else 1.0
            eve_key_rate = 1.0
            attack_type = "APD_BLINDING"

        sifted_key_length = int(np.sum(alice_bases == bob_bases))
        key_aborted = qber > self.qber_threshold

        result = {
            "key_length": self.key_length,
            "sifted_key_length": sifted_key_length,
            "qber": round(qber, 4),
            "qber_threshold": self.qber_threshold,
            "key_aborted": key_aborted,
            "under_attack": under_attack,
            "attack_type": attack_type,
            "eve_key_interception_rate": eve_key_rate if under_attack else 0.0,
            "security_status": "COMPROMISED" if (under_attack and not key_aborted) else ("ABORTED" if key_aborted else "SECURE"),
            "timestamp": time.time(),
        }
        self.session_log.append(result)
        return result

    def run_comparison(self) -> dict:
        safe = self.simulate_protocol(under_attack=False)
        attacked = self.simulate_protocol(under_attack=True)
        return {
            "safe_session": safe,
            "attacked_session": attacked,
            "vulnerability_confirmed": attacked["security_status"] == "COMPROMISED",
            "qber_difference": round(attacked["qber"] - safe["qber"], 4),
        }

    def status(self) -> dict:
        return {
            "sessions_simulated": len(self.session_log),
            "attacks_simulated": sum(1 for s in self.session_log if s["under_attack"]),
            "compromised_sessions": sum(1 for s in self.session_log if s["security_status"] == "COMPROMISED"),
        }
