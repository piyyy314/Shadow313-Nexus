from __future__ import annotations
"""
shadow313.v4.ghost_watch.cerberus
CERBERUS/GORGON: Behavioral Study and Analysis Unit — keystroke biometrics, memory integrity daemon.
"""
import time, statistics, hashlib
from typing import Optional

class CerberusBAU:
    """Behavioral biometric profiler + memory integrity monitor."""

    def __init__(self):
        self.keystroke_profiles: dict = {}
        self.memory_baseline: Optional[str] = None
        self.anomaly_log: list = []

    # ── Keystroke biometrics ───────────────────────────────────────────────
    def record_keystrokes(self, user_id: str, intervals_ms: list) -> dict:
        if user_id not in self.keystroke_profiles:
            self.keystroke_profiles[user_id] = {"samples": [], "mean": None, "std": None}
        profile = self.keystroke_profiles[user_id]
        profile["samples"].extend(intervals_ms)
        if len(profile["samples"]) >= 10:
            profile["mean"] = statistics.mean(profile["samples"])
            profile["std"] = statistics.stdev(profile["samples"]) if len(profile["samples"]) > 1 else 0
        return profile

    def verify_user(self, user_id: str, intervals_ms: list) -> dict:
        profile = self.keystroke_profiles.get(user_id)
        if not profile or profile["mean"] is None:
            return {"verified": False, "reason": "no_baseline", "user_id": user_id}
        sample_mean = statistics.mean(intervals_ms)
        deviation = abs(sample_mean - profile["mean"]) / max(profile["std"], 1)
        verified = deviation < 3.0  # 3-sigma threshold
        result = {
            "user_id": user_id,
            "verified": verified,
            "deviation_sigma": round(deviation, 2),
            "sample_mean_ms": round(sample_mean, 2),
            "baseline_mean_ms": round(profile["mean"], 2),
        }
        if not verified:
            self.anomaly_log.append({"type": "keystroke_anomaly", "ts": time.time(), **result})
        return result

    # ── Memory integrity ───────────────────────────────────────────────────
    def set_memory_baseline(self, memory_snapshot: bytes) -> str:
        self.memory_baseline = hashlib.sha3_256(memory_snapshot).hexdigest()
        return self.memory_baseline

    def check_memory_integrity(self, current_snapshot: bytes) -> dict:
        current_hash = hashlib.sha3_256(current_snapshot).hexdigest()
        intact = current_hash == self.memory_baseline
        result = {"intact": intact, "current_hash": current_hash, "baseline_hash": self.memory_baseline}
        if not intact:
            self.anomaly_log.append({"type": "memory_tampering", "ts": time.time(), **result})
        return result

    def status(self) -> dict:
        return {
            "profiles_tracked": len(self.keystroke_profiles),
            "memory_baseline_set": self.memory_baseline is not None,
            "anomalies_detected": len(self.anomaly_log),
        }
