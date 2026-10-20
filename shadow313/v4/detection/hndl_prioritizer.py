"""
shadow313.v4.detection.hndl_prioritizer
HNDL Prioritizer — Harvest-Now-Decrypt-Later threat stream prioritization.
"""
from __future__ import annotations
import time
from typing import Optional

ALGORITHM_RISK = {
    "RSA-2048": 0.95, "RSA-4096": 0.90, "ECDSA-P256": 0.92, "ECDSA-P384": 0.88,
    "DH-2048": 0.93, "ECDH-P256": 0.91, "AES-128-GCM": 0.10, "AES-256-GCM": 0.05,
    "ML-KEM-768": 0.01, "ML-DSA-65": 0.01, "SLH-DSA": 0.01, "ChaCha20-Poly1305": 0.08,
    "TLS-1.2": 0.75, "TLS-1.3": 0.30, "TLS-1.1": 0.98, "TLS-1.0": 0.99,
}


class HNDLPrioritizer:
    """Scores encrypted traffic streams by CRQC harvest risk."""

    def __init__(self, crqc_timeline_years: float = 7.0):
        self.crqc_timeline = crqc_timeline_years
        self.stream_registry: list = []

    def score_stream(self, stream: dict) -> dict:
        algorithm = stream.get("algorithm", "TLS-1.2")
        data_sensitivity = stream.get("sensitivity", 0.5)
        retention_years = stream.get("retention_years", 10)
        size_mb = stream.get("size_mb", 1.0)
        algo_risk = ALGORITHM_RISK.get(algorithm, 0.5)
        time_risk = min(1.0, retention_years / self.crqc_timeline)
        hndl_score = round(algo_risk * data_sensitivity * time_risk, 4)
        result = {
            "stream_id": stream.get("id", f"stream_{int(time.time())}"),
            "algorithm": algorithm,
            "hndl_score": hndl_score,
            "risk_level": self._risk_level(hndl_score),
            "algorithm_risk": algo_risk,
            "data_sensitivity": data_sensitivity,
            "time_risk": time_risk,
            "size_mb": size_mb,
            "recommendation": self._recommend(hndl_score, algorithm),
            "timestamp": time.time(),
        }
        self.stream_registry.append(result)
        return result

    def _risk_level(self, score: float) -> str:
        if score >= 0.7: return "CRITICAL"
        if score >= 0.5: return "HIGH"
        if score >= 0.3: return "MEDIUM"
        return "LOW"

    def _recommend(self, score: float, algorithm: str) -> str:
        if score >= 0.7:
            return f"URGENT: Migrate {algorithm} to ML-KEM-768 + ML-DSA-65 immediately"
        if score >= 0.5:
            return f"HIGH: Plan migration from {algorithm} to PQC within 12 months"
        return "LOW: Current algorithm acceptable for near-term use"

    def prioritize_streams(self) -> list:
        return sorted(self.stream_registry, key=lambda x: x["hndl_score"], reverse=True)

    def get_critical_streams(self) -> list:
        return [s for s in self.stream_registry if s["risk_level"] == "CRITICAL"]

    def status(self) -> dict:
        return {
            "streams_analyzed": len(self.stream_registry),
            "critical_count": len(self.get_critical_streams()),
            "crqc_timeline_years": self.crqc_timeline,
        }