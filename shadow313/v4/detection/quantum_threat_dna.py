"""
shadow313.v4.detection.quantum_threat_dna
Quantum Threat DNA Profiler — fingerprints threat actors by their cryptographic attack signatures.
"""
from __future__ import annotations
import hashlib
import time
from typing import Optional

KNOWN_PROFILES = {
    "APT_CRQC_HARVESTER": {
        "patterns": ["bulk_tls_capture", "rsa_key_extraction", "ecdh_session_harvest"],
        "risk": "CRITICAL",
        "description": "Nation-state HNDL harvesting operation",
    },
    "RANSOMWARE_PQC_BYPASS": {
        "patterns": ["ml_kem_downgrade", "slh_dsa_forgery_attempt", "pqc_oracle_probe"],
        "risk": "HIGH",
        "description": "Ransomware attempting PQC algorithm downgrade",
    },
    "SUPPLY_CHAIN_SIGNER": {
        "patterns": ["code_signing_abuse", "cert_chain_manipulation", "timestamp_forgery"],
        "risk": "HIGH",
        "description": "Supply chain attack via signing infrastructure",
    },
}


class QuantumThreatDNA:
    """Profiles threat actors by PQC attack patterns and cryptographic fingerprints."""

    def __init__(self):
        self.observed_patterns: list = []
        self.actor_matches: list = []

    def observe_pattern(self, pattern: str, context: dict) -> dict:
        obs = {"pattern": pattern, "context": context, "timestamp": time.time()}
        self.observed_patterns.append(obs)
        match = self._match_profile(pattern)
        if match:
            self.actor_matches.append({**match, "pattern": pattern, "timestamp": time.time()})
        return {"observed": obs, "match": match}

    def _match_profile(self, pattern: str) -> Optional[dict]:
        for actor, profile in KNOWN_PROFILES.items():
            if pattern in profile["patterns"]:
                return {
                    "actor": actor,
                    "risk": profile["risk"],
                    "description": profile["description"],
                }
        return None

    def generate_dna_fingerprint(self, patterns: list) -> str:
        combined = "|".join(sorted(patterns))
        return hashlib.sha3_256(combined.encode()).hexdigest()[:16]

    def get_threat_summary(self) -> dict:
        return {
            "patterns_observed": len(self.observed_patterns),
            "actor_matches": len(self.actor_matches),
            "unique_actors": len(set(m["actor"] for m in self.actor_matches)),
            "critical_matches": [m for m in self.actor_matches if m["risk"] == "CRITICAL"],
        }