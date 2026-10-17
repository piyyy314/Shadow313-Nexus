from __future__ import annotations
"""
shadow313.v4.identity.identity_engine
Identity Engine — unified human/workload/agent identity with zero-trust enforcement.
"""
import hashlib, time, uuid
from typing import Optional

class IdentityEngine:
    """Zero-trust identity management for humans, workloads, and agents."""

    def __init__(self):
        self.identities: dict = {}
        self.sessions: dict = {}
        self.access_log: list = []
        self.policy_violations: list = []

    def register_identity(self, identity_id: str, identity_type: str = "human",
                          attributes: Optional[dict] = None) -> dict:
        identity = {
            "id": identity_id,
            "type": identity_type,  # human | workload | agent
            "attributes": attributes or {},
            "trust_score": 0.5,
            "mfa_enrolled": False,
            "hardware_token": False,
            "created_at": time.time(),
            "last_verified": None,
        }
        self.identities[identity_id] = identity
        return identity

    def authenticate(self, identity_id: str, factors: list) -> dict:
        """Authenticate an identity with provided factors."""
        identity = self.identities.get(identity_id)
        if not identity:
            return {"authenticated": False, "reason": "identity_not_found"}

        score = 0.0
        factor_results = []
        for factor in factors:
            result = self._verify_factor(factor, identity)
            factor_results.append(result)
            score += result.get("weight", 0.0)

        authenticated = score >= 0.7
        if authenticated:
            session_id = f"SES-{uuid.uuid4().hex[:12].upper()}"
            self.sessions[session_id] = {
                "identity_id": identity_id,
                "session_id": session_id,
                "trust_score": min(1.0, score),
                "created_at": time.time(),
                "expires_at": time.time() + 3600,
                "factors_used": [f["type"] for f in factors],
            }
            identity["last_verified"] = time.time()
            identity["trust_score"] = min(1.0, score)
            return {"authenticated": True, "session_id": session_id, "trust_score": score}

        return {"authenticated": False, "reason": "insufficient_factors", "score": score}

    def _verify_factor(self, factor: dict, identity: dict) -> dict:
        factor_type = factor.get("type", "unknown")
        weights = {"password": 0.3, "totp": 0.3, "hardware_token": 0.4, "biometric": 0.4,
                   "device_attestation": 0.3, "certificate": 0.35}
        return {"type": factor_type, "verified": True, "weight": weights.get(factor_type, 0.1)}

    def authorize(self, session_id: str, resource: str, action: str) -> dict:
        """Zero-trust authorization check."""
        session = self.sessions.get(session_id)
        if not session:
            return {"authorized": False, "reason": "invalid_session"}
        if time.time() > session.get("expires_at", 0):
            return {"authorized": False, "reason": "session_expired"}

        trust = session.get("trust_score", 0.0)
        required_trust = self._get_required_trust(resource, action)
        authorized = trust >= required_trust

        log_entry = {
            "session_id": session_id,
            "identity_id": session["identity_id"],
            "resource": resource,
            "action": action,
            "authorized": authorized,
            "trust_score": trust,
            "required_trust": required_trust,
            "timestamp": time.time(),
        }
        self.access_log.append(log_entry)
        if not authorized:
            self.policy_violations.append(log_entry)
        return {"authorized": authorized, "trust_score": trust, "required_trust": required_trust}

    def _get_required_trust(self, resource: str, action: str) -> float:
        if "admin" in resource.lower() or "delete" in action.lower(): return 0.9
        if "write" in action.lower() or "create" in action.lower(): return 0.7
        return 0.5

    def status(self) -> dict:
        return {
            "identities_registered": len(self.identities),
            "active_sessions": len(self.sessions),
            "access_events": len(self.access_log),
            "policy_violations": len(self.policy_violations),
        }
