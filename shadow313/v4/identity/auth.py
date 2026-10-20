"""
shadow313.v4.identity.auth
Authentication engine — multi-factor, hardware token, certificate-based auth.
"""
from __future__ import annotations
import hashlib, hmac, time, secrets
from typing import Optional


class AuthEngine:
    """Multi-factor authentication engine with 313-BIND audit trail."""

    FACTOR_WEIGHTS = {
        "password": 0.3, "totp": 0.3, "hardware_token": 0.4,
        "biometric": 0.4, "certificate": 0.35, "sms": 0.2,
    }

    def __init__(self, min_score: float = 0.7):
        self.min_score = min_score
        self.auth_log: list = []
        self.failed_attempts: dict = {}
        self.lockout_threshold: int = 5

    def authenticate(self, identity_id: str, factors: list) -> dict:
        if self._is_locked_out(identity_id):
            return {"authenticated": False, "reason": "account_locked", "identity_id": identity_id}

        score = sum(self.FACTOR_WEIGHTS.get(f.get("type", ""), 0.0) for f in factors)
        authenticated = score >= self.min_score

        if not authenticated:
            self.failed_attempts[identity_id] = self.failed_attempts.get(identity_id, 0) + 1

        result = {
            "authenticated": authenticated,
            "identity_id": identity_id,
            "score": round(score, 3),
            "factors_used": [f.get("type") for f in factors],
            "timestamp": time.time(),
        }
        self.auth_log.append(result)
        return result

    def _is_locked_out(self, identity_id: str) -> bool:
        return self.failed_attempts.get(identity_id, 0) >= self.lockout_threshold

    def reset_lockout(self, identity_id: str) -> None:
        self.failed_attempts.pop(identity_id, None)

    def generate_totp_secret(self) -> str:
        return secrets.token_hex(20)

    def verify_hmac_token(self, secret: bytes, token: str, message: bytes) -> bool:
        expected = hmac.new(secret, message, hashlib.sha256).hexdigest()[:6]
        return hmac.compare_digest(expected, token)

    def status(self) -> dict:
        return {
            "auth_attempts": len(self.auth_log),
            "locked_accounts": len([k for k, v in self.failed_attempts.items() if v >= self.lockout_threshold]),
        }