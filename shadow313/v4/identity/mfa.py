"""
shadow313.v4.identity.mfa
Multi-Factor Authentication — TOTP, hardware tokens, biometrics.
"""
from __future__ import annotations
import hashlib, hmac, struct, time
from typing import Optional


class MFAEngine:
    """Multi-factor authentication with TOTP, hardware token, and biometric support."""

    def __init__(self):
        self.enrolled_factors: dict = {}
        self.verification_log: list = []

    def enroll_totp(self, identity_id: str, secret: bytes) -> dict:
        self.enrolled_factors.setdefault(identity_id, {})["totp"] = {"secret": secret, "enrolled_at": time.time()}
        return {"enrolled": True, "type": "totp", "identity_id": identity_id}

    def verify_totp(self, identity_id: str, token: str, window: int = 1) -> bool:
        factor = self.enrolled_factors.get(identity_id, {}).get("totp")
        if not factor:
            return False
        secret = factor["secret"]
        ts = int(time.time()) // 30
        for offset in range(-window, window + 1):
            expected = self._hotp(secret, ts + offset)
            if hmac.compare_digest(str(expected).zfill(6), token.zfill(6)):
                self._log(identity_id, "totp", True)
                return True
        self._log(identity_id, "totp", False)
        return False

    def _hotp(self, secret: bytes, counter: int) -> int:
        msg = struct.pack(">Q", counter)
        h = hmac.new(secret, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
        return code % 1_000_000

    def enroll_hardware_token(self, identity_id: str, token_id: str) -> dict:
        self.enrolled_factors.setdefault(identity_id, {})["hardware_token"] = {
            "token_id": token_id, "enrolled_at": time.time()
        }
        return {"enrolled": True, "type": "hardware_token", "token_id": token_id}

    def verify_hardware_token(self, identity_id: str, token_id: str) -> bool:
        factor = self.enrolled_factors.get(identity_id, {}).get("hardware_token")
        if not factor:
            return False
        result = factor["token_id"] == token_id
        self._log(identity_id, "hardware_token", result)
        return result

    def _log(self, identity_id: str, factor_type: str, success: bool) -> None:
        self.verification_log.append({
            "identity_id": identity_id, "factor": factor_type,
            "success": success, "timestamp": time.time(),
        })

    def status(self) -> dict:
        return {
            "enrolled_identities": len(self.enrolled_factors),
            "verifications": len(self.verification_log),
            "success_rate": round(
                sum(1 for v in self.verification_log if v["success"]) / max(len(self.verification_log), 1), 3
            ),
        }