"""
Shadow313 NEXUS — Identity Layer Controls
8 zero-trust identity controls (IDENTITY-1 through IDENTITY-8).
"""
from __future__ import annotations
import time, hashlib, uuid, math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

class BehaviouralBiometricProfiler:
    """IDENTITY-1: Insider threat detection via behavioral biometrics."""

    def __init__(self, baseline_window: int = 30):
        self.baseline_window = baseline_window
        self._profiles: Dict[str, List[float]] = {}

    def update_profile(self, user_id: str, features: Dict) -> float:
        """Update user behavioral profile and return anomaly score."""
        score = self._compute_features(features)
        if user_id not in self._profiles:
            self._profiles[user_id] = []
        self._profiles[user_id].append(score)
        if len(self._profiles[user_id]) > self.baseline_window:
            self._profiles[user_id].pop(0)
        return self._anomaly_score(user_id, score)

    def _compute_features(self, features: Dict) -> float:
        typing_speed   = features.get("typing_speed", 0)
        mouse_velocity = features.get("mouse_velocity", 0)
        session_hour   = features.get("hour_of_day", 12)
        after_hours    = 1.0 if session_hour < 7 or session_hour > 20 else 0.0
        return (typing_speed * 0.3 + mouse_velocity * 0.3 + after_hours * 0.4)

    def _anomaly_score(self, user_id: str, current: float) -> float:
        profile = self._profiles.get(user_id, [])
        if len(profile) < 5:
            return 0.0
        mean = sum(profile) / len(profile)
        std  = math.sqrt(sum((x-mean)**2 for x in profile) / len(profile))
        if std == 0:
            return 0.0
        z_score = abs(current - mean) / std
        return min(z_score / 3.0, 1.0)

class ZeroTrustNetworkAccessEngine:
    """IDENTITY-2: Zero-trust network access (T1557 mitigation)."""

    def __init__(self):
        self._sessions: Dict[str, Dict] = {}
        self._denied:   List[Dict] = []

    def evaluate_access(self, user_id: str, resource: str, context: Dict) -> Tuple[bool, str]:
        device_trusted  = context.get("device_attested", False)
        mfa_verified    = context.get("mfa_verified", False)
        network_trusted = context.get("network_trusted", False)
        risk_score      = context.get("risk_score", 1.0)

        if not device_trusted:
            self._denied.append({"user":user_id,"resource":resource,"reason":"device_not_attested"})
            return False, "Device attestation required"
        if not mfa_verified:
            self._denied.append({"user":user_id,"resource":resource,"reason":"mfa_required"})
            return False, "MFA verification required"
        if risk_score > 0.7:
            self._denied.append({"user":user_id,"resource":resource,"reason":"high_risk_score"})
            return False, f"Risk score too high: {risk_score}"

        session_id = str(uuid.uuid4())
        self._sessions[session_id] = {
            "user": user_id, "resource": resource,
            "granted": datetime.now(timezone.utc).isoformat(),
            "context": context
        }
        return True, session_id

class OAuthTokenAnomalyDetector:
    """IDENTITY-3: OAuth token theft detection (T1528)."""

    def __init__(self):
        self._token_profiles: Dict[str, Dict] = {}

    def register_token(self, token_hash: str, context: Dict):
        self._token_profiles[token_hash] = {
            "ip": context.get("ip"), "ua": context.get("user_agent"),
            "registered": datetime.now(timezone.utc).isoformat()
        }

    def validate_token_use(self, token_hash: str, context: Dict) -> Tuple[bool, float]:
        profile = self._token_profiles.get(token_hash)
        if not profile:
            return False, 1.0
        anomaly = 0.0
        if profile["ip"] != context.get("ip"):
            anomaly += 0.5
        if profile["ua"] != context.get("user_agent"):
            anomaly += 0.3
        return anomaly < 0.5, anomaly

class MFAChallengeOrchestrator:
    """IDENTITY-4: MFA challenge orchestration."""

    METHODS = ["totp", "push", "sms", "hardware_token", "biometric"]

    def __init__(self):
        self._challenges: Dict[str, Dict] = {}

    def issue_challenge(self, user_id: str, method: str = "totp") -> Dict:
        challenge_id = str(uuid.uuid4())
        challenge = {
            "id":      challenge_id,
            "user":    user_id,
            "method":  method,
            "code":    hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:6],
            "issued":  datetime.now(timezone.utc).isoformat(),
            "expires": int(time.time()) + 300,
            "used":    False
        }
        self._challenges[challenge_id] = challenge
        return {"challenge_id": challenge_id, "method": method, "expires_in": 300}

    def verify_challenge(self, challenge_id: str, response: str) -> bool:
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            return False
        if challenge["used"] or int(time.time()) > challenge["expires"]:
            return False
        if challenge["code"] == response:
            challenge["used"] = True
            return True
        return False

class HardwareTokenBindingVerifier:
    """IDENTITY-5: Hardware token binding (T1556 mitigation)."""

    def __init__(self):
        self._bindings: Dict[str, str] = {}

    def bind_token(self, user_id: str, token_id: str, tpm_attestation: str) -> str:
        binding_hash = hashlib.sha3_256(f"{user_id}{token_id}{tpm_attestation}".encode()).hexdigest()
        self._bindings[user_id] = binding_hash
        return binding_hash

    def verify_binding(self, user_id: str, token_id: str, tpm_attestation: str) -> bool:
        expected = hashlib.sha3_256(f"{user_id}{token_id}{tpm_attestation}".encode()).hexdigest()
        return self._bindings.get(user_id) == expected

class MLAnomalyProfiler:
    """IDENTITY-6: ML-based user anomaly profiling."""

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self._user_vectors: Dict[str, List[List[float]]] = {}

    def add_observation(self, user_id: str, features: List[float]):
        if user_id not in self._user_vectors:
            self._user_vectors[user_id] = []
        self._user_vectors[user_id].append(features)
        if len(self._user_vectors[user_id]) > 1000:
            self._user_vectors[user_id].pop(0)

    def score(self, user_id: str, features: List[float]) -> float:
        vectors = self._user_vectors.get(user_id, [])
        if len(vectors) < 10:
            return 0.0
        mean = [sum(v[i] for v in vectors)/len(vectors) for i in range(len(features))]
        dist = math.sqrt(sum((f-m)**2 for f,m in zip(features,mean)))
        return min(dist / 10.0, 1.0)

class LOTLAuthBypassDetector:
    """IDENTITY-7: Living-off-the-land auth bypass detection (T1550/T1558)."""

    LOTL_TOOLS = ["mimikatz","rubeus","impacket","crackmapexec","bloodhound","sharphound"]
    SUSPICIOUS_CMDS = ["sekurlsa","lsadump","dcsync","kerberoast","asreproast","pass-the-hash"]

    def detect(self, event: Dict) -> Dict:
        cmd = event.get("command_line","").lower()
        proc = event.get("process_name","").lower()
        score = 0.0
        findings = []

        for tool in self.LOTL_TOOLS:
            if tool in proc or tool in cmd:
                score += 0.4
                findings.append(f"LOTL tool detected: {tool}")

        for suspicious in self.SUSPICIOUS_CMDS:
            if suspicious in cmd:
                score += 0.3
                findings.append(f"Suspicious command: {suspicious}")

        return {
            "detected":  score > 0.3,
            "score":     min(score, 1.0),
            "findings":  findings,
            "technique": "T1550" if "hash" in cmd else "T1558",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

class TLSInspectionEngine:
    """IDENTITY-8: TLS inspection for encrypted C2 detection (T1071)."""

    SUSPICIOUS_JA3 = [
        "e7d705a3286e19ea42f587b344ee6865",  # Cobalt Strike default
        "6734f37431670b3ab4292b8f60f29984",  # Metasploit
        "b386946a5a3aba9d7defb48869046904",  # Known malware
    ]

    def __init__(self):
        self._inspected: List[Dict] = []

    def inspect(self, tls_metadata: Dict) -> Dict:
        ja3 = tls_metadata.get("ja3","")
        sni = tls_metadata.get("sni","")
        cert_age = tls_metadata.get("cert_age_days", 365)
        score = 0.0
        findings = []

        if ja3 in self.SUSPICIOUS_JA3:
            score += 0.8
            findings.append(f"Known malicious JA3: {ja3}")

        if cert_age < 30:
            score += 0.2
            findings.append(f"Recently issued cert ({cert_age} days)")

        if not sni or sni.count(".") > 4:
            score += 0.2
            findings.append("Suspicious SNI pattern")

        result = {
            "detected":  score > 0.5,
            "score":     min(score, 1.0),
            "ja3":       ja3,
            "sni":       sni,
            "findings":  findings,
            "technique": "T1071.001",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self._inspected.append(result)
        return result

# ── Unified Identity Layer ────────────────────────────────────────────────
class IdentityLayer:
    """Unified interface for all 8 identity controls."""

    def __init__(self):
        self.biometric    = BehaviouralBiometricProfiler()
        self.ztna         = ZeroTrustNetworkAccessEngine()
        self.oauth        = OAuthTokenAnomalyDetector()
        self.mfa          = MFAChallengeOrchestrator()
        self.hw_token     = HardwareTokenBindingVerifier()
        self.ml_profiler  = MLAnomalyProfiler()
        self.lotl         = LOTLAuthBypassDetector()
        self.tls          = TLSInspectionEngine()

    def evaluate_event(self, event: Dict) -> Dict:
        """Run all applicable identity controls against an event."""
        results = {}
        event_type = event.get("type","")

        if event_type in ("login","auth"):
            results["ztna"]      = self.ztna.evaluate_access(event.get("user",""), event.get("resource",""), event)
            results["mfa"]       = {"required": True}
            results["biometric"] = self.biometric.update_profile(event.get("user",""), event)

        if event_type == "process":
            results["lotl"] = self.lotl.detect(event)

        if event_type == "network":
            results["tls"] = self.tls.inspect(event.get("tls_metadata",{}))

        return results
