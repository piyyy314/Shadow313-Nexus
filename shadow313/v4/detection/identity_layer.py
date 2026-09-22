"""
shadow313.v4.detection.identity_layer
──────────────────────────────────────
Identity-Layer Controls — closes the 3 irreducible gaps from the zero-day
evasion simulation that require controls beyond signature/behavioural detection:

  1. Insider threat (attacker IS the legitimate user)
     → BehaviouralBiometricProfiler: typing cadence, session entropy, peer-group
  2. Same-LAN MitM with identical IP
     → ZeroTrustNetworkAccessEngine: micro-segmentation, mTLS, device attestation
  3. Fresh OAuth token theft
     → OAuthTokenAnomalyDetector: refresh chain tracking, device fingerprint binding

Supporting controls:
  4. MFAChallengeOrchestrator: step-up auth triggers for high-risk events
  5. HardwareTokenBindingVerifier: FIDO2/WebAuthn device binding verification
"""
from __future__ import annotations

import hashlib
import hmac
import math
import random
import re
import statistics
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ── 1. BehaviouralBiometricProfiler ──────────────────────────────────────────

@dataclass
class KeystrokeEvent:
    key: str
    press_ts: float    # epoch seconds
    release_ts: float  # epoch seconds

    @property
    def dwell_ms(self) -> float:
        return (self.release_ts - self.press_ts) * 1000

    @property
    def flight_ms(self) -> float:
        """Time from this key press to next key press (set externally)."""
        return getattr(self, "_flight_ms", 0.0)


class BehaviouralBiometricProfiler:
    """
    Closes Gap 1: Insider threat — attacker IS the legitimate user.

    Builds a per-account biometric baseline from:
      - Keystroke dwell time (how long each key is held)
      - Keystroke flight time (time between consecutive key presses)
      - Session entropy (diversity of commands/URLs accessed)
      - Typing speed (WPM)
      - Mouse movement variance (simulated via event timing)

    Detection: Mahalanobis-like distance from baseline.
    If current session deviates > ANOMALY_THRESHOLD standard deviations
    across ≥ 2 dimensions → insider threat alert.

    Also implements peer-group anomaly:
      - Compares account behaviour to peer group (same role/department)
      - Flags if account is statistical outlier vs peers
    """

    ANOMALY_THRESHOLD = 2.5   # standard deviations
    MIN_BASELINE_SAMPLES = 10
    SESSION_ENTROPY_WINDOW = 300  # seconds

    def __init__(self):
        # account → {dwell_times, flight_times, wpm_samples, entropy_samples}
        self._baselines: dict[str, dict] = {}
        # role → list of accounts
        self._peer_groups: dict[str, list[str]] = defaultdict(list)
        # account → role
        self._account_roles: dict[str, str] = {}
        self._lock = threading.Lock()

    # ── Baseline building ────────────────────────────────────────────────────

    def record_baseline_session(self, account: str, role: str,
                                  keystrokes: list[KeystrokeEvent],
                                  commands: list[str]) -> None:
        """Feed a normal session to build the biometric baseline."""
        with self._lock:
            if account not in self._baselines:
                self._baselines[account] = {
                    "dwell_times": [], "flight_times": [],
                    "wpm_samples": [], "entropy_samples": [],
                }
                self._account_roles[account] = role
                self._peer_groups[role].append(account)

            b = self._baselines[account]

            # Dwell times
            b["dwell_times"].extend(k.dwell_ms for k in keystrokes)

            # Flight times (inter-key intervals)
            for i in range(len(keystrokes) - 1):
                flight = (keystrokes[i+1].press_ts - keystrokes[i].press_ts) * 1000
                b["flight_times"].append(flight)

            # WPM (approx: chars / 5 / minutes)
            if keystrokes:
                duration_min = (keystrokes[-1].release_ts - keystrokes[0].press_ts) / 60
                if duration_min > 0:
                    wpm = len(keystrokes) / 5 / duration_min
                    b["wpm_samples"].append(wpm)

            # Session entropy (Shannon entropy of command set)
            if commands:
                entropy = self._shannon_entropy(commands)
                b["entropy_samples"].append(entropy)

    # ── Evaluation ───────────────────────────────────────────────────────────

    def evaluate_session(self, account: str,
                          keystrokes: list[KeystrokeEvent],
                          commands: list[str]) -> dict:
        """Evaluate a live session against the account's biometric baseline."""
        with self._lock:
            baseline = self._baselines.get(account)

        if baseline is None:
            return {
                "technique": "T1078",
                "fix": "IDENTITY-1",
                "account": account,
                "detected": False,
                "verdict": "NO_BASELINE",
                "signals": ["no_biometric_baseline"],
                "confidence": 0.3,
            }

        # Check minimum samples (wpm_samples = one per session, more meaningful)
        if len(baseline["wpm_samples"]) < self.MIN_BASELINE_SAMPLES:
            return {
                "technique": "T1078",
                "fix": "IDENTITY-1",
                "account": account,
                "detected": False,
                "verdict": "INSUFFICIENT_BASELINE",
                "signals": [],
                "confidence": 0.1,
            }

        signals: list[str] = []

        # Dimension 1: Dwell time anomaly
        if keystrokes and len(baseline["dwell_times"]) >= 2:
            live_dwell = [k.dwell_ms for k in keystrokes]
            if live_dwell:
                live_mean = statistics.mean(live_dwell)
                base_mean = statistics.mean(baseline["dwell_times"])
                base_std  = statistics.stdev(baseline["dwell_times"])
                if base_std > 1e-6:
                    z = abs(live_mean - base_mean) / base_std
                    if z > self.ANOMALY_THRESHOLD:
                        signals.append(
                            f"dwell_anomaly:z={z:.2f} "
                            f"live={live_mean:.1f}ms base={base_mean:.1f}ms"
                        )
                else:
                    # Zero-variance baseline: use absolute ratio threshold
                    # If live mean differs by > 50% from baseline → anomaly
                    if base_mean > 0 and abs(live_mean - base_mean) / base_mean > 0.50:
                        signals.append(
                            f"dwell_anomaly:ratio={live_mean/base_mean:.2f} "
                            f"live={live_mean:.1f}ms base={base_mean:.1f}ms"
                        )

        # Dimension 2: Typing speed anomaly
        if keystrokes and len(baseline["wpm_samples"]) >= 2:
            duration_min = (keystrokes[-1].release_ts - keystrokes[0].press_ts) / 60
            if duration_min > 0:
                live_wpm = len(keystrokes) / 5 / duration_min
                base_mean = statistics.mean(baseline["wpm_samples"])
                base_std  = statistics.stdev(baseline["wpm_samples"])
                if base_std > 1e-6:
                    z = abs(live_wpm - base_mean) / base_std
                    if z > self.ANOMALY_THRESHOLD:
                        signals.append(
                            f"wpm_anomaly:z={z:.2f} "
                            f"live={live_wpm:.0f}wpm base={base_mean:.0f}wpm"
                        )
                else:
                    # Zero-variance baseline: use ratio threshold (> 3x or < 0.33x)
                    if base_mean > 0:
                        ratio = live_wpm / base_mean
                        if ratio > 3.0 or ratio < 0.33:
                            signals.append(
                                f"wpm_anomaly:ratio={ratio:.2f} "
                                f"live={live_wpm:.0f}wpm base={base_mean:.0f}wpm"
                            )

        # Dimension 3: Session entropy anomaly
        if commands and len(baseline["entropy_samples"]) >= 2:
            live_entropy = self._shannon_entropy(commands)
            base_mean = statistics.mean(baseline["entropy_samples"])
            base_std  = statistics.stdev(baseline["entropy_samples"])
            if base_std > 1e-6:
                z = abs(live_entropy - base_mean) / base_std
                if z > self.ANOMALY_THRESHOLD:
                    signals.append(
                        f"entropy_anomaly:z={z:.2f} "
                        f"live={live_entropy:.2f} base={base_mean:.2f}"
                    )
            else:
                # Zero-variance baseline: flag if entropy differs by > 1.5 bits
                if abs(live_entropy - base_mean) > 1.5:
                    signals.append(
                        f"entropy_anomaly:delta={live_entropy-base_mean:.2f} "
                        f"live={live_entropy:.2f} base={base_mean:.2f}"
                    )

        # Dimension 4: Peer-group anomaly
        peer_signal = self._peer_group_anomaly(account, keystrokes)
        if peer_signal:
            signals.append(peer_signal)

        fired = len(signals)
        if fired >= 2:
            confidence, verdict = 0.88, "INSIDER_THREAT_SUSPECTED"
        elif fired == 1:
            confidence, verdict = 0.60, "BEHAVIOURAL_ANOMALY"
        else:
            confidence, verdict = 0.05, "NORMAL"

        return {
            "technique": "T1078",
            "fix": "IDENTITY-1",
            "account": account,
            "signals": signals,
            "confidence": confidence,
            "verdict": verdict,
            "detected": fired >= 1,
        }

    def _peer_group_anomaly(self, account: str,
                             keystrokes: list[KeystrokeEvent]) -> str:
        """Compare account WPM to peer group — flag statistical outliers."""
        with self._lock:
            role = self._account_roles.get(account)
            if not role:
                return ""
            peers = [p for p in self._peer_groups[role] if p != account]
            peer_wpms = []
            for peer in peers:
                b = self._baselines.get(peer, {})
                if b.get("wpm_samples"):
                    peer_wpms.append(statistics.mean(b["wpm_samples"]))

        if len(peer_wpms) < 3 or not keystrokes:
            return ""

        duration_min = (keystrokes[-1].release_ts - keystrokes[0].press_ts) / 60
        if duration_min <= 0:
            return ""

        live_wpm = len(keystrokes) / 5 / duration_min
        peer_mean = statistics.mean(peer_wpms)
        peer_std  = statistics.stdev(peer_wpms)

        if peer_std > 1e-6:
            z = abs(live_wpm - peer_mean) / peer_std
            if z > self.ANOMALY_THRESHOLD:
                return (f"peer_group_outlier:z={z:.2f} "
                        f"live={live_wpm:.0f}wpm peer_mean={peer_mean:.0f}wpm")
        else:
            # Zero-variance peers: flag if live WPM differs by > 50% from peer mean
            if peer_mean > 0 and abs(live_wpm - peer_mean) / peer_mean > 0.50:
                return (f"peer_group_outlier:ratio={live_wpm/peer_mean:.2f} "
                        f"live={live_wpm:.0f}wpm peer_mean={peer_mean:.0f}wpm")
        return ""

        

    @staticmethod
    def _shannon_entropy(items: list[str]) -> float:
        if not items:
            return 0.0
        total = len(items)
        freq = {}
        for item in items:
            freq[item] = freq.get(item, 0) + 1
        return -sum((c / total) * math.log2(c / total) for c in freq.values())


# ── 2. ZeroTrustNetworkAccessEngine ──────────────────────────────────────────

@dataclass
class DeviceAttestation:
    device_id: str
    certificate_thumbprint: str
    platform: str          # "windows", "linux", "macos", "ios", "android"
    compliance_status: str # "compliant", "non_compliant", "unknown"
    last_check_ts: float
    mtls_verified: bool


class ZeroTrustNetworkAccessEngine:
    """
    Closes Gap 2: Same-LAN MitM with identical IP.

    Zero-trust principle: never trust the network, always verify the device.
    Even if an attacker has the same source IP (ARP poison / same LAN),
    they cannot forge:
      - mTLS client certificate (device certificate)
      - Device compliance attestation (MDM enrollment)
      - Hardware TPM attestation (device identity)

    Controls:
      - Device certificate verification (mTLS)
      - MDM compliance check
      - Micro-segmentation policy enforcement
      - Network access policy evaluation
    """

    COMPLIANCE_MAX_AGE_HOURS = 24
    CERT_THUMBPRINT_ALGO = "sha256"

    def __init__(self):
        # device_id → DeviceAttestation
        self._device_registry: dict[str, DeviceAttestation] = {}
        # account → set of authorized device_ids
        self._account_devices: dict[str, set[str]] = defaultdict(set)
        # micro-segmentation: segment → allowed_segments
        self._segment_policy: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def register_device(self, device_id: str, cert_thumbprint: str,
                         platform: str, account: str) -> None:
        """Register a device as authorized for an account."""
        with self._lock:
            self._device_registry[device_id] = DeviceAttestation(
                device_id=device_id,
                certificate_thumbprint=cert_thumbprint,
                platform=platform,
                compliance_status="compliant",
                last_check_ts=time.time(),
                mtls_verified=True,
            )
            self._account_devices[account].add(device_id)

    def evaluate_access(self, account: str, device_id: str,
                         presented_cert: str,
                         src_segment: str = "untrusted",
                         dst_segment: str = "internal") -> dict:
        """
        Evaluate a network access request under zero-trust policy.
        Returns allow/deny with detailed reasoning.
        """
        signals: list[str] = []
        deny_reasons: list[str] = []

        with self._lock:
            registered = self._device_registry.get(device_id)
            authorized_devices = self._account_devices.get(account, set())
            segment_policy = self._segment_policy.get(src_segment, set())

        # Check 1: Device registered for this account
        if device_id not in authorized_devices:
            deny_reasons.append(f"device_not_authorized:{device_id}")
            signals.append("unregistered_device")

        # Check 2: mTLS certificate matches
        if registered is None:
            deny_reasons.append("device_not_in_registry")
            signals.append("no_device_attestation")
        else:
            if registered.certificate_thumbprint != presented_cert:
                deny_reasons.append("cert_mismatch")
                signals.append(
                    f"mtls_cert_mismatch:"
                    f"expected={registered.certificate_thumbprint[:16]}... "
                    f"got={presented_cert[:16]}..."
                )

            # Check 3: Compliance freshness
            age_hours = (time.time() - registered.last_check_ts) / 3600
            if age_hours > self.COMPLIANCE_MAX_AGE_HOURS:
                deny_reasons.append(f"compliance_stale:{age_hours:.1f}h")
                signals.append("compliance_check_expired")

            # Check 4: Compliance status
            if registered.compliance_status != "compliant":
                deny_reasons.append(f"non_compliant:{registered.compliance_status}")
                signals.append("device_non_compliant")

        # Check 5: Micro-segmentation policy
        if dst_segment not in segment_policy and segment_policy:
            deny_reasons.append(
                f"segment_policy_violation:{src_segment}->{dst_segment}"
            )
            signals.append("micro_segmentation_block")

        allowed = len(deny_reasons) == 0
        fired = len(signals)

        return {
            "technique": "T1557",
            "fix": "IDENTITY-2",
            "account": account,
            "device_id": device_id,
            "allowed": allowed,
            "deny_reasons": deny_reasons,
            "signals": signals,
            "confidence": min(1.0, fired * 0.30),
            "detected": not allowed,
            "verdict": "ACCESS_DENIED" if not allowed else "ACCESS_GRANTED",
        }

    def set_segment_policy(self, src_segment: str,
                            allowed_destinations: set[str]) -> None:
        with self._lock:
            self._segment_policy[src_segment] = allowed_destinations

    def update_compliance(self, device_id: str, status: str) -> None:
        with self._lock:
            if device_id in self._device_registry:
                self._device_registry[device_id].compliance_status = status
                self._device_registry[device_id].last_check_ts = time.time()


# ── 3. OAuthTokenAnomalyDetector ─────────────────────────────────────────────

@dataclass
class TokenRecord:
    access_token_hash: str
    refresh_token_hash: str
    issued_at: float
    client_id: str
    device_fingerprint: str   # hash of device characteristics
    src_ip: str
    user_agent: str
    scope: str
    revoked: bool = False
    last_used: float = 0.0
    use_count: int = 0


class OAuthTokenAnomalyDetector:
    """
    Closes Gap 3: Fresh OAuth token theft.

    When an attacker steals a refresh token and generates a new access token,
    the new token has no anomaly history — defeating session-based detectors.

    This detector tracks the full OAuth token lifecycle:
      - Refresh token → access token chain (each refresh is tracked)
      - Device fingerprint binding (token must be used from same device)
      - Refresh token reuse detection (stolen refresh token used twice)
      - Token family invalidation (if refresh token is reused → revoke all)
      - Scope escalation detection (new token requests broader scope)
      - Rapid token rotation (attacker refreshes frequently to avoid expiry)
    """

    RAPID_REFRESH_THRESHOLD = 5    # refreshes per hour
    REFRESH_WINDOW_SECONDS  = 3600
    MAX_DEVICE_CHANGES      = 1    # max device fingerprint changes per token family

    def __init__(self):
        # access_token_hash → TokenRecord
        self._tokens: dict[str, TokenRecord] = {}
        # refresh_token_hash → list of access_token_hashes issued from it
        self._refresh_chains: dict[str, list[str]] = defaultdict(list)
        # refresh_token_hash → list of use timestamps
        self._refresh_uses: dict[str, list[float]] = defaultdict(list)
        # client_id → set of known device fingerprints
        self._client_devices: dict[str, set[str]] = defaultdict(set)
        self._lock = threading.Lock()

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha3_256(value.encode()).hexdigest()[:32]

    def issue_token(self, access_token: str, refresh_token: str,
                     client_id: str, device_fingerprint: str,
                     src_ip: str, user_agent: str, scope: str,
                     timestamp: float | None = None) -> None:
        """Record a newly issued token pair."""
        ts = timestamp or time.time()
        at_hash = self._hash(access_token)
        rt_hash = self._hash(refresh_token)

        with self._lock:
            self._tokens[at_hash] = TokenRecord(
                access_token_hash=at_hash,
                refresh_token_hash=rt_hash,
                issued_at=ts,
                client_id=client_id,
                device_fingerprint=device_fingerprint,
                src_ip=src_ip,
                user_agent=user_agent,
                scope=scope,
                last_used=ts,
            )
            self._refresh_chains[rt_hash].append(at_hash)
            self._client_devices[client_id].add(device_fingerprint)

    def use_token(self, access_token: str, device_fingerprint: str,
                   src_ip: str, timestamp: float | None = None) -> dict:
        """Validate token use and detect anomalies."""
        ts = timestamp or time.time()
        at_hash = self._hash(access_token)
        signals: list[str] = []

        with self._lock:
            record = self._tokens.get(at_hash)

        if record is None:
            return {
                "technique": "T1539",
                "fix": "IDENTITY-3",
                "detected": True,
                "signals": ["unknown_token"],
                "confidence": 0.70,
                "verdict": "UNKNOWN_TOKEN",
            }

        if record.revoked:
            signals.append("revoked_token_reuse")

        # Signal 1: Device fingerprint mismatch
        if record.device_fingerprint != device_fingerprint:
            signals.append(
                f"device_fingerprint_mismatch:"
                f"expected={record.device_fingerprint[:16]}... "
                f"got={device_fingerprint[:16]}..."
            )

        # Signal 2: IP change
        if record.src_ip != src_ip:
            signals.append(f"token_ip_change:{record.src_ip}->{src_ip}")

        # Signal 3: User-agent change (if tracked)
        # (stored in record, compared on use)

        with self._lock:
            record.last_used = ts
            record.use_count += 1

        fired = len(signals)
        return {
            "technique": "T1539",
            "fix": "IDENTITY-3",
            "token_hash": at_hash[:16] + "...",
            "signals": signals,
            "confidence": min(1.0, fired * 0.45),
            "detected": fired >= 1,
            "verdict": "TOKEN_ANOMALY" if fired >= 1 else "NORMAL",
        }

    def refresh_token(self, refresh_token: str, new_access_token: str,
                       device_fingerprint: str, src_ip: str,
                       new_scope: str, timestamp: float | None = None) -> dict:
        """
        Process a token refresh and detect:
          - Refresh token reuse (stolen token used twice)
          - Rapid refresh rate
          - Scope escalation
          - Device fingerprint change
        """
        ts = timestamp or time.time()
        rt_hash = self._hash(refresh_token)
        new_at_hash = self._hash(new_access_token)
        signals: list[str] = []

        with self._lock:
            uses = self._refresh_uses[rt_hash]
            chain = self._refresh_chains[rt_hash]

            # Signal 1: Refresh token reuse (already used → stolen)
            if len(uses) > 0:
                signals.append(
                    f"refresh_token_reuse:used_{len(uses)}_times_before"
                )
                # Token family invalidation — revoke all tokens in chain
                for at_hash in chain:
                    if at_hash in self._tokens:
                        self._tokens[at_hash].revoked = True

            # Signal 2: Rapid refresh rate
            recent_uses = [u for u in uses if ts - u <= self.REFRESH_WINDOW_SECONDS]
            if len(recent_uses) >= self.RAPID_REFRESH_THRESHOLD:
                signals.append(
                    f"rapid_refresh:{len(recent_uses)}_in_1h"
                )

            # Signal 3: Device fingerprint change
            if chain:
                # Get device from most recent token in chain
                last_at = self._tokens.get(chain[-1])
                if last_at and last_at.device_fingerprint != device_fingerprint:
                    signals.append(
                        f"refresh_device_change:"
                        f"{last_at.device_fingerprint[:16]}...->"
                        f"{device_fingerprint[:16]}..."
                    )

            # Signal 4: Scope escalation
            if chain:
                last_at = self._tokens.get(chain[-1])
                if last_at:
                    old_scopes = set(last_at.scope.split())
                    new_scopes = set(new_scope.split())
                    escalated = new_scopes - old_scopes
                    if escalated:
                        signals.append(f"scope_escalation:{escalated}")

            uses.append(ts)
            chain.append(new_at_hash)

        fired = len(signals)
        return {
            "technique": "T1539",
            "fix": "IDENTITY-3",
            "refresh_token_hash": rt_hash[:16] + "...",
            "signals": signals,
            "confidence": min(1.0, 0.4 + fired * 0.25),
            "detected": fired >= 1,
            "verdict": "REFRESH_ANOMALY" if fired >= 1 else "NORMAL",
            "family_revoked": "refresh_token_reuse" in " ".join(signals),
        }

    def revoke_token_family(self, refresh_token: str) -> int:
        """Revoke all access tokens issued from a refresh token."""
        rt_hash = self._hash(refresh_token)
        revoked_count = 0
        with self._lock:
            for at_hash in self._refresh_chains.get(rt_hash, []):
                if at_hash in self._tokens:
                    self._tokens[at_hash].revoked = True
                    revoked_count += 1
        return revoked_count


# ── 4. MFAChallengeOrchestrator ───────────────────────────────────────────────

class MFAChallengeOrchestrator:
    """
    Step-up authentication triggers for high-risk events.

    Integrates with all other identity-layer controls:
    when any detector fires with confidence >= MFA_TRIGGER_THRESHOLD,
    a step-up MFA challenge is issued before access is granted.

    Risk levels:
      LOW    (0.3–0.5): Log only
      MEDIUM (0.5–0.7): Soft challenge (push notification)
      HIGH   (0.7–0.9): Hard challenge (TOTP/FIDO2 required)
      CRITICAL (≥0.9):  Block + alert security team
    """

    MFA_TRIGGER_THRESHOLD = 0.50

    # Risk triggers and their base confidence
    RISK_TRIGGERS = {
        "impossible_travel":        0.95,
        "login_velocity":           0.80,
        "subnet_change":            0.65,
        "dwell_anomaly":            0.70,
        "wpm_anomaly":              0.65,
        "entropy_anomaly":          0.60,
        "peer_group_outlier":       0.75,
        "device_fingerprint_mismatch": 0.90,
        "refresh_token_reuse":      0.95,
        "scope_escalation":         0.80,
        "rapid_refresh":            0.75,
        "unregistered_device":      0.85,
        "mtls_cert_mismatch":       0.95,
        "concurrent_sessions":      0.80,
        "geo_anomaly":              0.85,
        "ip_change_24h":            0.60,
    }

    def __init__(self):
        # account → list of (timestamp, challenge_type, resolved)
        self._challenges: dict[str, list[dict]] = defaultdict(list)
        self._lock = threading.Lock()

    def evaluate_risk(self, account: str, signals: list[str],
                       confidence: float) -> dict:
        """Evaluate risk and determine MFA challenge level."""
        # Find highest-risk signal
        max_signal_confidence = 0.0
        triggered_by = []
        for signal in signals:
            for trigger, conf in self.RISK_TRIGGERS.items():
                if trigger in signal:
                    if conf > max_signal_confidence:
                        max_signal_confidence = conf
                    triggered_by.append(trigger)

        effective_confidence = max(confidence, max_signal_confidence)

        if effective_confidence >= 0.90:
            level, action = "CRITICAL", "BLOCK_AND_ALERT"
        elif effective_confidence >= 0.70:
            level, action = "HIGH", "REQUIRE_FIDO2"
        elif effective_confidence >= 0.50:
            level, action = "MEDIUM", "REQUIRE_TOTP"
        elif effective_confidence >= 0.30:
            level, action = "LOW", "PUSH_NOTIFICATION"
        else:
            level, action = "NONE", "ALLOW"

        challenge = {
            "account": account,
            "risk_level": level,
            "action": action,
            "confidence": effective_confidence,
            "triggered_by": triggered_by,
            "mfa_required": effective_confidence >= self.MFA_TRIGGER_THRESHOLD,
            "timestamp": time.time(),
        }

        if level != "NONE":
            with self._lock:
                self._challenges[account].append({**challenge, "resolved": False})

        return challenge

    def resolve_challenge(self, account: str, method: str,
                           success: bool) -> dict:
        """Record MFA challenge resolution."""
        with self._lock:
            pending = [c for c in self._challenges[account] if not c["resolved"]]
            for c in pending:
                c["resolved"] = True
                c["resolution_method"] = method
                c["resolution_success"] = success

        return {
            "account": account,
            "method": method,
            "success": success,
            "challenges_resolved": len(pending),
        }

    def get_pending_challenges(self, account: str) -> list[dict]:
        with self._lock:
            return [c for c in self._challenges[account] if not c["resolved"]]


# ── 5. HardwareTokenBindingVerifier ──────────────────────────────────────────

class HardwareTokenBindingVerifier:
    """
    FIDO2/WebAuthn device binding verification.

    Binds sessions to hardware security keys (YubiKey, TPM, Secure Enclave).
    Even if an attacker steals a session token, they cannot forge:
      - The hardware authenticator's cryptographic signature
      - The TPM-bound device attestation
      - The FIDO2 assertion (requires physical device presence)

    Implements:
      - Credential registration (device → account binding)
      - Assertion verification (challenge-response with hardware key)
      - Authenticator data validation (RP ID, flags, counter)
      - Counter replay detection (authenticator sign counter must increase)
    """

    def __init__(self):
        # credential_id → {account, public_key_hash, sign_counter, aaguid, rp_id}
        self._credentials: dict[str, dict] = {}
        self._lock = threading.Lock()

    def register_credential(self, credential_id: str, account: str,
                              public_key_hash: str, aaguid: str,
                              rp_id: str) -> dict:
        """Register a FIDO2 credential for an account."""
        with self._lock:
            self._credentials[credential_id] = {
                "account": account,
                "public_key_hash": public_key_hash,
                "sign_counter": 0,
                "aaguid": aaguid,
                "rp_id": rp_id,
                "registered_at": time.time(),
            }
        return {
            "fix": "IDENTITY-5",
            "credential_id": credential_id[:16] + "...",
            "account": account,
            "status": "REGISTERED",
        }

    def verify_assertion(self, credential_id: str, account: str,
                          rp_id: str, sign_counter: int,
                          user_present: bool, user_verified: bool,
                          signature_valid: bool) -> dict:
        """
        Verify a FIDO2 assertion.

        Checks:
          1. Credential exists and belongs to account
          2. RP ID matches (prevents cross-origin attacks)
          3. Sign counter increased (prevents replay attacks)
          4. User presence flag set
          5. Signature valid (simulated — in production: verify with public key)
        """
        signals: list[str] = []
        deny_reasons: list[str] = []

        with self._lock:
            cred = self._credentials.get(credential_id)

        if cred is None:
            return {
                "fix": "IDENTITY-5",
                "detected": True,
                "verdict": "UNKNOWN_CREDENTIAL",
                "signals": ["unknown_credential_id"],
                "confidence": 0.90,
            }

        # Check 1: Account match
        if cred["account"] != account:
            deny_reasons.append(f"account_mismatch:{cred['account']}!={account}")
            signals.append("credential_account_mismatch")

        # Check 2: RP ID match
        if cred["rp_id"] != rp_id:
            deny_reasons.append(f"rp_id_mismatch:{cred['rp_id']}!={rp_id}")
            signals.append("rp_id_mismatch")

        # Check 3: Sign counter replay detection
        if sign_counter <= cred["sign_counter"]:
            deny_reasons.append(
                f"counter_replay:got={sign_counter} expected>{cred['sign_counter']}"
            )
            signals.append("authenticator_counter_replay")
        else:
            with self._lock:
                self._credentials[credential_id]["sign_counter"] = sign_counter

        # Check 4: User presence
        if not user_present:
            deny_reasons.append("user_presence_flag_not_set")
            signals.append("no_user_presence")

        # Check 5: Signature validity
        if not signature_valid:
            deny_reasons.append("invalid_signature")
            signals.append("fido2_signature_invalid")

        allowed = len(deny_reasons) == 0
        fired = len(signals)

        return {
            "fix": "IDENTITY-5",
            "credential_id": credential_id[:16] + "...",
            "account": account,
            "allowed": allowed,
            "deny_reasons": deny_reasons,
            "signals": signals,
            "confidence": min(1.0, fired * 0.35),
            "detected": not allowed,
            "verdict": "FIDO2_DENIED" if not allowed else "FIDO2_VERIFIED",
        }

    def get_credential_count(self, account: str) -> int:
        with self._lock:
            return sum(1 for c in self._credentials.values()
                       if c["account"] == account)


# ── Registry ──────────────────────────────────────────────────────────────────

IDENTITY_LAYER_CONTROLS = {
    "IDENTITY-1": ("BehaviouralBiometricProfiler",
                   "Insider threat — keystroke biometrics + peer-group anomaly"),
    "IDENTITY-2": ("ZeroTrustNetworkAccessEngine",
                   "Same-LAN MitM — mTLS + device attestation + micro-segmentation"),
    "IDENTITY-3": ("OAuthTokenAnomalyDetector",
                   "Fresh token theft — refresh chain + device binding + family revocation"),
    "IDENTITY-4": ("MFAChallengeOrchestrator",
                   "Step-up MFA triggers for all high-risk identity events"),
    "IDENTITY-5": ("HardwareTokenBindingVerifier",
                   "FIDO2/WebAuthn hardware key binding + counter replay detection"),
}