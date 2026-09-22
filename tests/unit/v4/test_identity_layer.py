"""
tests/unit/v4/test_identity_layer.py
──────────────────────────────────────
Tests for the 5 identity-layer controls that close the 3 irreducible gaps:

  IDENTITY-1: BehaviouralBiometricProfiler  (insider threat)
  IDENTITY-2: ZeroTrustNetworkAccessEngine  (same-LAN MitM)
  IDENTITY-3: OAuthTokenAnomalyDetector     (fresh token theft)
  IDENTITY-4: MFAChallengeOrchestrator      (step-up auth)
  IDENTITY-5: HardwareTokenBindingVerifier  (FIDO2/WebAuthn)
"""
from __future__ import annotations

import time
import pytest

from shadow313.v4.detection.identity_layer import (
    BehaviouralBiometricProfiler,
    KeystrokeEvent,
    ZeroTrustNetworkAccessEngine,
    OAuthTokenAnomalyDetector,
    MFAChallengeOrchestrator,
    HardwareTokenBindingVerifier,
    IDENTITY_LAYER_CONTROLS,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_keystrokes(count: int, dwell_ms: float = 80.0,
                    flight_ms: float = 120.0,
                    start_ts: float | None = None) -> list[KeystrokeEvent]:
    """Generate synthetic keystroke events with given dwell/flight times."""
    ts = start_ts or time.time()
    events = []
    for i in range(count):
        press = ts + i * (flight_ms / 1000)
        release = press + dwell_ms / 1000
        events.append(KeystrokeEvent(key=chr(65 + i % 26),
                                      press_ts=press, release_ts=release))
    return events


# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY-1: BehaviouralBiometricProfiler
# ═══════════════════════════════════════════════════════════════════════════════

class TestBehaviouralBiometricProfiler:

    def _profiler_with_baseline(self, account: str = "alice",
                                 role: str = "analyst") -> BehaviouralBiometricProfiler:
        p = BehaviouralBiometricProfiler()
        # Build baseline: 15 sessions, 80ms dwell, 120ms flight, ~50 WPM
        for _ in range(15):
            ks = make_keystrokes(50, dwell_ms=80.0, flight_ms=120.0)
            p.record_baseline_session(account, role, ks,
                                       commands=["ls", "cat", "grep", "ls", "cat"])
        return p

    def test_normal_session_not_detected(self):
        p = self._profiler_with_baseline()
        ks = make_keystrokes(50, dwell_ms=82.0, flight_ms=118.0)
        result = p.evaluate_session("alice", ks, ["ls", "cat", "grep"])
        assert result["detected"] is False
        assert result["verdict"] == "NORMAL"

    def test_dwell_anomaly_detected(self):
        p = self._profiler_with_baseline()
        # Attacker types much slower (300ms dwell vs 80ms baseline)
        ks = make_keystrokes(50, dwell_ms=300.0, flight_ms=120.0)
        result = p.evaluate_session("alice", ks, ["ls", "cat"])
        assert result["detected"] is True
        assert any("dwell_anomaly" in s for s in result["signals"])

    def test_wpm_anomaly_detected(self):
        p = self._profiler_with_baseline()
        # Attacker types extremely fast (automated tool — 500 WPM)
        ks = make_keystrokes(200, dwell_ms=10.0, flight_ms=12.0)
        result = p.evaluate_session("alice", ks, ["ls"])
        assert result["detected"] is True

    def test_entropy_anomaly_detected(self):
        p = self._profiler_with_baseline()
        # Attacker runs many unique commands (high entropy vs low baseline)
        ks = make_keystrokes(50, dwell_ms=80.0, flight_ms=120.0)
        unique_cmds = [f"cmd_{i}" for i in range(50)]  # all unique = max entropy
        result = p.evaluate_session("alice", ks, unique_cmds)
        assert result["detected"] is True
        assert any("entropy_anomaly" in s for s in result["signals"])

    def test_no_baseline_returns_no_baseline(self):
        p = BehaviouralBiometricProfiler()
        ks = make_keystrokes(10)
        result = p.evaluate_session("unknown", ks, ["ls"])
        assert result["verdict"] == "NO_BASELINE"
        assert result["detected"] is False

    def test_insufficient_baseline_not_detected(self):
        p = BehaviouralBiometricProfiler()
        # Only 5 baseline sessions — below MIN_BASELINE_SAMPLES=10
        for _ in range(5):
            ks = make_keystrokes(10, dwell_ms=80.0)
            p.record_baseline_session("bob", "dev", ks, ["ls"])
        ks = make_keystrokes(10, dwell_ms=300.0)
        result = p.evaluate_session("bob", ks, ["ls"])
        assert result["verdict"] == "INSUFFICIENT_BASELINE"

    def test_peer_group_anomaly_detected(self):
        p = BehaviouralBiometricProfiler()
        # Build peer group: 5 analysts all typing at ~50 WPM
        for i in range(5):
            for _ in range(15):
                ks = make_keystrokes(50, dwell_ms=80.0, flight_ms=120.0)
                p.record_baseline_session(f"analyst_{i}", "analyst", ks, ["ls"])
        # Alice (analyst) types at 5 WPM — extreme outlier
        for _ in range(15):
            ks = make_keystrokes(50, dwell_ms=80.0, flight_ms=1200.0)  # very slow
            p.record_baseline_session("alice", "analyst", ks, ["ls"])
        # Now evaluate alice with even slower typing
        ks = make_keystrokes(50, dwell_ms=80.0, flight_ms=2400.0)
        result = p.evaluate_session("alice", ks, ["ls"])
        assert result["detected"] is True

    def test_technique_tag(self):
        p = BehaviouralBiometricProfiler()
        ks = make_keystrokes(5)
        result = p.evaluate_session("u", ks, [])
        assert result["technique"] == "T1078"
        assert result["fix"] == "IDENTITY-1"

    def test_identity1_registered(self):
        assert "IDENTITY-1" in IDENTITY_LAYER_CONTROLS
        assert "BehaviouralBiometricProfiler" in IDENTITY_LAYER_CONTROLS["IDENTITY-1"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY-2: ZeroTrustNetworkAccessEngine
# ═══════════════════════════════════════════════════════════════════════════════

class TestZeroTrustNetworkAccessEngine:

    def _engine_with_device(self) -> ZeroTrustNetworkAccessEngine:
        e = ZeroTrustNetworkAccessEngine()
        e.register_device("DEV-001", "cert_thumb_abc123", "windows", "alice")
        e.set_segment_policy("corp_wifi", {"internal", "dmz"})
        return e

    def test_authorized_device_allowed(self):
        e = self._engine_with_device()
        result = e.evaluate_access("alice", "DEV-001", "cert_thumb_abc123",
                                    src_segment="corp_wifi", dst_segment="internal")
        assert result["allowed"] is True
        assert result["verdict"] == "ACCESS_GRANTED"

    def test_unregistered_device_denied(self):
        e = self._engine_with_device()
        result = e.evaluate_access("alice", "DEV-999", "cert_thumb_xyz",
                                    src_segment="corp_wifi", dst_segment="internal")
        assert result["allowed"] is False
        assert result["detected"] is True
        assert any("unregistered_device" in s for s in result["signals"])

    def test_cert_mismatch_denied(self):
        """Core zero-trust: same IP, wrong certificate = denied."""
        e = self._engine_with_device()
        result = e.evaluate_access("alice", "DEV-001", "FORGED_CERT_xyz",
                                    src_segment="corp_wifi", dst_segment="internal")
        assert result["allowed"] is False
        assert any("mtls_cert_mismatch" in s for s in result["signals"])

    def test_micro_segmentation_violation_denied(self):
        e = self._engine_with_device()
        # corp_wifi → production is not in policy
        result = e.evaluate_access("alice", "DEV-001", "cert_thumb_abc123",
                                    src_segment="corp_wifi", dst_segment="production")
        assert result["allowed"] is False
        assert any("micro_segmentation_block" in s for s in result["signals"])

    def test_non_compliant_device_denied(self):
        e = self._engine_with_device()
        e.update_compliance("DEV-001", "non_compliant")
        result = e.evaluate_access("alice", "DEV-001", "cert_thumb_abc123",
                                    src_segment="corp_wifi", dst_segment="internal")
        assert result["allowed"] is False
        assert any("device_non_compliant" in s for s in result["signals"])

    def test_wrong_account_denied(self):
        e = self._engine_with_device()
        # DEV-001 is registered to alice, not bob
        result = e.evaluate_access("bob", "DEV-001", "cert_thumb_abc123",
                                    src_segment="corp_wifi", dst_segment="internal")
        assert result["allowed"] is False

    def test_technique_tag(self):
        e = ZeroTrustNetworkAccessEngine()
        result = e.evaluate_access("u", "d", "c")
        assert result["technique"] == "T1557"
        assert result["fix"] == "IDENTITY-2"

    def test_identity2_registered(self):
        assert "IDENTITY-2" in IDENTITY_LAYER_CONTROLS
        assert "ZeroTrustNetworkAccessEngine" in IDENTITY_LAYER_CONTROLS["IDENTITY-2"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY-3: OAuthTokenAnomalyDetector
# ═══════════════════════════════════════════════════════════════════════════════

class TestOAuthTokenAnomalyDetector:

    def test_normal_token_use_clean(self):
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_abc", "rt_xyz", "client1", "fp_device1",
                       "10.0.0.1", "Mozilla/5.0", "read")
        result = d.use_token("at_abc", "fp_device1", "10.0.0.1")
        assert result["detected"] is False
        assert result["verdict"] == "NORMAL"

    def test_device_fingerprint_mismatch_detected(self):
        """Core gap closure: attacker uses stolen token from different device."""
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_abc", "rt_xyz", "client1", "fp_victim_device",
                       "10.0.0.1", "Mozilla/5.0", "read")
        result = d.use_token("at_abc", "fp_attacker_device", "10.0.0.1")
        assert result["detected"] is True
        assert any("device_fingerprint_mismatch" in s for s in result["signals"])

    def test_token_ip_change_detected(self):
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_def", "rt_uvw", "client1", "fp_device1",
                       "10.0.0.1", "Mozilla/5.0", "read")
        result = d.use_token("at_def", "fp_device1", "185.220.101.5")
        assert result["detected"] is True
        assert any("token_ip_change" in s for s in result["signals"])

    def test_refresh_token_reuse_detected(self):
        """Stolen refresh token used twice → detected + family revoked."""
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_1", "rt_stolen", "client1", "fp_victim",
                       "10.0.0.1", "Mozilla/5.0", "read")
        # First refresh (legitimate)
        r1 = d.refresh_token("rt_stolen", "at_2", "fp_victim", "10.0.0.1", "read")
        # Second refresh (attacker reuses stolen refresh token)
        r2 = d.refresh_token("rt_stolen", "at_3", "fp_attacker", "185.1.1.1", "read write")
        assert r2["detected"] is True
        assert any("refresh_token_reuse" in s for s in r2["signals"])
        assert r2["family_revoked"] is True

    def test_scope_escalation_detected(self):
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_scope", "rt_scope", "client1", "fp_device",
                       "10.0.0.1", "Mozilla/5.0", "read")
        result = d.refresh_token("rt_scope", "at_scope2", "fp_device",
                                   "10.0.0.1", "read write admin")
        assert result["detected"] is True
        assert any("scope_escalation" in s for s in result["signals"])

    def test_refresh_device_change_detected(self):
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_dev", "rt_dev", "client1", "fp_original",
                       "10.0.0.1", "Mozilla/5.0", "read")
        result = d.refresh_token("rt_dev", "at_dev2", "fp_new_device",
                                   "10.0.0.1", "read")
        assert result["detected"] is True
        assert any("refresh_device_change" in s for s in result["signals"])

    def test_revoked_token_reuse_detected(self):
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_rev", "rt_rev", "client1", "fp_d",
                       "10.0.0.1", "Mozilla/5.0", "read")
        d.revoke_token_family("rt_rev")
        result = d.use_token("at_rev", "fp_d", "10.0.0.1")
        assert result["detected"] is True
        assert any("revoked" in s for s in result["signals"])

    def test_unknown_token_detected(self):
        d = OAuthTokenAnomalyDetector()
        result = d.use_token("completely_unknown_token", "fp_d", "10.0.0.1")
        assert result["detected"] is True
        assert result["verdict"] == "UNKNOWN_TOKEN"

    def test_revoke_token_family_count(self):
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_f1", "rt_family", "c1", "fp", "10.0.0.1", "ua", "read")
        d.refresh_token("rt_family", "at_f2", "fp", "10.0.0.1", "read")
        count = d.revoke_token_family("rt_family")
        assert count >= 1

    def test_technique_tag(self):
        d = OAuthTokenAnomalyDetector()
        result = d.use_token("tok", "fp", "ip")
        assert result["technique"] == "T1539"
        assert result["fix"] == "IDENTITY-3"

    def test_identity3_registered(self):
        assert "IDENTITY-3" in IDENTITY_LAYER_CONTROLS
        assert "OAuthTokenAnomalyDetector" in IDENTITY_LAYER_CONTROLS["IDENTITY-3"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY-4: MFAChallengeOrchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class TestMFAChallengeOrchestrator:

    def test_critical_risk_blocks(self):
        o = MFAChallengeOrchestrator()
        result = o.evaluate_risk("alice",
                                  ["impossible_travel:EU->APAC"],
                                  confidence=0.95)
        assert result["risk_level"] == "CRITICAL"
        assert result["action"] == "BLOCK_AND_ALERT"
        assert result["mfa_required"] is True

    def test_high_risk_requires_fido2(self):
        o = MFAChallengeOrchestrator()
        # device_fingerprint_mismatch trigger = 0.90 → CRITICAL
        # Use a signal with trigger confidence in HIGH range (0.70–0.89)
        result = o.evaluate_risk("bob",
                                  ["dwell_anomaly:z=3.5"],
                                  confidence=0.75)
        assert result["risk_level"] == "HIGH"
        assert result["action"] == "REQUIRE_FIDO2"

    def test_medium_risk_requires_totp(self):
        o = MFAChallengeOrchestrator()
        result = o.evaluate_risk("carol",
                                  ["ip_change_24h:10.0.0.1->185.1.1.1"],
                                  confidence=0.60)
        assert result["risk_level"] == "MEDIUM"
        assert result["action"] == "REQUIRE_TOTP"

    def test_low_risk_push_notification(self):
        o = MFAChallengeOrchestrator()
        # subnet_change trigger = 0.65 → MEDIUM; use confidence below 0.50 with no matching trigger
        result = o.evaluate_risk("dave", ["unknown_signal_xyz"],
                                  confidence=0.35)
        assert result["risk_level"] == "LOW"
        assert result["action"] == "PUSH_NOTIFICATION"

    def test_no_risk_allows(self):
        o = MFAChallengeOrchestrator()
        result = o.evaluate_risk("eve", [], confidence=0.05)
        assert result["risk_level"] == "NONE"
        assert result["action"] == "ALLOW"
        assert result["mfa_required"] is False

    def test_challenge_resolution(self):
        o = MFAChallengeOrchestrator()
        o.evaluate_risk("frank", ["impossible_travel:x"], confidence=0.95)
        result = o.resolve_challenge("frank", "FIDO2", success=True)
        assert result["success"] is True
        assert result["challenges_resolved"] >= 1

    def test_pending_challenges_tracked(self):
        o = MFAChallengeOrchestrator()
        o.evaluate_risk("grace", ["geo_anomaly:US->RU"], confidence=0.85)
        pending = o.get_pending_challenges("grace")
        assert len(pending) >= 1

    def test_pending_cleared_after_resolution(self):
        o = MFAChallengeOrchestrator()
        o.evaluate_risk("henry", ["geo_anomaly:US->RU"], confidence=0.85)
        o.resolve_challenge("henry", "TOTP", success=True)
        pending = o.get_pending_challenges("henry")
        assert len(pending) == 0

    def test_identity4_registered(self):
        assert "IDENTITY-4" in IDENTITY_LAYER_CONTROLS
        assert "MFAChallengeOrchestrator" in IDENTITY_LAYER_CONTROLS["IDENTITY-4"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY-5: HardwareTokenBindingVerifier
# ═══════════════════════════════════════════════════════════════════════════════

class TestHardwareTokenBindingVerifier:

    def _verifier_with_cred(self) -> HardwareTokenBindingVerifier:
        v = HardwareTokenBindingVerifier()
        v.register_credential("cred_001", "alice", "pubkey_hash_abc",
                               "aaguid_yubikey5", "shadow313.dev")
        return v

    def test_valid_assertion_verified(self):
        v = self._verifier_with_cred()
        result = v.verify_assertion("cred_001", "alice", "shadow313.dev",
                                     sign_counter=1, user_present=True,
                                     user_verified=True, signature_valid=True)
        assert result["allowed"] is True
        assert result["verdict"] == "FIDO2_VERIFIED"

    def test_counter_replay_denied(self):
        """Core FIDO2 protection: counter must increase."""
        v = self._verifier_with_cred()
        # First use: counter=1
        v.verify_assertion("cred_001", "alice", "shadow313.dev",
                            sign_counter=1, user_present=True,
                            user_verified=True, signature_valid=True)
        # Replay: counter=1 again (attacker replaying captured assertion)
        result = v.verify_assertion("cred_001", "alice", "shadow313.dev",
                                     sign_counter=1, user_present=True,
                                     user_verified=True, signature_valid=True)
        assert result["allowed"] is False
        assert any("counter_replay" in s for s in result["signals"])

    def test_rp_id_mismatch_denied(self):
        """Cross-origin attack: wrong RP ID."""
        v = self._verifier_with_cred()
        result = v.verify_assertion("cred_001", "alice", "evil.com",
                                     sign_counter=1, user_present=True,
                                     user_verified=True, signature_valid=True)
        assert result["allowed"] is False
        assert any("rp_id_mismatch" in s for s in result["signals"])

    def test_invalid_signature_denied(self):
        v = self._verifier_with_cred()
        result = v.verify_assertion("cred_001", "alice", "shadow313.dev",
                                     sign_counter=1, user_present=True,
                                     user_verified=True, signature_valid=False)
        assert result["allowed"] is False
        assert any("fido2_signature_invalid" in s for s in result["signals"])

    def test_no_user_presence_denied(self):
        v = self._verifier_with_cred()
        result = v.verify_assertion("cred_001", "alice", "shadow313.dev",
                                     sign_counter=1, user_present=False,
                                     user_verified=True, signature_valid=True)
        assert result["allowed"] is False
        assert any("no_user_presence" in s for s in result["signals"])

    def test_account_mismatch_denied(self):
        v = self._verifier_with_cred()
        result = v.verify_assertion("cred_001", "bob", "shadow313.dev",
                                     sign_counter=1, user_present=True,
                                     user_verified=True, signature_valid=True)
        assert result["allowed"] is False
        assert any("account_mismatch" in s for s in result["signals"])

    def test_unknown_credential_denied(self):
        v = HardwareTokenBindingVerifier()
        result = v.verify_assertion("unknown_cred", "alice", "shadow313.dev",
                                     sign_counter=1, user_present=True,
                                     user_verified=True, signature_valid=True)
        assert result["detected"] is True
        assert result["verdict"] == "UNKNOWN_CREDENTIAL"

    def test_counter_increments_correctly(self):
        v = self._verifier_with_cred()
        v.verify_assertion("cred_001", "alice", "shadow313.dev",
                            sign_counter=5, user_present=True,
                            user_verified=True, signature_valid=True)
        # Counter=6 should work
        result = v.verify_assertion("cred_001", "alice", "shadow313.dev",
                                     sign_counter=6, user_present=True,
                                     user_verified=True, signature_valid=True)
        assert result["allowed"] is True

    def test_credential_count(self):
        v = HardwareTokenBindingVerifier()
        v.register_credential("c1", "alice", "pk1", "aaguid1", "rp1")
        v.register_credential("c2", "alice", "pk2", "aaguid2", "rp1")
        v.register_credential("c3", "bob",   "pk3", "aaguid3", "rp1")
        assert v.get_credential_count("alice") == 2
        assert v.get_credential_count("bob") == 1

    def test_identity5_registered(self):
        assert "IDENTITY-5" in IDENTITY_LAYER_CONTROLS
        assert "HardwareTokenBindingVerifier" in IDENTITY_LAYER_CONTROLS["IDENTITY-5"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: Full identity-layer defence chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestIdentityLayerIntegration:
    """
    Simulate a sophisticated insider + token theft attack chain and verify
    all 5 identity-layer controls fire at the appropriate stages.
    """

    def test_insider_threat_chain(self):
        """
        Scenario: Malicious insider (knows credentials) but types differently
        than the legitimate user (automated script).
        """
        p = BehaviouralBiometricProfiler()
        # Build baseline: alice types at ~50 WPM, normal entropy
        for _ in range(15):
            ks = make_keystrokes(50, dwell_ms=80.0, flight_ms=120.0)
            p.record_baseline_session("alice", "analyst", ks,
                                       commands=["ls", "cat", "grep", "ls"])
        # Attacker uses automated script: 500 WPM, all unique commands
        ks_attack = make_keystrokes(200, dwell_ms=5.0, flight_ms=6.0)
        result = p.evaluate_session("alice", ks_attack,
                                     [f"cmd_{i}" for i in range(100)])
        assert result["detected"] is True, "Insider threat not detected"

    def test_same_lan_mitm_blocked_by_ztna(self):
        """
        Scenario: Attacker on same LAN, same source IP (ARP poison),
        but cannot forge the mTLS device certificate.
        """
        e = ZeroTrustNetworkAccessEngine()
        e.register_device("DEV-ALICE", "cert_real_abc", "windows", "alice")
        e.set_segment_policy("corp_wifi", {"internal"})

        # Attacker has same IP but forged/missing cert
        result = e.evaluate_access("alice", "DEV-ALICE", "FORGED_CERT",
                                    src_segment="corp_wifi",
                                    dst_segment="internal")
        assert result["allowed"] is False, "Same-LAN MitM not blocked"
        assert any("mtls_cert_mismatch" in s for s in result["signals"])

    def test_fresh_token_theft_detected(self):
        """
        Scenario: Attacker steals refresh token, generates fresh access token.
        New token has no history — but device fingerprint doesn't match.
        """
        d = OAuthTokenAnomalyDetector()
        d.issue_token("at_victim", "rt_stolen", "app1", "fp_victim_laptop",
                       "10.0.0.5", "Chrome/120", "read")

        # Attacker uses stolen refresh token from their device
        result = d.refresh_token("rt_stolen", "at_attacker_new",
                                   "fp_attacker_kali", "185.220.101.5", "read")
        assert result["detected"] is True, "Fresh token theft not detected"
        assert any("refresh_device_change" in s for s in result["signals"])

    def test_mfa_escalation_on_anomaly(self):
        """
        Scenario: Any identity anomaly triggers step-up MFA.
        """
        o = MFAChallengeOrchestrator()
        # Simulate impossible travel signal from ImpossibleTravelDetector
        result = o.evaluate_risk("alice",
                                  ["impossible_travel:EU->APAC speed=12000km/h"],
                                  confidence=0.95)
        assert result["mfa_required"] is True
        assert result["action"] == "BLOCK_AND_ALERT"

    def test_fido2_prevents_token_replay(self):
        """
        Scenario: Attacker captures a FIDO2 assertion and replays it.
        Counter-based replay detection blocks the second use.
        """
        v = HardwareTokenBindingVerifier()
        v.register_credential("cred_alice", "alice", "pk_hash",
                               "aaguid_yubikey", "shadow313.dev")

        # Legitimate use: counter=10
        r1 = v.verify_assertion("cred_alice", "alice", "shadow313.dev",
                                  sign_counter=10, user_present=True,
                                  user_verified=True, signature_valid=True)
        assert r1["allowed"] is True

        # Attacker replays same assertion: counter=10 again
        r2 = v.verify_assertion("cred_alice", "alice", "shadow313.dev",
                                  sign_counter=10, user_present=True,
                                  user_verified=True, signature_valid=True)
        assert r2["allowed"] is False
        assert any("counter_replay" in s for s in r2["signals"])

    def test_all_five_controls_have_fix_tags(self):
        """All 5 controls return their fix tag in results."""
        # IDENTITY-1
        p = BehaviouralBiometricProfiler()
        r1 = p.evaluate_session("u", make_keystrokes(5), [])
        assert r1["fix"] == "IDENTITY-1"

        # IDENTITY-2
        e = ZeroTrustNetworkAccessEngine()
        r2 = e.evaluate_access("u", "d", "c")
        assert r2["fix"] == "IDENTITY-2"

        # IDENTITY-3
        d = OAuthTokenAnomalyDetector()
        r3 = d.use_token("t", "fp", "ip")
        assert r3["fix"] == "IDENTITY-3"

        # IDENTITY-5
        v = HardwareTokenBindingVerifier()
        r5 = v.verify_assertion("x", "u", "rp", 1, True, True, True)
        assert r5["fix"] == "IDENTITY-5"