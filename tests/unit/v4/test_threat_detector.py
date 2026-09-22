"""
Unit tests for shadow313.v4.detection.threat_detector

Covers:
  - ThreatSignature scoring logic
  - Indicator matching (substring + regex)
  - Required indicator enforcement
  - LSTMHead amplification
  - EvasionDetector bonus
  - DetectionEngine.score_event / detect / detect_all
  - ThreatDetectionSuite.run — all 42 threats detected
  - All 17 previously-missed threats now detected
  - Tactic / LSTM head / evasion breakdowns
  - Score clamping to [0.0, 1.0]
  - DETECT_THRESHOLD boundary
"""
from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from shadow313.v4.detection.threat_detector import (
    Indicator,
    ThreatSignature,
    LSTMHead,
    EvasionDetector,
    DetectionEngine,
    ThreatDetectionSuite,
    SIGNATURES,
    DETECT_THRESHOLD,
    _SIG_MAP,
)
from shadow313.tests.test_comprehensive_threat_suite import EVENTS


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    return DetectionEngine()

@pytest.fixture
def suite():
    return ThreatDetectionSuite()

@pytest.fixture
def run_result(suite):
    return suite.run(EVENTS)


# ═══════════════════════════════════════════════════════════════════════════════
# INDICATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIndicator:

    def test_substring_match(self):
        ind = Indicator("description", "powershell", 0.3)
        assert ind.matches({"description": "PowerShell encoded command"})

    def test_substring_case_insensitive(self):
        ind = Indicator("description", "MIMIKATZ", 0.3)
        assert ind.matches({"description": "mimikatz credential dump"})

    def test_substring_no_match(self):
        ind = Indicator("description", "cobalt strike", 0.3)
        assert not ind.matches({"description": "nmap port scan"})

    def test_missing_field_no_match(self):
        ind = Indicator("command", "powershell", 0.3)
        assert not ind.matches({"description": "powershell"})

    def test_regex_match(self):
        ind = Indicator("command", r"net\s+user", 0.3, regex=True)
        assert ind.matches({"command": "net user /domain"})

    def test_regex_no_match(self):
        ind = Indicator("command", r"^mimikatz$", 0.3, regex=True)
        assert not ind.matches({"command": "run mimikatz now"})

    def test_weight_preserved(self):
        ind = Indicator("description", "test", 0.75)
        assert ind.weight == 0.75


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT SIGNATURE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatSignature:

    def test_score_zero_no_match(self):
        sig = ThreatSignature(
            threat_id="TEST-001", name="Test", tactic="execution", technique="T1059",
            indicators=[Indicator("description", "powershell", 0.5)],
        )
        assert sig.score({"description": "nmap scan"}) == 0.0

    def test_score_single_indicator(self):
        sig = ThreatSignature(
            threat_id="TEST-001", name="Test", tactic="execution", technique="T1059",
            indicators=[Indicator("description", "powershell", 0.5)],
        )
        assert sig.score({"description": "powershell encoded"}) == pytest.approx(0.5)

    def test_score_multiple_indicators_sum(self):
        sig = ThreatSignature(
            threat_id="TEST-001", name="Test", tactic="execution", technique="T1059",
            indicators=[
                Indicator("description", "powershell", 0.3),
                Indicator("command",     "encoded",    0.3),
            ],
        )
        score = sig.score({"description": "powershell", "command": "encoded"})
        assert score == pytest.approx(0.6)

    def test_score_clamped_to_1(self):
        sig = ThreatSignature(
            threat_id="TEST-001", name="Test", tactic="execution", technique="T1059",
            indicators=[
                Indicator("description", "a", 0.5),
                Indicator("description", "b", 0.5),
                Indicator("description", "c", 0.5),
            ],
        )
        score = sig.score({"description": "a b c"})
        assert score == 1.0

    def test_required_indicator_blocks_score(self):
        sig = ThreatSignature(
            threat_id="TEST-001", name="Test", tactic="execution", technique="T1059",
            indicators=[Indicator("description", "powershell", 0.8)],
            required=[Indicator("event_type", "process", 0.0)],
        )
        # Required field missing → score = 0
        assert sig.score({"description": "powershell"}) == 0.0

    def test_required_indicator_allows_score(self):
        sig = ThreatSignature(
            threat_id="TEST-001", name="Test", tactic="execution", technique="T1059",
            indicators=[Indicator("description", "powershell", 0.8)],
            required=[Indicator("event_type", "process", 0.0)],
        )
        score = sig.score({"description": "powershell", "event_type": "process"})
        assert score == pytest.approx(0.8)


# ═══════════════════════════════════════════════════════════════════════════════
# LSTM HEAD TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestLSTMHead:

    def test_amplify_c2_head_beacon(self):
        head = LSTMHead()
        base = 0.5
        event = {"description": "cobalt strike beacon c2"}
        result = head.amplify(base, event, "c2_head")
        assert result > base

    def test_amplify_ransomware_head(self):
        head = LSTMHead()
        base = 0.5
        event = {"description": "ryuk ransomware encrypt vssadmin"}
        result = head.amplify(base, event, "ransomware_head")
        assert result > base

    def test_amplify_clamped_to_1(self):
        head = LSTMHead()
        event = {"description": "beacon c2 cobalt strike malleable reflective jitter"}
        result = head.amplify(0.95, event, "c2_head")
        assert result <= 1.0

    def test_amplify_unknown_head_no_change(self):
        head = LSTMHead()
        base = 0.5
        result = head.amplify(base, {"description": "anything"}, "unknown_head")
        assert result == base

    def test_amplify_exfiltration_head(self):
        head = LSTMHead()
        base = 0.4
        event = {"description": "exfil upload cloud staging compress"}
        result = head.amplify(base, event, "exfiltration_head")
        assert result > base

    def test_amplify_lateral_movement_head(self):
        head = LSTMHead()
        base = 0.4
        event = {"description": "pass-the-hash kerberoast token impersonation"}
        result = head.amplify(base, event, "lateral_movement_head")
        assert result > base


# ═══════════════════════════════════════════════════════════════════════════════
# EVASION DETECTOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestEvasionDetector:

    def test_token_evasion_detected(self):
        det = EvasionDetector()
        event = {"description": "seimpersonateprivilege token impersonation juicy potato"}
        bonus = det.bonus("token", event)
        assert bonus > 0.0

    def test_uac_evasion_detected(self):
        det = EvasionDetector()
        event = {"description": "uac bypass fodhelper eventvwr"}
        bonus = det.bonus("uac", event)
        assert bonus > 0.0

    def test_process_injection_detected(self):
        det = EvasionDetector()
        event = {"api_call": "VirtualAllocEx WriteProcessMemory CreateRemoteThread"}
        bonus = det.bonus("process_injection", event)
        assert bonus > 0.0

    def test_timestomp_detected(self):
        det = EvasionDetector()
        event = {"description": "timestomping setfiletime modify timestamp"}
        bonus = det.bonus("timestomp", event)
        assert bonus > 0.0

    def test_dll_sideload_detected(self):
        det = EvasionDetector()
        event = {"description": "dll side-loading dll hijack search order"}
        bonus = det.bonus("dll_sideload", event)
        assert bonus > 0.0

    def test_kerberos_detected(self):
        det = EvasionDetector()
        event = {"description": "kerberoasting rubeus invoke-kerberoast spn tgs"}
        bonus = det.bonus("kerberos", event)
        assert bonus > 0.0

    def test_pth_detected(self):
        det = EvasionDetector()
        event = {"description": "pass-the-hash wmiexec impacket ntlm hash"}
        bonus = det.bonus("pth", event)
        assert bonus > 0.0

    def test_https_beacon_detected(self):
        det = EvasionDetector()
        event = {"description": "cobalt strike malleable profile sleep jitter reflective dll beacon"}
        bonus = det.bonus("https_beacon", event)
        assert bonus > 0.0

    def test_trusted_process_detected(self):
        det = EvasionDetector()
        event = {"description": "phantomwire trusted process living off the land signed binary"}
        bonus = det.bonus("trusted_process", event)
        assert bonus > 0.0

    def test_cloud_exfil_detected(self):
        det = EvasionDetector()
        event = {"destination": "amazonaws.com dropbox.com onedrive"}
        bonus = det.bonus("cloud", event)
        assert bonus > 0.0

    def test_signed_cert_detected(self):
        det = EvasionDetector()
        event = {"description": "apt41 winnti supply chain trojanized signed binary"}
        bonus = det.bonus("signed_cert", event)
        assert bonus > 0.0

    def test_com_hijack_detected(self):
        det = EvasionDetector()
        event = {"description": "com hijack clsid inprocserver32 fin7 carbanak"}
        bonus = det.bonus("com_hijack", event)
        assert bonus > 0.0

    def test_none_evasion_no_bonus(self):
        det = EvasionDetector()
        event = {"description": "anything at all"}
        bonus = det.bonus("none", event)
        assert bonus == 0.0

    def test_unknown_evasion_no_bonus(self):
        det = EvasionDetector()
        bonus = det.bonus("nonexistent_evasion", {"description": "test"})
        assert bonus == 0.0

    def test_bonus_clamped_to_0_3(self):
        det = EvasionDetector()
        event = {"description": "seimpersonateprivilege token impersonation juicy potato rogue potato printspoofer sweet potato"}
        bonus = det.bonus("token", event)
        assert bonus <= 0.30


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetectionEngine:

    def test_score_event_known_threat(self, engine):
        score = engine.score_event("EX-001", EVENTS["EX-001"])
        assert score >= DETECT_THRESHOLD

    def test_score_event_unknown_threat(self, engine):
        score = engine.score_event("UNKNOWN-999", {"description": "test"})
        assert score == 0.0

    def test_detect_returns_dict(self, engine):
        result = engine.detect("EX-001", EVENTS["EX-001"])
        assert isinstance(result, dict)
        assert "threat_id" in result
        assert "score" in result
        assert "detected" in result

    def test_detect_all_returns_list(self, engine):
        results = engine.detect_all(EVENTS)
        assert isinstance(results, list)
        assert len(results) == 42

    def test_detect_all_sorted_by_threat_id(self, engine):
        results = engine.detect_all(EVENTS)
        ids = [r["threat_id"] for r in results]
        assert ids == sorted(ids)

    def test_score_clamped_to_1(self, engine):
        for threat_id, event in EVENTS.items():
            score = engine.score_event(threat_id, event)
            assert 0.0 <= score <= 1.0, f"{threat_id} score={score} out of range"

    def test_empty_event_scores_low(self, engine):
        score = engine.score_event("C2-001", {})
        assert score < DETECT_THRESHOLD


# ═══════════════════════════════════════════════════════════════════════════════
# FULL SUITE — ALL 42 THREATS
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullSuite:

    def test_detection_rate_100_percent(self, run_result):
        assert run_result["summary"]["detection_rate"] == 1.0

    def test_total_threats_42(self, run_result):
        assert run_result["summary"]["total"] == 42

    def test_zero_missed(self, run_result):
        assert run_result["summary"]["missed"] == 0

    def test_all_42_detected(self, run_result):
        for r in run_result["results"]:
            assert r["detected"], f"{r['threat_id']} not detected (score={r['score']})"

    def test_result_has_required_fields(self, run_result):
        for r in run_result["results"]:
            for field in ("threat_id", "name", "tactic", "technique", "score", "detected", "lstm_head"):
                assert field in r, f"Missing field '{field}' in {r['threat_id']}"

    def test_summary_has_required_fields(self, run_result):
        for field in ("total", "detected", "missed", "detection_rate", "elapsed_ms"):
            assert field in run_result["summary"]

    def test_tactic_stats_present(self, run_result):
        assert len(run_result["tactic_stats"]) > 0

    def test_head_stats_present(self, run_result):
        assert len(run_result["head_stats"]) > 0

    def test_all_tactics_100_percent(self, run_result):
        for tactic, stats in run_result["tactic_stats"].items():
            rate = stats["detected"] / max(1, stats["total"])
            assert rate == 1.0, f"Tactic '{tactic}' not 100%: {stats}"

    def test_all_lstm_heads_100_percent(self, run_result):
        for head, stats in run_result["head_stats"].items():
            rate = stats["detected"] / max(1, stats["total"])
            assert rate == 1.0, f"LSTM head '{head}' not 100%: {stats}"

    def test_no_evasion_stats_when_all_detected(self, run_result):
        # When all threats are detected, no missed evasion stats
        assert run_result["evasion_stats"] == {}


# ═══════════════════════════════════════════════════════════════════════════════
# THE 17 PREVIOUSLY MISSED THREATS — explicit regression tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPreviouslyMissedThreats:
    """
    Regression tests for the 17 threats that scored 0.000 in the original run.
    Each test verifies the threat is now detected with score >= DETECT_THRESHOLD.
    """

    PREVIOUSLY_MISSED = [
        "IA-003",   # Valid accounts — stolen credentials
        "PE-003",   # Create local admin account
        "PV-001",   # Token impersonation via SeImpersonatePrivilege
        "PV-002",   # UAC bypass via fodhelper
        "DE-001",   # Process injection into svchost
        "DE-002",   # Timestomping to evade forensics
        "DE-003",   # DLL side-loading via legitimate app
        "CA-002",   # Kerberoasting — SPN ticket request
        "DI-002",   # Account and group enumeration
        "LM-001",   # Pass-the-Hash via WMI
        "CO-001",   # Data staged for exfiltration
        "C2-001",   # Cobalt Strike beacon over HTTPS
        "C2-003",   # C2 via trusted process (PhantomWire scenario)
        "EF-001",   # Exfiltration over C2 channel
        "EF-002",   # Exfiltration to cloud storage
        "APT41-001",# APT41 supply chain implant
        "FIN7-001", # FIN7 COM object hijacking
    ]

    @pytest.mark.parametrize("threat_id", PREVIOUSLY_MISSED)
    def test_previously_missed_now_detected(self, threat_id):
        engine = DetectionEngine()
        event  = EVENTS[threat_id]
        result = engine.detect(threat_id, event)
        assert result["detected"], (
            f"{threat_id} ({result['name']}) still not detected. "
            f"score={result['score']:.3f} < threshold={DETECT_THRESHOLD}"
        )

    @pytest.mark.parametrize("threat_id", PREVIOUSLY_MISSED)
    def test_previously_missed_score_above_threshold(self, threat_id):
        engine = DetectionEngine()
        score  = engine.score_event(threat_id, EVENTS[threat_id])
        assert score >= DETECT_THRESHOLD, (
            f"{threat_id} score={score:.3f} below threshold={DETECT_THRESHOLD}"
        )

    def test_all_17_previously_missed_now_detected(self, run_result):
        result_map = {r["threat_id"]: r for r in run_result["results"]}
        for tid in self.PREVIOUSLY_MISSED:
            r = result_map.get(tid)
            assert r is not None, f"{tid} not in results"
            assert r["detected"], f"{tid} still not detected (score={r['score']})"


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNATURE LIBRARY INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

class TestSignatureLibrary:

    def test_42_signatures_defined(self):
        assert len(SIGNATURES) == 42

    def test_all_signatures_have_threat_id(self):
        for sig in SIGNATURES:
            assert sig.threat_id, f"Signature missing threat_id: {sig}"

    def test_all_signatures_have_name(self):
        for sig in SIGNATURES:
            assert sig.name, f"Signature {sig.threat_id} missing name"

    def test_all_signatures_have_tactic(self):
        for sig in SIGNATURES:
            assert sig.tactic, f"Signature {sig.threat_id} missing tactic"

    def test_all_signatures_have_technique(self):
        for sig in SIGNATURES:
            assert sig.technique, f"Signature {sig.threat_id} missing technique"

    def test_all_signatures_have_indicators(self):
        for sig in SIGNATURES:
            assert len(sig.indicators) > 0, f"Signature {sig.threat_id} has no indicators"

    def test_all_signatures_have_valid_lstm_head(self):
        valid_heads = {"c2_head", "exfiltration_head", "lateral_movement_head", "ransomware_head"}
        for sig in SIGNATURES:
            assert sig.lstm_head in valid_heads, (
                f"Signature {sig.threat_id} has invalid lstm_head: {sig.lstm_head}"
            )

    def test_no_duplicate_threat_ids(self):
        ids = [sig.threat_id for sig in SIGNATURES]
        assert len(ids) == len(set(ids)), "Duplicate threat IDs found"

    def test_sig_map_matches_signatures(self):
        assert len(_SIG_MAP) == len(SIGNATURES)
        for sig in SIGNATURES:
            assert sig.threat_id in _SIG_MAP

    def test_all_indicator_weights_valid(self):
        for sig in SIGNATURES:
            for ind in sig.indicators:
                assert 0.0 < ind.weight <= 1.0, (
                    f"{sig.threat_id} indicator '{ind.pattern}' weight={ind.weight} invalid"
                )

    def test_detect_threshold_value(self):
        assert DETECT_THRESHOLD == 0.60

    def test_all_events_have_matching_signature(self):
        for threat_id in EVENTS:
            assert threat_id in _SIG_MAP, f"Event {threat_id} has no matching signature"

    def test_all_signatures_have_matching_event(self):
        for sig in SIGNATURES:
            assert sig.threat_id in EVENTS, f"Signature {sig.threat_id} has no matching event"