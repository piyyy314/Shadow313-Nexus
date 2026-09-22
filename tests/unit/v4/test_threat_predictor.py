"""
Tests for shadow313.v3.threat_predictor.ThreatPredictor
"""
from __future__ import annotations

import time
import pytest
from shadow313.v3.threat_predictor.predictor import (
    ThreatPredictor,
    HostRiskProfile,
    TechniqueForecast,
    EPSS_DATABASE,
    CISA_KEV,
    TECHNIQUE_BASE_RISK,
)


class TestThreatPredictor:

    def setup_method(self):
        self.predictor = ThreatPredictor()

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def test_ingest_behavioral(self):
        self.predictor.ingest_behavioral("10.0.0.1", 0.85, ["T1190", "T1059.001"])
        events = self.predictor._behavioral.get("10.0.0.1", [])
        assert len(events) == 1
        assert events[0]["anomaly_score"] == 0.85

    def test_ingest_ti_match(self):
        self.predictor.ingest_ti_match("10.0.0.1", 90, "T1190", "185.220.101.47", "MISP")
        matches = self.predictor._ti_matches.get("10.0.0.1", [])
        assert len(matches) == 1
        assert matches[0]["confidence"] == 90

    def test_ingest_cve(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        cves = self.predictor._cve_matches.get("10.0.0.1", [])
        assert "CVE-2021-44228" in cves

    def test_ingest_cve_no_duplicates(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        cves = self.predictor._cve_matches.get("10.0.0.1", [])
        assert cves.count("CVE-2021-44228") == 1

    def test_behavioral_capped_at_100(self):
        for i in range(150):
            self.predictor.ingest_behavioral("10.0.0.1", 0.5, [])
        events = self.predictor._behavioral.get("10.0.0.1", [])
        assert len(events) == 100

    # ── Scoring ───────────────────────────────────────────────────────────────

    def test_epss_score_known_cve(self):
        score = self.predictor._compute_epss_score(["CVE-2021-44228"])
        assert score == pytest.approx(0.975, abs=0.01)

    def test_epss_score_unknown_cve(self):
        score = self.predictor._compute_epss_score(["CVE-9999-99999"])
        assert score == 0.0

    def test_epss_score_empty(self):
        score = self.predictor._compute_epss_score([])
        assert score == 0.0

    def test_kev_multiplier_in_kev(self):
        mult = self.predictor._compute_kev_multiplier(["CVE-2021-44228"])
        assert mult == 1.0

    def test_kev_multiplier_not_in_kev(self):
        mult = self.predictor._compute_kev_multiplier(["CVE-2024-27198"])
        assert mult == 0.0

    def test_kev_multiplier_empty(self):
        mult = self.predictor._compute_kev_multiplier([])
        assert mult == 0.0

    def test_behavioral_score_no_events(self):
        score = self.predictor._compute_behavioral_score("unknown_host")
        assert score == 0.0

    def test_behavioral_score_with_events(self):
        self.predictor.ingest_behavioral("10.0.0.1", 0.9, ["T1190"])
        score = self.predictor._compute_behavioral_score("10.0.0.1")
        assert 0.0 < score <= 1.0

    def test_ti_score_no_matches(self):
        score = self.predictor._compute_ti_score("unknown_host")
        assert score == 0.0

    def test_ti_score_with_matches(self):
        self.predictor.ingest_ti_match("10.0.0.1", 80, "T1190")
        score = self.predictor._compute_ti_score("10.0.0.1")
        assert score == pytest.approx(0.80, abs=0.01)

    def test_threat_score_bounded(self):
        score = self.predictor._compute_threat_score(1.0, 1.0, 1.0, 1.0)
        assert score <= 1.0

    def test_threat_score_zero(self):
        score = self.predictor._compute_threat_score(0.0, 0.0, 0.0, 0.0)
        assert score == 0.0

    def test_risk_level_critical(self):
        assert self.predictor._risk_level(0.85) == "CRITICAL"

    def test_risk_level_high(self):
        assert self.predictor._risk_level(0.65) == "HIGH"

    def test_risk_level_medium(self):
        assert self.predictor._risk_level(0.50) == "MEDIUM"

    def test_risk_level_low(self):
        assert self.predictor._risk_level(0.10) == "LOW"

    # ── Forecast host ─────────────────────────────────────────────────────────

    def test_forecast_host_returns_profile(self):
        profile = self.predictor.forecast_host("10.0.0.1")
        assert isinstance(profile, HostRiskProfile)
        assert profile.host == "10.0.0.1"

    def test_forecast_host_with_kev_cve(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        profile = self.predictor.forecast_host("10.0.0.1")
        assert profile.overall_risk > 0.0
        assert profile.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_forecast_host_kev_recommendation(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        profile = self.predictor.forecast_host("10.0.0.1")
        recs = " ".join(profile.recommendations)
        assert "IMMEDIATE" in recs or "KEV" in recs

    def test_forecast_host_behavioral_recommendation(self):
        for _ in range(5):
            self.predictor.ingest_behavioral("10.0.0.1", 0.95, ["T1190"])
        profile = self.predictor.forecast_host("10.0.0.1")
        assert len(profile.recommendations) >= 1

    def test_forecast_host_top_techniques(self):
        self.predictor.ingest_behavioral("10.0.0.1", 0.8, ["T1190", "T1059.001"])
        self.predictor.ingest_behavioral("10.0.0.1", 0.7, ["T1190"])
        profile = self.predictor.forecast_host("10.0.0.1")
        techniques = [t["technique"] for t in profile.top_techniques]
        assert "T1190" in techniques

    def test_forecast_host_matched_cves(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        self.predictor.ingest_cve("10.0.0.1", "CVE-2024-3400")
        profile = self.predictor.forecast_host("10.0.0.1")
        cve_ids = [c["cve"] for c in profile.matched_cves]
        assert "CVE-2021-44228" in cve_ids

    def test_forecast_host_risk_bounded(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        self.predictor.ingest_behavioral("10.0.0.1", 1.0, ["T1190"])
        self.predictor.ingest_ti_match("10.0.0.1", 100, "T1190")
        profile = self.predictor.forecast_host("10.0.0.1")
        assert 0.0 <= profile.overall_risk <= 1.0

    def test_forecast_host_empty_host(self):
        profile = self.predictor.forecast_host("unknown_host")
        assert profile.overall_risk == 0.0
        assert profile.risk_level == "LOW"

    # ── Forecast technique ────────────────────────────────────────────────────

    def test_forecast_technique_returns_forecast(self):
        forecast = self.predictor.forecast_technique("T1190")
        assert isinstance(forecast, TechniqueForecast)
        assert forecast.technique_id == "T1190"

    def test_forecast_technique_known(self):
        forecast = self.predictor.forecast_technique("T1486")
        assert forecast.base_risk == pytest.approx(0.91, abs=0.01)

    def test_forecast_technique_unknown(self):
        forecast = self.predictor.forecast_technique("T9999")
        assert forecast.base_risk == 0.5  # default

    def test_forecast_technique_probability_bounded(self):
        forecast = self.predictor.forecast_technique("T1190")
        assert 0.0 <= forecast.probability_24h <= 1.0

    def test_forecast_technique_trend_values(self):
        forecast = self.predictor.forecast_technique("T1190")
        assert forecast.trend in ("rising", "stable", "declining")

    def test_forecast_technique_with_behavioral(self):
        self.predictor.ingest_behavioral("10.0.0.1", 0.9, ["T1190"])
        forecast = self.predictor.forecast_technique("T1190")
        assert forecast.behavioral_boost > 0.0

    # ── Remediation queue ─────────────────────────────────────────────────────

    def test_remediation_queue_empty(self):
        queue = self.predictor.get_remediation_queue()
        assert queue == []

    def test_remediation_queue_sorted(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")  # high risk
        self.predictor.ingest_behavioral("10.0.0.2", 0.1, [])    # low risk
        queue = self.predictor.get_remediation_queue()
        assert len(queue) >= 2
        scores = [q["risk_score"] for q in queue]
        assert scores == sorted(scores, reverse=True)

    def test_remediation_queue_fields(self):
        self.predictor.ingest_cve("10.0.0.1", "CVE-2021-44228")
        queue = self.predictor.get_remediation_queue()
        assert len(queue) >= 1
        item = queue[0]
        assert "host" in item
        assert "risk_score" in item
        assert "risk_level" in item
        assert "top_action" in item

    # ── EPSS/KEV data integrity ───────────────────────────────────────────────

    def test_epss_database_not_empty(self):
        assert len(EPSS_DATABASE) > 0

    def test_cisa_kev_not_empty(self):
        assert len(CISA_KEV) > 0

    def test_log4shell_in_kev(self):
        assert "CVE-2021-44228" in CISA_KEV

    def test_vsat_cve_in_database(self):
        assert "CVE-2026-3392" in EPSS_DATABASE

    def test_technique_base_risk_values_bounded(self):
        for technique, risk in TECHNIQUE_BASE_RISK.items():
            assert 0.0 <= risk <= 1.0, f"{technique} risk {risk} out of bounds"