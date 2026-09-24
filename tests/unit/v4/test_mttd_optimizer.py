"""
tests/unit/v4/test_mttd_optimizer.py
Tests for MTTDOptimizer — 6 architectural changes to push MTTD <2 min
"""
from __future__ import annotations
import pytest
from shadow313.v4.detection.mttd_optimizer import (
    StreamingDetectionEngine, EPSSAdaptiveThreshold,
    KernelTelemetryBridge, PredictivePreloader,
    ParallelDetectionPipeline, EarlyWarningSystem,
    MTTDOptimizer, MTTDProjection,
)
from shadow313.v4.simulation.full_technique_simulation import run_full_simulation


@pytest.fixture
def optimizer():
    return MTTDOptimizer()

@pytest.fixture
def sim_report():
    return run_full_simulation(seed=313)


class TestStreamingDetectionEngine:
    def test_mttd_reduction_positive(self):
        s = StreamingDetectionEngine()
        assert s.mttd_reduction_seconds > 0

    def test_streaming_faster_than_batch(self):
        s = StreamingDetectionEngine()
        assert s.INGESTION_DELAY_STREAMING < s.INGESTION_DELAY_CURRENT

    def test_streaming_latency_under_5s(self):
        s = StreamingDetectionEngine()
        assert s.INGESTION_DELAY_STREAMING < 5.0

    def test_reduction_at_least_60s(self):
        s = StreamingDetectionEngine()
        assert s.mttd_reduction_seconds >= 60


class TestEPSSAdaptiveThreshold:
    def test_high_epss_reduces_threshold(self):
        e = EPSSAdaptiveThreshold()
        assert e.get_threshold_multiplier(0.95) < 1.0

    def test_low_epss_no_reduction(self):
        e = EPSSAdaptiveThreshold()
        assert e.get_threshold_multiplier(0.20) == 1.0

    def test_epss_90_gives_25pct_reduction(self):
        e = EPSSAdaptiveThreshold()
        assert e.get_threshold_multiplier(0.95) == 0.75

    def test_adjusted_mttd_lower_for_high_epss(self):
        e = EPSSAdaptiveThreshold()
        base = 200.0
        adjusted = e.adjusted_mttd(base, 0.95)
        assert adjusted < base

    def test_avg_reduction_positive(self):
        e = EPSSAdaptiveThreshold()
        assert e.avg_mttd_reduction_high > 0


class TestKernelTelemetryBridge:
    def test_windows_techniques_covered(self):
        k = KernelTelemetryBridge()
        covered = k.get_techniques_covered("windows")
        assert len(covered) >= 10

    def test_linux_techniques_covered(self):
        k = KernelTelemetryBridge()
        covered = k.get_techniques_covered("linux")
        assert len(covered) >= 5

    def test_both_platforms_more_than_single(self):
        k = KernelTelemetryBridge()
        both = k.get_techniques_covered("both")
        win  = k.get_techniques_covered("windows")
        assert len(both) >= len(win)

    def test_lsass_covered_by_etw(self):
        k = KernelTelemetryBridge()
        covered = k.get_techniques_covered("windows")
        assert "T1003.001" in covered

    def test_mttd_reduction_significant(self):
        k = KernelTelemetryBridge()
        assert k.mttd_reduction_windows >= 60


class TestPredictivePreloader:
    def test_spearphishing_predicts_powershell(self):
        p = PredictivePreloader()
        preds = p.get_predicted_techniques("T1566.001")
        assert "T1059.001" in preds

    def test_lsass_predicts_pth(self):
        p = PredictivePreloader()
        preds = p.get_predicted_techniques("T1003.001")
        assert "T1550.002" in preds

    def test_unknown_technique_empty_prediction(self):
        p = PredictivePreloader()
        assert p.get_predicted_techniques("T9999") == []

    def test_pre_armed_mttd_much_lower(self):
        p = PredictivePreloader()
        base = 200.0
        armed = p.pre_armed_mttd(base)
        assert armed < base * 0.20

    def test_pre_armed_mttd_max_30s(self):
        p = PredictivePreloader()
        assert p.pre_armed_mttd(1000.0) <= 30.0


class TestParallelDetectionPipeline:
    def test_parallel_faster_than_sequential(self):
        p = ParallelDetectionPipeline()
        assert p.PARALLEL_EVAL_TIME < p.SEQUENTIAL_EVAL_TIME

    def test_reduction_at_least_30s(self):
        p = ParallelDetectionPipeline()
        assert p.mttd_reduction_seconds >= 30


class TestEarlyWarningSystem:
    def test_lsass_has_precursor(self):
        e = EarlyWarningSystem()
        assert "T1003.001" in e.PRECURSOR_MAP

    def test_ransomware_has_precursor(self):
        e = EarlyWarningSystem()
        assert "T1486" in e.PRECURSOR_MAP

    def test_effective_mttd_lower_with_precursor(self):
        e = EarlyWarningSystem()
        base = 200.0
        effective = e.get_effective_mttd("T1003.001", base)
        assert effective < base

    def test_unknown_technique_unchanged(self):
        e = EarlyWarningSystem()
        base = 200.0
        assert e.get_effective_mttd("T9999", base) == base


class TestMTTDOptimizer:
    def test_project_single_technique(self, optimizer):
        proj = optimizer.project_mttd(
            "T1003.001", "LSASS Memory Dump", "CRITICAL", 0.97, 52.0
        )
        assert isinstance(proj, MTTDProjection)
        assert proj.projected_mttd < proj.current_mttd
        assert proj.reduction_pct > 0

    def test_critical_meets_2min_target(self, optimizer):
        proj = optimizer.project_mttd(
            "T1003.001", "LSASS Memory Dump", "CRITICAL", 0.97, 52.0
        )
        assert proj.meets_2min_target

    def test_improvements_list_populated(self, optimizer):
        proj = optimizer.project_mttd(
            "T1059.001", "PowerShell", "HIGH", 0.87, 208.0
        )
        assert len(proj.improvements) >= 2

    def test_projected_mttd_floor_5s(self, optimizer):
        proj = optimizer.project_mttd(
            "T1055.001", "DLL Injection", "CRITICAL", 0.95, 20.0
        )
        assert proj.projected_mttd >= 5.0

    def test_to_dict_complete(self, optimizer):
        proj = optimizer.project_mttd(
            "T1490", "VSS Deletion", "CRITICAL", 0.97, 45.0
        )
        d = proj.to_dict()
        assert "technique_id"      in d
        assert "current_mttd_s"    in d
        assert "projected_mttd_s"  in d
        assert "reduction_pct"     in d
        assert "meets_2min_target" in d
        assert "improvements"      in d

    def test_project_all_runs(self, optimizer, sim_report):
        result = optimizer.project_all(sim_report.results)
        assert "current_avg_mttd_s"   in result
        assert "projected_avg_mttd_s" in result
        assert "reduction_pct"        in result
        assert "by_severity"          in result

    def test_overall_reduction_at_least_30pct(self, optimizer, sim_report):
        result = optimizer.project_all(sim_report.results)
        assert result["reduction_pct"] >= 30.0

    def test_critical_all_meet_2min_target(self, optimizer, sim_report):
        result = optimizer.project_all(sim_report.results)
        crit = result["by_severity"].get("CRITICAL", {})
        assert crit.get("meets_target", 0) == crit.get("total", -1)

    def test_high_majority_meet_2min_target(self, optimizer, sim_report):
        result = optimizer.project_all(sim_report.results)
        high = result["by_severity"].get("HIGH", {})
        rate = high.get("meets_target", 0) / high.get("total", 1)
        assert rate >= 0.70

    def test_projected_avg_below_4min(self, optimizer, sim_report):
        result = optimizer.project_all(sim_report.results)
        assert result["projected_avg_mttd_s"] < 240
