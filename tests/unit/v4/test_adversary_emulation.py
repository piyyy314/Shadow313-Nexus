"""
Tests for shadow313.v4.simulation.adversary_emulation
Validates the Purple Team adversary emulation framework with Mann-Whitney U testing.
"""
import re
import pytest
from shadow313.v4.simulation.adversary_emulation import (
    ATOMIC_TESTS,
    PurpleTeamHarness,
    StatisticalAnalyzer,
    ScenarioResult,
    run_adversary_emulation,
)


class TestAtomicTests:
    """Validate the ATOMIC_TESTS scenario definitions."""

    def test_atomic_tests_has_8_scenarios(self):
        assert len(ATOMIC_TESTS) == 8

    def test_all_scenarios_have_required_keys(self):
        required = {
            "scenario_id", "technique", "name", "nexus_claimed_mttd_s",
            "crowdstrike_benchmark_s", "true_positive_rate", "false_positive_rate",
        }
        for s in ATOMIC_TESTS:
            missing = required - set(s.keys())
            assert not missing, f"Scenario {s.get('scenario_id')} missing: {missing}"

    def test_all_technique_ids_valid_attck(self):
        for s in ATOMIC_TESTS:
            assert re.match(r"T\d{4}(\.\d{3})?", s["technique"]), \
                f"Invalid ATT&CK ID: {s['technique']}"

    def test_all_scenario_ids_unique(self):
        ids = [s["scenario_id"] for s in ATOMIC_TESTS]
        assert len(ids) == len(set(ids))

    def test_all_benchmarks_positive(self):
        for s in ATOMIC_TESTS:
            assert s["crowdstrike_benchmark_s"] > 0
            assert s["nexus_claimed_mttd_s"] > 0

    def test_tpr_in_valid_range(self):
        for s in ATOMIC_TESTS:
            assert 0.0 <= s["true_positive_rate"] <= 1.0
            assert 0.0 <= s["false_positive_rate"] <= 1.0


class TestStatisticalAnalyzer:
    """Tests for the StatisticalAnalyzer utility class."""

    def test_mann_whitney_u_returns_expected_keys(self):
        analyzer = StatisticalAnalyzer()
        result = analyzer.mann_whitney_u([1.0, 2.0, 3.0], [4.0, 5.0, 6.0])
        assert "u_statistic" in result
        assert "p_value" in result
        assert "interpretation" in result
        assert "significant" in result

    def test_mann_whitney_u_identical_groups_not_significant(self):
        analyzer = StatisticalAnalyzer()
        group = [5.0] * 10
        result = analyzer.mann_whitney_u(group, group)
        assert result["p_value"] >= 0.05
        assert result["significant"] is False

    def test_mann_whitney_u_clearly_different_is_significant(self):
        analyzer = StatisticalAnalyzer()
        result = analyzer.mann_whitney_u([1.0] * 30, [100.0] * 30)
        assert result["p_value"] < 0.05
        assert result["significant"] is True

    def test_mann_whitney_u_interpretation_is_string(self):
        analyzer = StatisticalAnalyzer()
        result = analyzer.mann_whitney_u([1.0, 2.0], [3.0, 4.0])
        assert isinstance(result["interpretation"], str)
        assert len(result["interpretation"]) > 0

    def test_mann_whitney_u_z_score_present(self):
        analyzer = StatisticalAnalyzer()
        result = analyzer.mann_whitney_u([1.0, 2.0, 3.0], [4.0, 5.0, 6.0])
        assert "z_score" in result
        assert isinstance(result["z_score"], float)

    def test_required_sample_size_positive(self):
        analyzer = StatisticalAnalyzer()
        n = analyzer.required_sample_size()
        assert n > 0
        assert isinstance(n, int)

    def test_analyze_returns_statistical_result(self):
        analyzer = StatisticalAnalyzer()
        mttds = [10.0, 12.0, 11.0, 13.0, 9.0, 10.5, 11.5, 12.5]
        result = analyzer.analyze(mttds, target_s=52.0)
        assert result is not None
        assert hasattr(result, "mean")
        assert result.mean > 0


class TestPurpleTeamHarness:
    """Tests for the main PurpleTeamHarness emulation class."""

    @pytest.fixture
    def harness(self):
        return PurpleTeamHarness(seed=313)

    def test_harness_initializes(self, harness):
        assert harness is not None

    def test_harness_has_n_runs(self, harness):
        assert hasattr(harness, "N_RUNS")
        assert harness.N_RUNS > 0

    def test_run_scenario_returns_scenario_result(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        assert isinstance(result, ScenarioResult)

    def test_run_scenario_has_scenario_id(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        assert result.scenario_id == ATOMIC_TESTS[0]["scenario_id"]

    def test_run_scenario_has_technique(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        assert re.match(r"T\d{4}(\.\d{3})?", result.technique)

    def test_run_scenario_has_nexus_stats(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        assert result.nexus_stats is not None
        assert result.nexus_stats.mean > 0

    def test_run_scenario_has_cs_benchmark(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        assert result.cs_benchmark_s > 0

    def test_run_scenario_has_mann_whitney(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        assert result.mann_whitney is not None
        assert "p_value" in result.mann_whitney

    def test_run_scenario_has_claim_validated(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        assert isinstance(result.claim_validated, bool)

    def test_run_scenario_to_dict(self, harness):
        result = harness.run_scenario(ATOMIC_TESTS[0])
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "scenario_id" in d

    def test_run_all_scenarios_runs_8(self, harness):
        report = harness.run_all_scenarios()
        assert report["scenarios_run"] == 8

    def test_run_all_scenarios_has_results(self, harness):
        report = harness.run_all_scenarios()
        assert len(report["results"]) == 8

    def test_run_all_scenarios_has_overall_nexus(self, harness):
        report = harness.run_all_scenarios()
        assert "overall_nexus" in report
        assert "mean_s" in report["overall_nexus"]

    def test_run_all_scenarios_has_overall_cs(self, harness):
        report = harness.run_all_scenarios()
        assert "overall_crowdstrike" in report

    def test_run_all_scenarios_has_mann_whitney(self, harness):
        report = harness.run_all_scenarios()
        assert "overall_mann_whitney" in report
        assert "p_value" in report["overall_mann_whitney"]

    def test_run_all_scenarios_has_claims_validated(self, harness):
        report = harness.run_all_scenarios()
        assert "claims_validated" in report
        assert isinstance(report["claims_validated"], int)
        assert 0 <= report["claims_validated"] <= 8

    def test_run_all_scenarios_has_nexus_beats_cs(self, harness):
        report = harness.run_all_scenarios()
        assert "nexus_beats_cs" in report
        assert 0 <= report["nexus_beats_cs"] <= 8

    def test_run_all_scenarios_has_min_sample_size(self, harness):
        report = harness.run_all_scenarios()
        assert "min_sample_size" in report
        assert report["min_sample_size"] > 0

    def test_all_nexus_mttd_positive(self, harness):
        report = harness.run_all_scenarios()
        for r in report["results"]:
            assert r["nexus_measured"]["mean_s"] > 0

    def test_all_cs_benchmarks_positive(self, harness):
        report = harness.run_all_scenarios()
        for r in report["results"]:
            assert r["cs_benchmark_s"] > 0

    def test_scenario_ids_unique_in_report(self, harness):
        report = harness.run_all_scenarios()
        ids = [r["scenario_id"] for r in report["results"]]
        assert len(ids) == len(set(ids))


class TestRunAdversaryEmulation:
    """Tests for the top-level convenience function."""

    def test_run_returns_report(self):
        report = run_adversary_emulation(seed=42)
        assert report is not None
        assert report["scenarios_run"] == 8

    def test_run_same_seed_reproducible(self):
        r1 = run_adversary_emulation(seed=313)
        r2 = run_adversary_emulation(seed=313)
        assert r1["overall_nexus"]["mean_s"] == pytest.approx(
            r2["overall_nexus"]["mean_s"], rel=0.01
        )

    def test_run_nexus_beats_cs_is_int(self):
        report = run_adversary_emulation(seed=313)
        assert isinstance(report["nexus_beats_cs"], int)
        assert 0 <= report["nexus_beats_cs"] <= 8

    def test_run_has_8_results(self):
        report = run_adversary_emulation(seed=1)
        assert len(report["results"]) == 8
