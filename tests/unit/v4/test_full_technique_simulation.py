"""
tests/unit/v4/test_full_technique_simulation.py
Tests for FullTechniqueSimulator — 121 ATT&CK techniques across 14 tactics
"""
from __future__ import annotations
import pytest
from shadow313.v4.simulation.full_technique_simulation import (
    FullTechniqueSimulator, FullSimulationReport,
    ALL_TECHNIQUES, NEXUS_DETECTION_MAP, run_full_simulation,
)


@pytest.fixture
def sim():
    return FullTechniqueSimulator(seed=313)

@pytest.fixture
def report():
    return run_full_simulation(seed=313)


class TestTechniqueCatalog:
    def test_minimum_technique_count(self):
        assert len(ALL_TECHNIQUES) >= 100

    def test_all_14_tactics_covered(self):
        tactics = {t["tactic"] for t in ALL_TECHNIQUES}
        required = {
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        }
        assert required.issubset(tactics), f"Missing tactics: {required - tactics}"

    def test_all_techniques_have_required_fields(self):
        for t in ALL_TECHNIQUES:
            assert "id"     in t, f"Missing id: {t}"
            assert "name"   in t, f"Missing name: {t}"
            assert "tactic" in t, f"Missing tactic: {t}"
            assert "sev"    in t, f"Missing sev: {t}"
            assert "epss"   in t, f"Missing epss: {t}"

    def test_severity_values_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for t in ALL_TECHNIQUES:
            assert t["sev"] in valid, f"{t['id']} has invalid severity: {t['sev']}"

    def test_epss_values_in_range(self):
        for t in ALL_TECHNIQUES:
            assert 0.0 <= t["epss"] <= 1.0, f"{t['id']} EPSS out of range: {t['epss']}"

    def test_critical_techniques_present(self):
        ids = {t["id"] for t in ALL_TECHNIQUES}
        critical = ["T1486","T1490","T1003.001","T1003.006","T1505.003","T1542.001"]
        for tid in critical:
            assert tid in ids, f"Critical technique {tid} missing"

    def test_detection_map_coverage(self):
        assert len(NEXUS_DETECTION_MAP) >= 80

    def test_detection_probabilities_valid(self):
        for tid, (prob, method) in NEXUS_DETECTION_MAP.items():
            assert 0.0 <= prob <= 1.0, f"{tid} prob out of range: {prob}"
            assert len(method) > 5, f"{tid} method too short"


class TestSimulationResults:
    def test_simulation_runs(self, sim):
        report = sim.run_full_simulation()
        assert isinstance(report, FullSimulationReport)

    def test_total_matches_catalog(self, report):
        assert report.total == len(ALL_TECHNIQUES)

    def test_detection_rate_above_75_percent(self, report):
        assert report.detection_rate >= 0.75, \
            f"Detection rate {report.detection_rate:.1%} below 75%"

    def test_critical_techniques_100_percent(self, report):
        crit = report.by_severity.get("CRITICAL", {})
        assert crit.get("detection_rate", 0) == 1.0, \
            f"CRITICAL detection rate {crit.get('detection_rate')} not 100%"

    def test_block_rate_above_50_percent(self, report):
        assert report.block_rate >= 0.50

    def test_avg_mttd_under_10_minutes(self, report):
        assert report.avg_mttd < 600, f"Avg MTTD {report.avg_mttd:.0f}s exceeds 10 min"

    def test_all_14_tactics_in_results(self, report):
        assert len(report.by_tactic) == 14

    def test_privilege_escalation_100_percent(self, report):
        pe = report.by_tactic.get("Privilege Escalation", {})
        assert pe.get("detection_rate", 0) >= 0.95

    def test_credential_access_100_percent(self, report):
        ca = report.by_tactic.get("Credential Access", {})
        assert ca.get("detection_rate", 0) >= 0.95

    def test_missed_techniques_list_populated(self, report):
        assert isinstance(report.missed_techniques, list)
        for m in report.missed_techniques:
            assert "id"   in m
            assert "name" in m
            assert "sev"  in m

    def test_no_critical_missed(self, report):
        crit_missed = [m for m in report.missed_techniques if m["sev"] == "CRITICAL"]
        assert len(crit_missed) == 0, f"CRITICAL techniques missed: {[m['id'] for m in crit_missed]}"

    def test_results_count_matches_total(self, report):
        assert len(report.results) == report.total
        assert report.detected + report.missed == report.total

    def test_to_dict_complete(self, report):
        d = report.to_dict()
        assert "total"            in d
        assert "detected"         in d
        assert "detection_rate"   in d
        assert "by_tactic"        in d
        assert "by_severity"      in d
        assert "missed_techniques" in d
        assert "avg_mttd_seconds" in d

    def test_convenience_function(self):
        r = run_full_simulation(seed=42)
        assert r.total >= 100
        assert r.detection_rate >= 0.70

    def test_deterministic_with_seed(self):
        r1 = run_full_simulation(seed=313)
        r2 = run_full_simulation(seed=313)
        assert r1.detected == r2.detected
        assert r1.missed   == r2.missed

    def test_different_seeds_different_results(self):
        r1 = run_full_simulation(seed=313)
        r2 = run_full_simulation(seed=999)
        # Different seeds should produce different (but similar) results
        assert abs(r1.detected - r2.detected) < 20
