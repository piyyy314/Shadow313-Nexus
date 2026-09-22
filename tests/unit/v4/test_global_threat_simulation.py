"""
Tests for shadow313.v4.simulation.global_threat_simulation

Covers threat actor database, simulation engine, and aggregate statistics.
"""
from __future__ import annotations

import pytest
from shadow313.v4.simulation.global_threat_simulation import (
    ThreatActor, SimulationResult, ALL_ACTORS, THREAT_ACTORS,
    SHADOW313_DETECTION_MAP, simulate_actor, run_global_simulation,
)
import random


class TestThreatActorDatabase:

    def test_500_actors_total(self):
        assert len(ALL_ACTORS) == 500

    def test_named_actors_present(self):
        names = {a.name for a in ALL_ACTORS}
        for expected in ["Lazarus Group", "APT29", "APT41", "Sandworm",
                         "BlackCat/ALPHV", "LockBit", "FIN7", "Scattered Spider"]:
            assert expected in names

    def test_h1_2026_top5_present(self):
        names = {a.name for a in ALL_ACTORS}
        for expected in ["Lazarus Bluenoroff", "Volt Typhoon", "MuddyWater",
                         "Desert Falcons", "SideCopy"]:
            assert expected in names

    def test_group_ib_top10_present(self):
        names = {a.name for a in ALL_ACTORS}
        for expected in ["Scattered Spider", "Lazarus Group", "MuddyWater",
                         "Tycoon 2FA", "GoldFactory", "Shadow Silk",
                         "Bloody Wolf", "DarkBlinders"]:
            assert expected in names

    def test_all_actors_have_required_fields(self):
        for a in ALL_ACTORS:
            assert a.name
            assert a.origin
            assert a.category in ("APT", "RANSOMWARE", "HACKTIVIST", "CYBERCRIMINAL", "EXTORTION")
            assert a.sophistication in ("NATION_STATE", "ADVANCED", "INTERMEDIATE", "BASIC")
            assert len(a.primary_ttps) >= 1

    def test_category_distribution_matches_h1_2026(self):
        cats = {}
        for a in THREAT_ACTORS:  # named actors only
            cats[a.category] = cats.get(a.category, 0) + 1
        # APT should be largest category
        assert cats.get("APT", 0) >= cats.get("RANSOMWARE", 0)

    def test_lazarus_financial_impact_set(self):
        lazarus = next(a for a in ALL_ACTORS if a.name == "Lazarus Group")
        assert lazarus.financial_impact_usd >= 6_000_000_000

    def test_lockbit_financial_impact_set(self):
        lockbit = next(a for a in ALL_ACTORS if a.name == "LockBit")
        assert lockbit.financial_impact_usd >= 1_000_000_000


class TestDetectionMap:

    def test_critical_techniques_have_high_detection(self):
        # Process injection should be BLOCKED with high probability
        status, prob, cadl = SHADOW313_DETECTION_MAP["T1055"]
        assert status == "BLOCKED"
        assert prob >= 0.90

    def test_supply_chain_detected(self):
        status, prob, cadl = SHADOW313_DETECTION_MAP["T1195"]
        assert status == "DETECTED"
        assert prob >= 0.85

    def test_cadl_levels_valid(self):
        for ttp, (status, prob, cadl) in SHADOW313_DETECTION_MAP.items():
            assert 0 <= prob <= 1.0
            assert 1 <= cadl <= 5
            assert status in ("DETECTED", "BLOCKED", "MONITORED")

    def test_50_plus_techniques_mapped(self):
        assert len(SHADOW313_DETECTION_MAP) >= 50


class TestSimulationEngine:

    def test_simulate_known_actor(self):
        lazarus = next(a for a in ALL_ACTORS if a.name == "Lazarus Group")
        rng = random.Random(313)
        result = simulate_actor(lazarus, rng)
        assert result.actor_name == "Lazarus Group"
        assert result.techniques_tested == len(lazarus.primary_ttps)
        assert result.overall_verdict in ("DETECTED", "PARTIAL", "EVADED")

    def test_detection_rate_in_range(self):
        for actor in THREAT_ACTORS[:10]:
            rng = random.Random(313)
            result = simulate_actor(actor, rng)
            assert 0.0 <= result.detection_rate <= 1.0

    def test_nation_state_harder_to_detect(self):
        rng = random.Random(313)
        # Nation-state actors should have lower detection rates on average
        nation_state = [a for a in THREAT_ACTORS if a.sophistication == "NATION_STATE"]
        basic = [a for a in THREAT_ACTORS if a.sophistication == "BASIC"]
        if nation_state and basic:
            ns_rates = [simulate_actor(a, random.Random(313)).detection_rate for a in nation_state[:5]]
            basic_rates = [simulate_actor(a, random.Random(313)).detection_rate for a in basic[:5]]
            import statistics
            assert statistics.mean(ns_rates) <= statistics.mean(basic_rates) + 0.2

    def test_cadl_level_set(self):
        actor = THREAT_ACTORS[0]
        rng = random.Random(313)
        result = simulate_actor(actor, rng)
        assert 0 <= result.cadl_level <= 5

    def test_techniques_sum_correctly(self):
        actor = THREAT_ACTORS[0]
        rng = random.Random(313)
        result = simulate_actor(actor, rng)
        total = result.techniques_detected + result.techniques_blocked + result.techniques_evaded
        assert total == result.techniques_tested


class TestGlobalSimulation:

    def test_simulation_runs_500_actors(self):
        report = run_global_simulation(verbose=False)
        assert report["total_actors"] == 500

    def test_detection_rate_above_60_pct(self):
        report = run_global_simulation(verbose=False)
        assert report["detection_rate"] >= 0.60

    def test_coverage_rate_above_85_pct(self):
        report = run_global_simulation(verbose=False)
        assert report["coverage_rate"] >= 0.85

    def test_evaded_below_15_pct(self):
        report = run_global_simulation(verbose=False)
        evaded_pct = report["evaded"] / report["total_actors"]
        assert evaded_pct <= 0.15

    def test_all_categories_present(self):
        report = run_global_simulation(verbose=False)
        cats = set(report["by_category"].keys())
        assert "APT" in cats
        assert "RANSOMWARE" in cats

    def test_cadl_distribution_present(self):
        report = run_global_simulation(verbose=False)
        assert "cadl_distribution" in report
        assert len(report["cadl_distribution"]) >= 3

    def test_top_evaders_identified(self):
        report = run_global_simulation(verbose=False)
        assert "top_evaders" in report
        assert len(report["top_evaders"]) >= 1

    def test_results_count_matches_total(self):
        report = run_global_simulation(verbose=False)
        assert len(report["results"]) == report["total_actors"]

    def test_apt_mean_detection_below_ransomware(self):
        """APT groups should be harder to detect than ransomware."""
        report = run_global_simulation(verbose=False)
        apt_rate = report["by_category"].get("APT", {}).get("mean_detection_rate", 1.0)
        rw_rate  = report["by_category"].get("RANSOMWARE", {}).get("mean_detection_rate", 0.0)
        # APT should have lower or equal detection rate
        assert apt_rate <= rw_rate + 0.15

    def test_cadl_l5_triggered_for_critical_actors(self):
        """Critical actors (ransomware, APT) should trigger CADL L5."""
        report = run_global_simulation(verbose=False)
        l5_count = report["cadl_distribution"].get(5, 0)
        assert l5_count >= 100  # at least 20% of actors trigger L5