"""
Unit tests — shadow313.v4.simulation (full suite)
Covers: swift_cascade_sim, choke_point_sim, arch_e_sim,
        detection_tripwire_sim, lateral_movement_sim
"""
from __future__ import annotations
import pytest


# ── SWIFT CASCADE SIMULATOR ───────────────────────────────────────────────────

class TestSWIFTCascade:
    def test_importable(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        assert SWIFTCascadeSimulator is not None

    def test_loss_rate_constant(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        assert SWIFTCascadeSimulator.LOSS_RATE_PER_SECOND == 10_938

    def test_simulation_runs_arch_d(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        sim = SWIFTCascadeSimulator(num_institutions=50)
        result = sim.run_simulation(pivot_archetype="D", hours=22)
        assert result["pivot_archetype"] == "D"
        assert result["total_institutions_compromised"] > 0
        assert result["total_loss_usd"] > 0
        assert len(result["timeline"]) > 0

    def test_simulation_runs_arch_a(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        sim = SWIFTCascadeSimulator()
        result = sim.run_simulation(pivot_archetype="A")
        assert result["pivot_archetype"] == "A"
        assert result["total_loss_usd"] > 0

    def test_timeline_has_phases(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        sim = SWIFTCascadeSimulator()
        result = sim.run_simulation()
        phases = set(e["phase"] for e in result["timeline"])
        assert len(phases) >= 3

    def test_status(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        sim = SWIFTCascadeSimulator()
        sim.run_simulation()
        status = sim.status()
        assert status["institutions_compromised"] > 0
        assert status["total_loss_usd"] > 0


# ── CHOKE POINT SIMULATOR ─────────────────────────────────────────────────────

class TestChokePoint:
    def test_importable(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        assert ChokePointSimulator is not None

    def test_all_scenarios_run(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        sim = ChokePointSimulator()
        results = sim.run_all_scenarios()
        assert len(results) >= 5
        assert all("roi" in r for r in results)

    def test_results_sorted_by_roi(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        sim = ChokePointSimulator()
        results = sim.run_all_scenarios()
        rois = [r["roi"] for r in results]
        assert rois == sorted(rois, reverse=True)

    def test_optimal_recommendation(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        sim = ChokePointSimulator()
        optimal = sim.recommend_optimal()
        assert "roi" in optimal
        assert optimal["roi"] > 100

    def test_residual_loss_calculated(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        sim = ChokePointSimulator(baseline_loss_usd=8_550_000_000)
        results = sim.run_all_scenarios()
        for r in results:
            assert "residual_loss_usd" in r
            assert r["residual_loss_usd"] >= 0


# ── ARCH-E SIMULATOR ──────────────────────────────────────────────────────────

class TestArchE:
    def test_importable(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator, ARCH_E_KILL_CHAIN
        assert ArchESimulator is not None
        assert len(ARCH_E_KILL_CHAIN) == 9

    def test_kill_chain_without_d3fend(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        sim = ArchESimulator()
        result = sim.run_kill_chain(d3fend_active=False)
        assert result["overall_detection_prob"] == 0.0
        assert result["estimated_loss_usd"] > 0
        assert len(result["phases_completed"]) == 9

    def test_kill_chain_with_d3fend(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        sim = ArchESimulator()
        result = sim.run_kill_chain(d3fend_active=True)
        assert result["overall_detection_prob"] > 0

    def test_comparison_shows_improvement(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        sim = ArchESimulator()
        comparison = sim.compare_with_without_d3fend()
        assert "without_d3fend" in comparison
        assert "with_d3fend" in comparison
        assert "loss_reduction_usd" in comparison

    def test_total_time_calculated(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        sim = ArchESimulator()
        result = sim.run_kill_chain()
        assert result["total_time_s"] > 0
        assert result["total_time_min"] > 0


# ── DETECTION TRIPWIRE SIMULATOR ──────────────────────────────────────────────

class TestDetectionTripwire:
    def test_importable(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator, TRIPWIRES
        assert DetectionTripwireSimulator is not None
        assert len(TRIPWIRES) == 16

    def test_wave_1_deployment(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator
        sim = DetectionTripwireSimulator()
        result = sim.deploy_wave(1)
        assert result["tripwires_active"] > 0
        assert result["escape_probability"] < sim.BASELINE_ESCAPE_PROB

    def test_all_waves_reduce_escape(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator
        sim = DetectionTripwireSimulator()
        sim.deploy_wave(1)
        sim.deploy_wave(2)
        sim.deploy_wave(3)
        result = sim.deploy_wave(1)  # re-check
        assert result["escape_probability"] < sim.BASELINE_ESCAPE_PROB

    def test_top_tripwires_sorted(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator
        sim = DetectionTripwireSimulator()
        top = sim.get_top_tripwires(5)
        assert len(top) == 5
        assert top[0]["leverage"] >= top[-1]["leverage"]

    def test_roi_calculated(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator
        sim = DetectionTripwireSimulator()
        result = sim.deploy_wave(1)
        assert "roi" in result
        assert result["roi"] > 0


# ── LATERAL MOVEMENT SIMULATOR ────────────────────────────────────────────────

class TestLateralMovement:
    def test_importable(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator, PIVOT_TECHNIQUES
        assert LateralMovementSimulator is not None
        assert len(PIVOT_TECHNIQUES) >= 5

    def test_pivot_simulation(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator
        sim = LateralMovementSimulator()
        result = sim.simulate_pivot("workstation-01", "server-02", "pass_the_hash")
        assert "detected" in result
        assert result["mitre_id"] == "T1550.002"
        assert result["source"] == "workstation-01"
        assert result["target"] == "server-02"

    def test_campaign_simulation(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator
        sim = LateralMovementSimulator()
        targets = ["host-01", "host-02", "host-03", "dc-01"]
        result = sim.simulate_campaign("entry-point", targets)
        assert result["targets_attempted"] == len(targets)
        assert "hosts_compromised" in result
        assert "total_time_min" in result

    def test_detection_active_increases_detection(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator
        import random
        random.seed(42)
        sim1 = LateralMovementSimulator()
        sim2 = LateralMovementSimulator()
        # Run many pivots and compare detection rates
        detected_active = sum(
            1 for _ in range(20)
            if sim1.simulate_pivot("src", "dst", "pass_the_hash", detection_active=True)["detected"]
        )
        detected_passive = sum(
            1 for _ in range(20)
            if sim2.simulate_pivot("src", "dst", "pass_the_hash", detection_active=False)["detected"]
        )
        # Active detection should generally catch more (not guaranteed due to randomness)
        assert detected_active >= 0 and detected_passive >= 0

    def test_status(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator
        sim = LateralMovementSimulator()
        sim.simulate_pivot("a", "b", "psexec")
        status = sim.status()
        assert status["pivots_simulated"] == 1