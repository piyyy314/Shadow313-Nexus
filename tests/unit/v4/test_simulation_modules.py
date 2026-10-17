"""Unit tests — shadow313.v4.simulation (SWIFT cascade, choke point, Arch-E, tripwires, lateral movement)"""
import pytest

class TestSWIFTCascadeSim:
    def test_importable(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        assert SWIFTCascadeSimulator is not None

    def test_simulation_runs(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        sim = SWIFTCascadeSimulator(num_institutions=50)
        result = sim.run_simulation(pivot_archetype="D", hours=22)
        assert result["total_institutions_compromised"] > 0
        assert result["total_loss_usd"] > 0
        assert len(result["timeline"]) > 0

    def test_loss_rate(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        assert SWIFTCascadeSimulator.LOSS_RATE_PER_SECOND == 10_938

    def test_archetype_d_pivot(self):
        from shadow313.v4.simulation.swift_cascade_sim import SWIFTCascadeSimulator
        sim = SWIFTCascadeSimulator()
        result = sim.run_simulation("D")
        assert result["pivot_archetype"] == "D"

class TestChokePointSim:
    def test_importable(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        assert ChokePointSimulator is not None

    def test_all_scenarios(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        sim = ChokePointSimulator()
        results = sim.run_all_scenarios()
        assert len(results) >= 5
        assert all("roi" in r for r in results)

    def test_optimal_recommendation(self):
        from shadow313.v4.simulation.choke_point_sim import ChokePointSimulator
        sim = ChokePointSimulator()
        optimal = sim.recommend_optimal()
        assert "roi" in optimal
        assert optimal["roi"] > 100

class TestArchESim:
    def test_importable(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        assert ArchESimulator is not None

    def test_kill_chain_without_d3fend(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        sim = ArchESimulator()
        result = sim.run_kill_chain(d3fend_active=False)
        assert result["overall_detection_prob"] == 0.0
        assert result["estimated_loss_usd"] > 0

    def test_kill_chain_with_d3fend(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        sim = ArchESimulator()
        result = sim.run_kill_chain(d3fend_active=True)
        assert result["overall_detection_prob"] > 0

    def test_comparison(self):
        from shadow313.v4.simulation.arch_e_sim import ArchESimulator
        sim = ArchESimulator()
        comparison = sim.compare_with_without_d3fend()
        assert "without_d3fend" in comparison
        assert "with_d3fend" in comparison

class TestDetectionTripwireSim:
    def test_importable(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator, TRIPWIRES
        assert DetectionTripwireSimulator is not None
        assert len(TRIPWIRES) == 16

    def test_wave_deployment(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator
        sim = DetectionTripwireSimulator()
        result = sim.deploy_wave(1)
        assert result["tripwires_active"] > 0
        assert result["escape_probability"] < sim.BASELINE_ESCAPE_PROB

    def test_top_tripwires(self):
        from shadow313.v4.simulation.detection_tripwire_sim import DetectionTripwireSimulator
        sim = DetectionTripwireSimulator()
        top = sim.get_top_tripwires(5)
        assert len(top) == 5
        assert top[0]["leverage"] >= top[-1]["leverage"]

class TestLateralMovementSim:
    def test_importable(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator
        assert LateralMovementSimulator is not None

    def test_pivot_simulation(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator
        sim = LateralMovementSimulator()
        result = sim.simulate_pivot("workstation-01", "server-02", "pass_the_hash")
        assert "detected" in result
        assert result["mitre_id"] == "T1550.002"

    def test_campaign_simulation(self):
        from shadow313.v4.simulation.lateral_movement_sim import LateralMovementSimulator
        sim = LateralMovementSimulator()
        targets = ["host-01", "host-02", "host-03", "dc-01"]
        result = sim.simulate_campaign("entry-point", targets)
        assert result["targets_attempted"] == len(targets)
        assert "hosts_compromised" in result
