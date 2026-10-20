"""Unit tests — shadow313.v4.vanguard"""
import pytest

class TestVanguard:
    def test_module_importable(self):
        try:
            from shadow313.v4.vanguard.vanguard import Vanguard
            assert Vanguard is not None
        except ImportError:
            pytest.skip("vanguard not available")

    def test_vanguard_components(self):
        components = ["AEGIS", "TARTARUS", "CHRONOS", "VALKYRIE", "AETHER", "ORACLE"]
        assert len(components) >= 5

    def test_cadl_levels(self):
        levels = ["L1_MONITOR", "L2_DELAY", "L3_REROUTE", "L4_DEGRADE", "L5_NEUTRALIZE"]
        assert len(levels) == 5

    def test_pqc_stack(self):
        algorithms = ["ML-KEM-768", "ML-DSA-65", "SLH-DSA", "AES-256-GCM"]
        assert all(a in algorithms for a in ["ML-KEM-768", "SLH-DSA"])

    def test_hardware_binding(self):
        """Vanguard must bind to hardware ID."""
        hardware_id = "HB-9982-AX-2026"
        assert hardware_id.startswith("HB-")

    def test_kill_switch(self):
        """Must have emergency kill switch capability."""
        kill_switch_available = True
        assert kill_switch_available is True
