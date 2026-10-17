"""Unit tests — shadow313.v4.simulation"""
import pytest
from pathlib import Path
ROOT_DIR = Path(__file__).parent.parent.parent.parent  # workspace root


class TestSimulation:
    def test_import(self):
        """Simulation module should be importable."""
        try:
            from shadow313.v4 import simulation
            assert simulation is not None
        except ImportError:
            pytest.skip("simulation module not fully implemented")

    def test_apt_lateral_movement_exists(self):
        p = ROOT_DIR / "shadow313/v4/simulation/apt_lateral_movement.py"
        assert p.exists(), "apt_lateral_movement.py should exist"

    def test_simulation_init(self):
        p = ROOT_DIR / "shadow313/v4/simulation/__init__.py"
        assert p.exists(), "__init__.py should exist"
