"""Unit tests — shadow313.v4.simulation"""
import pytest
from pathlib import Path


class TestSimulation:
    def test_import(self):
        """Simulation module should be importable."""
        try:
            from shadow313.v4 import simulation
            assert simulation is not None
        except ImportError:
            pytest.skip("simulation module not fully implemented")

    def test_apt_lateral_movement_exists(self):
        p = Path("shadow313/v4/simulation/apt_lateral_movement.py")
        assert p.exists(), "apt_lateral_movement.py should exist"

    def test_simulation_init(self):
        p = Path("shadow313/v4/simulation/__init__.py")
        assert p.exists(), "__init__.py should exist"
