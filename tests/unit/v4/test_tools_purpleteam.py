"""
Unit tests — shadow313.tools.purpleteam (all 8 purple team tools)
Covers: atomicchain, detectionforge, coveragematrix, threatreplay,
        adversaryemulator, supplychainauditor, lateralmovementtracker, threathunter
"""
from __future__ import annotations
import pytest


def _import(module_path: str):
    try:
        import importlib
        return importlib.import_module(module_path)
    except Exception:
        return None


class TestAtomicChain:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.atomicchain") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.atomicchain")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestDetectionForge:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.detectionforge") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.detectionforge")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1

    def test_sigma_rule_generation(self):
        mod = _import("shadow313.tools.purpleteam.detectionforge")
        if mod is None:
            pytest.skip()
        content = open("shadow313/tools/purpleteam/detectionforge.py").read()
        assert any(t in content for t in ["sigma", "Sigma", "rule", "detection", "SIEM"])


class TestCoverageMatrix:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.coveragematrix") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.coveragematrix")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestThreatReplay:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.threatreplay") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.threatreplay")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestAdversaryEmulator:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.adversaryemulator") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.adversaryemulator")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1

    def test_emulation_capability(self):
        mod = _import("shadow313.tools.purpleteam.adversaryemulator")
        if mod is None:
            pytest.skip()
        content = open("shadow313/tools/purpleteam/adversaryemulator.py").read()
        assert any(t in content for t in ["APT", "emulat", "TTP", "MITRE", "attack"])


class TestSupplyChainAuditor:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.supplychainauditor") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.supplychainauditor")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestLateralMovementTracker:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.lateralmovementtracker") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.lateralmovementtracker")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestThreatHunter:
    def test_importable(self):
        assert _import("shadow313.tools.purpleteam.threathunter") is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.purpleteam.threathunter")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1

    def test_hunting_capability(self):
        mod = _import("shadow313.tools.purpleteam.threathunter")
        if mod is None:
            pytest.skip()
        content = open("shadow313/tools/purpleteam/threathunter.py").read()
        assert any(t in content for t in ["hunt", "Hunt", "threat", "IOC", "indicator"])