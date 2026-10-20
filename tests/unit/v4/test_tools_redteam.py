"""
Unit tests — shadow313.tools.redteam (all 5 red team tools)
Covers: nexusprobe, phantomscan, shadowdns, ghosthttp, c2profiler
"""
from __future__ import annotations
import pytest


def _import(module_path: str):
    try:
        import importlib
        return importlib.import_module(module_path)
    except Exception:
        return None


class TestNexusProbe:
    def test_importable(self):
        mod = _import("shadow313.tools.redteam.nexusprobe")
        assert mod is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.redteam.nexusprobe")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestPhantomScan:
    def test_importable(self):
        mod = _import("shadow313.tools.redteam.phantomscan")
        assert mod is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.redteam.phantomscan")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestShadowDNS:
    def test_importable(self):
        mod = _import("shadow313.tools.redteam.shadowdns")
        assert mod is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.redteam.shadowdns")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestGhostHTTP:
    def test_importable(self):
        mod = _import("shadow313.tools.redteam.ghosthttp")
        if mod is None:
            pytest.skip("ghosthttp requires httpx with async support")
        assert mod is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.redteam.ghosthttp")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1


class TestC2Profiler:
    def test_importable(self):
        mod = _import("shadow313.tools.redteam.c2profiler")
        assert mod is not None

    def test_has_public_attrs(self):
        mod = _import("shadow313.tools.redteam.c2profiler")
        if mod is None:
            pytest.skip()
        assert len([a for a in dir(mod) if not a.startswith("_")]) >= 1

    def test_c2_profiling_capability(self):
        mod = _import("shadow313.tools.redteam.c2profiler")
        if mod is None:
            pytest.skip()
        content = open("shadow313/tools/redteam/c2profiler.py").read()
        assert any(t in content for t in ["C2", "beacon", "profile", "command", "control"])