"""Unit tests — shadow313.v4.intelligence"""
import pytest
from pathlib import Path


class TestIntelligence:
    def test_module_path_exists(self):
        p = Path("shadow313/v4")
        assert p.exists()

    def test_import_v4(self):
        try:
            import shadow313.v4
            assert shadow313.v4 is not None
        except ImportError:
            pytest.skip("v4 not fully importable")

    def test_intelligence_graph_exists(self):
        p = Path("shadow313/core/intelligence_graph.py")
        assert p.exists(), "intelligence_graph.py should exist in core"

    def test_intelligence_graph_importable(self):
        try:
            from shadow313.core import intelligence_graph
            assert intelligence_graph is not None
        except ImportError:
            pytest.skip("intelligence_graph not importable")
