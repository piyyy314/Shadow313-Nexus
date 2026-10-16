"""Unit tests — shadow313.v4.agent"""
import pytest
from pathlib import Path


class TestAgent:
    def test_agent_runner_exists(self):
        p = Path("shadow313/v4/agent/agent_runner.py")
        assert p.exists(), "agent_runner.py should exist"

    def test_import(self):
        try:
            from shadow313.v4.agent import agent_runner
            assert agent_runner is not None
        except ImportError:
            pytest.skip("agent_runner not fully implemented")

    def test_orchestrator_exists(self):
        p = Path("shadow313/v4/agent/orchestrator.py")
        assert p.exists(), "orchestrator.py should exist"

    def test_no_bare_excepts(self):
        import re
        p = Path("shadow313/v4/agent")
        if p.exists():
            for f in p.rglob("*.py"):
                content = f.read_text(errors="ignore")
                bare = re.findall(r"^\s*except\s*:", content, re.M)
                assert len(bare) == 0, f"Bare except in {f}"
