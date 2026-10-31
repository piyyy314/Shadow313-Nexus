"""Cross-platform regressions without requiring real Windows or real sleeps."""

import sqlite3
from pathlib import PureWindowsPath
from unittest.mock import Mock

import pytest

from shadow313.v2.threat_intel.threat_intel import ThreatIntelDB
from shadow313.v4.temporal_binding import attack_simulation


def test_windows_relative_public_paths_match_manifest_format():
    root = PureWindowsPath("C:/project/public-site")
    file = root / "sentinelos" / "js" / "workspace.js"
    assert file.relative_to(root).as_posix() == "sentinelos/js/workspace.js"


def test_database_context_closes_handle_before_unlink(tmp_path):
    path = tmp_path / "intel.db"
    with ThreatIntelDB(path) as db:
        assert db.stats()["ioc_ip"] == 0
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        db.stats()
    db.close()  # sqlite close is idempotent
    path.unlink()
    assert not path.exists()


def test_database_context_closes_on_error(tmp_path):
    with pytest.raises(ValueError):
        with ThreatIntelDB(tmp_path / "intel.db") as db:
            raise ValueError("fixture")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        db.stats()


def test_coarse_clock_uses_short_monotonic_budget(monkeypatch):
    ticks = iter([0, 0, 0.005, 0.011])
    monkeypatch.setattr(attack_simulation.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(attack_simulation.time, "time_ns", lambda: 1234500)
    sleep = Mock()
    monkeypatch.setattr(attack_simulation.time, "sleep", sleep)
    assert attack_simulation._wait_for_313(max_wait_ms=2000) == 1234313
    sleep.assert_called_once()
    assert sleep.call_args.args[0] <= 0.0001


def test_matching_clock_returns_without_sleep(monkeypatch):
    monkeypatch.setattr(attack_simulation.time, "monotonic", lambda: 0)
    monkeypatch.setattr(attack_simulation.time, "time_ns", lambda: 1234313)
    sleep = Mock()
    monkeypatch.setattr(attack_simulation.time, "sleep", sleep)
    assert attack_simulation._wait_for_313() == 1234313
    sleep.assert_not_called()
