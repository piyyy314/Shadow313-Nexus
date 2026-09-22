"""
Tests for shadow313.v4.attack.attack_coverage

Covers ATT&CK coverage map, statistics, and Navigator JSON export.
"""
from __future__ import annotations

import json
import os
import tempfile
import pytest

from shadow313.v4.attack.attack_coverage import (
    COVERAGE_MAP, TechniqueCoverage, get_stats, export_navigator_layer,
)


class TestCoverageMap:

    def test_fifty_techniques_defined(self):
        assert len(COVERAGE_MAP) == 50

    def test_all_have_required_fields(self):
        for t in COVERAGE_MAP:
            assert t.technique_id
            assert t.technique_name
            assert t.tactic
            assert t.coverage in ("DETECTED", "BLOCKED", "MONITORED", "PARTIAL", "GAP")
            assert 0 <= t.score <= 100
            assert t.module

    def test_no_gaps(self):
        gaps = [t for t in COVERAGE_MAP if t.coverage == "GAP"]
        assert len(gaps) == 0, f"Gaps found: {[t.technique_id for t in gaps]}"

    def test_detection_rate_above_75_pct(self):
        stats = get_stats()
        assert stats["detection_pct"] >= 75.0

    def test_overall_coverage_above_90_pct(self):
        stats = get_stats()
        assert stats["coverage_pct"] >= 90.0

    def test_all_eleven_tactics_covered(self):
        tactics = set(t.tactic for t in COVERAGE_MAP)
        expected = {"Reconnaissance", "Initial Access", "Execution", "Persistence",
                    "Privilege Escalation", "Defense Evasion", "Credential Access",
                    "Discovery", "Lateral Movement", "Command and Control"}
        assert expected.issubset(tactics)

    def test_supply_chain_detected(self):
        sc = next((t for t in COVERAGE_MAP if t.technique_id == "T1195"), None)
        assert sc is not None
        assert sc.coverage == "DETECTED"
        assert sc.score >= 80

    def test_process_injection_blocked(self):
        pi = next((t for t in COVERAGE_MAP if t.technique_id == "T1055"), None)
        assert pi is not None
        assert pi.coverage == "BLOCKED"

    def test_technique_ids_unique(self):
        ids = [t.technique_id for t in COVERAGE_MAP]
        assert len(set(ids)) == len(ids)


class TestNavigatorExport:

    def test_export_creates_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "layer.json")
            result = export_navigator_layer(path)
            assert os.path.exists(result)

    def test_export_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = export_navigator_layer(os.path.join(d, "layer.json"))
            with open(path) as f:
                data = json.load(f)
            assert data["domain"] == "enterprise-attack"
            assert len(data["techniques"]) == 50

    def test_export_has_gradient(self):
        with tempfile.TemporaryDirectory() as d:
            path = export_navigator_layer(os.path.join(d, "layer.json"))
            data = json.load(open(path))
            assert "gradient" in data
            assert len(data["gradient"]["colors"]) == 3

    def test_navigator_entry_format(self):
        t = COVERAGE_MAP[0]
        entry = t.to_navigator_entry()
        assert "techniqueID" in entry
        assert "score" in entry
        assert "color" in entry
        assert "comment" in entry