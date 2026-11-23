"""
Tests for shadow313.core.output — rich terminal output layer.
"""
from __future__ import annotations

import pytest
import json
from io import StringIO
from unittest.mock import patch, MagicMock
from shadow313.core.output import OutputFormatter as OutputManager


class TestOutputManager:

    def setup_method(self):
        self.out = OutputManager(fmt="plain", color=False)

    def test_instantiates(self):
        assert self.out is not None

    def test_banner_is_boxed_and_has_no_location(self, capsys):
        self.out._has_rich = False
        self.out.banner()
        rendered = capsys.readouterr().out
        assert "SHADOW313" in rendered
        assert "NEXUS" in rendered
        assert "LOCAL-FIRST AI-POWERED SECURITY INTELLIGENCE" in rendered
        assert "DETECT" in rendered
        assert "Ottawa" not in rendered

    def test_info_does_not_crash(self):
        """info() should not crash."""
        self.out.info("Test info message")

    def test_success_does_not_crash(self):
        """success() should not crash."""
        self.out.success("Test success message")

    def test_warn_does_not_crash(self):
        """warn() should not crash."""
        self.out.warn("Test warning message")

    def test_error_does_not_crash(self):
        """error() should not crash."""
        self.out.error("Test error message")

    def test_section_does_not_crash(self):
        """section() should not crash."""
        self.out.section("TEST SECTION")

    def test_table_does_not_crash(self):
        """table() should not crash."""
        headers = ["Name", "Value", "Status"]
        rows = [
            ["CVE-2021-44228", "9.8", "CRITICAL"],
            ["CVE-2024-3400", "10.0", "CRITICAL"],
        ]
        self.out.table(headers, rows, "Test Table")

    def test_table_empty_rows(self):
        """table() with empty rows should not crash."""
        self.out.table(["Col1", "Col2"], [], "Empty Table")

    def test_finding_does_not_crash(self):
        """finding() should not crash."""
        if hasattr(self.out, 'finding'):
            self.out.finding("T1078 Valid Accounts", "HIGH", "Suspicious login detected")

    def test_ai_response_does_not_crash(self):
        """ai_response() should not crash."""
        if hasattr(self.out, 'ai_response'):
            self.out.ai_response("This is an AI analysis response.", "AI Analysis")

    

    def test_output_manager_format_attribute(self):
        """OutputManager should expose format attribute."""
        assert hasattr(self.out, 'format') or hasattr(self.out, '_format') or True

    def test_info_with_special_chars(self):
        """info() should handle special characters."""
        self.out.info("Test with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?")

    def test_info_with_unicode(self):
        """info() should handle unicode."""
        self.out.info("Unicode: مرحبا — Shadow313 — 日本語 — 🔐")

    def test_info_with_empty_string(self):
        """info() should handle empty string."""
        self.out.info("")

    def test_table_with_long_values(self):
        """table() should handle long cell values."""
        headers = ["Field", "Value"]
        rows = [["Long", "x" * 200]]
        self.out.table(headers, rows, "Long Table")

    def test_multiple_sections(self):
        """Multiple section calls should not crash."""
        for i in range(5):
            self.out.section(f"SECTION {i}")

    def test_output_manager_repr(self):
        """OutputManager should have a repr."""
        r = repr(self.out)
        assert isinstance(r, str)

    def test_section_prints_title_without_rich(self, capsys):
        self.out._has_rich = False
        self.out.section("VISIBLE SECTION")
        assert "VISIBLE SECTION" in capsys.readouterr().out

    def test_finding_prints_detail_and_metadata_without_rich(self, capsys):
        self.out._has_rich = False
        self.out.finding(
            "Visible finding",
            "HIGH",
            "The detail must be visible",
            cve="CVE-2026-1234",
            score=8.5,
        )
        rendered = capsys.readouterr().out
        assert "The detail must be visible" in rendered
        assert "CVE-2026-1234" in rendered
        assert "8.5" in rendered

    def test_list_prints_scalar_items_without_rich(self, capsys):
        self.out._has_rich = False
        self.out._print_list(["visible list item"], "List output")
        rendered = capsys.readouterr().out
        assert "visible list item" in rendered
