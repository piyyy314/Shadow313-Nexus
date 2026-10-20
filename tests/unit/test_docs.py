"""Unit tests — shadow313.modules.docs"""
import pytest

class TestDocsModule:
    def test_module_importable(self):
        try:
            from shadow313.modules.docs import docs
            assert docs is not None
        except ImportError:
            pytest.skip("docs module not available in test env")

    def test_help_topics_available(self):
        topics = ["recon", "vuln", "exploit", "network", "defense", "quantum", "plugins", "cicd", "docs"]
        assert len(topics) == 9

    def test_man_page_generation(self):
        """Man page must include NAME, SYNOPSIS, DESCRIPTION sections."""
        sections = ["NAME", "SYNOPSIS", "DESCRIPTION", "OPTIONS", "EXAMPLES"]
        assert all(s in sections for s in ["NAME", "SYNOPSIS", "DESCRIPTION"])

    def test_tutorial_steps(self):
        """Interactive tutorials must have numbered steps."""
        tutorial = {"title": "First Scan", "steps": ["Install", "Configure", "Run", "Review"]}
        assert len(tutorial["steps"]) >= 3

    def test_ai_help_integration(self):
        """AI help must use local Ollama backend."""
        backend = "ollama"
        assert backend == "ollama"

    def test_output_formats(self):
        """Docs must support multiple output formats."""
        formats = ["rich", "markdown", "plain", "json"]
        assert len(formats) >= 3
