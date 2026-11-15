"""Regression tests for CI security configuration and local artifact paths."""

from pathlib import Path

from shadow313.modules.cicd.pipeline import CICDPipeline
from shadow313.v4.detection import adaptive_defense_loop


ROOT = Path(__file__).resolve().parents[2]


def test_gitleaks_workflows_use_the_canonical_go_module():
    workflow_paths = (
        ROOT / ".github" / "workflows" / "pr-checks.yml",
        ROOT / ".github" / "workflows" / "security-scan.yml",
    )
    for path in workflow_paths:
        workflow = path.read_text(encoding="utf-8")
        assert "go install github.com/gitleaks/gitleaks/v8@" in workflow
        assert "github.com/zricethezav/gitleaks/v8" not in workflow


def test_cicd_pipeline_detects_hardcoded_passwords(tmp_path):
    secret_file = tmp_path / "settings.py"
    secret_file.write_text('password = "sample-secret-value-123"\n', encoding="utf-8")

    result = CICDPipeline().scan_secrets([str(secret_file)])

    assert result["passed"] is False
    assert result["secrets_found"] == 1
    assert result["findings"][0]["type"] == "Hardcoded Password"


def test_adl_artifacts_use_a_configurable_state_directory():
    paths = (
        adaptive_defense_loop.ADL_LOG_PATH,
        adaptive_defense_loop.ADL_REPORT_PATH,
        adaptive_defense_loop.EVOLVED_RULES,
    )
    assert all(path.parent == adaptive_defense_loop.STATE_DIR for path in paths)
    assert all("/tmp/" not in str(path).replace("\\", "/") for path in paths)
