"""Regression tests for CI security configuration and local artifact paths."""

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

import shadow313.tools.redteam.ghosthttp as ghosthttp
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
        assert "go install github.com/zricethezav/gitleaks/v8@" in workflow
        assert "github.com/gitleaks/gitleaks/v8" not in workflow


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
    temp_dir = Path(tempfile.gettempdir())
    assert all(path.parent != temp_dir for path in paths)


def test_ghosthttp_returns_anomaly_for_slow_response_without_type_error():
    class DelayedClient:
        def __init__(self):
            self.delays = iter((0.7, 0.1, 0.1, 0.1, 0.1))

        async def get(self, url: str) -> SimpleNamespace:
            await asyncio.sleep(next(self.delays))
            return SimpleNamespace(status_code=200)

    result = asyncio.run(
        ghosthttp.GhostHTTP._timing_analysis(
            None,
            DelayedClient(),
            "https://example.test",
        )
    )

    assert len(result["anomalies"]) == 1
    assert result["anomalies"][0]["ms"] > 500


def test_mypy_checks_changed_files_without_blocking_on_imported_modules():
    workflow = (ROOT / ".github" / "workflows" / "shadow313-ci.yml").read_text(
        encoding="utf-8"
    )
    assert '--follow-imports=silent' in workflow


def test_pr_checks_lint_and_security_gates_fail_closed():
    workflow = (ROOT / ".github" / "workflows" / "pr-checks.yml").read_text(
        encoding="utf-8"
    )
    assert "Identify changed Python and YAML files" in workflow
    assert "Run Ruff on changed Python files" in workflow
    assert "Run Black on changed Python files" in workflow
    assert "Run yamllint on changed YAML files" in workflow
    for line in workflow.splitlines():
        if any(
            command in line
            for command in ("ruff check", "black --check", "yamllint -c")
        ):
            assert "|| true" not in line
    assert "name: SAST (Bandit)" in workflow
    assert "Bandit + Semgrep" not in workflow
    assert "Enforce high-severity Bandit threshold" in workflow
    assert 'finding.get("issue_severity") == "HIGH"' in workflow
    assert "safety==3.8.1" in workflow
    assert "safety check --full-report || true" not in workflow


def test_nightly_security_scanners_do_not_hide_tool_failures():
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "safety==3.8.1" in workflow
    assert "safety check --full-report --json > nightly-safety.json || true" not in workflow
    assert "bandit -r shadow313/ nexus_toolkit/" in workflow
    assert "docker build --target production -t shadow313-scan:nightly . || true" not in workflow


def test_api_and_predeploy_validation_do_not_suppress_setup_or_test_failures():
    api_workflow = (ROOT / ".github" / "workflows" / "shadow313-api-validate.yml").read_text(
        encoding="utf-8"
    )
    predeploy_workflow = (ROOT / ".github" / "workflows" / "shadow313-validate.yml").read_text(
        encoding="utf-8"
    )
    for workflow in (api_workflow, predeploy_workflow):
        for line in workflow.splitlines():
            if "pip install -e \\".[dev]\\"" in line:
                assert not line.rstrip().endswith("|| true")
    assert "--cov=shadow313 --cov-report=term-missing 2>&1 || true" not in predeploy_workflow
    assert "python3 -m pytest tests/" in predeploy_workflow
