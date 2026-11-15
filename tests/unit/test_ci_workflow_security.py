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
    assert workflow.count("pip-audit --local") == 1
    assert "pip-audit==2.10.1" in workflow
    assert "--skip-editable" in workflow
    assert "pip-audit-local-report.json" in workflow
    assert "pip-audit-requirements-report.json" in workflow
    assert "pip-audit --desc --format json -o pip-audit-requirements-report.json -r requirements.txt" in workflow
    assert "pip install -r requirements.txt" in workflow
    assert "pip freeze --exclude-editable > requirements-audit-resolved.txt" in workflow
    assert "python -m venv \"$RUNNER_TEMP/safety-env\"" in workflow
    assert "safety-env/bin/safety\" check --full-report --check-unpinned-requirements -r requirements-audit-resolved.txt" in workflow
    assert workflow.index("pip-audit --local") < workflow.index("pip freeze --exclude-editable") < workflow.index("safety-env")


def test_nightly_security_scanners_do_not_hide_tool_failures():
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "safety==3.8.1" in workflow
    assert "pip install -r requirements.txt" in workflow
    assert "pip freeze --exclude-editable > requirements-audit-resolved.txt" in workflow
    assert "safety-env/bin/safety\" check --full-report --json --check-unpinned-requirements -r requirements-audit-resolved.txt > nightly-safety.json" in workflow
    assert "pip-audit --local --skip-editable" in workflow
    assert "pip-audit --desc --format json -o nightly-pip-audit-requirements.json -r requirements.txt" in workflow
    assert "pip-audit==2.10.1" in workflow
    assert "bandit==1.9.4" in workflow
    assert "Enforce dependency and SAST results" in workflow
    assert "BANDIT_OUTCOME" in workflow
    assert workflow.index("pip-audit --local") < workflow.index("pip freeze --exclude-editable") < workflow.index("safety-env")
    assert "requirements-audit-resolved.txt" in workflow
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
            if "pip install -e" in line:
                assert not line.rstrip().endswith("|| true")
    assert "--cov=shadow313 --cov-report=term-missing 2>&1 || true" not in predeploy_workflow
    assert "python3 -m pytest tests/" in predeploy_workflow


def test_changed_workflows_have_clean_end_of_file_formatting():
    for name in (
        "pr-checks.yml",
        "security-scan.yml",
        "shadow313-api-validate.yml",
        "shadow313-validate.yml",
    ):
        content = (ROOT / ".github" / "workflows" / name).read_text(
            encoding="utf-8"
        )
        assert content.endswith("\n")
        assert not content.endswith("\n\n")


def test_primary_ci_security_scanners_are_pinned_to_shared_versions():
    workflow = (ROOT / ".github" / "workflows" / "shadow313-ci.yml").read_text(
        encoding="utf-8"
    )
    dev_requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "bandit==1.9.4" in workflow
    assert "pip-audit==2.10.1" in workflow
    assert "bandit>=1.9.4" in dev_requirements
    assert "pip-audit>=2.10.1" in dev_requirements


def test_nightly_trivy_scan_preserves_findings_and_fails_closed():
    workflow = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
    assert 'severity: "CRITICAL,HIGH"' in workflow
    assert 'exit-code: "1"' in workflow
    assert 'output: "trivy-container.sarif"' in workflow
    assert "Archive Trivy SARIF for diagnosis" in workflow
    assert "path: trivy-container.sarif" in workflow
    assert "if-no-files-found: warn" in workflow


def test_runtime_requirements_exclude_ci_scanners_and_test_tools():
    runtime = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    development = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").lower()
    assert "-r requirements.txt" in development
    for package in ("bandit", "pip-audit", "safety", "pytest", "pytest-asyncio", "pytest-cov"):
        assert not any(line.strip().startswith(package) for line in runtime.splitlines())
    for package in ("bandit", "pip-audit", "pytest", "pytest-asyncio", "pytest-cov"):
        assert any(line.strip().startswith(package) for line in development.splitlines())
    assert not any(line.strip().startswith("safety") for line in development.splitlines())
