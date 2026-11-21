"""Regression tests for CI security configuration and local artifact paths."""

import ast
import json
import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

import shadow313.tools.redteam.ghosthttp as ghosthttp
from shadow313.modules.cicd.pipeline import CICDPipeline
from shadow313.v4.detection import adaptive_defense_loop

ROOT = Path(__file__).resolve().parents[2]


def test_gitleaks_workflows_use_supported_official_installers():
    pr_checks = (ROOT / ".github" / "workflows" / "pr-checks.yml").read_text(
        encoding="utf-8"
    )
    security_scan = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )

    assert "gitleaks/gitleaks-action@" in pr_checks
    assert "go install github.com/zricethezav/gitleaks/v8@" in security_scan
    assert "github.com/gitleaks/gitleaks/v8" not in pr_checks + security_scan


def test_ci_workflows_pin_the_same_black_formatter():
    expected = "black==24.3.0"
    pr_checks = (ROOT / ".github" / "workflows" / "pr-checks.yml").read_text(
        encoding="utf-8"
    )
    shadow313_ci = (ROOT / ".github" / "workflows" / "shadow313-ci.yml").read_text(
        encoding="utf-8"
    )

    assert expected in pr_checks
    assert expected in shadow313_ci


def test_api_and_full_validation_workflows_cover_every_branch():
    for name in (
        "shadow313-api-validate.yml",
        "shadow313-validate.yml",
    ):
        workflow = (ROOT / ".github" / "workflows" / name).read_text(
            encoding="utf-8"
        )
        assert "  push:\n    branches: ['**']" in workflow
        assert "  pull_request:\n    branches: ['**']" in workflow


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
    assert "Resolve current PR base SHA" in workflow
    assert "Run Ruff on changed Python files" in workflow
    assert "Run Black on changed Shadow313 files" in workflow
    assert "Run yamllint on changed workflow files" in workflow
    assert "set -o pipefail" in workflow
    assert "$GITHUB_REPOSITORY_OWNER:$GITHUB_REF_NAME" in workflow
    assert 'select(.status != "removed")' in workflow
    for line in workflow.splitlines():
        if any(
            command in line
            for command in ("ruff check", "black --check", "yamllint -c")
        ):
            assert "|| true" not in line
    assert "name: SAST (Bandit)" in workflow
    assert "Bandit + Semgrep" not in workflow
    assert "Run Bandit on changed Python files" in workflow
    assert "Bandit high-severity gate passed" in workflow
    assert 'finding.get("issue_severity") == "HIGH"' in workflow
    assert "safety==3.8.1" in workflow
    assert "safety check --full-report || true" not in workflow

    unit_tests = workflow[workflow.index("  unit-tests:") : workflow.index("  sast:")]
    assert 'pip install -e ".[dev]" alembic "psycopg[binary]>=3.1"' in unit_tests

    sca = workflow[workflow.index("  sca:") : workflow.index("  docker-lint:")]
    assert "pip-audit==2.7.3" in sca
    assert "pip-audit --desc --format json -o pip-audit-report.json" in sca
    assert "pip freeze --exclude-editable > safety-requirements.txt" in sca
    assert "python -m venv .safety-venv" in sca
    assert ".safety-venv/bin/safety check --full-report --file safety-requirements.txt" in sca
    assert (
        sca.index("pip freeze --exclude-editable")
        < sca.index("pip-audit --desc")
        < sca.index("safety check --full-report")
    )


def test_nightly_security_scanners_do_not_hide_tool_failures():
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "safety==3.8.1" in workflow
    assert "pip freeze --exclude-editable > requirements-audit-resolved.txt" in workflow
    assert "safety-env/bin/safety\" check --json --check-unpinned-requirements --save-json nightly-safety.json -r requirements-audit-resolved.txt > /dev/null" in workflow
    assert "Safety report unavailable or invalid" in workflow
    assert "safety_report.get(\"report_meta\")" in workflow
    assert "> nightly-safety.json" not in workflow
    assert "pip-audit --local --skip-editable" in workflow
    assert "pip-audit --desc --format json -o nightly-pip-audit-requirements.json -r requirements.txt" in workflow
    assert "pip-audit==2.10.1" in workflow
    assert "bandit==1.9.4" in workflow
    assert "Enforce dependency and SAST results" in workflow
    assert "BANDIT_OUTCOME" in workflow
    assert 'report.get("errors")' in workflow
    assert "--exit-zero" in workflow
    assert "--severity-level high" not in workflow
    assert "issue_severity" in workflow
    assert "high severity" in workflow
    assert "--full-report --json" not in workflow
    assert workflow.index("pip-audit --local") < workflow.index("pip freeze --exclude-editable") < workflow.index("safety-env")
    assert "requirements-audit-resolved.txt" in workflow
    assert "bandit -r shadow313/ nexus_toolkit/" in workflow
    assert "docker build --target production -t shadow313-scan:nightly . || true" not in workflow


def test_nightly_security_scan_runs_for_security_relevant_pull_requests():
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "  pull_request:" in workflow
    assert "    branches:" in workflow
    assert "      - master" in workflow
    for path in (
        ".github/workflows/security-scan.yml",
        "Dockerfile",
        "docker-compose.yml",
        "pyproject.toml",
        "requirements*.txt",
        "shadow313/**",
        "shadow313_sdk/**",
        "shadow313_platform/**",
        "nexus_toolkit/**",
        "scripts/**",
    ):
        assert f'      - "{path}"' in workflow


def test_trivy_scan_archives_json_diagnostics_when_threshold_fails():
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "Generate Trivy JSON diagnostic report" in workflow
    assert "--scanners vuln" in workflow
    assert "--severity CRITICAL,HIGH" in workflow
    assert "--format json" in workflow
    assert "--output trivy-container.json" in workflow
    assert "--exit-code 0" in workflow
    assert "trivy-container.json" in workflow


def test_runtime_image_removes_build_tools_after_dependency_check():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    ci_workflow = (ROOT / ".github" / "workflows" / "shadow313-ci.yml").read_text(encoding="utf-8")
    assert "no-cache-filters: production-base,production" in ci_workflow
    install_index = dockerfile.index("pip install --no-cache-dir --prefix=/install .")
    patch_index = dockerfile.index(
        "pip install --no-cache-dir --prefix=/install --upgrade"
    )
    copy_index = dockerfile.index("COPY --from=builder /install /usr/local")
    assert install_index < patch_index < copy_index
    builder_patch = dockerfile[patch_index:copy_index]
    assert '"msgpack==1.2.3"' in builder_patch
    assert '"urllib3==2.8.0"' in builder_patch
    assert '"setuptools==84.1.0"' not in dockerfile

    python_base_images = [line.split()[1] for line in dockerfile.splitlines() if line.startswith("FROM python:")]
    assert python_base_images == ["python:3.12-slim-trixie", "python:3.12-slim-trixie"]

    production_start = dockerfile.index("FROM production-base AS production")
    nexus_start = dockerfile.index("FROM production-base AS nexus")
    production_stage = dockerfile[production_start:nexus_start]
    nexus_stage = dockerfile[nexus_start:]
    assert production_stage.index("USER root") < production_stage.index(
        "python -m pip uninstall -y pip setuptools"
    )
    assert production_stage.index("python -m pip uninstall -y pip setuptools") < (
        production_stage.index("USER shadow313")
    )
    for stage in (production_stage, nexus_stage):
        check_index = stage.index("python -m pip check")
        uninstall_index = stage.index("python -m pip uninstall -y pip setuptools")
        assert check_index < uninstall_index

    nexus_install_index = nexus_stage.index("RUN pip install --no-cache-dir")
    nexus_cleanup_index = nexus_stage.index("python -m pip uninstall -y pip setuptools")
    assert nexus_install_index < nexus_cleanup_index
    nexus_dependencies = nexus_stage[nexus_install_index:nexus_cleanup_index]
    for dependency in ('"sqlalchemy>=2.0"', '"psycopg[binary]>=3.1"', '"alembic>=1.13"'):
        assert dependency in nexus_dependencies


def test_compose_audit_uses_the_dockerfile_runner_only_for_dockerfiles():
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "name: Dockerfile and Compose Security Audit" in workflow
    assert "Run Checkov on Dockerfile" in workflow
    assert "checkov -f Dockerfile" in workflow
    assert "--framework dockerfile" in workflow
    assert "checkov -f docker-compose.yml" not in workflow
    assert "Verify Compose hardening assertions" in workflow
    assert "with open('docker-compose.yml') as f:" in workflow


def test_docker_compose_postgres_overlay_is_health_gated():
    overlay = (ROOT / "docker-compose.postgres.yml").read_text(encoding="utf-8")
    assert "shiatoali-postgres:" in overlay
    assert "POSTGRES_PASSWORD_FILE: /run/secrets/shiatoali_postgres_password" in overlay
    assert "condition: service_healthy" in overlay
    assert "service_completed_successfully" in overlay


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
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert 'severity: "CRITICAL,HIGH"' in workflow
    # Trivy emits diagnostics without stopping before the JSON enforcement gate.
    assert 'exit-code: "0"' in workflow
    assert 'version: "v0.76.2"' in workflow
    assert 'output: "trivy-container.sarif"' in workflow
    gate_start = workflow.index("      - name: Enforce actionable Trivy findings")
    archive_start = workflow.index("      - name: Archive Trivy SARIF for diagnosis")
    gate = workflow[gate_start:archive_start]
    assert "Trivy JSON report is missing" in gate
    assert "if not report_path.is_file()" in gate
    assert "if actionable or actionable_secrets:" in gate
    assert "actionable_secrets" in gate
    assert 'result.get("Secrets", [])' in gate
    assert "github.event.pull_request.head.repo.full_name == github.repository" in workflow
    assert "unpatched" in gate
    assert "sys.exit(1)" in gate
    archive_end = workflow.index("\n      - name:", archive_start + 1)
    archive_step = workflow[archive_start:archive_end]
    assert "path: |" in archive_step
    assert "trivy-container.sarif" in archive_step
    assert "trivy-container.json" in archive_step
    assert "if-no-files-found: warn" in archive_step


def test_runtime_requirements_exclude_ci_scanners_and_test_tools():
    runtime = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    development = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").lower()
    assert "-r requirements.txt" in development
    for package in ("bandit", "pip-audit", "safety", "pytest", "pytest-asyncio", "pytest-cov"):
        assert not any(line.strip().startswith(package) for line in runtime.splitlines())
    for package in ("bandit", "pip-audit", "pytest", "pytest-asyncio", "pytest-cov"):
        assert any(line.strip().startswith(package) for line in development.splitlines())
    assert not any(line.strip().startswith("safety") for line in development.splitlines())


def test_md5_fingerprints_are_nonsecurity_and_bandit_b324_is_enabled():
    workflow = (ROOT / ".github" / "workflows" / "shadow313-ci.yml").read_text(
        encoding="utf-8"
    )
    assert "B324" not in workflow

    md5_paths = (
        ROOT / "shadow313" / "modules" / "cicd" / "pipeline.py",
        ROOT / "shadow313" / "tools" / "redteam" / "ghosthttp.py",
        ROOT / "shadow313" / "v4" / "detection" / "advanced_detection_layer.py",
    )
    for path in md5_paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
            and node.func.attr == "md5"
        ]
        assert calls, f"Expected a documented compatibility fingerprint in {path}"
        for call in calls:
            usedforsecurity = next(
                (keyword.value for keyword in call.keywords if keyword.arg == "usedforsecurity"),
                None,
            )
            assert (
                isinstance(usedforsecurity, ast.Constant)
                and usedforsecurity.value is False
            ), f"{path}:{call.lineno} must mark MD5 as non-security use"

    adl_path = ROOT / "shadow313" / "v4" / "detection" / "adaptive_defense_loop.py"
    adl_tree = ast.parse(adl_path.read_text(encoding="utf-8"), filename=str(adl_path))
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "hashlib"
        and node.func.attr == "md5"
        for node in ast.walk(adl_tree)
    )


def test_secret_scanner_fixture_catalog_is_present_and_well_formed():
    fixture_path = ROOT / "scripts" / "secret-fixtures.json"
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert fixtures
    for source_path, fingerprints in fixtures.items():
        assert source_path and not Path(source_path).is_absolute()
        assert fingerprints
        assert all(
            len(fingerprint) == 64
            and all(character in "0123456789abcdef" for character in fingerprint)
            for fingerprint in fingerprints
        )


def test_publish_jobs_stage_only_distributions():
    workflow = (ROOT / ".github" / "workflows" / "shadow313-ci.yml").read_text(
        encoding="utf-8"
    )
    assert "twine check dist/*.whl dist/*.tar.gz" in workflow
    publish_section = workflow[
        workflow.index("# ── Publish to TestPyPI") : workflow.index("# ── Docker Build")
    ]
    assert publish_section.count("name: Stage only Python distributions") == 2
    assert publish_section.count("packages-dir: dist/publish/") == 2
    assert publish_section.count("packages=(dist/*.whl dist/*.tar.gz)") == 2
    assert publish_section.count('cp -- "${packages[@]}" dist/publish/') == 2
    assert publish_section.count("No wheel or source distribution found in dist/.") == 2
    assert "manifest.json" not in publish_section

