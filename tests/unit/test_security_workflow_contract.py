"""Regression tests for nightly scanner reliability and Docker Buildx configuration."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_nightly_security_scanners_fail_closed_and_preserve_diagnostics():
    workflow = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(
        encoding="utf-8"
    )
    assert "safety==3.8.1" in workflow
    assert workflow.count('"shadow313_sdk/**"') == 2
    assert workflow.count('"shadow313_platform/**"') == 2
    assert "Safety report unavailable or invalid" in workflow
    assert "Enforce dependency and SAST results" in workflow
    assert "SAFETY_OUTCOME" in workflow
    assert "docker build --target production -t shadow313-scan:nightly . || true" not in workflow
    assert "Generate Trivy JSON diagnostic report" in workflow
    assert "trivy-container.json" in workflow
    assert "checkov -f Dockerfile" in workflow
    assert "--framework dockerfile" in workflow
    assert "--scanners vuln,secret" in workflow
    assert 'result.get("Secrets", [])' in workflow
    assert 'report.get("errors")' in workflow
    assert "github.event.pull_request.head.repo.full_name == github.repository" in workflow
    assert "checkov -f docker-compose.yml --framework yaml" in workflow


def test_docker_buildx_uses_supported_no_cache_filters_input():
    workflow = (ROOT / ".github" / "workflows" / "shadow313-ci.yml").read_text(
        encoding="utf-8"
    )
    assert "no-cache-filters:" in workflow
    assert "production-base,production" in workflow
    assert "no-cache-filter:" not in workflow
