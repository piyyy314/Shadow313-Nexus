"""Regression tests for CI package publishing and container Python compatibility."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_publish_jobs_stage_only_python_distributions() -> None:
    workflow = (ROOT / ".github/workflows/shadow313-ci.yml").read_text(encoding="utf-8")

    assert workflow.count("name: Stage only Python distributions") == 2
    assert workflow.count("packages-dir: dist/publish/") == 2
    assert "packages=(dist/*.whl dist/*.tar.gz)" in workflow
    assert 'cp -- "${packages[@]}" dist/publish/' in workflow
    assert "No wheel or source distribution found in dist/" in workflow
    assert "twine check dist/*.whl dist/*.tar.gz" in workflow


def test_docker_base_images_match_supported_python_matrix() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    python_images = [
        line.split()[1]
        for line in dockerfile.splitlines()
        if line.startswith("FROM python:")
    ]

    assert len(python_images) == 2
    assert python_images == [
        "python:3.12-slim-trixie",
        "python:3.12-slim-trixie",
    ]


def test_buildx_uses_supported_no_cache_filters_input() -> None:
    workflow = (ROOT / ".github/workflows/shadow313-ci.yml").read_text(encoding="utf-8")
    assert "no-cache-filters:" in workflow
    assert "no-cache-filter:" not in workflow


def test_nightly_security_scanners_do_not_mask_build_or_safety_failures() -> None:
    workflow = (ROOT / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
    assert "safety==3.8.1" in workflow
    assert "nightly-safety.json || true" not in workflow
    assert "docker build --pull --target production -t shadow313-scan:nightly ." in workflow
    assert "checkov -f Dockerfile --framework dockerfile" in workflow
    assert "Verify Compose hardening assertions" in workflow
    assert "cap_drop_all" in workflow
    assert "no_privileged" in workflow
    assert "internal_network" in workflow
    assert "localhost_binding" in workflow


def test_pr_safety_scanner_does_not_pin_incompatible_cli_dependencies() -> None:
    workflow = (ROOT / ".github/workflows/pr-checks.yml").read_text(encoding="utf-8")
    assert "safety==3.8.1" in workflow
    assert "typer<0.13" not in workflow
    assert "click<8.2" not in workflow
