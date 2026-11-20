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
