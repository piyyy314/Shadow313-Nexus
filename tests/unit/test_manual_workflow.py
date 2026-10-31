"""Regression check installed with the manual workflow patch."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_workflow_deploys_only_on_explicit_manual_request():
    # YAML 1.1 interprets the GitHub Actions `on` key as boolean True.
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))
    assert "push" in triggers and "pull_request" in triggers
    assert triggers["workflow_dispatch"]["inputs"]["target"]["default"] == "preview"
    for job in ("preview", "production"):
        gate = workflow["jobs"][job]["if"]
        assert "github.event_name == 'workflow_dispatch'" in gate
        assert f"inputs.target == '{job}'" in gate
    assert "refs/heads/" in workflow["jobs"]["production"]["if"]


def test_manual_deployments_cannot_be_canceled_by_ci():
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8"))
    concurrency = workflow["concurrency"]
    assert "github.event_name" in concurrency["group"]
    assert concurrency["cancel-in-progress"] == "${{ github.event_name != 'workflow_dispatch' }}"
