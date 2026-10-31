"""Check the manual workflow handoff before it is installed by the maintainer."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def patched_workflow(tmp_path_factory):
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))
    if "workflow_dispatch" in triggers:
        # After the maintainer installs the handoff, validate the active workflow.
        return workflow
    checkout = tmp_path_factory.mktemp("manual-workflow")
    for relative in (".github/workflows/deploy.yml", "tests/unit/test_deploy_workflow_config.py"):
        destination = checkout / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    patch = str(ROOT / "docs/manual-vercel-workflow.patch")
    subprocess.run(["git", "apply", "--check", patch], cwd=checkout, check=True)
    subprocess.run(["git", "apply", patch], cwd=checkout, check=True)
    return yaml.safe_load((checkout / ".github/workflows/deploy.yml").read_text(encoding="utf-8"))


def test_manual_runs_have_separate_non_canceling_concurrency(patched_workflow):
    concurrency = patched_workflow["concurrency"]
    assert "github.event_name" in concurrency["group"]
    assert concurrency["cancel-in-progress"] == "${{ github.event_name != 'workflow_dispatch' }}"


def test_quality_runs_manual_gate_tests(patched_workflow):
    steps = patched_workflow["jobs"]["quality"]["steps"]
    safety = next(
        step
        for step in steps
        if step["name"] == "Test manual deployment controls and static routing"
    )
    assert "tests/unit/test_manual_workflow.py" in safety["run"]


def test_failure_notification_does_not_claim_previous_version_is_live(patched_workflow):
    steps = patched_workflow["jobs"]["notify-failure"]["steps"]
    script = steps[0]["with"]["script"]
    assert "previous deployment remains live" not in script
    assert "may be live" in script
    assert "explicit rollback" in script


def test_patch_keeps_manual_only_deployment_gates(patched_workflow):
    triggers = patched_workflow.get("on", patched_workflow.get(True))
    assert "push" in triggers and "pull_request" in triggers
    for job in ("preview", "production"):
        gate = patched_workflow["jobs"][job]["if"]
        assert "github.event_name == 'workflow_dispatch'" in gate
        assert f"inputs.target == '{job}'" in gate
    assert "github.ref == 'refs/heads/master'" in patched_workflow["jobs"]["production"]["if"]
