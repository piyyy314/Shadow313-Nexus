import json
import re
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy.yml"
VERCEL_CONFIG_PATH = REPO_ROOT / "vercel.json"


def test_vercel_config_has_name_and_valid_destinations():
    config = json.loads(VERCEL_CONFIG_PATH.read_text())

    assert config["version"] == 2
    assert config["name"] == "shadow313-nexus"
    assert isinstance(config["rewrites"], list)
    assert config["rewrites"]

    for rewrite in config["rewrites"]:
        destination = REPO_ROOT / rewrite["destination"].lstrip("/")
        assert destination.exists(), rewrite["destination"]


def test_deploy_workflow_targets_allowlisted_public_site():
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text())

    quality_steps = workflow["jobs"]["quality"]["steps"]
    required_step = next(step for step in quality_steps if step.get("name") == "Verify required files exist")
    assert required_step.get("working-directory") is None
    required_block = re.search(r'required=\(\s*(.*?)\s*\)', required_step["run"], re.DOTALL)
    assert required_block is not None
    required_paths = set(re.findall(r'"([^"]+)"', required_block.group(1)))

    for path in (
        "index.html",
        "vercel.json",
        "docs/index.html",
        "docs/shadow313-nexus-dashboard.html",
        "docs/S313-Nexus-Dashboard-v3.html",
        "docs/S313-SSP-Dashboard.html",
        "docs/shadow313-nexus-architecture.html",
        "docs/shadow313-ai-stack-map.html",
    ):
        assert path in required_paths
        assert (REPO_ROOT / path).is_file()

    build_test = next(
        step for step in quality_steps
        if step.get("name") == "Build and verify allowlisted deployment artifact"
    )
    assert "tests/public-site-build.test.cjs" in build_test["run"]

    preview_steps = workflow["jobs"]["preview"]["steps"]
    preview_build = next(
        step for step in preview_steps if step.get("name") == "Build allowlisted deployment root"
    )
    assert preview_build["run"] == "node scripts/build-public-site.cjs"
    preview_pull = next(step for step in preview_steps if step.get("name") == "Pull Vercel environment")
    assert preview_pull["working-directory"] == "public-site"
    deploy_step = next(step for step in preview_steps if step.get("name") == "Deploy Preview")
    assert deploy_step["working-directory"] == "public-site"
    assert "vercel deploy --yes" in deploy_step["run"]
    assert "grep -Eo" in deploy_step["run"]
    assert r"\.vercel\.(app|dev)" in deploy_step["run"]
    summary_step = next(
        step for step in preview_steps if step.get("name") == "Summarize preview deployment"
    )
    assert "steps.deploy.outputs.preview_url" in summary_step["run"]
    assert "GITHUB_STEP_SUMMARY" in summary_step["run"]

    production_steps = workflow["jobs"]["production"]["steps"]
    production_build = next(
        step for step in production_steps if step.get("name") == "Build allowlisted deployment root"
    )
    assert production_build["run"] == "node scripts/build-public-site.cjs"
    production_pull = next(
        step for step in production_steps if step.get("name") == "Pull Vercel environment"
    )
    assert production_pull["working-directory"] == "public-site"
    production_deploy = next(
        step for step in production_steps if step.get("name") == "Deploy to Production"
    )
    assert production_deploy["working-directory"] == "public-site"
    assert "vercel deploy --prod --yes" in production_deploy["run"]

    smoke_step = next(
        step for step in production_steps if step.get("name") == "Smoke test production deployment"
    )
    smoke_block = re.search(r'routes=\(\s*(.*?)\s*\)', smoke_step["run"], re.DOTALL)
    assert smoke_block is not None
    smoke_routes = set(re.findall(r'"([^"]+)"', smoke_block.group(1)))
    for route in ("/", "/docs", "/dashboard", "/dashboard-v3", "/ssp", "/architecture", "/ai-stack"):
        assert route in smoke_routes

    for stale_route in ("/tools", "/marketplace", "/analytics", "/about"):
        assert stale_route not in smoke_routes
