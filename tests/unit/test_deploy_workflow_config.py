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


def test_deploy_workflow_targets_repo_root_static_site():
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text())

    quality_steps = workflow["jobs"]["quality"]["steps"]
    required_step = next(step for step in quality_steps if step.get("name") == "Verify required files exist")
    assert required_step.get("working-directory") is None
    required_paths = set(re.findall(r'"([^"]+)"', required_step["run"]))

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

    for stale_path in (
        "tools/index.html",
        "tools/aegis-nexus.html",
        "tools/sovereign-shield.html",
        "tools/vsat-tactical-suite.html",
        "marketplace/index.html",
        "marketplace/analytics.html",
        "marketplace/analytics-live.html",
        "about/index.html",
    ):
        assert stale_path not in required_paths

    preview_steps = workflow["jobs"]["preview"]["steps"]
    preview_comment_step = next(
        step for step in preview_steps if step.get("name") == "Comment preview URL on PR"
    )
    preview_section = preview_comment_step["with"]["script"]
    for route in ("/docs", "/dashboard", "/dashboard-v3", "/ssp", "/architecture", "/ai-stack"):
        assert f"${{url}}{route}" in preview_section

    for stale_route in ("/tools", "/marketplace", "/analytics", "/about"):
        assert f"${{url}}{stale_route}" not in preview_section

    production_steps = workflow["jobs"]["production"]["steps"]
    smoke_step = next(step for step in production_steps if step.get("name") == "Smoke test production deployment")
    smoke_block = re.search(r'routes=\(\s*(.*?)\s*\)', smoke_step["run"], re.DOTALL)
    assert smoke_block is not None
    smoke_routes = set(re.findall(r'"([^"]+)"', smoke_block.group(1)))
    for route in ("/", "/docs", "/dashboard", "/dashboard-v3", "/ssp", "/architecture", "/ai-stack"):
        assert route in smoke_routes

    for stale_route in ("/tools", "/marketplace", "/analytics", "/about"):
        assert stale_route not in smoke_routes
