import json
from pathlib import Path


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
    workflow = WORKFLOW_PATH.read_text()

    assert "working-directory: shadow313-landing" not in workflow

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
        assert f'"{path}"' in workflow
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
        assert f'"{stale_path}"' not in workflow

    for route in ("/docs", "/dashboard", "/dashboard-v3", "/ssp", "/architecture", "/ai-stack"):
        assert route in workflow

    for stale_route in ("/tools", "/marketplace", "/analytics", "/about"):
        assert stale_route not in workflow
