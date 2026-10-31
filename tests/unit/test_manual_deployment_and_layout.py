"""Prevent accidental deployments and regression of the mobile roadmap layout."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_automatic_git_deployments_disabled():
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    assert config["git"]["deploymentEnabled"] is False


def test_api_nested_paths_reach_the_handler():
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    assert {"source": "/api/:path*", "destination": "/api/index.js"} in config["rewrites"]


def test_mobile_roadmap_has_one_column_per_visible_child():
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    assert ".roadmap-phase { grid-template-columns: 40px minmax(0, 1fr); }" in page
    assert ".rp-content { min-width: 0; overflow-wrap: anywhere; }" in page
    assert ".waitlist-form { flex-direction: column; }" in page
    assert "flex: 1; min-width: 0;" in page


def test_footer_uses_readable_color_outside_mobile_media_query():
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    base_styles = page.split("@media", 1)[0]
    assert ".footer-copy { font-size: 12px; color: var(--text-muted); }" in base_styles
