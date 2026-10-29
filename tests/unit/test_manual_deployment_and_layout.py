"""Prevent accidental deployments and regression of the mobile roadmap layout."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_automatic_git_deployments_disabled():
    config = json.loads((ROOT / 'vercel.json').read_text())
    assert config['git']['deploymentEnabled'] is False


def test_api_nested_paths_reach_the_handler():
    config = json.loads((ROOT / 'vercel.json').read_text())
    assert {'source': '/api/:path*', 'destination': '/api/index.js'} in config['rewrites']


def test_mobile_roadmap_has_one_column_per_visible_child():
    page = (ROOT / 'index.html').read_text()
    assert '.roadmap-phase { grid-template-columns: 40px minmax(0, 1fr); }' in page
    assert '.rp-content { min-width: 0; overflow-wrap: anywhere; }' in page
    assert '.waitlist-form { flex-direction: column; }' in page
    assert 'flex: 1; min-width: 0;' in page
