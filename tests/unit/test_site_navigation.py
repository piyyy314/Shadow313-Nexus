"""Public navigation stays on either custom domain and resolves without JS."""
import json
import re
import subprocess
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[2]
FOLDERS = ('docs', 'platform', 'pricing', 'tools', 'about', 'blog', 'marketplace')


def pages():
    return [p for folder in FOLDERS for p in (ROOT / folder).glob('*.html')]


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links = []
        self.primary = 0
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'nav' and attrs.get('id') == 'site-nav':
            self.primary += 1
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])


class SiteNavigationTests(unittest.TestCase):
    def test_contributor_guide_uses_current_reproducible_setup(self):
        guide = (ROOT / 'CONTRIBUTING.md').read_text()
        self.assertIn('python -m pip install -e ".[dev]"', guide)
        self.assertIn('python -m pytest tests/ -q --tb=short', guide)
        self.assertNotRegex(
            guide,
            r"\b\d[\d,]*(?:\s*/\s*\d[\d,]*)?\s*\+?\s*"
            r"tests?\s+(?:GREEN|passing|passed|included|all passing)\b",
        )

    def test_html_pages_do_not_publish_fixed_test_scores(self):
        fixed_score = re.compile(
            r"\b\d[\d,]*(?:\s*/\s*\d[\d,]*)?\s*\+?\s*tests?\s+"
            r"(?:GREEN|passing|passed|included|all passing)\b",
            re.IGNORECASE,
        )
        for path in ROOT.rglob("*.html"):
            if ".git" in path.parts or "public-site" in path.parts:
                continue
            text = path.read_text()
            # Flatten tags so adjacent number/label elements cannot hide a stale score.
            visible = re.sub(r"<[^>]+>", " ", text)
            visible = re.sub(r"\s+", " ", visible)
            with self.subTest(page=path.relative_to(ROOT)):
                self.assertIsNone(fixed_score.search(visible))
                self.assertNotRegex(visible, r"tests_passing\s*:\s*[\d,]+")
                self.assertNotRegex(
                    visible,
                    r"\b\d+(?:\.\d+)?%\s*(?:MITRE\s+)?ATT&amp;CK\s+coverage\b",
                )

    def test_dashboard_export_scripts_are_valid_javascript(self):
        dashboard_pages = (
            ROOT / 'docs/shadow313-nexus-dashboard.html',
            ROOT / 'local_bundle/dashboard.html',
            ROOT / 'local_bundle/command-center.html',
        )
        script_pattern = re.compile(r'<script\b([^>]*)>(.*?)</script\s*>', re.I | re.S)
        for path in dashboard_pages:
            scripts = [
                code for attrs, code in script_pattern.findall(path.read_text())
                if code.strip() and not re.search(r'type=["\']application/json', attrs, re.I)
            ]
            self.assertTrue(scripts, path)
            for index, code in enumerate(scripts):
                result = subprocess.run(
                    ['node', '--check', '-'], input=code, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, f'{path}:{index}: {result.stderr}')

    def test_one_shared_primary_nav_without_injected_menus(self):
        for path in pages():
            with self.subTest(page=path.name):
                text = path.read_text()
                page = Page(text)
                self.assertEqual(page.primary, 1)
                # Embedded downloadable HTML in script strings is not page markup.
                visible = text.split('<script', 1)[0] if path.name == 'shadow313-file-portal.html' else text
                self.assertNotIn('id="s313-nav"', visible)
                self.assertNotIn('id="nav-clock"', visible)

    def test_docs_and_dashboard_directory_are_separate(self):
        docs = (ROOT / 'docs/index.html').read_text()
        self.assertIn('<h1>Documentation</h1>', docs)
        links = Page(docs).links
        for route in ('/docs/install', '/docs/quickstart', '/docs/api', '/docs/modules', '/dashboards'):
            self.assertIn(route, links)
        self.assertNotIn('LIVE DASHBOARDS', docs)
        dashboard = (ROOT / 'docs/dashboards.html').read_text()
        self.assertIn('DASHBOARD DEMONSTRATIONS', dashboard)
        self.assertNotIn('LIVE DASHBOARDS', dashboard)
        self.assertIn('Demonstration data only.', dashboard)
        self.assertNotIn('3,449', dashboard)
        self.assertNotIn('98%', dashboard)

    def test_internal_navigation_targets_exist(self):
        config = json.loads((ROOT / 'vercel.json').read_text())
        routes = {r['source']: r['destination'] for r in config['rewrites']
                  if ':' not in r['source'] and not r.get('has')}
        for path in pages() + [ROOT / 'index.html', ROOT / 'sentinelos/index.html']:
            for href in Page(path.read_text()).links:
                url = urlsplit(href)
                if url.scheme or url.netloc or href.startswith('#'):
                    continue
                target = urlsplit(urljoin('/' + str(path.relative_to(ROOT)), href)).path
                normalized = target.rstrip('/') or '/'
                dest = ROOT / routes.get(normalized, normalized).lstrip('/')
                with self.subTest(page=path.name, link=href):
                    self.assertTrue(dest.is_file() or (dest / 'index.html').is_file(), target)

    def test_local_bundle_internal_links_resolve_offline(self):
        bundle = ROOT / 'local_bundle'
        for path in bundle.glob('*.html'):
            for href in Page(path.read_text()).links:
                url = urlsplit(href)
                if url.scheme or url.netloc or href.startswith('#'):
                    continue
                target = (bundle / url.path.lstrip('/')) if url.path.startswith('/') else path.parent / url.path
                with self.subTest(page=path.name, link=href):
                    self.assertTrue(target.is_file(), href)

    def test_links_do_not_send_visitors_to_github_pages(self):
        for path in pages() + [ROOT / 'index.html', ROOT / 'sentinelos/index.html']:
            for href in Page(path.read_text()).links:
                self.assertNotEqual(urlsplit(href).hostname, 'piyyy314.github.io')

    def test_portal_download_payload_is_data_not_nested_page_markup(self):
        text = (ROOT / 'docs/shadow313-file-portal.html').read_text()
        payload = re.search(r'<script id="download-files" type="application/json">(.*?)</script>', text, re.S)
        self.assertIsNotNone(payload)
        self.assertNotIn('<', payload[1])
        files = json.loads(payload[1])
        self.assertEqual(len(files), 11)
        for filename, content in files.items():
            self.assertEqual(content, (ROOT / 'docs' / filename).read_text())

    def test_navigation_template_is_current(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/render-site-nav.py'), '--check'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sentinelos_router_only_intercepts_app_tabs(self):
        text = (ROOT / 'sentinelos/js/app.js').read_text()
        self.assertIn("querySelectorAll('.nav-item[data-view]')", text)

    def test_both_docs_paths_have_explicit_routes(self):
        routes = json.loads((ROOT / 'vercel.json').read_text())['rewrites']
        for source in ('/docs', '/docs/'):
            self.assertIn({'source': source, 'destination': '/docs/index.html'}, routes)
        self.assertIn(
            {'source': '/tools/recon', 'destination': '/docs/recon.html'},
            routes,
        )

    def test_shared_css_is_scoped_and_mobile_navigation_is_available(self):
        css = (ROOT / 'assets/site-nav.css').read_text()
        self.assertIn('#site-nav', css)
        self.assertIn('flex-wrap: wrap', css)
        self.assertNotIn('display: none', css)


    def test_dashboard_and_receipt_pages_disclose_demo_boundaries(self):
        demo_pages = (
            'docs/dashboards.html',
            'docs/shadow313-nexus-dashboard.html',
            'local_bundle/dashboard.html',
            'docs/s313-threat-board.html',
            'local_bundle/threat-board.html',
            'docs/s313-command-center-v6.html',
            'local_bundle/command-center.html',
            'docs/S313-Nexus-Dashboard-v3.html',
            'local_bundle/dashboard-v3.html',
            'docs/S313-SSP-Dashboard.html',
            'local_bundle/ssp.html',
            'docs/aegis_nexus.html',
            'tools/aegis-nexus.html',
            'local_bundle/aegis-nexus.html',
            'docs/nvsm-chain-score-dashboard.html',
            'docs/313-bind-verification-portal.html',
            'docs/attck-coverage-graph.html',
            'docs/vendor-scorecard.html',
            'local_bundle/vendor-scorecard.html',
        )
        for relative in demo_pages:
            page = ROOT / relative
            text = page.read_text()
            with self.subTest(page=relative):
                self.assertIn('role="note"', text)
                self.assertNotRegex(
                    text,
                    r'CVE-2026-(?:3392|0001|1847)',
                )
                self.assertNotIn('REAL DATA', text)
                self.assertNotIn('REAL SESSION DATA', text)
                self.assertNotIn('LIVE DATA', text)

        receipt = (ROOT / 'docs/313-bind-verification-portal.html').read_text()
        self.assertIn('Sample Receipt — Not Verified', receipt)
        self.assertNotIn('Receipt VALID — Chain Intact', receipt)
        self.assertNotIn('Every receipt is signed with SLH-DSA', receipt)

    def test_compliance_and_vendor_demo_scores_are_not_presented_as_assessed(self):
        for relative in ('docs/S313-SSP-Dashboard.html', 'local_bundle/ssp.html'):
            text = (ROOT / relative).read_text()
            with self.subTest(page=relative):
                self.assertNotIn('~23%', text)
                self.assertNotIn('~40%', text)
                self.assertIn('Not assessed', text)
        for relative in ('docs/vendor-scorecard.html', 'local_bundle/vendor-scorecard.html'):
            text = (ROOT / relative).read_text()
            with self.subTest(page=relative):
                self.assertNotIn('#1 of 13', text)
                self.assertNotIn('96.2/100', text)
                self.assertIn('No independently sourced', text)


if __name__ == '__main__':
    unittest.main()
