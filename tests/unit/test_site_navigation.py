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
        self.assertIn('LIVE DASHBOARDS', (ROOT / 'docs/dashboards.html').read_text())

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

    def test_shared_css_is_scoped_and_mobile_navigation_is_available(self):
        css = (ROOT / 'assets/site-nav.css').read_text()
        self.assertIn('#site-nav', css)
        self.assertIn('flex-wrap: wrap', css)
        self.assertNotIn('display: none', css)


if __name__ == '__main__':
    unittest.main()
