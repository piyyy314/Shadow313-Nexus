"""Regression checks for the original domain-specific static entrypoints."""
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ('src', 'href'):
            value = attrs.get(key, '')
            if value.startswith('/sentinelos/'):
                self.paths.append(value)


class DomainSplitTests(unittest.TestCase):
    def destination(self, host, path):
        config = json.loads((ROOT / 'vercel.json').read_text())
        for rule in config['rewrites']:
            if rule['source'] != path:
                continue
            if all(c['value'] == host for c in rule.get('has', []) if c['type'] == 'host'):
                return rule['destination']

    def test_original_domain_roots(self):
        self.assertEqual(self.destination('shadow313.dev', '/'), '/sentinelos/index.html')
        for host in ('shadow313.com', 'www.shadow313.com', 'preview.vercel.app'):
            self.assertEqual(self.destination(host, '/'), '/index.html')

    def test_shared_dashboard_routes_preserved(self):
        for host in ('shadow313.dev', 'shadow313.com'):
            self.assertEqual(self.destination(host, '/dashboard'),
                             '/docs/shadow313-nexus-dashboard.html')

    def test_sentinelos_assets_exist(self):
        page = Assets()
        page.feed((ROOT / 'sentinelos/index.html').read_text())
        self.assertEqual(len(page.paths), 15)
        for path in page.paths:
            self.assertTrue((ROOT / path.lstrip('/')).is_file(), path)


if __name__ == '__main__':
    unittest.main()
