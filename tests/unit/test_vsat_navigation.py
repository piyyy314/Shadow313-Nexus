"""VSAT navigation must work without JS and never pretend to run real tools."""
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links = []
        self.ids = set()
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        if 'sidebar-item' in attrs.get('class', '').split():
            self.links.append((tag, attrs))


class VSATNavigationTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / 'docs/vsat-tactical-suite.html'
        self.text = self.path.read_text()
        self.page = Page(self.text)

    def test_all_fourteen_menu_items_are_native_links(self):
        self.assertEqual(len(self.page.links), 14)
        for tag, attrs in self.page.links:
            self.assertEqual(tag, 'a')
            self.assertTrue(attrs.get('href'))
            self.assertNotIn('onclick', attrs)
        self.assertNotIn('showSection(', self.text)

    def test_sidebar_destinations_and_fragments_exist(self):
        routes = {r['source']: r['destination'] for r in json.loads((ROOT / 'vercel.json').read_text())['rewrites']
                  if not r.get('has')}
        for _, attrs in self.page.links:
            url = urlsplit(attrs['href'])
            self.assertFalse(url.scheme or url.netloc)
            path = ROOT / routes.get(url.path, url.path).lstrip('/') if url.path else self.path
            self.assertTrue(path.is_file(), str(path))
            if url.fragment:
                self.assertIn(url.fragment, Page(path.read_text()).ids)

    def test_pqc_and_guide_links_lead_to_actual_content(self):
        targets = {attrs['href'] for _, attrs in self.page.links}
        for target in ('/docs/pqc', '/platform/vuln', '/platform/network', '/platform/exploit',
                       '/aegis-nexus#firmware-finding', '/aegis-nexus#qkd-status'):
            self.assertIn(target, targets)

    def test_demo_and_missing_simulator_are_disclosed(self):
        for text in ('SIMULATION ONLY', 'No live scans', 'QKD BB84 Reference', 'No simulator available'):
            self.assertIn(text, self.text)
        self.assertIn('simulation: true', self.text)
        self.assertIn('bind_receipt: null', self.text)
        self.assertNotIn('Report exported with 313-BIND receipt', self.text)

    def test_element_cards_are_links_not_fake_activation(self):
        self.assertNotIn('activateElement(', self.text)
        self.assertEqual(self.text.count('<a class="element-card"'), 6)


if __name__ == '__main__':
    unittest.main()
