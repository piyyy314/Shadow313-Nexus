"""The .com homepage is the reference for the shared public website shell."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FOLDERS = ('docs', 'platform', 'pricing', 'tools', 'about', 'blog', 'marketplace')


class SiteThemeTests(unittest.TestCase):
    def test_public_pages_share_the_homepage_theme(self):
        paths = [ROOT / 'index.html'] + [p for folder in FOLDERS for p in (ROOT / folder).glob('*.html')]
        for path in paths:
            with self.subTest(page=path.name):
                text = path.read_text()
                self.assertIn('href="/assets/site-theme.css"', text)
                self.assertRegex(text, r'<body[^>]*class="[^"]*site-page')
                self.assertEqual(len(re.findall('id="site-nav"', text)), 1)

    def test_homepage_is_shared_by_both_domains(self):
        routes = json.loads((ROOT / 'vercel.json').read_text())['rewrites']
        home = [r for r in routes if r['source'] == '/']
        self.assertEqual(home, [{'source': '/', 'destination': '/index.html'}])
        self.assertIn({'source': '/sentinelos', 'destination': '/sentinelos/index.html'}, routes)

    def test_theme_uses_homepage_palette_and_semantic_status_colors(self):
        css = (ROOT / 'assets/site-theme.css').read_text()
        for color in ('#04060f', '#7b61ff', '#00d4ff', '#00f5a0', '#ff4757'):
            self.assertIn(color, css)
        for font in ('Inter', 'Orbitron', 'Fira Code'):
            self.assertIn(font, css)
        self.assertNotRegex(css, r'--green:\s*#7b61ff')
        self.assertIn('prefers-reduced-motion', css)


if __name__ == '__main__':
    unittest.main()
