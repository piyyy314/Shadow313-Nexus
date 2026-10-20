"""Dependency-free regression checks for static homepage deployment wiring."""
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.anchors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("href", "").startswith("#"):
            self.anchors.append(attrs["href"][1:])


class StaticHomepageTests(unittest.TestCase):
    def test_root_serves_recovered_purple_homepage(self):
        config = json.loads((ROOT / "vercel.json").read_text())
        route = next(r for r in config["rewrites"] if r["source"] == "/")
        self.assertEqual(route["destination"], "/index.html")
        page = (ROOT / "index.html").read_text()
        self.assertIn("--accent:         #7b61ff", page)
        self.assertIn("Advanced Quantum-Ready CLI Platform", page)
        self.assertNotIn('http-equiv="refresh"', page)

    def test_all_rewrite_destinations_exist(self):
        config = json.loads((ROOT / "vercel.json").read_text())
        for route in config["rewrites"]:
            with self.subTest(source=route["source"]):
                self.assertTrue((ROOT / route["destination"].lstrip("/")).is_file())

    def test_homepage_anchors_exist(self):
        page = Links()
        page.feed((ROOT / "index.html").read_text())
        self.assertFalse(set(filter(None, page.anchors)) - page.ids)

    def test_restored_demo_does_not_request_missing_backends_or_assets(self):
        page = (ROOT / "index.html").read_text()
        self.assertNotIn("localhost:8000", page)
        self.assertNotIn("fetch(", page)
        self.assertIn("Browser demonstration", page)
        self.assertIn('href="/docs/"', page)

    def test_speed_insights_uses_same_origin_script(self):
        for path in ROOT.rglob("*.html"):
            page = path.read_text()
            with self.subTest(page=str(path.relative_to(ROOT))):
                self.assertNotIn("cdn.jsdelivr.net/npm/@vercel/speed-insights", page)
                if "window.siq" in page:
                    self.assertIn('/_vercel/speed-insights/script.js', page)

    def test_icon_font_cdn_is_allowed(self):
        config = json.loads((ROOT / "vercel.json").read_text())
        csp = next(h["value"] for group in config["headers"] for h in group["headers"]
                   if h["key"] == "Content-Security-Policy")
        fonts = next(part for part in csp.split(";") if part.strip().startswith("font-src"))
        self.assertIn("https://cdnjs.cloudflare.com", fonts)


if __name__ == "__main__":
    unittest.main()
