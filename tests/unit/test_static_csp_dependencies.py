"""External scripts used by published HTML must be allowed by the deployed CSP."""
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]


class ScriptSources(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.sources = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        src = dict(attrs).get("src")
        if src and urlsplit(src).scheme in ("http", "https"):
            self.sources.append(urlsplit(src).hostname)


def test_every_published_external_script_host_is_allowed_by_csp():
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    csp = next(
        header["value"]
        for group in config["headers"]
        for header in group["headers"]
        if header["key"].lower() == "content-security-policy"
    )
    script_policy = next(
        directive.strip()
        for directive in csp.split(";")
        if directive.strip().startswith("script-src ")
    )
    allowed = {
        token.removeprefix("https://").removeprefix("http://").strip()
        for token in script_policy.split()[1:]
        if token.startswith(("https://", "http://"))
    }
    files = json.loads((ROOT / "site/public-files.json").read_text(encoding="utf-8"))
    missing = []
    for relative in files:
        if not relative.endswith((".html", ".htm")):
            continue
        page = ROOT / relative
        if not page.is_file():
            continue
        for host in ScriptSources(page.read_text(encoding="utf-8", errors="replace")).sources:
            if host and host not in allowed:
                missing.append(f"{relative}: {host}")
    assert not missing, "CSP blocks published external scripts:\\n" + "\\n".join(missing)


def test_vsat_and_web3_cdn_dependencies_are_explicitly_allowed():
    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    csp = next(
        header["value"]
        for group in config["headers"]
        for header in group["headers"]
        if header["key"].lower() == "content-security-policy"
    )
    assert "https://cdn.tailwindcss.com" in csp
    assert "https://cdn.jsdelivr.net" in csp
