#!/usr/bin/env python3
"""Audit local HTML links, Vercel rewrite targets, and the public-site allowlist."""
from __future__ import annotations

import argparse
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Links(HTMLParser):
    def __init__(self, source: str):
        super().__init__(convert_charrefs=True)
        self.refs: list[tuple[str, str]] = []
        self.ids: set[str] = set()
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        for key in ("href", "src", "action", "poster"):
            value = attrs.get(key)
            if value:
                self.refs.append((key, value.strip()))


def normalize(path: str) -> str:
    parts: list[str] = []
    for part in path.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-only", action="store_true")
    args = parser.parse_args()

    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    rewrites = {
        rule["source"]: rule["destination"].lstrip("/")
        for rule in config.get("rewrites", [])
        if "source" in rule and "destination" in rule
    }
    public_files = set(json.loads((ROOT / "site/public-files.json").read_text(encoding="utf-8")))
    tracked = [p for p in ROOT.rglob("*.html") if ".git" not in p.parts and "node_modules" not in p.parts]
    if args.public_only:
        tracked = [ROOT / item for item in public_files if item.endswith((".html", ".htm"))]

    errors: list[str] = []
    checked = 0
    html_cache: dict[str, Links] = {}

    def page(path: str) -> Links | None:
        if path not in html_cache:
            file = ROOT / path
            if not file.is_file():
                return None
            try:
                html_cache[path] = Links(file.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                return None
        return html_cache[path]

    for source_file in sorted(tracked):
        if not source_file.is_file():
            errors.append(f"MISSING HTML FILE: {source_file.relative_to(ROOT)}")
            continue
        source = source_file.relative_to(ROOT).as_posix()
        source_page = page(source)
        if source_page is None:
            errors.append(f"UNREADABLE HTML: {source}")
            continue
        for attr, raw in source_page.refs:
            if not raw or re.match(r"^(?:[a-z][a-z0-9+.-]*:|//)", raw, re.I):
                continue
            parsed = urlsplit(raw)
            path = parsed.path
            if not path:
                target = source
            elif path.startswith("/"):
                target = rewrites.get(path, path.lstrip("/"))
                if target == path.lstrip("/") and path.endswith("/"):
                    target = path.lstrip("/") + "index.html"
                if target == path.lstrip("/") and not Path(target).suffix and (ROOT / target / "index.html").is_file():
                    target = target.rstrip("/") + "/index.html"
            else:
                target = normalize(f"{Path(source).parent.as_posix()}/{path}")
            target = normalize(target)
            target_file = ROOT / target
            if not target_file.is_file():
                errors.append(f"BROKEN {attr}: {source} -> {raw} (missing {target})")
                continue
            if source in public_files and target not in public_files and not target.startswith("api/"):
                errors.append(f"NOT PUBLISHED: {source} -> {raw} (add {target} to site/public-files.json or change the link)")
                continue
            checked += 1
            if parsed.fragment and target.lower().endswith((".html", ".htm")):
                target_page = page(target)
                if target_page is not None and parsed.fragment not in target_page.ids:
                    errors.append(f"BROKEN FRAGMENT: {source} -> {raw} (#{parsed.fragment} absent in {target})")

    print(f"HTML files scanned: {len(tracked)}")
    print(f"Local references checked: {checked}")
    print(f"Findings: {len(errors)}")
    for error in errors[:500]:
        print(f"ERROR: {error}")
    if len(errors) > 500:
        print(f"... {len(errors) - 500} additional findings omitted")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
