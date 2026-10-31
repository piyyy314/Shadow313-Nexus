#!/usr/bin/env python3
"""Update existing static navigation from its template, without injecting menus.

Run from any directory. --check is read-only and suitable for CI.
"""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = ('docs', 'platform', 'pricing', 'tools', 'about', 'blog', 'marketplace')
PATTERN = re.compile(r'<!-- Shared navigation:.*?-->\s*<nav id="site-nav".*?</nav>', re.S)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    template = (ROOT / 'assets/site-nav.html').read_text()
    stale = []
    for folder in FOLDERS:
        for path in sorted((ROOT / folder).glob('*.html')):
            text = path.read_text()
            matches = list(PATTERN.finditer(text))
            if len(matches) != 1:
                raise SystemExit(f'Expected one primary navigation: {path.relative_to(ROOT)}')
            updated = PATTERN.sub(lambda _: template, text, count=1)
            if text != updated:
                stale.append(str(path.relative_to(ROOT)))
                if not args.check:
                    path.write_text(updated)
    # Keep the legacy download portal safe: JSON escapes prevent embedded HTML
    # from closing the script element and rendering additional pages/headers.
    portal = ROOT / 'docs/shadow313-file-portal.html'
    text = portal.read_text()
    pattern = re.compile(r'(<script id="download-files" type="application/json">)(.*?)(</script>)', re.S)
    match = pattern.search(text)
    if match:
        files = json.loads(match[2])
        payload = json.dumps({name: (ROOT / 'docs' / name).read_text() for name in files},
                             ensure_ascii=False).replace('<', r'\u003c')
        updated = text[:match.start(2)] + payload + text[match.end(2):]
        if updated != text:
            stale.append(str(portal.relative_to(ROOT)))
            if not args.check:
                portal.write_text(updated)
    print(f'{len(stale)} navigation sections {"out of date" if args.check else "updated"}')
    return int(args.check and bool(stale))


if __name__ == '__main__':
    raise SystemExit(main())
