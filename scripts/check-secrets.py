#!/usr/bin/env python3
"""Scan tracked files, allowing only reviewed fixture fingerprints at exact paths.

Fingerprints avoid duplicating token-shaped test data in the scanner config.
Adding a fixture requires reviewing both the exact source line and its specific path.
No candidate values are printed in diagnostics.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

PATTERNS = [
    r'client_secret', r'AKIA[0-9A-Z]{16}', r'sk-[a-zA-Z0-9]{32,}',
    r'ghp_[a-zA-Z0-9]{36}', r'-----BEGIN RSA PRIVATE KEY-----',
    r'-----BEGIN OPENSSH PRIVATE KEY-----',
]


def violations(path, content, fixtures):
    allowed = fixtures.get(path, [])
    for pattern in PATTERNS:
        for match in re.finditer(pattern, content):
            digest = hashlib.sha256(content.splitlines()[content.count('\n', 0, match.start())].encode()).hexdigest()
            if digest not in allowed:
                yield content.count('\n', 0, match.start()) + 1


def main():
    root = Path(__file__).resolve().parents[1]
    fixtures = json.loads((root / 'scripts/secret-fixtures.json').read_text())
    paths = subprocess.run(['git', 'ls-files', '-z'], cwd=root, check=True,
                           capture_output=True).stdout.decode().split('\0')
    errors = 0
    for path in filter(None, paths):
        # Keep the workflow's existing exclusions; scanner source holds regexes only.
        if any(part in {'node_modules', 'docs-archive', '.github'}
               for part in Path(path).parts) or path == 'scripts/check-secrets.py':
            continue
        content = (root / path).read_text(encoding='utf-8', errors='replace')
        for line in violations(path, content, fixtures):
            print(f'FAIL: possible secret at {path}:{line} (value withheld)')
            errors += 1
    print(f'Secret scan: {errors} unapproved match(es).')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
