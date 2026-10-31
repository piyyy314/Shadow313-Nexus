#!/usr/bin/env python3
"""Classify tracked files without deleting or modifying them."""

import csv
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
public = set(json.loads((ROOT / "site/public-files.json").read_text())["files"])
files = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
rows = []
for name in sorted(filter(None, files)):
    parts = Path(name).parts
    top = parts[0]
    if name in public:
        area, action = "public-website", "publish-only-through-allowlist"
    elif top in ("shadow313", "shadow313_sdk", "shadow313_platform", "nexus_toolkit"):
        area, action = "python-source", "keep; verify package/resource tests"
    elif (
        top in ("docs-archive", "local_bundle", "notes", "audit-results")
        or "session-exports" in parts
    ):
        area, action = (
            "historical-or-local",
            "repository-only; review content/licensing/PII before archival or removal",
        )
    elif top in ("api", "server"):
        area, action = "server-source", "keep server-side; never publish as static files"
    elif top == "docs":
        area, action = (
            "reference-or-internal-document",
            "repository-only unless explicitly allowlisted",
        )
    elif name in ("html_redesign.ps1", "fix_html_architecture.ps1"):
        area, action = "retired-migration", "disabled entrypoint; retain for history, do not run"
    else:
        area, action = "development-or-metadata", "repository-only; no automatic deletion"
    rows.append((name, area, action))
with (ROOT / "site/repository-inventory.csv").open("w", newline="") as output:
    writer = csv.writer(output)
    writer.writerow(("path", "classification", "disposition"))
    writer.writerows(rows)
print(f"Inventoried {len(rows)} files. No files deleted.")
