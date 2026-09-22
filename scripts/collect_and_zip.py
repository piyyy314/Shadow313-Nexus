#!/usr/bin/env python3
"""
Shadow313 NEXUS — Project File Collector & Zipper
==================================================
Automatically collects all Shadow313 project files from their various
paths into one staging folder and creates a single zip archive.

Usage:
    # Collect everything from workspace
    python3 scripts/collect_and_zip.py

    # Collect only new/modified files (since last zip)
    python3 scripts/collect_and_zip.py --since 2026-09-01

    # Collect specific categories
    python3 scripts/collect_and_zip.py --categories code,tests,docs

    # Dry run — show what would be collected
    python3 scripts/collect_and_zip.py --dry-run

    # Custom output path
    python3 scripts/collect_and_zip.py --output ~/Desktop/shadow313_batch.zip
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Configuration ─────────────────────────────────────────────────────────────

WORKSPACE = Path(__file__).parent.parent  # /workspace

# What to collect — organized by category
COLLECTION_RULES = {
    "code": {
        "description": "All Python source files",
        "patterns": ["**/*.py"],
        "exclude_dirs": {
            "__pycache__", ".git", "node_modules", ".venv", "venv",
            "uploaded_files", ".github", "dist", "build", ".eggs",
        },
        "exclude_files": {"*.pyc", "*.pyo"},
    },
    "tests": {
        "description": "All test files",
        "patterns": ["tests/**/*.py"],
        "exclude_dirs": {"__pycache__"},
    },
    "docs": {
        "description": "Documentation and reports",
        "patterns": ["docs/**/*.md", "docs/**/*.html", "docs/**/*.ps1"],
        "exclude_dirs": set(),
    },
    "config": {
        "description": "Configuration files",
        "patterns": [
            "*.toml", "*.yaml", "*.yml", "*.json",
            ".github/**/*.yml", "netlify.toml",
        ],
        "exclude_dirs": {"node_modules", "uploaded_files"},
        "exclude_files": {"package-lock.json"},
    },
    "scripts": {
        "description": "Utility scripts",
        "patterns": ["scripts/**/*.py", "scripts/**/*.sh", "scripts/**/*.ps1"],
        "exclude_dirs": set(),
    },
    "tools": {
        "description": "Shadow313 tool suite",
        "patterns": ["shadow313/tools/**/*.py"],
        "exclude_dirs": {"__pycache__"},
    },
    "detection": {
        "description": "Detection and hardening modules",
        "patterns": [
            "shadow313/v4/detection/**/*.py",
            "shadow313/v4/simulation/**/*.py",
        ],
        "exclude_dirs": {"__pycache__"},
    },
    "nexus": {
        "description": "NEXUS toolkit",
        "patterns": ["nexus_toolkit/**/*.py"],
        "exclude_dirs": {"__pycache__"},
    },
    "terminal_outputs": {
        "description": "Terminal output files from stalled thread",
        "patterns": ["uploaded_files/office_agent*.txt", "uploaded_files/new*.txt"],
        "exclude_dirs": set(),
    },
}

# Files to always include regardless of category
ALWAYS_INCLUDE = [
    "README.md",
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "netlify.toml",
    ".github/workflows/deploy.yml",
    "todo.md",
]

# ── Collector ─────────────────────────────────────────────────────────────────

class Shadow313Collector:
    """Collects and zips Shadow313 project files."""

    def __init__(
        self,
        workspace: Path = WORKSPACE,
        output: Optional[Path] = None,
        categories: Optional[list[str]] = None,
        since: Optional[str] = None,
        dry_run: bool = False,
        verbose: bool = True,
    ):
        self.workspace  = workspace
        self.output     = output or workspace / f"shadow313_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        self.categories = categories or list(COLLECTION_RULES.keys())
        self.since_ts   = self._parse_since(since) if since else None
        self.dry_run    = dry_run
        self.verbose    = verbose
        self.collected: list[Path] = []
        self.skipped:   list[tuple[Path, str]] = []
        self.manifest:  dict = {}

    def collect(self) -> dict:
        """Run the full collection pipeline."""
        self._print_header()

        # Collect files by category
        for category in self.categories:
            if category not in COLLECTION_RULES:
                self._warn(f"Unknown category: {category}")
                continue
            self._collect_category(category, COLLECTION_RULES[category])

        # Always-include files
        self._collect_always_include()

        # Deduplicate
        seen = set()
        unique = []
        for f in self.collected:
            if f not in seen:
                seen.add(f)
                unique.append(f)
        self.collected = sorted(unique)

        # Build manifest
        self.manifest = self._build_manifest()

        # Create zip
        if not self.dry_run:
            self._create_zip()
        else:
            self._print_dry_run()

        return self.manifest

    def _collect_category(self, name: str, rules: dict) -> None:
        """Collect files matching a category's rules."""
        count = 0
        exclude_dirs  = rules.get("exclude_dirs", set())
        exclude_files = rules.get("exclude_files", set())

        for pattern in rules["patterns"]:
            for path in self.workspace.glob(pattern):
                # Skip excluded directories
                if any(part in exclude_dirs for part in path.parts):
                    self.skipped.append((path, "excluded_dir"))
                    continue

                # Skip excluded file patterns
                if any(path.match(ep) for ep in exclude_files):
                    self.skipped.append((path, "excluded_file"))
                    continue

                # Skip if older than --since
                if self.since_ts and path.stat().st_mtime < self.since_ts:
                    self.skipped.append((path, "too_old"))
                    continue

                # Skip empty files (< 5 bytes)
                if path.stat().st_size < 5:
                    self.skipped.append((path, "empty"))
                    continue

                self.collected.append(path)
                count += 1

        if self.verbose:
            print(f"  [{name:<20}] {count:>4} files — {rules['description']}")

    def _collect_always_include(self) -> None:
        """Add always-include files."""
        count = 0
        for rel_path in ALWAYS_INCLUDE:
            full = self.workspace / rel_path
            if full.exists():
                self.collected.append(full)
                count += 1
        if self.verbose and count:
            print(f"  [{'always_include':<20}] {count:>4} files — Core project files")

    def _build_manifest(self) -> dict:
        """Build a manifest of all collected files."""
        files_info = []
        total_size = 0

        for path in self.collected:
            try:
                stat = path.stat()
                rel  = path.relative_to(self.workspace)
                size = stat.st_size
                total_size += size
                files_info.append({
                    "path":     str(rel),
                    "size":     size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "hash":     self._file_hash(path),
                })
            except Exception as e:
                self._warn(f"Cannot stat {path}: {e}")

        # Group by directory
        by_dir: dict[str, int] = {}
        for info in files_info:
            d = str(Path(info["path"]).parent)
            by_dir[d] = by_dir.get(d, 0) + 1

        return {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "workspace":     str(self.workspace),
            "output":        str(self.output),
            "total_files":   len(files_info),
            "total_size_kb": round(total_size / 1024, 1),
            "categories":    self.categories,
            "files":         files_info,
            "by_directory":  dict(sorted(by_dir.items())),
            "skipped":       len(self.skipped),
        }

    def _create_zip(self) -> None:
        """Create the zip archive."""
        print(f"\n  Creating zip: {self.output}")
        start = time.time()

        with zipfile.ZipFile(self.output, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for path in self.collected:
                try:
                    rel = path.relative_to(self.workspace)
                    zf.write(path, rel)
                except Exception as e:
                    self._warn(f"Cannot add {path}: {e}")

            # Add manifest
            manifest_json = json.dumps(self.manifest, indent=2)
            zf.writestr("MANIFEST.json", manifest_json)

        elapsed = time.time() - start
        zip_size = self.output.stat().st_size / 1024 / 1024

        print(f"\n  ✅ ZIP CREATED")
        print(f"     Files:    {self.manifest['total_files']}")
        print(f"     Source:   {self.manifest['total_size_kb']} KB")
        print(f"     Zip size: {zip_size:.1f} MB")
        print(f"     Time:     {elapsed:.1f}s")
        print(f"     Path:     {self.output}")

    def _print_dry_run(self) -> None:
        """Print dry-run summary."""
        print(f"\n  DRY RUN — would collect {len(self.collected)} files:")
        for path in self.collected[:20]:
            rel = path.relative_to(self.workspace)
            print(f"    {rel}")
        if len(self.collected) > 20:
            print(f"    ... and {len(self.collected) - 20} more")

    def _print_header(self) -> None:
        print("=" * 65)
        print("  SHADOW313 NEXUS — File Collector & Zipper")
        print("=" * 65)
        print(f"  Workspace:  {self.workspace}")
        print(f"  Output:     {self.output}")
        print(f"  Categories: {', '.join(self.categories)}")
        if self.since_ts:
            print(f"  Since:      {datetime.fromtimestamp(self.since_ts).isoformat()}")
        print(f"  Dry run:    {self.dry_run}")
        print()
        print("  Collecting files:")

    @staticmethod
    def _file_hash(path: Path) -> str:
        """SHA-256 hash of file content (first 64KB for speed)."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                h.update(f.read(65536))
            return h.hexdigest()[:16]
        except Exception:
            return ""

    @staticmethod
    def _parse_since(since: str) -> float:
        """Parse --since date string to timestamp."""
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(since, fmt).timestamp()
            except ValueError:
                continue
        raise ValueError(f"Cannot parse date: {since}. Use YYYY-MM-DD format.")

    def _warn(self, msg: str) -> None:
        print(f"  ⚠️  {msg}", file=sys.stderr)


# ── Windows PowerShell Script Generator ──────────────────────────────────────

def generate_windows_script(output_path: Path) -> str:
    """Generate a Windows PowerShell version of the collector."""
    return '''# Shadow313 NEXUS — Windows File Collector
# Run in PowerShell: .\\collect_shadow313.ps1
# Or with custom output: .\\collect_shadow313.ps1 -OutputPath "C:\\Desktop\\shadow313.zip"

param(
    [string]$OutputPath = "$env:USERPROFILE\\Desktop\\shadow313_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip",
    [string]$WorkspacePath = "C:\\path\\to\\shadow313",  # UPDATE THIS
    [switch]$DryRun
)

Write-Host "Shadow313 NEXUS — File Collector" -ForegroundColor Cyan
Write-Host "Workspace: $WorkspacePath"
Write-Host "Output:    $OutputPath"
Write-Host ""

# Collect all Python files
$files = @()
$files += Get-ChildItem -Path $WorkspacePath -Recurse -Filter "*.py" |
    Where-Object { $_.FullName -notmatch "__pycache__|node_modules|\\.git|uploaded_files" }

# Collect docs
$files += Get-ChildItem -Path "$WorkspacePath\\docs" -Recurse -Filter "*.md" -ErrorAction SilentlyContinue
$files += Get-ChildItem -Path "$WorkspacePath\\docs" -Recurse -Filter "*.html" -ErrorAction SilentlyContinue

# Collect config
$files += Get-ChildItem -Path $WorkspacePath -Filter "*.toml" -ErrorAction SilentlyContinue
$files += Get-ChildItem -Path $WorkspacePath -Filter "*.yaml" -ErrorAction SilentlyContinue
$files += Get-ChildItem -Path $WorkspacePath -Filter "README.md" -ErrorAction SilentlyContinue

Write-Host "Found $($files.Count) files" -ForegroundColor Green

if ($DryRun) {
    $files | Select-Object -First 20 | ForEach-Object {
        Write-Host "  $($_.FullName.Replace($WorkspacePath, ''))"
    }
    Write-Host "DRY RUN — no zip created"
} else {
    # Create zip
    Compress-Archive -Path $files.FullName -DestinationPath $OutputPath -Force
    $zipSize = (Get-Item $OutputPath).Length / 1MB
    Write-Host ""
    Write-Host "ZIP CREATED: $OutputPath ($([math]::Round($zipSize, 1)) MB)" -ForegroundColor Green
}
'''


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Shadow313 NEXUS — File Collector & Zipper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect everything
  python3 scripts/collect_and_zip.py

  # Only new files since Sept 1
  python3 scripts/collect_and_zip.py --since 2026-09-01

  # Only code and tests
  python3 scripts/collect_and_zip.py --categories code,tests

  # Dry run to preview
  python3 scripts/collect_and_zip.py --dry-run

  # Custom output path
  python3 scripts/collect_and_zip.py --output /tmp/shadow313_batch.zip

  # Generate Windows PowerShell script
  python3 scripts/collect_and_zip.py --generate-windows-script
        """
    )
    parser.add_argument("--output",    "-o", help="Output zip path")
    parser.add_argument("--since",     "-s", help="Only files modified after this date (YYYY-MM-DD)")
    parser.add_argument("--categories","-c", help="Comma-separated categories to collect")
    parser.add_argument("--dry-run",   "-n", action="store_true", help="Preview without creating zip")
    parser.add_argument("--quiet",     "-q", action="store_true", help="Suppress verbose output")
    parser.add_argument("--generate-windows-script", action="store_true",
                        help="Generate Windows PowerShell collector script")
    parser.add_argument("--list-categories", action="store_true",
                        help="List available categories and exit")

    args = parser.parse_args()

    if args.list_categories:
        print("Available categories:")
        for name, rules in COLLECTION_RULES.items():
            print(f"  {name:<25} — {rules['description']}")
        return

    if args.generate_windows_script:
        script_path = WORKSPACE / "scripts" / "collect_shadow313.ps1"
        script_path.write_text(generate_windows_script(script_path))
        print(f"✅ Windows script generated: {script_path}")
        print(f"   Update WorkspacePath in the script before running.")
        return

    categories = args.categories.split(",") if args.categories else None
    output     = Path(args.output) if args.output else None

    collector = Shadow313Collector(
        workspace  = WORKSPACE,
        output     = output,
        categories = categories,
        since      = args.since,
        dry_run    = args.dry_run,
        verbose    = not args.quiet,
    )

    manifest = collector.collect()

    if not args.dry_run:
        # Save manifest separately
        manifest_path = WORKSPACE / "shadow313_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        print(f"\n  Manifest: {manifest_path}")
        print(f"\n  Upload the zip file to continue processing.")


if __name__ == "__main__":
    main()