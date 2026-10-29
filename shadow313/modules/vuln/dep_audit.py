"""shadow313.modules.vuln.dep_audit — Dependency auditor for 5 package ecosystems."""
from __future__ import annotations
import json
import re
from pathlib import Path

from .cve_db import CVEDatabase


class DependencyAuditor:
    PARSERS = {
        "requirements.txt": "_parse_requirements",
        "package.json":     "_parse_package_json",
        "go.mod":           "_parse_go_mod",
        "Gemfile.lock":     "_parse_gemfile",
        "Cargo.toml":       "_parse_cargo",
    }

    def __init__(self, db: CVEDatabase) -> None:
        self.db = db

    def audit_file(self, path: str) -> list[dict]:
        p = Path(path)
        if not p.exists():
            return [{"error": f"File not found: {path}"}]
        parser_method = self.PARSERS.get(p.name)
        if not parser_method:
            return [{"error": f"Unsupported file: {p.name}"}]
        packages = getattr(self, parser_method)(p.read_text(errors="replace"))
        findings = []
        for pkg, ver in packages.items():
            hits = self.db.search_by_keyword(pkg, limit=5)
            for h in hits:
                h["package"]    = pkg
                h["version"]    = ver
                h["dep_source"] = p.name
                findings.append(h)
        return sorted(findings, key=lambda x: x.get("cvss_v3", 0), reverse=True)

    def _parse_requirements(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)([>=<!~^]+)(.+)?", line)
            if m:
                pkgs[m.group(1).lower()] = m.group(3) or ""
        return pkgs

    def _parse_package_json(self, text: str) -> dict[str, str]:
        try:
            data = json.loads(text)
            pkgs = {}
            for section in ("dependencies", "devDependencies"):
                pkgs.update({k.lower(): v for k, v in data.get(section, {}).items()})
            return pkgs
        except Exception:
            return {}

    def _parse_go_mod(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            m = re.match(r"\s+(\S+)\s+v(\S+)", line)
            if m:
                pkgs[m.group(1).split("/")[-1].lower()] = m.group(2)
        return pkgs

    def _parse_gemfile(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            m = re.match(r"\s+(\w[\w\-]+)\s+\((.+)\)", line)
            if m:
                pkgs[m.group(1).lower()] = m.group(2)
        return pkgs

    def _parse_cargo(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            m = re.match(r'(\w[\w\-]+)\s*=\s*"(.+)"', line)
            if m:
                pkgs[m.group(1).lower()] = m.group(2)
        return pkgs