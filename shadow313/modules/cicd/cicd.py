"""
shadow313.modules.cicd
CI/CD integration — SARIF output, secret scanning, dependency audit,
GitHub Actions / GitLab CI template generation, pipeline threshold gating.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── SARIF 2.1.0 builder ───────────────────────────────────────────────────────

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}


class SARIFBuilder:
    """Build a SARIF 2.1.0 compliant report from Shadow313 findings."""

    def __init__(self, tool_name: str = "shadow313",
                 tool_version: str = "4.0.0") -> None:
        self.tool_name    = tool_name
        self.tool_version = tool_version
        self._rules: list[dict]   = []
        self._results: list[dict] = []
        self._rule_ids: set[str]  = set()

    def add_finding(self, rule_id: str, message: str, level: str,
                    file_path: str = "", line: int = 0,
                    cve: str = "", help_uri: str = "") -> None:
        # Register rule
        if rule_id not in self._rule_ids:
            self._rule_ids.add(rule_id)
            rule: dict[str, Any] = {
                "id":   rule_id,
                "name": rule_id.replace("-", " ").title(),
                "shortDescription": {"text": message[:200]},
            }
            if help_uri:
                rule["helpUri"] = help_uri
            if cve:
                rule["properties"] = {"cve": cve}
            self._rules.append(rule)

        # Build result
        result: dict[str, Any] = {
            "ruleId":  rule_id,
            "level":   SEVERITY_TO_SARIF.get(level.lower(), "warning"),
            "message": {"text": message},
        }
        if file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                }
            }
            if line > 0:
                location["physicalLocation"]["region"] = {"startLine": line}
            result["locations"] = [location]
        self._results.append(result)

    def build(self) -> dict:
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name":            self.tool_name,
                        "version":         self.tool_version,
                        "informationUri":  "https://github.com/shadow313/shadow313",
                        "rules":           self._rules,
                    }
                },
                "results":   self._results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc":          _now(),
                }],
            }],
        }

    def to_json(self) -> str:
        return json.dumps(self.build(), indent=2)


# ── Secret scanner ────────────────────────────────────────────────────────────

class SecretScanner:
    """Detect hardcoded secrets in source files and git diffs."""

    PATTERNS: list[tuple[str, str, str]] = [
        ("SECRET-AWS-KEY",      "AWS Access Key ID",
         r"AKIA[0-9A-Z]{16}"),
        ("SECRET-AWS-SECRET",   "AWS Secret Access Key",
         r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
        ("SECRET-GITHUB-TOKEN", "GitHub Personal Access Token",
         r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        ("SECRET-SLACK-TOKEN",  "Slack Token",
         r"xox[baprs]-[A-Za-z0-9\-]{10,48}"),
        ("SECRET-PRIVATE-KEY",  "Private Key Material",
         r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
        ("SECRET-GENERIC-KEY",  "Generic API Key",
         r"(?i)(api[_\-]?key|apikey|secret[_\-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9]{20,}"),
        ("SECRET-DB-PASSWORD",  "Database Password",
         r"(?i)(db_password|database_password|mysql_password|postgres_password)\s*[=:]\s*['\"]?\S{8,}"),
        ("SECRET-GOOGLE-KEY",   "Google API Key",
         r"AIza[0-9A-Za-z\-_]{35}"),
        ("SECRET-STRIPE-KEY",   "Stripe Secret Key",
         r"sk_live_[A-Za-z0-9]{24,}"),
        ("SECRET-PRIVATE-CERT", "Certificate / Private Key Block",
         r"-----BEGIN CERTIFICATE-----"),
        ("SECRET-JWT",          "JSON Web Token",
         r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
        ("SECRET-SENDGRID",     "SendGrid API Key",
         r"SG\.[A-Za-z0-9\-._]{22,}\.[A-Za-z0-9\-._]{43,}"),
        ("SECRET-HARDCODED-PW", "Hardcoded Password Assignment",
         r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]"),
    ]

    IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                         ".woff", ".woff2", ".ttf", ".eot", ".map", ".lock",
                         ".min.js", ".min.css", ".pdf", ".zip", ".tar", ".gz"}
    IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv",
                   "venv", "env", "dist", "build", ".mypy_cache"}

    def scan_directory(self, path: str, max_file_size: int = 1_000_000) -> list[dict]:
        findings = []
        base = Path(path)
        for fpath in base.rglob("*"):
            if fpath.is_file():
                if any(part in self.IGNORE_DIRS for part in fpath.parts):
                    continue
                if fpath.suffix.lower() in self.IGNORE_EXTENSIONS:
                    continue
                if fpath.stat().st_size > max_file_size:
                    continue
                findings.extend(self._scan_file(fpath))
        return findings

    def scan_diff(self, diff_text: str) -> list[dict]:
        findings = []
        lines    = diff_text.splitlines()
        current_file = ""
        for lineno, line in enumerate(lines, 1):
            if line.startswith("--- ") or line.startswith("+++ "):
                current_file = line[4:].strip().lstrip("b/")
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                for rule_id, desc, pattern in self.PATTERNS:
                    if re.search(pattern, content):
                        findings.append({
                            "rule_id":  rule_id,
                            "desc":     desc,
                            "file":     current_file,
                            "line":     lineno,
                            "content":  self._redact(content.strip()[:120]),
                            "severity": "critical",
                            "source":   "git_diff",
                        })
        return findings

    def _scan_file(self, path: Path) -> list[dict]:
        findings = []
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except Exception:
            return []
        for lineno, line in enumerate(lines, 1):
            for rule_id, desc, pattern in self.PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "rule_id":  rule_id,
                        "desc":     desc,
                        "file":     str(path),
                        "line":     lineno,
                        "content":  self._redact(line.strip()[:120]),
                        "severity": "critical",
                        "source":   "file_scan",
                    })
        return findings

    @staticmethod
    def _redact(text: str) -> str:
        """Partially redact detected secrets before displaying."""
        patterns = [
            (r"(AKIA[0-9A-Z]{4})[0-9A-Z]{12}",          r"\1************"),
            (r"(ghp_[A-Za-z0-9]{6})[A-Za-z0-9]{30}",     r"\1****...****"),
            (r"=['\"]([A-Za-z0-9+/=]{20,})['\"]",        r"='***REDACTED***'"),
        ]
        for pat, repl in patterns:
            try:
                text = re.sub(pat, repl, text)
            except re.error:
                pass
        return text


# ── JUnit XML builder ─────────────────────────────────────────────────────────

def build_junit_xml(findings: list[dict], suite_name: str = "shadow313") -> str:
    failures = [f for f in findings if f.get("severity", "").lower() in ("critical", "high")]
    total    = len(findings)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="{suite_name}" tests="{total}" '
        f'failures="{len(failures)}" timestamp="{_now()}">',
    ]
    for f in findings:
        name = f.get("rule_id", "finding").replace("&", "&amp;")
        msg  = f.get("desc", "").replace("&", "&amp;").replace("<", "&lt;")
        sev  = f.get("severity", "").lower()
        lines.append(f'  <testcase name="{name}" classname="{f.get("file","")}">')
        if sev in ("critical", "high"):
            lines.append(f'    <failure message="{msg}">{f.get("content","")}</failure>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    return "\n".join(lines)


# ── CI/CD config generators ───────────────────────────────────────────────────

GITHUB_ACTIONS_WORKFLOW = """\
# Shadow313 Security Scan — GitHub Actions
# Place in: .github/workflows/shadow313.yml
name: Shadow313 Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'   # Weekly Monday 02:00 UTC

jobs:
  security-scan:
    name: Shadow313 Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Shadow313
        run: |
          pip install shadow313
          shadow313 --version

      - name: Run Dependency Vulnerability Audit
        run: |
          shadow313 vuln --audit-deps requirements.txt \\
            --output json > vuln-report.json || true

      - name: Run Secret Scan (diff)
        run: |
          git diff HEAD~1 | shadow313 cicd --secrets --diff - \\
            --output sarif > secrets.sarif || true

      - name: Run Full Security Scan
        run: |
          shadow313 cicd --scan \\
            --threshold ${{ vars.SHADOW313_THRESHOLD || 'high' }} \\
            --output sarif > shadow313-results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: shadow313-results.sarif
          category: shadow313

      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: shadow313-reports
          path: |
            shadow313-results.sarif
            vuln-report.json
            secrets.sarif
"""

GITLAB_CI_TEMPLATE = """\
# Shadow313 Security Scan — GitLab CI
shadow313-security:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install shadow313
  script:
    - shadow313 vuln --audit-deps requirements.txt --output json > gl-vuln.json || true
    - shadow313 cicd --scan --threshold high --output sarif > gl-results.sarif
  artifacts:
    when: always
    paths:
      - gl-results.sarif
      - gl-vuln.json
    reports:
      sast: gl-results.sarif
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == "main"
"""

PRE_COMMIT_HOOK = """\
#!/usr/bin/env bash
# Shadow313 pre-commit hook
echo "[Shadow313] Running pre-commit security checks..."

DIFF=$(git diff --cached)
if [ -n "$DIFF" ]; then
    echo "$DIFF" | shadow313 cicd --secrets --diff -
    SECRET_RC=$?
    if [ $SECRET_RC -ne 0 ]; then
        echo "[Shadow313] ✗ Secrets detected in staged changes. Commit blocked."
        exit 1
    fi
fi

echo "[Shadow313] ✓ Pre-commit security checks passed."
exit 0
"""


# ── CICDModule ────────────────────────────────────────────────────────────────

class CICDModule:
    """
    shadow313.cicd — Pipeline security integration.
    Registered commands: cicd
    """

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("cicd", self.run)

    def run(self, scan: bool = False, threshold: str = "high",
            output: str = "rich", secrets: bool = False, diff: str = "",
            scan_path: str = ".", generate: str = "",
            pr_summary: bool = False, from_file: str = "",
            quiet: bool = False) -> dict:

        if not quiet:
            self.out.section("CI/CD SECURITY INTEGRATION")
        self.session.audit("cicd", "start")

        result: dict[str, Any] = {
            "timestamp":    _now(),
            "findings":     [],
            "secret_hits":  [],
            "threshold":    threshold,
            "gate_passed":  True,
        }

        # 1. Generate CI/CD config templates
        if generate:
            self._generate_template(generate)
            return result

        # 2. Secret scanning
        if secrets:
            scanner = SecretScanner()
            if diff == "-":
                diff_text = self._read_stdin()
                result["secret_hits"] = scanner.scan_diff(diff_text)
            elif diff:
                diff_text = Path(diff).read_text(errors="replace")
                result["secret_hits"] = scanner.scan_diff(diff_text)
            else:
                result["secret_hits"] = scanner.scan_directory(scan_path)

            if result["secret_hits"]:
                if not quiet:
                    rows = [[h["rule_id"], h["file"], h["line"],
                             h["content"][:60]] for h in result["secret_hits"][:20]]
                    self.out.table(["Rule", "File", "Line", "Content (redacted)"],
                                   rows, f"Secrets Detected ({len(result['secret_hits'])})")
                result["findings"].extend(result["secret_hits"])

        # 3. Full security scan
        if scan:
            vuln_findings = self._run_vuln_scan(scan_path)
            result["findings"].extend(vuln_findings)

        # 4. Threshold gate
        threshold_level = self.SEVERITY_ORDER.get(threshold.lower(), 2)
        blocking = [f for f in result["findings"]
                    if self.SEVERITY_ORDER.get(f.get("severity", "").lower(), 0)
                    >= threshold_level]
        result["gate_passed"]    = len(blocking) == 0
        result["blocking_count"] = len(blocking)

        if not quiet:
            if result["gate_passed"]:
                self.out.success(f"Pipeline gate PASSED (threshold: {threshold})")
            else:
                self.out.error(
                    f"Pipeline gate FAILED — {len(blocking)} finding(s) at "
                    f"or above '{threshold}' severity"
                )

        # 5. Output formats
        if output == "sarif":
            sarif = self._build_sarif(result["findings"])
            print(json.dumps(sarif, indent=2))
        elif output == "junit":
            print(build_junit_xml(result["findings"]))
        elif output == "json":
            print(json.dumps(result, indent=2, default=str))

        # 6. PR summary
        if pr_summary:
            summary = self._ai_pr_summary(result, from_file)
            print(summary)
            result["pr_summary"] = summary

        # Exit code for pipeline gating
        if not result["gate_passed"]:
            import sys
            sys.exit(1)

        self.session.audit("cicd", "complete",
                           f"gate={'pass' if result['gate_passed'] else 'fail'}")
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _run_vuln_scan(self, path: str) -> list[dict]:
        """Run dependency audit if dependency files found."""
        findings = []
        base = Path(path)
        dep_files = list(base.rglob("requirements.txt")) + \
                    list(base.rglob("package.json")) + \
                    list(base.rglob("go.mod"))
        if not dep_files:
            return []
        vuln_module = self.kernel.get_module("vuln")
        if not vuln_module:
            return []
        for dep_file in dep_files[:3]:
            try:
                res = vuln_module.run(audit_deps=str(dep_file), quick=True)
                for f in res.get("findings", []):
                    f["source"] = str(dep_file)
                findings.extend(res.get("findings", []))
            except Exception:
                pass
        return findings

    def _build_sarif(self, findings: list[dict]) -> dict:
        builder = SARIFBuilder()
        for f in findings:
            builder.add_finding(
                rule_id   = f.get("rule_id", f.get("cve", "SHADOW313-FINDING")),
                message   = f.get("desc", f.get("description", "Security finding")),
                level     = f.get("severity", "medium"),
                file_path = f.get("file", ""),
                line      = int(f.get("line", 0)),
                cve       = f.get("cve", ""),
            )
        return builder.build()

    def _generate_template(self, target: str) -> None:
        templates = {
            "github-actions": (".github/workflows/shadow313.yml", GITHUB_ACTIONS_WORKFLOW),
            "gitlab-ci":      (".shadow313-ci.yml",               GITLAB_CI_TEMPLATE),
            "pre-commit":     (".git/hooks/pre-commit",            PRE_COMMIT_HOOK),
        }
        if target not in templates:
            self.out.error(f"Unknown template '{target}'. Available: {', '.join(templates)}")
            return
        filename, content = templates[target]
        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.out.success(f"Generated → {filename}")

    def _ai_pr_summary(self, data: dict, from_file: str = "") -> str:
        if from_file and Path(from_file).exists():
            vuln_data = json.loads(Path(from_file).read_text())
        else:
            vuln_data = data
        ctx = {
            "total_findings": len(data.get("findings", [])),
            "secrets_found":  len(data.get("secret_hits", [])),
            "gate_passed":    data.get("gate_passed", True),
            "threshold":      data.get("threshold", "high"),
            "top_findings":   data.get("findings", [])[:10],
        }
        return self.ai.chat(
            "Generate a concise GitHub PR security review comment in Markdown. "
            "Include: overall security status (✅/⚠️/🚨), key findings summary, "
            "and recommended actions before merge. Keep it under 300 words.",
            context=ctx,
        )

    @staticmethod
    def _read_stdin() -> str:
        import sys
        try:
            return sys.stdin.read()
        except Exception:
            return ""