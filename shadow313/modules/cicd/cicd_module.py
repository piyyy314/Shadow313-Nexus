"""shadow313.modules.cicd.cicd_module — CICDModule orchestrator."""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .sarif_builder  import SARIFBuilder
from .secret_scanner import SecretScanner
from .junit_builder  import build_junit_xml

GITHUB_ACTIONS_WORKFLOW = """\
# Shadow313 v2 Security Scan — GitHub Actions
name: Shadow313 Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'
      - name: Install Shadow313
        run: pip install shadow313
      - name: Run Secret Scan
        run: git diff HEAD~1 | shadow313 cicd --scan-secrets - --output-sarif secrets.sarif || true
      - name: Run Full Security Scan
        run: shadow313 cicd --scan-secrets ./ --severity-threshold high --output-sarif shadow313.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: shadow313.sarif
"""

GITLAB_CI_TEMPLATE = """\
shadow313-security:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install shadow313
  script:
    - shadow313 cicd --scan-secrets ./ --severity-threshold high --output-sarif gl-results.sarif
  artifacts:
    when: always
    paths:
      - gl-results.sarif
    reports:
      sast: gl-results.sarif
"""

PRE_COMMIT_HOOK = """\
#!/usr/bin/env bash
echo "[Shadow313] Running pre-commit security checks..."
DIFF=$(git diff --cached)
if [ -n "$DIFF" ]; then
    echo "$DIFF" | shadow313 cicd --scan-diff - --severity-threshold critical
    if [ $? -ne 0 ]; then
        echo "[Shadow313] Secrets detected. Commit blocked."
        exit 1
    fi
fi
echo "[Shadow313] Pre-commit checks passed."
exit 0
"""


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class CICDModule:
    """shadow313.cicd — Pipeline security integration."""

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def __init__(self, kernel) -> None:
        """Bind pipeline checks to the kernel and its session services."""
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        """Register the cicd command with the supplied kernel."""
        kernel.register("cicd", self.run)

    def run(self, scan: bool = False, threshold: str = "high",
            output: str = "rich", secrets: bool = False, diff: str = "",
            scan_path: str = ".", generate: str = "",
            pr_summary: bool = False, from_file: str = "",
            quiet: bool = False,
            # v2 flag names
            scan_secrets: str = "", scan_diff: str = "",
            output_sarif: str = "", output_junit: bool = False,
            gen_workflow: str = "", severity_threshold: str = "") -> dict:
        """Run selected security checks and return the pipeline gate result.

        The v2 aliases override their corresponding v1 options. Secret diff
        input may be a filename, literal diff, or "-" for stdin; it is scanned
        only when secret scanning is enabled. Unknown thresholds use medium.
        A template request writes the template and returns before scanning.

        Reports are printed or written to output_sarif. A failed severity gate
        raises SystemExit(1) after report generation. File I/O errors propagate.
        """
        if not quiet:
            self.out.section("CI/CD SECURITY INTEGRATION")
        self.session.audit("cicd", "start")

        # Normalise v1/v2 flag aliases
        if scan_secrets:
            secrets   = True
            scan_path = scan_secrets
        if scan_diff:
            diff = scan_diff
        if severity_threshold:
            threshold = severity_threshold
        if gen_workflow:
            generate = gen_workflow

        result: dict[str, Any] = {
            "timestamp":    _now(),
            "findings":     [],
            "secret_hits":  [],
            "threshold":    threshold,
            "gate_passed":  True,
        }

        if generate:
            self._generate_template(generate)
            return result

        if secrets or scan_secrets:
            scanner = SecretScanner()
            if diff == "-":
                diff_text = sys.stdin.read()
                result["secret_hits"] = scanner.scan_diff(diff_text)
            elif diff:
                diff_text = Path(diff).read_text(errors="replace") if Path(diff).exists() else diff
                result["secret_hits"] = scanner.scan_diff(diff_text)
            else:
                result["secret_hits"] = scanner.scan_directory(scan_path)
            if result["secret_hits"] and not quiet:
                rows = [[h["rule_id"], h["file"], h["line"],
                         h["content"][:60]] for h in result["secret_hits"][:20]]
                self.out.table(["Rule", "File", "Line", "Content (redacted)"],
                               rows, f"Secrets Detected ({len(result['secret_hits'])})")
            result["findings"].extend(result["secret_hits"])

        if scan:
            vuln_findings = self._run_vuln_scan(scan_path)
            result["findings"].extend(vuln_findings)

        threshold_level = self.SEVERITY_ORDER.get(threshold.lower(), 2)
        blocking = [f for f in result["findings"]
                    if self.SEVERITY_ORDER.get(f.get("severity", "").lower(), 0) >= threshold_level]
        result["gate_passed"]    = len(blocking) == 0
        result["blocking_count"] = len(blocking)

        if not quiet:
            if result["gate_passed"]:
                self.out.success(f"Pipeline gate PASSED (threshold: {threshold})")
            else:
                self.out.error(f"Pipeline gate FAILED — {len(blocking)} finding(s) at or above '{threshold}'")

        sarif_path = output_sarif
        if output == "sarif" or sarif_path:
            sarif = self._build_sarif(result["findings"])
            sarif_json = json.dumps(sarif, indent=2)
            if sarif_path:
                Path(sarif_path).write_text(sarif_json)
                self.out.success(f"SARIF written → {sarif_path}")
            else:
                print(sarif_json)
        elif output == "junit" or output_junit:
            print(build_junit_xml(result["findings"]))
        elif output == "json":
            print(json.dumps(result, indent=2, default=str))

        if pr_summary:
            summary = self._ai_pr_summary(result, from_file)
            print(summary)
            result["pr_summary"] = summary

        if not result["gate_passed"]:
            sys.exit(1)

        self.session.audit("cicd", "complete",
                           f"gate={'pass' if result['gate_passed'] else 'fail'}")
        return result

    def ai_context(self) -> dict:
        """Return the pipeline security context for AI requests."""
        return {"module": "cicd", "mode": "pipeline_security"}

    def _run_vuln_scan(self, path: str) -> list[dict]:
        """Audit up to three dependency files below path using the vuln module.

        Return collected findings; absent modules and individual audit failures
        contribute no findings.
        """
        findings = []
        base = Path(path)
        dep_files = (list(base.rglob("requirements.txt")) +
                     list(base.rglob("package.json")) +
                     list(base.rglob("go.mod")))
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
        """Convert findings to a SARIF report; invalid numeric line values propagate."""
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
        """Write the selected CI template, creating parents and replacing any file.

        Unknown targets return without writing. File I/O errors propagate.
        """
        templates = {
            "github-actions": (".github/workflows/shadow313.yml", GITHUB_ACTIONS_WORKFLOW),
            "github":         (".github/workflows/shadow313.yml", GITHUB_ACTIONS_WORKFLOW),
            "gitlab-ci":      (".shadow313-ci.yml",               GITLAB_CI_TEMPLATE),
            "gitlab":         (".shadow313-ci.yml",               GITLAB_CI_TEMPLATE),
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
        """Return an AI security summary of the findings; from_file is unused."""
        ctx = {
            "total_findings": len(data.get("findings", [])),
            "secrets_found":  len(data.get("secret_hits", [])),
            "gate_passed":    data.get("gate_passed", True),
            "threshold":      data.get("threshold", "high"),
            "top_findings":   data.get("findings", [])[:10],
        }
        return self.ai.chat(
            "Generate a concise GitHub PR security review comment in Markdown. "
            "Include: overall security status, key findings summary, "
            "and recommended actions before merge. Keep it under 300 words.",
            context=ctx,
        )

    @staticmethod
    def _read_stdin() -> str:
        """Read stdin, returning an empty string if reading fails."""
        try:
            return sys.stdin.read()
        except Exception:
            return ""