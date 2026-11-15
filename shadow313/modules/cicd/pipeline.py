"""Shadow313 NEXUS — CI/CD security pipeline.

Secret scanning, SARIF export, and dependency-check reporting.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Key"),
    (r"-----BEGIN.*PRIVATE KEY-----", "Private Key"),
    (r"password\s*=\s*['\"]{1}\S{8,}", "Hardcoded Password"),
    (r"api_key\s*=\s*['\"]{1}\S{8,}", "API Key"),
]


class CICDPipeline:
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self._findings: list[dict[str, object]] = []

    def scan_secrets(self, paths: list[str] | None = None) -> dict[str, object]:
        findings: list[dict[str, object]] = []
        scan_paths = [Path(path) for path in (paths or [str(self.repo_path)])]
        for scan_path in scan_paths:
            if scan_path.is_file():
                findings.extend(self._scan_file(scan_path))
            elif scan_path.is_dir():
                for file_path in scan_path.rglob("*"):
                    if (
                        file_path.is_file()
                        and file_path.suffix in {".py", ".js", ".yml", ".env", ".json", ".sh"}
                        and ".git" not in str(file_path)
                        and "node_modules" not in str(file_path)
                    ):
                        findings.extend(self._scan_file(file_path))
        self._findings.extend(findings)
        return {
            "scan_type": "secret_detection",
            "timestamp": datetime.now(UTC).isoformat(),
            "secrets_found": len(findings),
            "findings": findings,
            "passed": not findings,
        }

    def _scan_file(self, path: Path) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        try:
            content = path.read_text(errors="ignore")
        except OSError as exc:
            logger.warning("Unable to read %s during secret scan: %s", path, exc)
            return findings

        for line_number, line in enumerate(content.splitlines(), 1):
            for pattern, secret_type in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    rule_digest = (
                        hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:6].upper()
                    )
                    findings.append(
                        {
                            "file": str(path),
                            "line": line_number,
                            "type": secret_type,
                            "severity": "CRITICAL",
                            "mitre_ttp": "T1552.001",
                            "rule_id": f"S313-{rule_digest}",
                        }
                    )
        return findings

    def generate_sarif(self) -> dict[str, object]:
        rules: list[dict[str, object]] = []
        results: list[dict[str, object]] = []
        for finding in self._findings:
            rule_id = finding.get("rule_id", "S313-UNKNOWN")
            if not any(rule["id"] == rule_id for rule in rules):
                rules.append(
                    {
                        "id": rule_id,
                        "name": str(finding["type"]).replace(" ", ""),
                        "shortDescription": {"text": finding["type"]},
                        "defaultConfiguration": {"level": "error"},
                    }
                )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {"text": f"{finding['type']} detected"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding["file"]},
                                "region": {"startLine": finding["line"]},
                            }
                        }
                    ],
                }
            )
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Shadow313 NEXUS",
                            "version": "4.0.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def gate_check(self) -> tuple[bool, list[str]]:
        critical = [finding for finding in self._findings if finding.get("severity") == "CRITICAL"]
        failures = [f"{len(critical)} critical secrets detected"] if critical else []
        return not failures, failures
