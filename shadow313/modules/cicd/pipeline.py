"""
Shadow313 NEXUS — CI/CD Security Pipeline
Secret scanning, SARIF export, dependency checking.
"""
from __future__ import annotations
import json, hashlib, re, uuid
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from pathlib import Path

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
        self._findings: List[Dict] = []

    def scan_secrets(self, paths: List[str] = None) -> Dict:
        findings = []
        scan_paths = [Path(p) for p in (paths or [str(self.repo_path)])]
        for sp in scan_paths:
            if sp.is_file():
                findings.extend(self._scan_file(sp))
            elif sp.is_dir():
                for f in sp.rglob("*"):
                    if f.is_file() and f.suffix in [".py",".js",".yml",".env",".json",".sh"]:
                        if ".git" not in str(f) and "node_modules" not in str(f):
                            findings.extend(self._scan_file(f))
        self._findings.extend(findings)
        return {
            "scan_type": "secret_detection",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "secrets_found": len(findings),
            "findings": findings,
            "passed": len(findings) == 0
        }

    def _scan_file(self, path: Path) -> List[Dict]:
        findings = []
        try:
            content = path.read_text(errors="ignore")
            for ln, line in enumerate(content.splitlines(), 1):
                for pattern, stype in SECRET_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "file": str(path), "line": ln, "type": stype,
                            "severity": "CRITICAL", "mitre_ttp": "T1552.001",
                            "rule_id": f"S313-{hashlib.md5(pattern.encode()).hexdigest()[:6].upper()}"
                        })
        except Exception:
            pass
        return findings

    def generate_sarif(self) -> Dict:
        rules = []; results = []
        for f in self._findings:
            rid = f.get("rule_id", "S313-UNKNOWN")
            if not any(r["id"] == rid for r in rules):
                rules.append({"id": rid, "name": f["type"].replace(" ", ""),
                               "shortDescription": {"text": f["type"]},
                               "defaultConfiguration": {"level": "error"}})
            results.append({
                "ruleId": rid, "level": "error",
                "message": {"text": f"{f['type']} detected"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]}
                }}]
            })
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Shadow313 NEXUS",
                                          "version": "4.0.0", "rules": rules}},
                      "results": results}]
        }

    def gate_check(self) -> Tuple[bool, List[str]]:
        failures = []
        critical = [f for f in self._findings if f.get("severity") == "CRITICAL"]
        if critical:
            failures.append(f"{len(critical)} critical secrets detected")
        return len(failures) == 0, failures
