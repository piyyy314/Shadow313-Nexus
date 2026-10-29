"""shadow313.modules.cicd.sarif_builder — SARIF 2.1.0 compliant report builder."""
from __future__ import annotations
import json
from datetime import datetime, timezone

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SARIFBuilder:
    def __init__(self, tool_name: str = "shadow313", tool_version: str = "2.0.0") -> None:
        self.tool_name    = tool_name
        self.tool_version = tool_version
        self._rules: list[dict]   = []
        self._results: list[dict] = []
        self._rule_ids: set[str]  = set()

    def add_finding(self, rule_id: str, message: str, level: str,
                    file_path: str = "", line: int = 0,
                    cve: str = "", help_uri: str = "") -> None:
        if rule_id not in self._rule_ids:
            self._rule_ids.add(rule_id)
            rule: dict = {
                "id":   rule_id,
                "name": rule_id.replace("-", " ").title(),
                "shortDescription": {"text": message[:200]},
            }
            if help_uri:
                rule["helpUri"] = help_uri
            if cve:
                rule["properties"] = {"cve": cve}
            self._rules.append(rule)
        result: dict = {
            "ruleId":  rule_id,
            "level":   SEVERITY_TO_SARIF.get(level.lower(), "warning"),
            "message": {"text": message},
        }
        if file_path:
            location: dict = {"physicalLocation": {"artifactLocation": {"uri": file_path}}}
            if line > 0:
                location["physicalLocation"]["region"] = {"startLine": line}
            result["locations"] = [location]
        self._results.append(result)

    def build(self) -> dict:
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {"driver": {
                    "name":           self.tool_name,
                    "version":        self.tool_version,
                    "informationUri": "https://github.com/shadow313/shadow313",
                    "rules":          self._rules,
                }},
                "results":     self._results,
                "invocations": [{"executionSuccessful": True, "endTimeUtc": _now()}],
            }],
        }

    def to_json(self) -> str:
        return json.dumps(self.build(), indent=2)