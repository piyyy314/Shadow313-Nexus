"""shadow313.modules.cicd.junit_builder — JUnit XML builder for CI ingestion."""
from __future__ import annotations
from datetime import datetime, timezone


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def build_junit_xml(findings: list[dict], suite_name: str = "shadow313") -> str:
    """Return JUnit XML text with one test case per finding.

    Only high and critical severities count as failures, ignoring case.
    """
    from xml.etree.ElementTree import Element, SubElement, tostring

    failures = sum(f.get("severity", "").lower() in ("critical", "high") for f in findings)
    root = Element("testsuite", name=str(suite_name), tests=str(len(findings)),
                   failures=str(failures), timestamp=_now())
    for finding in findings:
        case = SubElement(root, "testcase", name=str(finding.get("rule_id", "finding")),
                          classname=str(finding.get("file", "")))
        if finding.get("severity", "").lower() in ("critical", "high"):
            failure = SubElement(case, "failure", message=str(finding.get("desc", "")))
            failure.text = str(finding.get("content", ""))
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(root, encoding="unicode")
