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