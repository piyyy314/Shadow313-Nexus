"""JUnit XML builder for CI ingestion without XML parser dependencies."""

from __future__ import annotations

import html
from datetime import UTC, datetime


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).isoformat()


def _xml_escape(value: object) -> str:
    """Escape valid XML 1.0 text and attribute characters."""
    text = str(value)
    valid = (
        character
        for character in text
        if character in "\t\n\r"
        or 0x20 <= ord(character) <= 0xD7FF
        or 0xE000 <= ord(character) <= 0xFFFD
        or 0x10000 <= ord(character) <= 0x10FFFF
    )
    return html.escape("".join(valid), quote=True)


def build_junit_xml(findings: list[dict], suite_name: str = "shadow313") -> str:
    """Build escaped JUnit XML; untrusted XML parsing is a separate concern."""
    failures = sum(
        str(finding.get("severity", "")).lower() in ("critical", "high") for finding in findings
    )
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<testsuite name="{_xml_escape(suite_name)}" '
            f'tests="{len(findings)}" failures="{failures}" '
            f'timestamp="{_xml_escape(_now())}">'
        ),
    ]

    for finding in findings:
        parts.append(
            f'<testcase name="{_xml_escape(finding.get("rule_id", "finding"))}" '
            f'classname="{_xml_escape(finding.get("file", ""))}">'
        )
        if str(finding.get("severity", "")).lower() in ("critical", "high"):
            parts.append(
                f'<failure message="{_xml_escape(finding.get("desc", ""))}">'
                f'{_xml_escape(finding.get("content", ""))}</failure>'
            )
        parts.append("</testcase>")

    parts.append("</testsuite>")
    return "\n".join(parts) + "\n"
