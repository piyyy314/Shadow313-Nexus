"""shadow313.modules.cicd.junit_builder — JUnit XML builder for CI ingestion."""
from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO
from xml.sax.saxutils import XMLGenerator


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).isoformat()


def build_junit_xml(findings: list[dict], suite_name: str = "shadow313") -> str:
    """Build escaped JUnit XML without parsing or evaluating untrusted XML.

    XMLGenerator escapes all attribute values and character data. This module
    only constructs XML; consumers parsing untrusted XML must use a hardened
    parser such as defusedxml.ElementTree.
    """
    failures = sum(
        str(f.get("severity", "")).lower() in ("critical", "high")
        for f in findings
    )
    output = StringIO()
    xml = XMLGenerator(output, encoding="UTF-8", short_empty_elements=True)
    xml.startDocument()
    xml.startElement(
        "testsuite",
        {
            "name": str(suite_name),
            "tests": str(len(findings)),
            "failures": str(failures),
            "timestamp": _now(),
        },
    )

    for finding in findings:
        xml.startElement(
            "testcase",
            {
                "name": str(finding.get("rule_id", "finding")),
                "classname": str(finding.get("file", "")),
            },
        )
        if str(finding.get("severity", "")).lower() in ("critical", "high"):
            xml.startElement(
                "failure",
                {"message": str(finding.get("desc", ""))},
            )
            xml.characters(str(finding.get("content", "")))
            xml.endElement("failure")
        xml.endElement("testcase")

    xml.endElement("testsuite")
    xml.endDocument()
    return output.getvalue()
