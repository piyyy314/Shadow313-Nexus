"""Behavioral coverage for the CI submodules introduced in PR #86."""

import json
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock
from xml.etree import ElementTree

import pytest

from shadow313.modules.cicd.cicd_module import CICDModule
from shadow313.modules.cicd.junit_builder import build_junit_xml
from shadow313.modules.cicd.sarif_builder import SARIFBuilder
from shadow313.modules.cicd.secret_scanner import SecretScanner, _shannon_entropy


@pytest.fixture
def cicd():
    return CICDModule(SimpleNamespace(out=Mock(), ai=Mock(), session=Mock()))


@pytest.mark.parametrize(
    ("rule", "content"),
    [
        ("AWS-KEY", "AKIA" + "A" * 16),
        ("AWS-SECRET", "aws_secret_access_key=" + "A" * 40),
        ("GITHUB-TOKEN", "ghp_" + "A" * 36),
        ("GITHUB-TOKEN", "github_pat_" + "A" * 82),
        ("SLACK-TOKEN", "xoxb-" + "A" * 10),
        ("PRIVATE-KEY", "-----BEGIN RSA " + "PRIVATE KEY-----"),
        ("GENERIC-KEY", "api_key=" + "A" * 20),
        ("DB-PASSWORD", "db_password=" + "A" * 8),
        ("GOOGLE-KEY", "AIza" + "A" * 35),
        ("STRIPE-KEY", "sk_live_" + "A" * 24),
        ("JWT", "eyJ" + "A" * 20 + "." + "B" * 20 + "." + "C" * 20),
        ("SENDGRID", "SG." + "A" * 22 + "." + "B" * 43),
        ("HARDCODED-PW", 'password="' + "A" * 8 + '"'),
        ("OTX-KEY", "a" * 64),
    ],
)
def test_secret_patterns_through_file_and_diff_scans(tmp_path, rule, content):
    path = tmp_path / "credentials.txt"
    path.write_text("# heading\n" + content + "\n")
    scanner = SecretScanner()
    for findings, source, line in [
        (scanner.scan_directory(str(tmp_path)), "file_scan", 2),
        (scanner.scan_diff("+++ b/credentials.txt\n+" + content), "git_diff", 2),
    ]:
        hits = [f for f in findings if f["rule_id"] == "SECRET-" + rule]
        assert len(hits) == 1
        assert hits[0]["severity"] == "critical"
        assert hits[0]["source"] == source
        assert hits[0]["line"] == line
        assert hits[0]["file"].endswith("credentials.txt")


def test_diff_ignores_removed_and_context_lines_and_redacts_keys():
    key = "AKIA" + "A" * 16
    diff = f"--- a/config.py\n+++ b/config.py\n-{key}\n {key}\n+token={key}"
    hits = SecretScanner().scan_diff(diff)
    assert len(hits) == 1
    assert hits[0]["file"] == "config.py"
    assert hits[0]["line"] == 5
    assert key not in hits[0]["content"]
    assert "************" in hits[0]["content"]


def test_directory_skips_ignored_and_oversized_files_at_size_boundary(tmp_path):
    content = "AKIA" + "A" * 16
    (tmp_path / "at_limit.txt").write_text(content)
    (tmp_path / "too_large.txt").write_text(content + " ")
    (tmp_path / "image.PNG").write_text(content)
    hidden = tmp_path / "node_modules"
    hidden.mkdir()
    (hidden / "config.txt").write_text(content)
    hits = SecretScanner().scan_directory(str(tmp_path), max_file_size=len(content))
    assert [f["file"] for f in hits] == [str(tmp_path / "at_limit.txt")]


def test_unreadable_file_and_absent_directory_are_safe(tmp_path, monkeypatch):
    path = tmp_path / "gone.txt"
    monkeypatch.setattr(type(path), "read_text", Mock(side_effect=PermissionError))
    assert SecretScanner()._scan_file(path) == []
    assert SecretScanner().scan_directory(str(tmp_path / "absent")) == []


def test_entropy_detects_one_alert_per_added_line():
    sample = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    findings = SecretScanner().scan_diff(f"+{sample} {sample}\n+{'a' * 50}")
    assert [f["rule_id"] for f in findings] == ["SECRET-HIGH-ENTROPY"]
    assert findings[0]["severity"] == "high"
    assert _shannon_entropy("") == 0
    assert _shannon_entropy("aaaa") == 0
    assert _shannon_entropy("abcd") == pytest.approx(2)


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        ("CRITICAL", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "note"),
        ("unexpected", "warning"),
    ],
)
def test_sarif_severity_and_location(severity, level):
    builder = SARIFBuilder(tool_name="test-tool", tool_version="1.2.3")
    builder.add_finding("RULE-1", "message", severity, "src/app.py", 7)
    report = json.loads(builder.to_json())
    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert run["tool"]["driver"]["name"] == "test-tool"
    assert run["results"][0]["level"] == level
    assert run["results"][0]["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/app.py"},
                "region": {"startLine": 7},
            }
        }
    ]


def test_sarif_deduplicates_rules_preserves_results_and_optional_metadata():
    builder = SARIFBuilder()
    builder.add_finding(
        "CVE-TEST", "x" * 250, "high", cve="CVE-TEST", help_uri="https://example.invalid/advisory"
    )
    builder.add_finding("CVE-TEST", "second location", "low", file_path="other.py")
    run = builder.build()["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert len(rules[0]["shortDescription"]["text"]) == 200
    assert rules[0]["properties"] == {"cve": "CVE-TEST"}
    assert rules[0]["helpUri"] == "https://example.invalid/advisory"
    assert len(run["results"]) == 2
    assert "locations" not in run["results"][0]
    assert "region" not in run["results"][1]["locations"][0]["physicalLocation"]
    assert SARIFBuilder().build()["runs"][0]["results"] == []


def test_junit_counts_case_insensitive_failures_and_escapes_messages():
    findings = [
        {"rule_id": "A&B", "desc": "a < b & c", "severity": "HIGH", "file": "a.py"},
        {"rule_id": "B", "severity": "CrItIcAl"},
        {"rule_id": "C", "severity": "medium"},
        {},
    ]
    root = ElementTree.fromstring(  # noqa: S314 - fixture XML
        build_junit_xml(findings, suite_name="scan")
    )
    assert root.attrib["tests"] == "4"
    assert root.attrib["failures"] == "2"
    assert root.attrib["name"] == "scan"
    assert root[0].attrib["name"] == "A&B"
    assert root[0][0].attrib["message"] == "a < b & c"
    assert len(root.findall("testcase/failure")) == 2
    assert len(ElementTree.fromstring(build_junit_xml([]))) == 0  # noqa: S314 - fixture XML


@pytest.mark.xfail(
    strict=True,
    raises=ElementTree.ParseError,
    reason="PR #86 JUnit builder does not escape XML attributes/content",
)
def test_junit_round_trips_quotes_and_xml_content():
    root = ElementTree.fromstring(  # noqa: S314 - fixture XML
        build_junit_xml(
            [
                {
                    "rule_id": 'rule"one',
                    "file": "a&b.py",
                    "desc": 'a "quoted" finding',
                    "severity": "high",
                    "content": "<secret>&value",
                }
            ]
        )
    )
    assert root[0].attrib["name"] == 'rule"one'
    assert root[0][0].text == "<secret>&value"


@pytest.mark.parametrize(
    ("threshold", "severity", "blocks"),
    [
        ("high", "HIGH", True),
        ("high", "medium", False),
        ("critical", "high", False),
        ("critical", "critical", True),
        ("low", "low", True),
        ("info", "info", True),
        ("unknown", "medium", True),
    ],
)
def test_pipeline_gate_thresholds(cicd, monkeypatch, threshold, severity, blocks):
    findings = [{"severity": severity}]
    monkeypatch.setattr(cicd, "_run_vuln_scan", Mock(return_value=findings))
    if blocks:
        with pytest.raises(SystemExit) as exc:
            cicd.run(scan=True, severity_threshold=threshold, quiet=True)
        assert exc.value.code == 1
    else:
        result = cicd.run(scan=True, severity_threshold=threshold, quiet=True)
        assert result["gate_passed"] is True
        assert result["blocking_count"] == 0
        assert result["findings"] == findings


def test_pipeline_writes_sarif_before_blocking_and_reads_stdin(cicd, tmp_path, monkeypatch):
    key = "AKIA" + "A" * 16
    monkeypatch.setattr("sys.stdin", StringIO(f"+++ b/config.py\n+{key}"))
    report = tmp_path / "scan.sarif"
    with pytest.raises(SystemExit, match="1"):
        cicd.run(scan_secrets="-", scan_diff="-", output_sarif=str(report), quiet=True)
    result = json.loads(report.read_text())["runs"][0]["results"][0]
    assert result["ruleId"] == "SECRET-AWS-KEY"
    assert key not in result["message"]["text"]
