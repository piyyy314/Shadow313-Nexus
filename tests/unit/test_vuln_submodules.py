"""CVE storage, dependency parsing, contextual scoring and exploit lookup."""

import json
from io import BytesIO
from unittest.mock import Mock

import pytest

from shadow313.modules.vuln.cve_db import CVEDatabase
from shadow313.modules.vuln.cvss import CVSSScorer
from shadow313.modules.vuln.dep_audit import DependencyAuditor
from shadow313.modules.vuln.exploit_check import ExploitChecker


@pytest.fixture
def db(tmp_path):
    database = CVEDatabase(tmp_path / "cves.sqlite")
    yield database
    database._conn.close()


def test_cve_insert_replace_search_order_limit_and_parameterization(db):
    db.insert_cve(
        {
            "id": "CVE-TEST-1",
            "description": "widget " + "x" * 250,
            "cvss_v3": 4.0,
            "cpe": ["cpe:test"],
            "references": ["https://example.invalid"],
        }
    )
    db.insert_cve({"id": "CVE-TEST-2", "description": "widget issue", "cvss_v3": 9.8})
    assert [row["cve"] for row in db.search_by_keyword("widget")] == ["CVE-TEST-2", "CVE-TEST-1"]
    assert len(db.search_by_keyword("widget", limit=1)) == 1
    assert len(db.search_by_keyword("CVE-TEST-1")[0]["description"]) == 200
    assert len(db.get_cve("CVE-TEST-1")["description"]) > 200
    assert json.loads(db.get_cve("CVE-TEST-1")["cpe"]) == ["cpe:test"]
    assert db.search_by_keyword("' OR 1=1 --") == []
    assert db.get_cve("' OR 1=1 --") is None
    db.insert_cve({"id": "CVE-TEST-1", "description": "fixed", "cvss_v3": 1.0})
    assert db.record_count() == 2
    assert db.get_cve("CVE-TEST-1")["description"] == "fixed"
    assert db.get_cve("missing") is None


@pytest.mark.parametrize(
    ("metric", "score", "severity"),
    [
        ("cvssMetricV31", 9.8, "CRITICAL"),
        ("cvssMetricV30", 7.5, "HIGH"),
        (None, 0.0, "UNKNOWN"),
    ],
)
def test_nvd_import_selects_english_and_supported_cvss_metrics(
    db, monkeypatch, metric, score, severity
):
    metrics = (
        {metric: [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]} if metric else {}
    )
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST-3",
                    "descriptions": [
                        {"lang": "fr", "value": "français"},
                        {"lang": "en", "value": "widget flaw"},
                    ],
                    "metrics": metrics,
                    "published": "2026-01-01",
                    "lastModified": "2026-02-01",
                    "references": [{"url": f"https://example.invalid/{i}"} for i in range(7)],
                }
            }
        ]
    }
    fetch = Mock(return_value=BytesIO(json.dumps(payload).encode()))
    monkeypatch.setattr("shadow313.modules.vuln.cve_db.urlreq.urlopen", fetch)
    records = db.update_from_nvd("widget", api_key="synthetic-test-key")
    assert len(records) == 1
    assert records[0]["description"] == "widget flaw"
    assert records[0]["cvss_v3"] == score
    assert records[0]["severity"] == severity
    assert len(records[0]["references"]) == 5
    assert db.record_count() == 1
    assert json.loads(db.get_cve("CVE-TEST-3")["references"]) == records[0]["references"]
    assert fetch.call_args.args[0].get_header("Apikey") == "synthetic-test-key"
    assert fetch.call_args.kwargs["timeout"] == 30


def test_nvd_failure_leaves_existing_database_untouched(db, monkeypatch):
    db.insert_cve({"id": "CVE-TEST-1"})
    monkeypatch.setattr(
        "shadow313.modules.vuln.cve_db.urlreq.urlopen", Mock(side_effect=OSError("offline"))
    )
    assert db.update_from_nvd() == [{"error": "offline"}]
    assert db.record_count() == 1


@pytest.mark.parametrize(
    ("filename", "text", "expected"),
    [
        (
            "requirements.txt",
            "# comment\nRequests==2.0\nPyYAML>=6.0\n\n",
            {"requests": "2.0", "pyyaml": "6.0"},
        ),
        (
            "package.json",
            '{"dependencies":{"Widget":"1"},"devDependencies":{"Dev":"2"}}',
            {"widget": "1", "dev": "2"},
        ),
        ("go.mod", "require (\n example.invalid/team/Widget v1.2.3\n)\n", {"widget": "1.2.3"}),
        ("Gemfile.lock", "GEM\n  specs:\n    Widget (1.2.3)\n", {"widget": "1.2.3"}),
        ("Cargo.toml", '[dependencies]\nWidget = "1.2.3"\n', {"widget": "1.2.3"}),
    ],
)
def test_dependency_audit_dispatches_each_ecosystem(tmp_path, filename, text, expected):
    path = tmp_path / filename
    path.write_text(text)
    db = Mock()
    db.search_by_keyword.side_effect = lambda package, limit: [
        {"cve": "CVE-TEST-" + package, "cvss_v3": 7.5},
    ]
    findings = DependencyAuditor(db).audit_file(str(path))
    assert {f["package"]: f["version"] for f in findings} == expected
    assert all(f["dep_source"] == filename for f in findings)
    assert sorted(call.args[0] for call in db.search_by_keyword.call_args_list) == sorted(expected)
    assert all(call.kwargs == {"limit": 5} for call in db.search_by_keyword.call_args_list)


def test_dependency_errors_and_invalid_json_do_not_query_database(tmp_path):
    db = Mock()
    auditor = DependencyAuditor(db)
    assert "File not found" in auditor.audit_file(str(tmp_path / "absent"))[0]["error"]
    path = tmp_path / "unsupported.txt"
    path.touch()
    assert auditor.audit_file(str(path)) == [{"error": "Unsupported file: unsupported.txt"}]
    path = tmp_path / "package.json"
    path.write_text("not json")
    assert auditor.audit_file(str(path)) == []
    db.search_by_keyword.assert_not_called()


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0, "NONE"),
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7, "HIGH"),
        (8.9, "HIGH"),
        (9, "CRITICAL"),
        (10, "CRITICAL"),
    ],
)
def test_cvss_severity_boundaries(score, severity):
    assert CVSSScorer.severity_from_score(score) == severity
    assert CVSSScorer.score_in_range(score, severity.lower()) is True


@pytest.mark.parametrize(
    ("exploit", "internet", "kev", "expected"),
    [
        (False, False, False, 5.0),
        (True, False, False, 6.5),
        (False, True, False, 5.5),
        (True, True, False, 7.2),
        (False, False, True, 10.0),
    ],
)
def test_contextual_modifiers_are_composed_and_kev_overrides(exploit, internet, kev, expected):
    assert CVSSScorer.contextual_score(5.0, exploit, internet, kev) == expected
    assert CVSSScorer.contextual_score(9.8, True, True) == 10.0


def test_exploit_checker_caps_details_preserves_total_and_caches(monkeypatch):
    pocs = [{"html_url": f"https://example.invalid/{i}", "stargazers_count": i} for i in range(7)]
    fetch = Mock(return_value=BytesIO(json.dumps({"pocs": pocs}).encode()))
    monkeypatch.setattr("shadow313.modules.vuln.exploit_check.urlreq.urlopen", fetch)
    checker = ExploitChecker()
    result = checker.check("CVE-TEST-1")
    assert result["poc_count"] == 7
    assert result["pocs"] == [
        {"url": p["html_url"], "stars": p["stargazers_count"]} for p in pocs[:5]
    ]
    assert checker.check("CVE-TEST-1") == result
    fetch.assert_called_once()


def test_exploit_lookup_failure_is_safe_and_cached(monkeypatch):
    fetch = Mock(side_effect=OSError("offline"))
    monkeypatch.setattr("shadow313.modules.vuln.exploit_check.urlreq.urlopen", fetch)
    checker = ExploitChecker()
    assert checker.check("CVE-TEST-1") == {"cve": "CVE-TEST-1", "poc_count": 0, "pocs": []}
    assert checker.check("CVE-TEST-1")["poc_count"] == 0
    fetch.assert_called_once()
