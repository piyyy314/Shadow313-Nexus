"""Unit tests — shadow313.modules.vuln v4"""
import pytest
from shadow313.modules.vuln.vuln import (
    CVEDatabase,
    DependencyAuditor,
    compute_risk_score,
)


class TestCVEDatabase:
    def test_init_creates_db(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        assert (tmp_path / "test.db").exists()

    def test_insert_and_retrieve(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        cve = {
            "id":          "CVE-2024-9999",
            "description": "Test vulnerability in test software",
            "cvss_v3":     9.8,
            "severity":    "CRITICAL",
            "published":   "2024-01-01",
            "modified":    "2024-01-02",
            "cpe":         [],
            "references":  [],
        }
        db.insert_cve(cve)
        result = db.get_cve("CVE-2024-9999")
        assert result is not None
        assert result["cve"]      == "CVE-2024-9999"
        assert result["cvss_v3"]  == 9.8
        assert result["severity"] == "CRITICAL"

    def test_search_by_keyword(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        db.insert_cve({
            "id":"CVE-2024-1111","description":"OpenSSH remote code execution",
            "cvss_v3":9.8,"severity":"CRITICAL","published":"2024-01-01",
            "modified":"2024-01-01","cpe":[],"references":[],
        })
        results = db.search_by_keyword("OpenSSH")
        assert len(results) >= 1
        assert any(r["cve"] == "CVE-2024-1111" for r in results)

    def test_search_by_keyword_empty(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        results = db.search_by_keyword("nonexistent_software_xyz")
        assert results == []

    def test_record_count(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        assert db.record_count() == 0
        db.insert_cve({
            "id":"CVE-2024-0001","description":"Test","cvss_v3":5.0,
            "severity":"MEDIUM","published":"2024-01-01","modified":"2024-01-01",
            "cpe":[],"references":[],
        })
        assert db.record_count() == 1

    def test_insert_or_replace(self, tmp_path):
        """INSERT OR REPLACE should update existing CVE."""
        db = CVEDatabase(db_path=tmp_path / "test.db")
        cve = {"id":"CVE-2024-0001","description":"Original","cvss_v3":5.0,
               "severity":"MEDIUM","published":"2024-01-01","modified":"2024-01-01",
               "cpe":[],"references":[]}
        db.insert_cve(cve)
        cve["description"] = "Updated"
        cve["cvss_v3"]     = 9.0
        db.insert_cve(cve)
        result = db.get_cve("CVE-2024-0001")
        assert result["description"] == "Updated"
        assert result["cvss_v3"]     == 9.0
        assert db.record_count()     == 1  # still only 1 record

    def test_get_nonexistent_cve(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        result = db.get_cve("CVE-9999-9999")
        assert result is None


class TestDependencyAuditor:
    def test_parse_requirements_txt(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        auditor = DependencyAuditor(db)
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests>=2.28.0\nflask==2.3.0\nnumpy>=1.24\n")
        packages = auditor._parse_requirements(req_file.read_text())
        assert "requests" in packages
        assert "flask"    in packages
        assert "numpy"    in packages

    def test_parse_requirements_with_extras(self, tmp_path):
        """FIX: requirements with extras like package[extra]>=1.0 should parse correctly."""
        db = CVEDatabase(db_path=tmp_path / "test.db")
        auditor = DependencyAuditor(db)
        text = "uvicorn[standard]>=0.24\ncryptography[ssh]>=41.0\n"
        packages = auditor._parse_requirements(text)
        assert "uvicorn"      in packages
        assert "cryptography" in packages

    def test_parse_requirements_ignores_comments(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        auditor = DependencyAuditor(db)
        text = "# This is a comment\nrequests>=2.28\n# Another comment\n"
        packages = auditor._parse_requirements(text)
        assert "requests" in packages
        assert len(packages) == 1

    def test_parse_package_json(self, tmp_path):
        import json
        db = CVEDatabase(db_path=tmp_path / "test.db")
        auditor = DependencyAuditor(db)
        pkg_json = json.dumps({
            "dependencies":    {"express": "^4.18.0", "lodash": "^4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        })
        packages = auditor._parse_package_json(pkg_json)
        assert "express" in packages
        assert "lodash"  in packages
        assert "jest"    in packages

    def test_parse_go_mod(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        auditor = DependencyAuditor(db)
        go_mod = "module example.com/myapp\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/crypto v0.14.0\n)\n"
        packages = auditor._parse_go_mod(go_mod)
        assert "gin"    in packages
        assert "crypto" in packages

    def test_audit_nonexistent_file(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        auditor = DependencyAuditor(db)
        result = auditor.audit_file(str(tmp_path / "nonexistent.txt"))
        assert len(result) == 1
        assert "error" in result[0]

    def test_audit_unsupported_file(self, tmp_path):
        db = CVEDatabase(db_path=tmp_path / "test.db")
        auditor = DependencyAuditor(db)
        f = tmp_path / "unsupported.xyz"
        f.write_text("content")
        result = auditor.audit_file(str(f))
        assert len(result) == 1
        assert "error" in result[0]


class TestComputeRiskScore:
    def test_base_score_no_modifiers(self):
        score = compute_risk_score(7.5, False, False)
        assert score == 7.5

    def test_exploit_increases_score(self):
        score = compute_risk_score(7.5, True, False)
        assert score > 7.5

    def test_internet_facing_increases_score(self):
        score = compute_risk_score(7.5, False, True)
        assert score > 7.5

    def test_both_modifiers_increase_score(self):
        score = compute_risk_score(7.5, True, True)
        assert score > 7.5

    def test_score_capped_at_10(self):
        """FIX: score should never exceed 10.0."""
        score = compute_risk_score(9.9, True, True)
        assert score <= 10.0

    def test_zero_cvss(self):
        score = compute_risk_score(0.0, False, False)
        assert score == 0.0

    def test_max_cvss_with_modifiers_capped(self):
        score = compute_risk_score(10.0, True, True)
        assert score == 10.0

    def test_returns_float(self):
        score = compute_risk_score(5.0, False, False)
        assert isinstance(score, float)

    def test_rounded_to_one_decimal(self):
        score = compute_risk_score(7.3, True, False)
        # Should be rounded to 1 decimal place
        assert score == round(score, 1)