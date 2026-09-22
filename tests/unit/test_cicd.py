"""Unit tests — shadow313.modules.cicd v4"""
import pytest
from shadow313.modules.cicd.cicd import (
    SecretScanner,
    SARIFBuilder,
    build_junit_xml,
    GITHUB_ACTIONS_WORKFLOW,
    GITLAB_CI_TEMPLATE,
    PRE_COMMIT_HOOK,
)


class TestSecretScanner:
    def test_aws_key_detection(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('AWS_ACCESS_KEY_ID = "EXAMPLEAWSKEY00000001"\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert any(r["rule_id"] == "SECRET-AWS-KEY" for r in findings)

    def test_github_token_detection(self, tmp_path):
        f = tmp_path / "deploy.sh"
        f.write_text('TOKEN="test_github_token_placeholder_not_real"\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert any(r["rule_id"] == "SECRET-GITHUB-TOKEN" for r in findings)

    def test_private_key_detection(self, tmp_path):
        f = tmp_path / "key.pem"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) > 0

    def test_no_false_positive_on_clean_file(self, tmp_path):
        f = tmp_path / "main.py"
        f.write_text('print("Hello, World!")\n# No secrets here\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_diff_scan(self):
        diff = (
            "--- a/config.py\n+++ b/config.py\n"
            "@@ -1 +1 @@\n"
            '+API_KEY = "AIzaSyAbcdefghijklmnopqrstuvwxyz1234567"\n'
        )
        scanner  = SecretScanner()
        findings = scanner.scan_diff(diff)
        assert any(r["rule_id"] == "SECRET-GOOGLE-KEY" for r in findings)

    def test_redaction_applied(self, tmp_path):
        f = tmp_path / "creds.py"
        f.write_text('key = "EXAMPLEAWSKEY000000012345678901"\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        for finding in findings:
            content = finding.get("content", "")
            # The full key should be redacted
            assert "EXAMPLEAWSKEY000000012345678901" not in content

    def test_ignore_node_modules(self, tmp_path):
        d = tmp_path / "node_modules" / "pkg"
        d.mkdir(parents=True)
        f = d / "index.js"
        f.write_text('const key = "EXAMPLEAWSKEY00000001"\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_ignore_git_dir(self, tmp_path):
        d = tmp_path / ".git"
        d.mkdir()
        f = d / "config"
        f.write_text('const key = "EXAMPLEAWSKEY00000001"\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) == 0

    def test_stripe_key_detection(self, tmp_path):
        f = tmp_path / "payment.py"
        f.write_text('STRIPE_KEY = "test_stripe_key_placeholder_not_real"\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert any(r["rule_id"] == "SECRET-STRIPE-KEY" for r in findings)

    def test_hardcoded_password_detection(self, tmp_path):
        f = tmp_path / "db.py"
        f.write_text('password = "supersecretpassword123"\n')
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert any(r["rule_id"] == "SECRET-HARDCODED-PW" for r in findings)


class TestSARIFBuilder:
    def test_valid_sarif_structure(self):
        builder = SARIFBuilder()
        builder.add_finding("SEC-001", "Test finding", "high",
                            file_path="src/main.py", line=42)
        sarif = builder.build()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "shadow313"
        assert len(run["results"]) == 1
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_severity_mapping(self):
        builder = SARIFBuilder()
        builder.add_finding("CRIT-001", "Critical", "critical")
        builder.add_finding("MED-001",  "Medium",   "medium")
        builder.add_finding("LOW-001",  "Low",      "low")
        sarif   = builder.build()
        results = sarif["runs"][0]["results"]
        levels  = {r["ruleId"]: r["level"] for r in results}
        assert levels["CRIT-001"] == "error"
        assert levels["MED-001"]  == "warning"
        assert levels["LOW-001"]  == "note"

    def test_deduplication_of_rules(self):
        builder = SARIFBuilder()
        builder.add_finding("RULE-001", "First",  "high", line=1)
        builder.add_finding("RULE-001", "Second", "high", line=2)
        sarif = builder.build()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1          # Rule registered once
        results = sarif["runs"][0]["results"]
        assert len(results) == 2        # But two result instances

    def test_location_with_line(self):
        builder = SARIFBuilder()
        builder.add_finding("LOC-001", "Found it", "high",
                            file_path="src/auth.py", line=99)
        sarif  = builder.build()
        result = sarif["runs"][0]["results"][0]
        loc    = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/auth.py"
        assert loc["region"]["startLine"] == 99

    def test_tool_version_is_v4(self):
        builder = SARIFBuilder()
        sarif = builder.build()
        assert sarif["runs"][0]["tool"]["driver"]["version"] == "4.0.0"

    def test_cve_in_rule_properties(self):
        builder = SARIFBuilder()
        builder.add_finding("CVE-2024-1234", "Test CVE", "high", cve="CVE-2024-1234")
        sarif = builder.build()
        rule  = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule.get("properties", {}).get("cve") == "CVE-2024-1234"


class TestJUnitXML:
    def test_junit_structure(self):
        findings = [
            {"rule_id":"SEC-001","desc":"High severity",  "severity":"high",  "file":"a.py"},
            {"rule_id":"SEC-002","desc":"Medium severity","severity":"medium","file":"b.py"},
        ]
        xml = build_junit_xml(findings)
        assert '<?xml version="1.0"' in xml
        assert "testsuite" in xml
        assert "SEC-001"   in xml
        assert "failure"   in xml    # high → failure
        assert "SEC-002"   in xml

    def test_no_failures_on_low(self):
        findings = [{"rule_id":"INFO-001","desc":"Low","severity":"low","file":"x.py"}]
        xml = build_junit_xml(findings)
        assert "<failure" not in xml

    def test_critical_is_failure(self):
        findings = [{"rule_id":"CRIT-001","desc":"Critical","severity":"critical","file":"y.py"}]
        xml = build_junit_xml(findings)
        assert "<failure" in xml


class TestCITemplates:
    def test_github_actions_has_sarif(self):
        assert "sarif" in GITHUB_ACTIONS_WORKFLOW.lower()
        assert "shadow313" in GITHUB_ACTIONS_WORKFLOW

    def test_gitlab_ci_valid(self):
        assert "shadow313" in GITLAB_CI_TEMPLATE
        assert "stage:" in GITLAB_CI_TEMPLATE

    def test_pre_commit_has_exit(self):
        assert "exit 1" in PRE_COMMIT_HOOK
        assert "shadow313" in PRE_COMMIT_HOOK

    def test_github_actions_has_v4_version(self):
        assert "actions/checkout@v4" in GITHUB_ACTIONS_WORKFLOW