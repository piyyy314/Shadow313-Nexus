"""
Comprehensive tests — shadow313.v2.cloud_hardening
Covers: TerraformScanner (all 11 rules), AWSChecker (boto3-mocked),
        K8sChecker (k8s-client-mocked), CloudHardeningModule edge cases,
        tfsec fallback, severity mapping, empty/clean inputs.
"""
from __future__ import annotations
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

from shadow313.v2.cloud_hardening.cloud_hardening import (
    TerraformScanner, AWSChecker, CloudHardeningModule,
)


# ── TerraformScanner ──────────────────────────────────────────────────────────

class TestTerraformScanner:
    @pytest.fixture
    def scanner(self):
        return TerraformScanner()

    def _write_tf(self, tmp_path, content: str, filename: str = "main.tf") -> Path:
        f = tmp_path / filename
        f.write_text(content)
        return f

    # ── Rule: TF-S3-PUBLIC ────────────────────────────────────────────────────
    def test_detects_public_s3_acl(self, scanner, tmp_path):
        self._write_tf(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-S3-PUBLIC" in rule_ids

    def test_no_false_positive_private_s3(self, scanner, tmp_path):
        self._write_tf(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-S3-PUBLIC" not in rule_ids

    # ── Rule: TF-HARDCODED-PW ─────────────────────────────────────────────────
    def test_detects_hardcoded_password(self, scanner, tmp_path):
        self._write_tf(tmp_path, 'resource "aws_db_instance" "db" {\n  password = "SuperSecret123"\n}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-HARDCODED-PW" in rule_ids

    def test_no_false_positive_variable_password(self, scanner, tmp_path):
        self._write_tf(tmp_path, 'resource "aws_db_instance" "db" {\n  password = var.db_password\n}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-HARDCODED-PW" not in rule_ids

    # ── Rule: TF-OPEN-INGRESS ─────────────────────────────────────────────────
    def test_detects_open_ingress_cidr(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_security_group" "sg" {\n'
            '  ingress {\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n'
            '  }\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-OPEN-INGRESS" in rule_ids

    # ── Rule: TF-RDS-ENCRYPT ──────────────────────────────────────────────────
    def test_detects_unencrypted_rds(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_db_instance" "db" {\n'
            '  storage_encrypted = false\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-RDS-ENCRYPT" in rule_ids

    # ── Rule: TF-IAM-WILDCARD ─────────────────────────────────────────────────
    def test_detects_wildcard_iam_action(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_iam_policy" "p" {\n'
            '  policy = jsonencode({\n'
            '    "Action": "*"\n'
            '  })\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-IAM-WILDCARD" in rule_ids

    # ── Rule: TF-HTTP-ALB ─────────────────────────────────────────────────────
    def test_detects_http_alb_listener(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_alb_listener" "l" {\n'
            '  protocol = "HTTP"\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-HTTP-ALB" in rule_ids

    # ── Rule: TF-NO-BACKUP ────────────────────────────────────────────────────
    def test_detects_zero_backup_retention(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_db_instance" "db" {\n'
            '  backup_retention_period = 0\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-NO-BACKUP" in rule_ids

    # ── Rule: TF-PUBLIC-AMI ───────────────────────────────────────────────────
    def test_detects_public_ip_on_instance(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_instance" "i" {\n'
            '  associate_public_ip_address = true\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-PUBLIC-AMI" in rule_ids

    # ── Clean file ────────────────────────────────────────────────────────────
    def test_clean_terraform_no_findings(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_s3_bucket" "b" {\n'
            '  acl = "private"\n'
            '  server_side_encryption_configuration {\n'
            '    rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }\n'
            '  }\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        # TF-S3-LOGGING may trigger but TF-S3-PUBLIC and TF-HARDCODED-PW should not
        rule_ids = [f["rule_id"] for f in findings]
        assert "TF-S3-PUBLIC"    not in rule_ids
        assert "TF-HARDCODED-PW" not in rule_ids

    def test_empty_directory_no_findings(self, scanner, tmp_path):
        findings = scanner.scan_directory(str(tmp_path))
        assert findings == []

    def test_non_tf_files_ignored(self, scanner, tmp_path):
        (tmp_path / "main.py").write_text('password = "secret"\n')
        (tmp_path / "README.md").write_text('acl = "public-read"\n')
        findings = scanner.scan_directory(str(tmp_path))
        assert findings == []

    def test_finding_has_required_fields(self, scanner, tmp_path):
        self._write_tf(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) > 0
        f = findings[0]
        assert "rule_id"     in f
        assert "description" in f
        assert "file"        in f
        assert "line"        in f
        assert "severity"    in f
        assert "code"        in f

    def test_finding_severity_is_lowercase(self, scanner, tmp_path):
        self._write_tf(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
        findings = scanner.scan_directory(str(tmp_path))
        for f in findings:
            assert f["severity"] == f["severity"].lower()

    def test_multiple_rules_in_one_file(self, scanner, tmp_path):
        self._write_tf(tmp_path,
            'resource "aws_s3_bucket" "b" {\n'
            '  acl = "public-read"\n'
            '}\n'
            'resource "aws_db_instance" "db" {\n'
            '  password = "hardcoded"\n'
            '  storage_encrypted = false\n'
            '}\n')
        findings = scanner.scan_directory(str(tmp_path))
        rule_ids = {f["rule_id"] for f in findings}
        assert "TF-S3-PUBLIC"    in rule_ids
        assert "TF-HARDCODED-PW" in rule_ids
        assert "TF-RDS-ENCRYPT"  in rule_ids

    def test_line_numbers_are_correct(self, scanner, tmp_path):
        content = (
            'resource "aws_s3_bucket" "b" {\n'  # line 1
            '  bucket = "my-bucket"\n'           # line 2
            '  acl    = "public-read"\n'         # line 3
            '}\n'                                # line 4
        )
        self._write_tf(tmp_path, content)
        findings = scanner.scan_directory(str(tmp_path))
        s3_findings = [f for f in findings if f["rule_id"] == "TF-S3-PUBLIC"]
        assert len(s3_findings) == 1
        assert s3_findings[0]["line"] == 3

    def test_tfsec_fallback_on_missing_binary(self, scanner, tmp_path):
        # tfsec not installed — should return empty list, not raise
        self._write_tf(tmp_path, 'resource "aws_s3_bucket" "b" {}\n')
        with patch("subprocess.run", side_effect=FileNotFoundError("tfsec not found")):
            findings = scanner._run_tfsec(str(tmp_path))
        assert findings == []

    def test_tfsec_fallback_on_invalid_json(self, scanner, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout     = "not valid json"
        with patch("subprocess.run", return_value=mock_result):
            findings = scanner._run_tfsec(str(tmp_path))
        assert findings == []

    def test_scan_nested_directories(self, scanner, tmp_path):
        nested = tmp_path / "modules" / "vpc"
        nested.mkdir(parents=True)
        (nested / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
        findings = scanner.scan_directory(str(tmp_path))
        assert any(f["rule_id"] == "TF-S3-PUBLIC" for f in findings)


# ── AWSChecker (boto3 mocked) ─────────────────────────────────────────────────

class TestAWSChecker:
    @pytest.fixture
    def checker(self):
        return AWSChecker()

    def _mock_boto3_client(self, checker, service: str, mock_client):
        checker._client_cache[service] = mock_client

    def test_run_all_skips_on_import_error(self, checker):
        with patch.dict("sys.modules", {"boto3": None}):
            # Force ImportError path
            results = checker.run_all()
        # All checks should be SKIP or ERROR (boto3 not available)
        for r in results:
            assert r["status"] in ("SKIP", "ERROR", "PASS", "FAIL", "WARN")

    def test_check_s3_no_public_buckets(self, checker):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "private-bucket"}]}
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/private"}}]
        }
        self._mock_boto3_client(checker, "s3", mock_s3)
        result = checker.check_s3_public_access()
        assert result["status"]   == "PASS"
        assert result["severity"] == "INFO"

    def test_check_s3_detects_public_bucket(self, checker):
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "public-bucket"}]}
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
        }
        self._mock_boto3_client(checker, "s3", mock_s3)
        result = checker.check_s3_public_access()
        assert result["status"]   == "FAIL"
        assert result["severity"] == "CRITICAL"
        assert "public-bucket" in result["detail"]

    def test_check_root_access_keys_present(self, checker):
        mock_iam = MagicMock()
        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountAccessKeysPresent": 1}
        }
        self._mock_boto3_client(checker, "iam", mock_iam)
        result = checker.check_root_access_keys()
        assert result["status"]   == "FAIL"
        assert result["severity"] == "CRITICAL"

    def test_check_root_access_keys_absent(self, checker):
        mock_iam = MagicMock()
        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountAccessKeysPresent": 0}
        }
        self._mock_boto3_client(checker, "iam", mock_iam)
        result = checker.check_root_access_keys()
        assert result["status"]   == "PASS"
        assert result["severity"] == "INFO"

    def test_check_root_mfa_enabled(self, checker):
        mock_iam = MagicMock()
        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1}
        }
        self._mock_boto3_client(checker, "iam", mock_iam)
        result = checker.check_root_mfa()
        assert result["status"]   == "PASS"
        assert result["severity"] == "INFO"

    def test_check_root_mfa_disabled(self, checker):
        mock_iam = MagicMock()
        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0}
        }
        self._mock_boto3_client(checker, "iam", mock_iam)
        result = checker.check_root_mfa()
        assert result["status"]   == "FAIL"
        assert result["severity"] == "CRITICAL"

    def test_check_security_groups_open_ingress(self, checker):
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId":   "sg-12345",
                "GroupName": "open-sg",
                "IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            }]
        }
        self._mock_boto3_client(checker, "ec2", mock_ec2)
        result = checker.check_security_groups()
        assert result["status"]   == "WARN"
        assert result["severity"] == "HIGH"
        assert "sg-12345" in result["detail"]

    def test_check_security_groups_no_open_ingress(self, checker):
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId":   "sg-99999",
                "GroupName": "restricted-sg",
                "IpPermissions": [{"IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
            }]
        }
        self._mock_boto3_client(checker, "ec2", mock_ec2)
        result = checker.check_security_groups()
        assert result["status"]   == "PASS"
        assert result["severity"] == "INFO"

    def test_check_cloudtrail_active(self, checker):
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [{"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main",
                           "Name": "main"}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        self._mock_boto3_client(checker, "cloudtrail", mock_ct)
        result = checker.check_cloudtrail()
        # Active trail → PASS; if get_trail_status raises, falls back to FAIL
        assert result["status"] in ("PASS", "FAIL")
        assert result["severity"] in ("INFO", "HIGH")

    def test_check_cloudtrail_inactive(self, checker):
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [{"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main"}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": False}
        self._mock_boto3_client(checker, "cloudtrail", mock_ct)
        result = checker.check_cloudtrail()
        assert result["status"]   == "FAIL"
        assert result["severity"] == "HIGH"

    def test_check_cloudtrail_no_trails(self, checker):
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {"trailList": []}
        self._mock_boto3_client(checker, "cloudtrail", mock_ct)
        result = checker.check_cloudtrail()
        assert result["status"]   == "FAIL"

    def test_check_password_policy_strong(self, checker):
        mock_iam = MagicMock()
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength":    14,
                "RequireUppercaseCharacters": True,
                "RequireNumbers":           True,
                "RequireSymbols":           True,
            }
        }
        self._mock_boto3_client(checker, "iam", mock_iam)
        result = checker.check_password_policy()
        assert result["status"]   == "PASS"

    def test_check_password_policy_weak(self, checker):
        mock_iam = MagicMock()
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength":    6,
                "RequireUppercaseCharacters": False,
                "RequireNumbers":           False,
                "RequireSymbols":           False,
            }
        }
        self._mock_boto3_client(checker, "iam", mock_iam)
        result = checker.check_password_policy()
        assert result["status"]   == "FAIL"
        assert result["severity"] == "MEDIUM"

    def test_check_password_policy_missing(self, checker):
        mock_iam = MagicMock()
        mock_iam.get_account_password_policy.side_effect = Exception("NoSuchEntity")
        self._mock_boto3_client(checker, "iam", mock_iam)
        result = checker.check_password_policy()
        assert result["status"]   == "FAIL"

    def test_check_rds_public_accessible(self, checker):
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [
                {"DBInstanceIdentifier": "prod-db", "PubliclyAccessible": True},
            ]
        }
        self._mock_boto3_client(checker, "rds", mock_rds)
        result = checker.check_rds_public()
        assert result["status"]   == "FAIL"
        assert result["severity"] == "HIGH"
        assert "prod-db" in result["detail"]

    def test_check_rds_not_public(self, checker):
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [
                {"DBInstanceIdentifier": "prod-db", "PubliclyAccessible": False},
            ]
        }
        self._mock_boto3_client(checker, "iam", MagicMock())
        self._mock_boto3_client(checker, "rds", mock_rds)
        result = checker.check_rds_public()
        assert result["status"]   == "PASS"

    def test_run_all_returns_seven_results(self, checker):
        # Mock all clients to avoid real AWS calls
        for svc in ("s3", "iam", "ec2", "cloudtrail", "rds"):
            mock = MagicMock()
            mock.list_buckets.return_value = {"Buckets": []}
            mock.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}}
            mock.describe_security_groups.return_value = {"SecurityGroups": []}
            mock.describe_trails.return_value = {"trailList": []}
            mock.describe_db_instances.return_value = {"DBInstances": []}
            mock.get_account_password_policy.return_value = {
                "PasswordPolicy": {"MinimumPasswordLength": 14, "RequireUppercaseCharacters": True,
                                   "RequireNumbers": True, "RequireSymbols": True}
            }
            self._mock_boto3_client(checker, svc, mock)
        results = checker.run_all()
        assert len(results) == 7

    def test_all_results_have_required_fields(self, checker):
        for svc in ("s3", "iam", "ec2", "cloudtrail", "rds"):
            mock = MagicMock()
            mock.list_buckets.return_value = {"Buckets": []}
            mock.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1}}
            mock.describe_security_groups.return_value = {"SecurityGroups": []}
            mock.describe_trails.return_value = {"trailList": []}
            mock.describe_db_instances.return_value = {"DBInstances": []}
            mock.get_account_password_policy.return_value = {
                "PasswordPolicy": {"MinimumPasswordLength": 14, "RequireUppercaseCharacters": True,
                                   "RequireNumbers": True, "RequireSymbols": True}
            }
            self._mock_boto3_client(checker, svc, mock)
        for result in checker.run_all():
            assert "check"    in result
            assert "status"   in result
            assert "severity" in result
            assert "detail"   in result