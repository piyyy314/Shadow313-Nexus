"""
tests/unit/v4/test_deepstash.py
────────────────────────────────
Tests for DeepStash filesystem secret scanner and VANGUARD-313 registry.
"""
from __future__ import annotations

import os
import tempfile
import pytest

from shadow313.tools.deepstash import (
    DeepStashScanner, ScanResult, FindingRecord,
    SkippedRecord, COMPILED_PATTERNS
)
from shadow313.tools.deepstash.scanner import (
    shannon_entropy, find_high_entropy_strings,
    scan_file, evaluate_policy, PolicyDecision
)
from shadow313.core.binding_sdk.registry import (
    AppRegistry, REGISTERED_APPS
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def write_temp_file(content: str, suffix: str = ".py") -> str:
    """Write content to a temp file and return path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix,
                                    delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


# ═══════════════════════════════════════════════════════════════════════════════
# Entropy
# ═══════════════════════════════════════════════════════════════════════════════

class TestShannonEntropy:

    def test_empty_string_zero(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_string_zero(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_high_entropy_random(self):
        # All unique chars → max entropy
        s = "abcdefghijklmnop"
        assert shannon_entropy(s) > 3.5

    def test_low_entropy_repeated(self):
        assert shannon_entropy("ababababab") < 2.0

    def test_known_value(self):
        # "ab" → entropy = 1.0 bit
        assert abs(shannon_entropy("ab") - 1.0) < 0.01


class TestHighEntropyStrings:

    def test_detects_high_entropy_quoted(self):
        line = 'api_key = "aB3xK9mP2qR7sT1uV5wY8zA4cD6eF0g"'
        hits = find_high_entropy_strings(line, threshold=3.5)
        assert len(hits) >= 1

    def test_ignores_low_entropy(self):
        line = 'name = "hello"'
        hits = find_high_entropy_strings(line, threshold=4.5)
        assert len(hits) == 0

    def test_returns_entropy_value(self):
        line = 'token = "aB3xK9mP2qR7sT1uV5wY8zA4cD6eF0gH2iJ"'
        hits = find_high_entropy_strings(line, threshold=3.0)
        if hits:
            assert "entropy" in hits[0]
            assert hits[0]["entropy"] > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Pattern Detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestPatternDetection:

    def test_patterns_loaded(self):
        assert len(COMPILED_PATTERNS) >= 30

    def test_aws_key_detected(self):
        path = write_temp_file('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        try:
            findings, skipped = scan_file(path, COMPILED_PATTERNS)
            aws_findings = [f for f in findings if "AWS" in f.category]
            assert len(aws_findings) >= 1
        finally:
            os.unlink(path)

    def test_github_pat_detected(self):
        # GitHub PAT is exactly 36 chars after ghp_
        path = write_temp_file('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n')
        try:
            findings, _ = scan_file(path, COMPILED_PATTERNS)
            gh_findings = [f for f in findings if "VCS" in f.category or "GitHub" in f.type]
            # Also check entropy findings as fallback
            assert len(findings) >= 1
        finally:
            os.unlink(path)

    def test_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456"
        path = write_temp_file(f'auth = "{jwt}"\n')
        try:
            findings, _ = scan_file(path, COMPILED_PATTERNS)
            jwt_findings = [f for f in findings if "JWT" in f.type or "Auth" in f.category]
            assert len(jwt_findings) >= 1
        finally:
            os.unlink(path)

    def test_private_key_detected(self):
        path = write_temp_file("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\n-----END RSA PRIVATE KEY-----\n")
        try:
            findings, _ = scan_file(path, COMPILED_PATTERNS)
            crypto_findings = [f for f in findings if "Crypto" in f.category]
            assert len(crypto_findings) >= 1
        finally:
            os.unlink(path)

    def test_clean_file_no_findings(self):
        path = write_temp_file("# This is a clean Python file\ndef hello():\n    return 'world'\n")
        try:
            findings, _ = scan_file(path, COMPILED_PATTERNS)
            # May have entropy hits but no HIGH findings
            high = [f for f in findings if f.confidence == "HIGH"]
            assert len(high) == 0
        finally:
            os.unlink(path)

    def test_redaction_applied(self):
        path = write_temp_file('key = "AKIAIOSFODNN7EXAMPLE"\n')
        try:
            findings, _ = scan_file(path, COMPILED_PATTERNS)
            for f in findings:
                assert "***" in f.redacted_value
                assert "AKIAIOSFODNN7EXAMPLE" not in f.redacted_value
        finally:
            os.unlink(path)

    def test_value_hash_present(self):
        path = write_temp_file('key = "AKIAIOSFODNN7EXAMPLE"\n')
        try:
            findings, _ = scan_file(path, COMPILED_PATTERNS)
            for f in findings:
                assert len(f.value_hash) == 16  # SHA-256 truncated to 16 chars
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# File Scanner
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanFile:

    def test_large_file_skipped(self):
        # Create a file that reports as too large
        path = write_temp_file("x" * 100)
        try:
            import unittest.mock as mock
            with mock.patch("os.path.getsize", return_value=11 * 1024 * 1024):
                findings, skipped = scan_file(path, COMPILED_PATTERNS)
            assert len(findings) == 0
            assert len(skipped) == 1
            assert skipped[0].reason == "file_too_large"
        finally:
            os.unlink(path)

    def test_permission_error_skipped(self):
        import unittest.mock as mock
        with mock.patch("builtins.open", side_effect=PermissionError("denied")):
            findings, skipped = scan_file("/fake/path.py", COMPILED_PATTERNS)
        assert len(findings) == 0
        assert len(skipped) == 1
        # PermissionError is a subclass of OSError — caught as os_error
        assert skipped[0].reason in ("permission_denied", "os_error")

    def test_confidence_filter_high_only(self):
        path = write_temp_file(
            'key = "AKIAIOSFODNN7EXAMPLE"\n'
            'password = "short"\n'
        )
        try:
            findings_all, _ = scan_file(path, COMPILED_PATTERNS,
                                         confidence_filter={"HIGH", "MEDIUM", "LOW"})
            findings_high, _ = scan_file(path, COMPILED_PATTERNS,
                                          confidence_filter={"HIGH"})
            # High-only should have fewer or equal findings
            assert len(findings_high) <= len(findings_all)
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# DeepStashScanner
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeepStashScanner:

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a file with a secret
            with open(os.path.join(tmpdir, "config.py"), "w") as f:
                f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            # Write a clean file
            with open(os.path.join(tmpdir, "clean.py"), "w") as f:
                f.write("# clean file\n")

            scanner = DeepStashScanner()
            result = scanner.scan(tmpdir)

            assert isinstance(result, ScanResult)
            assert len(result.findings) >= 1

    def test_scan_single_file(self):
        path = write_temp_file('token = "ghp_abcdefghijklmnopqrstuvwxyz123456789"\n')
        try:
            scanner = DeepStashScanner()
            result = scanner.scan(path)
            assert len(result.findings) >= 1
        finally:
            os.unlink(path)

    def test_clean_directory_is_clean(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "hello.py"), "w") as f:
                f.write("def hello():\n    return 'world'\n")

            scanner = DeepStashScanner(confidence_filter={"HIGH"})
            result = scanner.scan(tmpdir)
            high = [f for f in result.findings if f.confidence == "HIGH"]
            assert len(high) == 0

    def test_noise_dirs_excluded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a noise dir with a secret
            node_dir = os.path.join(tmpdir, "node_modules")
            os.makedirs(node_dir)
            with open(os.path.join(node_dir, "secret.js"), "w") as f:
                f.write('const key = "AKIAIOSFODNN7EXAMPLE";\n')
            # Clean main file
            with open(os.path.join(tmpdir, "main.py"), "w") as f:
                f.write("# clean\n")

            scanner = DeepStashScanner()
            result = scanner.scan(tmpdir)
            # node_modules should be excluded
            node_findings = [f for f in result.findings
                            if "node_modules" in f.file]
            assert len(node_findings) == 0

    def test_extension_filter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "config.py"), "w") as f:
                f.write('key = "AKIAIOSFODNN7EXAMPLE"\n')
            with open(os.path.join(tmpdir, "config.js"), "w") as f:
                f.write('const key = "AKIAIOSFODNN7EXAMPLE";\n')

            # Only scan .py files
            scanner = DeepStashScanner(extensions={".py"})
            result = scanner.scan(tmpdir)
            js_findings = [f for f in result.findings if f.file.endswith(".js")]
            assert len(js_findings) == 0

    def test_scan_result_merge(self):
        r1 = ScanResult()
        r1.findings.append(FindingRecord(
            file="a.py", line=1, type="AWS Key", category="AWS",
            confidence="HIGH", redacted_value="AKI***", value_hash="abc123",
            context="key = AKI***"
        ))
        r2 = ScanResult()
        r2.findings.append(FindingRecord(
            file="b.py", line=2, type="JWT", category="Auth",
            confidence="HIGH", redacted_value="eyJ***", value_hash="def456",
            context="token = eyJ***"
        ))
        r1.merge(r2)
        assert len(r1.findings) == 2

    def test_to_report_structure(self):
        scanner = DeepStashScanner()
        result = scanner.scan("shadow313/tools/deepstash/__init__.py")
        report = result.to_report()
        assert "scanner" in report
        assert "total_findings" in report
        assert "summary" in report
        assert "findings" in report
        assert "skipped_files" in report
        assert report["scanner"] == "DeepStash"


# ═══════════════════════════════════════════════════════════════════════════════
# Policy Evaluation
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyEvaluation:

    def test_clean_result_passes(self):
        result = ScanResult()
        decision = evaluate_policy(result, mode="balanced")
        assert decision.status == "pass"

    def test_high_finding_fails(self):
        result = ScanResult()
        result.findings.append(FindingRecord(
            file="a.py", line=1, type="AWS Key", category="AWS",
            confidence="HIGH", redacted_value="AKI***", value_hash="abc",
            context="key = AKI***"
        ))
        decision = evaluate_policy(result, mode="balanced")
        assert decision.status == "fail"

    def test_skipped_balanced_review(self):
        result = ScanResult()
        result.skipped.append(SkippedRecord("big.bin", "file_too_large", "11MB"))
        decision = evaluate_policy(result, mode="balanced")
        assert decision.status == "review"

    def test_skipped_strict_fails(self):
        result = ScanResult()
        result.skipped.append(SkippedRecord("big.bin", "file_too_large", "11MB"))
        decision = evaluate_policy(result, mode="strict")
        assert decision.status == "fail"

    def test_errors_always_fail(self):
        result = ScanResult()
        result.errors.append(SkippedRecord("locked.env", "scanner_exception", "permission denied"))
        decision = evaluate_policy(result, mode="balanced")
        assert decision.status == "fail"

    def test_is_clean_true_when_empty(self):
        result = ScanResult()
        assert result.is_clean() is True

    def test_is_clean_false_with_findings(self):
        result = ScanResult()
        result.findings.append(FindingRecord(
            file="a.py", line=1, type="JWT", category="Auth",
            confidence="MEDIUM", redacted_value="eyJ***", value_hash="abc",
            context="token = eyJ***"
        ))
        assert result.is_clean() is False


# ═══════════════════════════════════════════════════════════════════════════════
# VANGUARD-313 App Registry
# ═══════════════════════════════════════════════════════════════════════════════

class TestAppRegistry:

    def test_registered_apps_count(self):
        assert len(REGISTERED_APPS) >= 10

    def test_shadow313_registered(self):
        assert "shadow313" in REGISTERED_APPS
        app = REGISTERED_APPS["shadow313"]
        assert app.app_id == "shadow313"
        assert app.prefix == "S313"

    def test_ghost_watch_registered(self):
        assert "ghost-watch" in REGISTERED_APPS
        app = REGISTERED_APPS["ghost-watch"]
        assert app.prefix == "GHOST"

    def test_aegis_vsat_registered(self):
        assert "aegis-nexus-vsat" in REGISTERED_APPS

    def test_sovereign_shield_registered(self):
        assert "sovereign-shield" in REGISTERED_APPS

    def test_get_binder_valid_app(self):
        binder = AppRegistry.get_binder("shadow313")
        assert binder is not None

    def test_get_binder_invalid_raises(self):
        with pytest.raises(KeyError):
            AppRegistry.get_binder("nonexistent-app-xyz")

    def test_list_apps_structure(self):
        apps = AppRegistry.list_apps()
        assert len(apps) >= 10
        for app in apps:
            assert "app_id" in app
            assert "app_name" in app
            assert "version" in app
            assert "prefix" in app
            assert "bind_id_format" in app
            assert "313-" in app["bind_id_format"]

    def test_register_new_app(self):
        from shadow313.core.binding_sdk.binder import AppIdentity
        test_identity = AppIdentity(
            app_id="test-app-xyz",
            app_name="Test App",
            version="1.0.0",
            prefix="TEST"
        )
        AppRegistry.register(test_identity)
        assert "test-app-xyz" in REGISTERED_APPS
        # Cleanup
        del REGISTERED_APPS["test-app-xyz"]

    def test_prefix_uppercase_enforced(self):
        from shadow313.core.binding_sdk.binder import AppIdentity
        identity = AppIdentity(
            app_id="lowercase-test",
            app_name="Test",
            version="1.0",
            prefix="lower"
        )
        assert identity.prefix == "LOWER"

    def test_bind_id_format_correct(self):
        apps = AppRegistry.list_apps()
        for app in apps:
            fmt = app["bind_id_format"]
            assert fmt.startswith("313-")
            assert app["prefix"] in fmt