"""Regression coverage for classification, code scans and TLS/certificate audits."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadow313.modules.quantum.cert_auditor import CertificateAuditor
from shadow313.modules.quantum.code_scanner import SourceCodeScanner
from shadow313.modules.quantum.quantum_data import classify_algorithm
from shadow313.modules.quantum.timeline import estimate_threat_timeline
from shadow313.modules.quantum.tls_scanner import TLSScanner


@pytest.mark.parametrize(
    ("name", "canonical", "status"),
    [
        ("dsa", "DSA", "VULNERABLE"),
        ("slh_dsa_shake_128s", "SLH-DSA-SHAKE-128s", "SAFE"),
        ("ml_dsa_65", "ML-DSA-65", "SAFE"),
        ("ML-KEM-768", "ML-KEM-768", "SAFE"),
        ("certificate RSA-2048 key", "RSA-2048", "VULNERABLE"),
        ("aes_128", "AES-128", "WEAKENED"),
        ("AES-256", "AES-256", "SAFE"),
        ("unrecognized-cipher", "unrecognized-cipher", "UNKNOWN"),
    ],
)
def test_classification_prefers_specific_normalized_algorithms(name, canonical, status):
    info = classify_algorithm(name)
    assert info["algorithm"] == canonical
    assert info["vuln"] == status
    assert info["reason"]


def test_classification_result_cannot_mutate_reference_table():
    info = classify_algorithm("DSA")
    info["vuln"] = "SAFE"
    assert classify_algorithm("DSA")["vuln"] == "VULNERABLE"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="PR #86 empty algorithm matches a PQC substring as SAFE",
)
def test_empty_algorithm_is_unknown():
    assert classify_algorithm("")["vuln"] == "UNKNOWN"


def test_code_scanner_deduplicates_signatures_and_preserves_line_numbers(tmp_path):
    path = tmp_path / "crypto.py"
    path.write_text("# heading\nhashlib.md5(data)  # MD5\nRSA.generate(2048)\n")
    findings = SourceCodeScanner().scan_file(str(path))
    assert {(f["algorithm"], f["line"]) for f in findings} == {("MD5", 2), ("RSA", 3)}
    assert len(findings) == 2
    assert all(f["file"] == str(path) and f["language"] == "Python" for f in findings)
    assert all(f["quantum"] == "VULNERABLE" and f["replace"] for f in findings)


def test_code_scanner_language_filter_generic_fallback_and_missing_file(tmp_path):
    (tmp_path / "crypto.py").write_text("hashlib.sha1(data)\n")
    (tmp_path / "crypto.js").write_text("crypto.createHash('md5')\n")
    (tmp_path / "safe.py").write_text("hashlib.sha512(data)\n")
    findings = SourceCodeScanner(lang="PYTHON").scan_directory(str(tmp_path))
    assert [(f["algorithm"], f["line"]) for f in findings] == [("SHA-1", 1)]
    unknown = tmp_path / "crypto.unknown"
    unknown.write_text("RSA-2048\n")
    assert SourceCodeScanner().scan_file(str(unknown))[0]["language"] == "Unknown"
    assert SourceCodeScanner().scan_file(str(tmp_path / "missing.py")) == []


@pytest.mark.parametrize(
    ("algorithms", "risk", "urgency", "vulnerable"),
    [
        ([], "LOW", "MEDIUM", []),
        (["AES-256", "ML-KEM-768"], "LOW", "MEDIUM", []),
        (["AES-128"], "HIGH", "HIGH", []),
        (["RSA-2048"], "CRITICAL", "HIGH", ["RSA-2048"]),
        (["ECDSA", "AES-256"], "CRITICAL", "HIGH", ["ECDSA"]),
    ],
)
def test_timeline_risk_and_migration_urgency(algorithms, risk, urgency, vulnerable):
    result = estimate_threat_timeline(algorithms)
    assert result["risk_level"] == risk
    assert result["migration_urgency"] == urgency
    assert result["vulnerable_algorithms"] == vulnerable


@pytest.mark.parametrize("version", ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"])
def test_tls_deprecated_protocols_raise_critical_finding(version):
    findings = TLSScanner("example.invalid")._analyse_cipher("", version)
    assert len(findings) == 1
    assert findings[0]["type"] == "DEPRECATED_TLS"
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["replace"] == "TLS 1.3"


def test_tls_safe_and_weak_symmetric_suites():
    scanner = TLSScanner("example.invalid")
    assert scanner._analyse_cipher("AES-256", "TLSv1.3") == []
    findings = scanner._analyse_cipher("AES-128", "TLSv1.2")
    assert len(findings) == 1
    assert findings[0]["quantum"] == "WEAKENED"
    assert findings[0]["severity"] == "MEDIUM"


def test_tls_certificate_optional_fields_san_limit_and_bad_date():
    scanner = TLSScanner("example.invalid")
    assert scanner._parse_cert(None) == {}
    result = scanner._parse_cert(
        {
            "subject": ((("commonName", "example.invalid"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "subjectAltName": [("DNS", f"host{i}.invalid") for i in range(12)],
            "notAfter": "invalid-date",
        }
    )
    assert result["subject"] == "example.invalid"
    assert result["issuer"] == "Test CA"
    assert len(result["san"]) == 10
    assert result["days_left"] == -1


def test_tls_scan_reports_connection_error_without_network(monkeypatch):
    monkeypatch.setattr(
        "shadow313.modules.quantum.tls_scanner.socket.create_connection",
        Mock(side_effect=ConnectionRefusedError("offline")),
    )
    result = TLSScanner("example.invalid", 8443, 2).scan()
    assert result["host"] == "example.invalid"
    assert result["port"] == 8443
    assert result["error"] == "Connection error: offline"
    assert result["findings"] == []


@pytest.mark.parametrize(
    ("key_type", "size", "algorithm"),
    [
        ("RSAPublicKey", 2048, "RSA-2048"),
        ("EllipticCurvePublicKey", 256, "ECDSA (256-bit)"),
    ],
)
def test_certificate_key_analysis_identifies_quantum_risk(key_type, size, algorithm):
    key = type(key_type, (), {"key_size": size})()
    cert = SimpleNamespace(
        public_key=lambda: key,
        signature_hash_algorithm=SimpleNamespace(name="sha512"),
        subject=SimpleNamespace(rfc4514_string=lambda: "CN=subject"),
        issuer=SimpleNamespace(rfc4514_string=lambda: "CN=issuer"),
        not_valid_before_utc="2026-01-01",
        not_valid_after_utc="2027-01-01",
    )
    result = CertificateAuditor()._analyse_crypto_cert(cert)
    assert result["subject"] == "CN=subject"
    assert result["key_size"] == size
    assert len(result["findings"]) == 1
    assert result["findings"][0]["algorithm"] == algorithm
    assert result["findings"][0]["quantum"] == "VULNERABLE"


def test_certificate_directory_only_audits_supported_extensions(tmp_path, monkeypatch):
    for filename in ["one.pem", "two.crt", "three.cer", "four.der", "ignore.txt"]:
        (tmp_path / filename).touch()
    audit = Mock(side_effect=lambda path: {"findings": [], "subject": path})
    auditor = CertificateAuditor()
    monkeypatch.setattr(auditor, "audit_file", audit)
    results = auditor.audit_directory(str(tmp_path))
    assert len(results) == 4
    assert {r["path"] for r in results} == {
        str(tmp_path / name) for name in ["one.pem", "two.crt", "three.cer", "four.der"]
    }
