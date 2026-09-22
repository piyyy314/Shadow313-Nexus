"""Unit tests — shadow313.modules.quantum v4"""
import pytest
from shadow313.modules.quantum.quantum import (
    classify_algorithm,
    estimate_threat_timeline,
    SourceCodeScanner,
    NIST_PQC_STANDARDS,
)


class TestQuantumClassifier:
    def test_rsa_vulnerable(self):
        r = classify_algorithm("RSA-2048")
        assert r["vuln"] == "VULNERABLE"
        assert "Shor" in r["reason"]
        assert "Kyber" in r["replace"] or "KEM" in r["replace"]

    def test_ecdsa_vulnerable(self):
        r = classify_algorithm("ECDSA")
        assert r["vuln"] == "VULNERABLE"

    def test_aes256_safe(self):
        r = classify_algorithm("AES-256")
        assert r["vuln"] == "SAFE"

    def test_aes128_weakened(self):
        r = classify_algorithm("AES-128")
        assert r["vuln"] == "WEAKENED"

    def test_sha1_vulnerable(self):
        r = classify_algorithm("SHA-1")
        assert r["vuln"] == "VULNERABLE"

    def test_sha512_safe(self):
        r = classify_algorithm("SHA-512")
        assert r["vuln"] == "SAFE"

    def test_crystals_kyber_safe(self):
        r = classify_algorithm("CRYSTALS-KYBER")
        assert r["vuln"] == "SAFE"

    def test_unknown_algorithm(self):
        r = classify_algorithm("BLAH-CIPHER-9000")
        assert r["vuln"] == "UNKNOWN"

    def test_case_insensitive(self):
        r = classify_algorithm("rsa")
        assert r["vuln"] == "VULNERABLE"

    def test_md5_vulnerable(self):
        r = classify_algorithm("MD5")
        assert r["vuln"] == "VULNERABLE"

    def test_3des_vulnerable(self):
        r = classify_algorithm("3DES")
        assert r["vuln"] == "VULNERABLE"

    def test_rc4_vulnerable(self):
        r = classify_algorithm("RC4")
        assert r["vuln"] == "VULNERABLE"

    def test_sha384_safe(self):
        r = classify_algorithm("SHA-384")
        assert r["vuln"] == "SAFE"

    def test_ed25519_vulnerable(self):
        r = classify_algorithm("ED25519")
        assert r["vuln"] == "VULNERABLE"

    def test_sphincs_safe(self):
        r = classify_algorithm("SPHINCS+")
        assert r["vuln"] == "SAFE"

    def test_falcon_safe(self):
        r = classify_algorithm("FALCON")
        assert r["vuln"] == "SAFE"


class TestThreatTimeline:
    def test_rsa_is_critical(self):
        tl = estimate_threat_timeline(["RSA-2048", "ECDH", "AES-128"])
        assert tl["risk_level"] == "CRITICAL"
        assert tl["migration_urgency"] == "HIGH"

    def test_aes256_only_is_low(self):
        tl = estimate_threat_timeline(["AES-256", "SHA-512"])
        assert tl["risk_level"] == "LOW"

    def test_harvest_now_present(self):
        tl = estimate_threat_timeline(["RSA-2048"])
        assert "harvest" in tl["harvest_now_threat"].lower()

    def test_crqc_timeline(self):
        tl = estimate_threat_timeline(["RSA-2048"])
        assert "2030" in tl["crqc_estimated_arrival"]

    def test_empty_algorithms(self):
        tl = estimate_threat_timeline([])
        assert tl["risk_level"] == "LOW"

    def test_weakened_only_is_high(self):
        tl = estimate_threat_timeline(["AES-128", "SHA-256"])
        assert tl["risk_level"] == "HIGH"

    def test_vulnerable_algorithms_list(self):
        tl = estimate_threat_timeline(["RSA-2048", "AES-256"])
        assert "RSA-2048" in tl["vulnerable_algorithms"] or any(
            "RSA" in a for a in tl["vulnerable_algorithms"]
        )


class TestSourceCodeScanner:
    def test_python_rsa_detection(self, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        scanner = SourceCodeScanner(lang="Python")
        findings = scanner.scan_file(str(f))
        assert len(findings) > 0
        algos = [fn["algorithm"] for fn in findings]
        assert "RSA" in algos

    def test_md5_detection(self, tmp_path):
        f = tmp_path / "hashing.py"
        f.write_text("import hashlib\nhash = hashlib.md5(data).hexdigest()\n")
        scanner = SourceCodeScanner(lang="Python")
        findings = scanner.scan_file(str(f))
        assert any(fn["algorithm"] == "MD5" for fn in findings)

    def test_safe_code_no_vulnerable_findings(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text("import hashlib\nhash = hashlib.sha3_256(data).hexdigest()\n")
        scanner = SourceCodeScanner(lang="Python")
        findings = scanner.scan_file(str(f))
        vuln = [fn for fn in findings if fn.get("quantum") == "VULNERABLE"]
        assert len(vuln) == 0

    def test_nist_pqc_standards_present(self):
        assert "CRYSTALS-Kyber"     in NIST_PQC_STANDARDS
        assert "CRYSTALS-Dilithium" in NIST_PQC_STANDARDS
        assert "SPHINCS+"           in NIST_PQC_STANDARDS
        assert "FALCON"             in NIST_PQC_STANDARDS
        for name, info in NIST_PQC_STANDARDS.items():
            assert "fips"    in info
            assert "purpose" in info

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("from Crypto.PublicKey import RSA\n")
        (tmp_path / "b.py").write_text("import hashlib\nhash = hashlib.md5(x)\n")
        scanner = SourceCodeScanner(lang="Python")
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) >= 2

    def test_dedup_same_line_same_pattern(self, tmp_path):
        """FIX: scanner should not return duplicate findings for same (file, line, algo)."""
        f = tmp_path / "dup.py"
        f.write_text("from Crypto.PublicKey import RSA  # RSA RSA RSA\n")
        scanner = SourceCodeScanner(lang="Python")
        findings = scanner.scan_file(str(f))
        rsa_findings = [fn for fn in findings if fn["algorithm"] == "RSA" and fn["line"] == 1]
        assert len(rsa_findings) == 1  # deduplicated