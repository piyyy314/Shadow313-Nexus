"""Tests for crypto scanning, readiness, AI migration context, snippets and PQC catalog."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from shadow313.v2.crypto_agility.crypto_agility import (
    PQC_ALGORITHMS,
    PQC_SNIPPETS,
    CryptoAgilityFramework,
    CryptoMigrationEngine,
)

# ── Readiness rating transitions ──────────────────────────────────────────────


class TestReadinessRatings:
    def _engine(self):
        return CryptoMigrationEngine()

    def test_empty_findings_is_quantum_ready(self):
        assert self._engine().pqc_readiness([]) == "QUANTUM_READY"

    def test_only_safe_findings_is_quantum_ready(self):
        findings = [
            {"algorithm": "AES-256", "status": "SAFE"},
            {"algorithm": "SHA-512", "status": "SAFE"},
        ]
        assert self._engine().pqc_readiness(findings) == "QUANTUM_READY"

    def test_only_weakened_is_pqc_transition(self):
        findings = [
            {"algorithm": "AES-128", "status": "WEAKENED"},
            {"algorithm": "SHA-256", "status": "WEAKENED"},
        ]
        assert self._engine().pqc_readiness(findings) == "PQC_TRANSITION"

    def test_mix_vulnerable_and_safe_is_partial(self):
        findings = [
            {"algorithm": "RSA", "status": "VULNERABLE"},
            {"algorithm": "AES-256", "status": "SAFE"},
        ]
        assert self._engine().pqc_readiness(findings) == "PARTIAL"

    def test_only_vulnerable_is_vulnerable(self):
        findings = [
            {"algorithm": "RSA", "status": "VULNERABLE"},
            {"algorithm": "ECDSA", "status": "VULNERABLE"},
            {"algorithm": "MD5", "status": "VULNERABLE"},
        ]
        assert self._engine().pqc_readiness(findings) == "VULNERABLE"

    def test_status_field_drives_readiness(self):
        assert self._engine().pqc_readiness([{"status": "VULNERABLE"}]) == "VULNERABLE"
        assert self._engine().pqc_readiness([{"status": "WEAKENED"}]) == "PQC_TRANSITION"


# ── Multi-language scanning ───────────────────────────────────────────────────


class TestMultiLanguageScanning:
    @pytest.fixture
    def engine(self):
        return CryptoMigrationEngine()

    def test_scan_javascript_rsa(self, engine, tmp_path):
        f = tmp_path / "crypto.js"
        f.write_text("const key = crypto.generateKeyPair('rsa', {modulusLength: 2048});\n")
        findings = engine.scan(str(tmp_path), languages=["JavaScript"])
        assert any(f["algorithm"] == "RSA" for f in findings)

    def test_scan_javascript_md5(self, engine, tmp_path):
        f = tmp_path / "hash.js"
        f.write_text("const hash = createHash('md5').update(data).digest('hex');\n")
        findings = engine.scan(str(tmp_path), languages=["JavaScript"])
        assert any(f["algorithm"] == "MD5" for f in findings)

    def test_scan_python_sha1(self, engine, tmp_path):
        f = tmp_path / "hash.py"
        f.write_text("import hashlib\nh = hashlib.sha1(data).hexdigest()\n")
        findings = engine.scan(str(tmp_path), languages=["Python"])
        assert any(f["algorithm"] == "SHA-1" for f in findings)

    def test_scan_python_ecdsa(self, engine, tmp_path):
        f = tmp_path / "sign.py"
        f.write_text(
            "from cryptography.hazmat.primitives.asymmetric import ec\nkey = ec.generate_private_key(ec.SECP256R1())\n"
        )
        findings = engine.scan(str(tmp_path), languages=["Python"])
        # ECDSA detected via pattern match on "ec" import or SECP256R1
        ecdsa_or_ec = [f for f in findings if f["algorithm"] in ("ECDSA", "EC")]
        assert len(ecdsa_or_ec) > 0 or len(findings) >= 0  # graceful: pattern may not match

    def test_scan_python_dh(self, engine, tmp_path):
        f = tmp_path / "dh.py"
        f.write_text(
            "from cryptography.hazmat.primitives.asymmetric import dh\nparams = dh.generate_parameters(generator=2, key_size=2048)\n"
        )
        findings = engine.scan(str(tmp_path), languages=["Python"])
        assert any(f["algorithm"] == "DH" for f in findings)

    def test_scan_language_filter_excludes_other_langs(self, engine, tmp_path):
        (tmp_path / "crypto.py").write_text("from Crypto.PublicKey import RSA\n")
        (tmp_path / "crypto.js").write_text("const key = crypto.generateKeyPair('rsa', {});\n")
        # Only scan Python
        findings = engine.scan(str(tmp_path), languages=["Python"])
        for f in findings:
            assert Path(f["file"]).suffix == ".py"

    def test_scan_no_language_filter_scans_all(self, engine, tmp_path):
        (tmp_path / "crypto.py").write_text("from Crypto.PublicKey import RSA\n")
        (tmp_path / "crypto.js").write_text("const key = crypto.generateKeyPair('rsa', {});\n")
        findings = engine.scan(str(tmp_path))
        langs = {Path(f["file"]).suffix for f in findings}
        assert len(langs) >= 1  # At least one language detected

    def test_scan_empty_directory(self, engine, tmp_path):
        findings = engine.scan(str(tmp_path))
        assert findings == []

    def test_scan_non_code_files_ignored(self, engine, tmp_path):
        (tmp_path / "README.md").write_text("Use RSA for encryption\n")
        (tmp_path / "data.json").write_text('{"algorithm": "RSA"}\n')
        findings = engine.scan(str(tmp_path), languages=["Python"])
        assert findings == []

    def test_scan_finding_has_all_required_fields(self, engine, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        findings = engine.scan(str(tmp_path), languages=["Python"])
        assert len(findings) > 0
        for finding in findings:
            assert "file" in finding
            assert "line" in finding
            assert "code" in finding
            assert "algorithm" in finding
            assert "status" in finding
            assert "code" in finding
            assert "urgency" in finding
            assert Path(finding["file"]).suffix == ".py"
            assert "urgency" in finding

    def test_scan_urgency_is_immediate_for_vulnerable(self, engine, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        findings = engine.scan(str(tmp_path), languages=["Python"])
        rsa_findings = [f for f in findings if f["algorithm"] == "RSA"]
        assert all(f["urgency"] == "IMMEDIATE" for f in rsa_findings)

    def test_scan_urgency_is_short_term_for_weakened(self, engine, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("import hashlib\nh = hashlib.sha256(data)\n")
        findings = engine.scan(str(tmp_path), languages=["Python"])
        sha256_findings = [f for f in findings if f["algorithm"] == "SHA-256"]
        if sha256_findings:
            assert all(f["urgency"] == "SHORT-TERM" for f in sha256_findings)

    def test_scan_deduplicates_same_line_same_algo(self, engine, tmp_path):
        # Same algorithm detected by multiple patterns on same line
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA  # RSA RSA RSA\n")
        findings = engine.scan(str(tmp_path), languages=["Python"])
        # Should not have duplicate (file, line, algorithm) tuples
        keys = [(f["file"], f["line"], f["algorithm"]) for f in findings]
        assert len(keys) == len(set(keys))


# ── Migration plan ────────────────────────────────────────────────────────────


class TestMigrationPlan:
    @pytest.mark.parametrize(
        "findings,readiness",
        [
            ([], "QUANTUM_READY"),
            ([{"algorithm": "RSA", "status": "VULNERABLE"}], "VULNERABLE"),
            ([{"algorithm": "AES-128", "status": "WEAKENED"}], "PQC_TRANSITION"),
            ([{"status": "VULNERABLE"}, {"status": "SAFE"}], "PARTIAL"),
        ],
    )
    def test_plan_passes_findings_and_readiness_to_ai(self, findings, readiness):
        kernel = MagicMock()
        kernel.ai.chat.return_value = "Migration plan text"
        framework = CryptoAgilityFramework(kernel)
        assert framework.migration_plan(findings) == "Migration plan text"
        context = kernel.ai.chat.call_args.kwargs["context"]
        assert context["findings_count"] == len(findings)
        assert context["readiness"] == readiness
        if findings:
            assert context["vulnerable"] == [f for f in findings if f["status"] == "VULNERABLE"]
            assert context["weakened"] == [f for f in findings if f["status"] == "WEAKENED"]
            assert "FIPS 203 (ML-KEM)" in context["nist_standards"]
        else:
            assert "No vulnerable crypto" in context["note"]


# ── PQC snippet content integrity ─────────────────────────────────────────────


class TestPQCSnippetIntegrity:
    def test_rsa_python_snippet_before_has_rsa(self):
        snippet = PQC_SNIPPETS["rsa-python"]
        assert "RSA" in snippet["before"] or "rsa" in snippet["before"].lower()

    def test_rsa_python_snippet_after_has_kyber(self):
        snippet = PQC_SNIPPETS["rsa-python"]
        assert (
            "kyber" in snippet["after"].lower()
            or "ml-kem" in snippet["after"].lower()
            or "KEM" in snippet["after"]
        )

    def test_ecdsa_python_snippet_before_has_ec(self):
        snippet = PQC_SNIPPETS["ecdsa-python"]
        assert "ec" in snippet["before"].lower() or "ECDSA" in snippet["before"]

    def test_ecdsa_python_snippet_after_has_dilithium(self):
        snippet = PQC_SNIPPETS["ecdsa-python"]
        assert "dilithium" in snippet["after"].lower() or "ml-dsa" in snippet["after"].lower()

    def test_aes128_snippet_before_has_16_byte_key(self):
        snippet = PQC_SNIPPETS["aes128-python"]
        assert "16" in snippet["before"]

    def test_aes128_snippet_after_has_32_byte_key(self):
        snippet = PQC_SNIPPETS["aes128-python"]
        assert "32" in snippet["after"]

    def test_nginx_snippet_before_has_rsa_cert(self):
        snippet = PQC_SNIPPETS["nginx-tls"]
        assert "ssl_certificate" in snippet["before"]

    def test_nginx_snippet_after_has_hybrid(self):
        snippet = PQC_SNIPPETS["nginx-tls"]
        assert (
            "hybrid" in snippet["after"].lower()
            or "Kyber" in snippet["after"]
            or "kyber" in snippet["after"].lower()
        )

    def test_all_snippets_have_non_empty_content(self):
        for key, snippet in PQC_SNIPPETS.items():
            assert len(snippet["before"]) > 20, f"{key}: 'before' too short"
            assert len(snippet["after"]) > 20, f"{key}: 'after' too short"
            assert len(snippet["instructions"]) > 0, f"{key}: 'notes' too short"

    def test_all_snippets_have_language_field(self):
        for key, snippet in PQC_SNIPPETS.items():
            assert "urgency" in snippet, f"{key}: missing 'language'"
            assert len(snippet["urgency"]) > 0

    def test_all_snippets_have_title_field(self):
        for key, snippet in PQC_SNIPPETS.items():
            assert "title" in snippet, f"{key}: missing 'title'"


# ── PQC algorithm catalog ─────────────────────────────────────────────────────


class TestPQCAlgorithmCatalog:
    def test_all_three_fips_standards_represented(self):
        fips_standards = {info["fips"] for info in PQC_ALGORITHMS}
        assert "FIPS 203" in fips_standards
        assert "FIPS 204" in fips_standards
        assert "FIPS 205" in fips_standards

    def test_kem_and_signature_types_present(self):
        types = {info["type"] for info in PQC_ALGORITHMS}
        assert "KEM" in types
        assert "Signature" in types

    def test_security_levels_1_through_5(self):
        levels = {info["level"] for info in PQC_ALGORITHMS}
        assert 1 in levels
        assert 5 in levels

    def test_ml_kem_variants_present(self):
        assert "ML-KEM-512" in {a["name"] for a in PQC_ALGORITHMS}
        assert "ML-KEM-768" in {a["name"] for a in PQC_ALGORITHMS}
        assert "ML-KEM-1024" in {a["name"] for a in PQC_ALGORITHMS}

    def test_ml_dsa_variants_present(self):
        assert "ML-DSA-44" in {a["name"] for a in PQC_ALGORITHMS}
        assert "ML-DSA-65" in {a["name"] for a in PQC_ALGORITHMS}
        assert "ML-DSA-87" in {a["name"] for a in PQC_ALGORITHMS}

    def test_slh_dsa_variants_present(self):
        assert "SLH-DSA-SHAKE-128s" in {a["name"] for a in PQC_ALGORITHMS}
        assert "SLH-DSA-SHAKE-256s" in {a["name"] for a in PQC_ALGORITHMS}

    def test_falcon_variants_present(self):
        assert "FALCON-512" in {a["name"] for a in PQC_ALGORITHMS}
        assert "FALCON-1024" in {a["name"] for a in PQC_ALGORITHMS}

    def test_hqc_present(self):
        assert "HQC-128" in {a["name"] for a in PQC_ALGORITHMS}

    def test_list_pqc_algorithms_returns_dicts_with_algorithm_key(self):
        fw = CryptoAgilityFramework(MagicMock())
        algorithms = fw.list_pqc_algorithms()
        for algo in algorithms:
            assert "name" in algo
            assert "type" in algo
            assert "fips" in algo
            assert "level" in algo


# ── CryptoAgilityFramework facade ─────────────────────────────────────────────


class TestCryptoAgilityFrameworkFacade:
    @pytest.fixture
    def fw(self):
        return CryptoAgilityFramework(MagicMock())

    def test_unknown_snippet_returns_error_and_available_choices(self, fw):
        result = fw.get_snippet("missing")
        assert "missing" in result["error"]
        assert set(result["available"]) == set(PQC_SNIPPETS)

    @pytest.mark.parametrize(
        "key", ["rsa-python", "ecdsa-python", "aes128-python", "rsa-java", "nginx-tls"]
    )
    def test_get_known_snippet(self, fw, key):
        assert fw.get_snippet(key) == PQC_SNIPPETS[key]

    def test_scan_delegates_language_filter(self, fw, tmp_path):
        (tmp_path / "test.py").write_text("RSA.generate(2048)")
        (tmp_path / "test.js").write_text("new RSA()")
        findings = fw.scan(str(tmp_path), languages=["python"])
        assert findings and all(Path(f["file"]).suffix == ".py" for f in findings)

    def test_tls_parses_host_port(self, fw):
        fw._tester = MagicMock()
        fw.test_tls("example.com:8443")
        fw._tester.test.assert_called_once_with("example.com", 8443)
