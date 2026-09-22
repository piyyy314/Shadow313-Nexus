"""
Tests for shadow313.v4.temporal_binding.cmmc_audit_package

Covers:
  - AuditMerkleTree: full proof paths, cross-instance verification
  - MerkleProof: independent verification without shared state
  - AuditReceipt: canonical serialization, hash correctness
  - CMMCAuditPackageBuilder: receipt creation, package build, export
  - Standalone verification script: 3PAO simulation
  - Tamper detection: content modification, hash mismatch
  - CMMC control mapping: all 6 AU/SI controls satisfied
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import pytest

from shadow313.v4.temporal_binding.cmmc_audit_package import (
    AuditMerkleTree, MerkleProof, MerkleProofStep,
    AuditReceipt, CMMCAuditPackage, CMMCAuditPackageBuilder,
    build_vsat_audit_package, _generate_verification_script,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def builder():
    return CMMCAuditPackageBuilder(
        operator    = "test-operator",
        system_name = "TEST-SYSTEM-001",
        ipfs_api    = "http://localhost:19999",  # no IPFS
    )

@pytest.fixture
def builder_with_findings(builder):
    builder.add_finding(
        action="scan", finding="CVE-2026-3392 CWMP", severity="CRITICAL",
        cve_ids=["CVE-2026-3392"], mitre_techniques=["T1190"], threat_level="CRITICAL",
    )
    builder.add_finding(
        action="scan", finding="Unsigned firmware", severity="CRITICAL",
        cve_ids=["CVE-2023-5678"], mitre_techniques=["T1542.001"], threat_level="CRITICAL",
    )
    builder.add_finding(
        action="rf", finding="SNR 5.9 dB below threshold", severity="HIGH",
        cve_ids=[], mitre_techniques=["T1498"], threat_level="HIGH",
    )
    return builder

@pytest.fixture
def package(builder_with_findings):
    return builder_with_findings.build()

@pytest.fixture
def vsat_package_path(tmp_path):
    _, path = build_vsat_audit_package(output_dir=str(tmp_path))
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# AuditMerkleTree
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditMerkleTree:

    def _make_leaves(self, n: int) -> list[str]:
        return [hashlib.sha3_256(f"leaf_{i}".encode()).hexdigest() for i in range(n)]

    def test_root_deterministic(self):
        leaves = self._make_leaves(4)
        t1 = AuditMerkleTree(leaves)
        t2 = AuditMerkleTree(leaves)
        assert t1.root == t2.root

    def test_root_changes_with_leaves(self):
        leaves_a = self._make_leaves(4)
        leaves_b = self._make_leaves(4)
        leaves_b[2] = hashlib.sha3_256(b"different").hexdigest()
        assert AuditMerkleTree(leaves_a).root != AuditMerkleTree(leaves_b).root

    def test_proof_verifies_for_all_leaves(self):
        leaves = self._make_leaves(4)
        tree = AuditMerkleTree(leaves)
        for i in range(4):
            proof = tree.get_proof(i)
            assert proof.verify(), f"Proof failed for leaf {i}"

    def test_proof_verifies_odd_leaf_count(self):
        leaves = self._make_leaves(5)
        tree = AuditMerkleTree(leaves)
        for i in range(5):
            proof = tree.get_proof(i)
            assert proof.verify()

    def test_proof_verifies_single_leaf(self):
        leaves = self._make_leaves(1)
        tree = AuditMerkleTree(leaves)
        proof = tree.get_proof(0)
        assert proof.verify()

    def test_proof_cross_instance_verification(self):
        """Key test: proof verifies without access to original tree instance."""
        leaves = self._make_leaves(4)
        tree1 = AuditMerkleTree(leaves)
        proof = tree1.get_proof(2)

        # Serialize and deserialize proof (simulates 3PAO receiving JSON)
        proof_dict = proof.to_dict()
        proof2 = MerkleProof(
            leaf_hash  = proof_dict["leaf_hash"],
            leaf_index = proof_dict["leaf_index"],
            root       = proof_dict["root"],
            path       = [MerkleProofStep(**s) for s in proof_dict["path"]],
        )
        assert proof2.verify()

    def test_tampered_leaf_fails_verification(self):
        leaves = self._make_leaves(4)
        tree = AuditMerkleTree(leaves)
        proof = tree.get_proof(0)
        # Tamper with leaf hash
        tampered = MerkleProof(
            leaf_hash  = hashlib.sha3_256(b"tampered").hexdigest(),
            leaf_index = proof.leaf_index,
            root       = proof.root,
            path       = proof.path,
        )
        assert tampered.verify() is False

    def test_tampered_root_fails_verification(self):
        leaves = self._make_leaves(4)
        tree = AuditMerkleTree(leaves)
        proof = tree.get_proof(0)
        tampered = MerkleProof(
            leaf_hash  = proof.leaf_hash,
            leaf_index = proof.leaf_index,
            root       = "0" * 64,  # wrong root
            path       = proof.path,
        )
        assert tampered.verify() is False

    def test_proof_path_length(self):
        """Proof path length = ceil(log2(n)) for n leaves."""
        import math
        for n in [2, 4, 8]:
            leaves = self._make_leaves(n)
            tree = AuditMerkleTree(leaves)
            proof = tree.get_proof(0)
            expected_depth = math.ceil(math.log2(n))
            assert len(proof.path) == expected_depth


# ═══════════════════════════════════════════════════════════════════════════════
# AuditReceipt
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditReceipt:

    def test_timestamp_ends_313(self, builder_with_findings):
        pkg = builder_with_findings.build()
        for r in pkg.receipts:
            assert str(r.timestamp_ns).endswith("313"), \
                f"Receipt {r.receipt_id} timestamp {r.timestamp_ns} doesn't end in 313"

    def test_content_hash_is_sha3_256(self, package):
        for r in package.receipts:
            assert r.content_hash.startswith("sha3_256:")

    def test_leaf_hash_is_sha3_256_of_content_hash(self, package):
        for r in package.receipts:
            expected = hashlib.sha3_256(r.content_hash.encode()).hexdigest()
            assert r.leaf_hash == expected

    def test_multihash_has_three_components(self, package):
        for r in package.receipts:
            parts = r.multihash.split(":")
            assert parts[0] == "mh"
            assert len(parts) == 4

    def test_receipt_id_is_unique(self, package):
        ids = [r.receipt_id for r in package.receipts]
        assert len(set(ids)) == len(ids)

    def test_sequence_is_monotonic(self, package):
        seqs = [r.sequence for r in package.receipts]
        assert seqs == sorted(seqs)
        assert seqs[0] == 1

    def test_ipfs_status_is_no_ipfs_when_unavailable(self, package):
        for r in package.receipts:
            assert r.ipfs_status == "no-ipfs"

    def test_canonical_is_deterministic(self, package):
        r = package.receipts[0]
        c1 = r.canonical()
        c2 = r.canonical()
        assert c1 == c2

    def test_to_dict_has_all_required_fields(self, package):
        r = package.receipts[0]
        d = r.to_dict()
        for field in ("receipt_id", "sequence", "timestamp_ns", "timestamp_iso",
                      "operator", "system", "action", "finding", "severity",
                      "cve_ids", "mitre_techniques", "threat_level",
                      "content_hash", "multihash", "leaf_hash", "ipfs_status"):
            assert field in d, f"Missing field: {field}"


# ═══════════════════════════════════════════════════════════════════════════════
# CMMCAuditPackageBuilder
# ═══════════════════════════════════════════════════════════════════════════════

class TestCMMCAuditPackageBuilder:

    def test_build_requires_receipts(self, builder):
        with pytest.raises(ValueError, match="No receipts"):
            builder.build()

    def test_build_returns_package(self, package):
        assert isinstance(package, CMMCAuditPackage)

    def test_merkle_root_is_set(self, package):
        assert len(package.merkle_root) == 64  # SHA3-256 hex

    def test_merkle_proofs_for_all_receipts(self, package):
        for r in package.receipts:
            assert r.receipt_id in package.merkle_proofs

    def test_package_hash_is_sha3_512(self, package):
        assert package.package_hash.startswith("sha3_512:")

    def test_sig_algorithm_is_set(self, package):
        assert len(package.sig_algorithm) > 5

    def test_cmmc_controls_all_satisfied(self, package):
        for ctrl_id, ctrl in package.cmmc_controls.items():
            assert ctrl["status"] == "SATISFIED", f"{ctrl_id} not satisfied"

    def test_six_cmmc_controls_present(self, package):
        expected = {"AU.2.041", "AU.2.042", "AU.3.045", "AU.3.046", "SI.1.210", "SI.2.216"}
        assert set(package.cmmc_controls.keys()) == expected

    def test_verification_script_embedded(self, package):
        assert len(package.verification_script) > 1000
        assert "def verify_merkle_proof" in package.verification_script
        assert "def verify_multihash" in package.verification_script
        assert "def verify_content_hash" in package.verification_script

    def test_export_creates_json_file(self, package, tmp_path):
        builder = CMMCAuditPackageBuilder(operator="test", system_name="TEST")
        path = builder.export(package, output_dir=str(tmp_path))
        assert os.path.exists(path)
        assert path.endswith(".json")

    def test_exported_json_is_valid(self, package, tmp_path):
        builder = CMMCAuditPackageBuilder(operator="test", system_name="TEST")
        path = builder.export(package, output_dir=str(tmp_path))
        with open(path) as f:
            data = json.load(f)
        assert data["schema"] == "S313-CMMC-AUDIT-v1"
        assert len(data["receipts"]) == len(package.receipts)

    def test_package_hash_verifiable(self, package):
        """Package hash must be independently recomputable."""
        receipts = package.receipts
        hash_input = package.merkle_root + "".join(r.content_hash for r in receipts)
        expected = "sha3_512:" + hashlib.sha3_512(hash_input.encode()).hexdigest()
        assert package.package_hash == expected


# ═══════════════════════════════════════════════════════════════════════════════
# Merkle proof cross-instance verification (3PAO simulation)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossInstanceVerification:

    def test_merkle_proof_verifies_from_json(self, package):
        """3PAO can verify proof from JSON without Shadow313."""
        for receipt in package.receipts:
            proof_dict = package.merkle_proofs[receipt.receipt_id]
            # Reconstruct proof from JSON (as 3PAO would)
            proof = MerkleProof(
                leaf_hash  = proof_dict["leaf_hash"],
                leaf_index = proof_dict["leaf_index"],
                root       = proof_dict["root"],
                path       = [MerkleProofStep(**s) for s in proof_dict["path"]],
            )
            assert proof.verify(), f"Cross-instance proof failed for {receipt.receipt_id}"

    def test_content_hash_verifiable_from_canonical(self, package):
        """3PAO can recompute content hash from receipt fields."""
        for r in package.receipts:
            canonical = json.dumps({
                "receipt_id":       r.receipt_id,
                "sequence":         r.sequence,
                "timestamp_ns":     r.timestamp_ns,
                "operator":         r.operator,
                "system":           r.system,
                "action":           r.action,
                "finding":          r.finding,
                "severity":         r.severity,
                "cve_ids":          sorted(r.cve_ids),
                "mitre_techniques": sorted(r.mitre_techniques),
                "threat_level":     r.threat_level,
            }, sort_keys=True, separators=(',', ':'))
            expected = "sha3_256:" + hashlib.sha3_256(canonical.encode()).hexdigest()
            assert r.content_hash == expected

    def test_multihash_verifiable_from_canonical(self, package):
        """3PAO can verify triple hash from canonical content."""
        for r in package.receipts:
            canonical = r.canonical()
            b = canonical.encode()
            h256 = hashlib.sha3_256(b).hexdigest()[:20]
            h512 = hashlib.sha3_512(b).hexdigest()[:20]
            h384 = hashlib.sha3_384(b).hexdigest()[:20]
            expected = f"mh:{h256}:{h512}:{h384}"
            assert r.multihash == expected


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone verification script (3PAO simulation)
# ═══════════════════════════════════════════════════════════════════════════════

class TestStandaloneVerificationScript:

    def test_script_passes_on_valid_package(self, vsat_package_path, tmp_path):
        """3PAO verification script returns exit code 0 for valid package."""
        with open(vsat_package_path) as f:
            data = json.load(f)
        script_path = str(tmp_path / "verify_audit.py")
        with open(script_path, "w") as f:
            f.write(data["verification_script"])
        result = subprocess.run(
            [sys.executable, script_path, vsat_package_path],
            capture_output=True, text=True
        )
        assert result.returncode == 0, f"Verification failed:\n{result.stdout}\n{result.stderr}"

    def test_script_detects_finding_tampering(self, vsat_package_path, tmp_path):
        """Modifying a finding causes exit code 1."""
        with open(vsat_package_path) as f:
            data = json.load(f)
        data["receipts"][0]["finding"] = "TAMPERED: no findings here"
        tampered_path = str(tmp_path / "tampered.json")
        with open(tampered_path, "w") as f:
            json.dump(data, f)
        script_path = str(tmp_path / "verify_audit.py")
        with open(str(tmp_path / "verify_audit.py"), "w") as f:
            f.write(data["verification_script"])
        result = subprocess.run(
            [sys.executable, script_path, tampered_path],
            capture_output=True, text=True
        )
        assert result.returncode == 1

    def test_script_detects_severity_tampering(self, vsat_package_path, tmp_path):
        """Changing severity from CRITICAL to LOW causes exit code 1."""
        with open(vsat_package_path) as f:
            data = json.load(f)
        data["receipts"][0]["severity"] = "LOW"
        tampered_path = str(tmp_path / "tampered_sev.json")
        with open(tampered_path, "w") as f:
            json.dump(data, f)
        script_path = str(tmp_path / "verify_audit.py")
        with open(script_path, "w") as f:
            f.write(data["verification_script"])
        result = subprocess.run(
            [sys.executable, script_path, tampered_path],
            capture_output=True, text=True
        )
        assert result.returncode == 1

    def test_script_output_contains_cmmc_controls(self, vsat_package_path, tmp_path):
        """Verification output lists all 6 CMMC controls."""
        with open(vsat_package_path) as f:
            data = json.load(f)
        script_path = str(tmp_path / "verify_audit.py")
        with open(script_path, "w") as f:
            f.write(data["verification_script"])
        result = subprocess.run(
            [sys.executable, script_path, vsat_package_path],
            capture_output=True, text=True
        )
        for ctrl in ("AU.2.041", "AU.2.042", "AU.3.045", "AU.3.046", "SI.1.210", "SI.2.216"):
            assert ctrl in result.stdout, f"CMMC control {ctrl} missing from output"

    def test_script_uses_only_stdlib(self):
        """Verification script must not import non-stdlib modules."""
        script = _generate_verification_script()
        import re
        imports = re.findall(r'^import (\w+)|^from (\w+)', script, re.MULTILINE)
        stdlib_only = {"sys", "json", "hashlib", "argparse", "pathlib"}
        for imp_tuple in imports:
            mod = imp_tuple[0] or imp_tuple[1]
            assert mod in stdlib_only, f"Non-stdlib import found: {mod}"

    def test_script_single_receipt_verification(self, vsat_package_path, tmp_path):
        """--receipt flag verifies only the specified receipt."""
        with open(vsat_package_path) as f:
            data = json.load(f)
        first_id = data["receipts"][0]["receipt_id"]
        script_path = str(tmp_path / "verify_audit.py")
        with open(script_path, "w") as f:
            f.write(data["verification_script"])
        result = subprocess.run(
            [sys.executable, script_path, vsat_package_path, "--receipt", first_id],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        assert first_id in result.stdout


# ═══════════════════════════════════════════════════════════════════════════════
# VSAT audit package (integration)
# ═══════════════════════════════════════════════════════════════════════════════

class TestVSATAuditPackage:

    def test_vsat_package_has_seven_receipts(self, vsat_package_path):
        with open(vsat_package_path) as f:
            data = json.load(f)
        assert len(data["receipts"]) == 7

    def test_vsat_package_has_five_critical(self, vsat_package_path):
        with open(vsat_package_path) as f:
            data = json.load(f)
        critical = [r for r in data["receipts"] if r["severity"] == "CRITICAL"]
        assert len(critical) == 5

    def test_vsat_package_cve_2026_3392_present(self, vsat_package_path):
        with open(vsat_package_path) as f:
            data = json.load(f)
        all_cves = [cve for r in data["receipts"] for cve in r["cve_ids"]]
        assert "CVE-2026-3392" in all_cves

    def test_vsat_package_schema_correct(self, vsat_package_path):
        with open(vsat_package_path) as f:
            data = json.load(f)
        assert data["schema"] == "S313-CMMC-AUDIT-v1"
        assert data["cmmc_level"] == "Level 2"

    def test_vsat_package_ipfs_status_no_ipfs(self, vsat_package_path):
        with open(vsat_package_path) as f:
            data = json.load(f)
        assert data["ipfs_status"] == "no-ipfs"

    def test_vsat_package_merkle_proofs_all_verify(self, vsat_package_path):
        with open(vsat_package_path) as f:
            data = json.load(f)
        root = data["merkle_root"]
        for receipt in data["receipts"]:
            proof_dict = data["merkle_proofs"][receipt["receipt_id"]]
            proof = MerkleProof(
                leaf_hash  = proof_dict["leaf_hash"],
                leaf_index = proof_dict["leaf_index"],
                root       = proof_dict["root"],
                path       = [MerkleProofStep(**s) for s in proof_dict["path"]],
            )
            assert proof.verify()
            assert proof_dict["root"] == root