"""NEXUS orchestration and verifiable security-intelligence reporting."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any


class NEXUSModule:
    """NEXUS platform orchestration. Registered command namespace: `nexus`."""

    def __init__(self, kernel) -> None:
        self.kernel = kernel
        self.out = kernel.out
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("nexus", self.run)

    def run(
        self,
        status: bool = False,
        bind_all: bool = False,
        verify_chain: bool = False,
        insider_attack_demo: bool = False,
        posture_report: bool = False,
    ) -> dict:
        if not any((status, bind_all, verify_chain, insider_attack_demo, posture_report)):
            status = True

        self.out.section("SHADOW313 NEXUS — VERIFIABLE SECURITY INTELLIGENCE")
        result: dict[str, Any] = {}

        if status:
            result["status"] = self._nexus_status()
            self.out.result(result["status"], "NEXUS Status")

        if bind_all:
            result["bindings"] = self._bind_all_session_outputs()

        if verify_chain:
            result["chain_verification"] = self._verify_audit_chain()

        if insider_attack_demo:
            result["insider_demo"] = self._demonstrate_insider_attack()

        if posture_report:
            result["posture"] = self._security_posture_report()

        return result

    def _nexus_status(self) -> dict:
        """Return the current NEXUS platform status."""
        temporal_module = self.kernel.get_module("temporal")
        receipts = []
        if temporal_module:
            receipts = temporal_module.engine.list_receipts(limit=5)

        ai_status = self.kernel.ai_status()
        modules = list(self.kernel._modules.keys())

        return {
            "version": "4.0.0-NEXUS",
            "session_id": self.session.id,
            "modules_loaded": len(modules),
            "modules": modules,
            "ai_backend": ai_status.get("backend"),
            "ai_available": ai_status.get("available"),
            "receipts_issued": len(receipts),
            "latest_receipt": receipts[0].get("receipt_id") if receipts else None,
            "temporal_binding": temporal_module is not None,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def _bind_all_session_outputs(self) -> list[dict]:
        """Bind JSON session outputs with individual 313 receipts."""
        temporal = self.kernel.get_module("temporal")
        if not temporal:
            self.out.warn("Temporal binding module not available")
            return []

        bindings = []
        for json_file in self.session.session_dir.glob("*.json"):
            try:
                content = json.loads(json_file.read_text(encoding="utf-8"))
                receipt = temporal.engine.bind(
                    content,
                    session_id=self.session.id,
                    module=json_file.stem,
                )
                bindings.append(
                    {
                        "file": json_file.name,
                        "receipt_id": receipt.receipt_id,
                        "ipfs_cid": receipt.ipfs_cid,
                    }
                )
                self.out.success(f"Bound {json_file.name} → {receipt.receipt_id}")
            except Exception as exc:
                self.out.warn(f"Could not bind {json_file.name}: {exc}")

        return bindings

    def _verify_audit_chain(self) -> dict:
        """
        Verify individual receipt integrity and report audit-log limitations.

        The current audit.log format is not signed. Therefore this method does
        not claim that the log itself is authenticated, even when receipts pass.
        """
        audit_path = self.session.session_dir / "audit.log"
        if not audit_path.exists():
            return {
                "valid": None,
                "status": "not_available",
                "audit_entries": 0,
                "audit_log_authenticated": False,
                "tamper_evident": False,
                "note": "No audit log exists; integrity cannot be established.",
            }

        try:
            entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {
                "valid": False,
                "status": "malformed_audit_log",
                "error": str(exc),
                "audit_log_authenticated": False,
                "tamper_evident": False,
            }

        temporal = self.kernel.get_module("temporal")
        if not temporal:
            return {
                "valid": None,
                "status": "verification_unavailable",
                "audit_entries": len(entries),
                "audit_log_authenticated": False,
                "tamper_evident": False,
                "note": "The temporal verification module is unavailable.",
            }

        receipt_limit = 10000
        receipts = temporal.engine.list_receipts(limit=receipt_limit)
        if not receipts:
            return {
                "valid": None,
                "status": "no_receipts",
                "audit_entries": len(entries),
                "receipts_checked": 0,
                "audit_log_authenticated": False,
                "tamper_evident": False,
                "note": "The audit log is parsed, but no signed receipts are available.",
            }

        checks = []
        for receipt in receipts:
            receipt_id = str(receipt.get("receipt_id", ""))
            try:
                verification = (
                    temporal.engine.verify(receipt_id)
                    if receipt_id
                    else {"valid": False, "error": "Receipt ID is missing"}
                )
            except Exception as exc:
                verification = {"valid": False, "error": str(exc)}

            if not isinstance(verification, dict):
                verification = {
                    "valid": False,
                    "error": "Receipt verifier returned an invalid result",
                }

            verification_checks = verification.get("checks", {})
            if not isinstance(verification_checks, dict):
                verification_checks = {}

            signature_verified = verification_checks.get("signature_verified") is True
            sha3_512_matches = verification_checks.get("sha3_512_matches") is True
            cryptographically_verified = (
                verification.get("valid") is True and signature_verified and sha3_512_matches
            )
            checks.append(
                {
                    "receipt_id": receipt_id or None,
                    "valid": cryptographically_verified,
                    "signature_verified": signature_verified,
                    "signer_trusted": verification_checks.get("signer_trusted") is True,
                    "sha3_512_matches": sha3_512_matches,
                    "error": verification.get("error"),
                }
            )

        invalid_receipts = [item["receipt_id"] for item in checks if not item["valid"]]
        untrusted_signers = [
            item["receipt_id"]
            for item in checks
            if item["signature_verified"] and not item["signer_trusted"]
        ]

        indices = []
        for receipt in receipts:
            try:
                bind_index = int(receipt.get("bind_index", 0))
            except (TypeError, ValueError):
                continue
            if bind_index > 0:
                indices.append(bind_index)
        indices.sort()
        gaps = [
            {"from": indices[index], "to": indices[index + 1]}
            for index in range(len(indices) - 1)
            if indices[index + 1] - indices[index] > 1
        ]
        index_counts = Counter(indices)
        duplicates = sorted(index for index, count in index_counts.items() if count > 1)

        receipt_integrity_valid = not invalid_receipts and len(checks) == len(receipts)
        signer_trust_complete = all(
            item["signature_verified"] and item["signer_trusted"] for item in checks
        )
        tamper_evident = (
            receipt_integrity_valid
            and signer_trust_complete
            and not gaps
            and not duplicates
            and len(receipts) < receipt_limit
        )

        return {
            "valid": None,
            "status": "partial_verification",
            "scope": "individual receipt integrity; audit.log authenticity is not verified",
            "audit_entries": len(entries),
            "audit_log_authenticated": False,
            "receipt_integrity_valid": receipt_integrity_valid,
            "trusted_receipt_chain": (
                receipt_integrity_valid and signer_trust_complete and not gaps and not duplicates
            ),
            "tamper_evident": tamper_evident,
            "receipts_checked": len(receipts),
            "receipt_limit_reached": len(receipts) == receipt_limit,
            "invalid_receipts": invalid_receipts,
            "untrusted_signers": untrusted_signers,
            "bind_index_gaps": gaps,
            "duplicate_bind_indices": duplicates,
            "note": (
                "Receipt hashes and signatures were checked individually. "
                "The audit.log file itself is not cryptographically authenticated; "
                "signer identity requires trusted signer IDs to be configured. "
                "Bind-index gaps are diagnostic and do not alone prove tampering."
            ),
        }

    def _demonstrate_insider_attack(self) -> dict:
        """
        Show why a hash chain needs a separately trusted signed checkpoint.

        This is an illustrative SHA-3 example. It does not execute the production
        SLH-DSA receipt verifier and is not evidence of a vulnerability in a SIEM.
        """
        self.out.warn("DEMO: self-consistent SHA-3 hash-chain rewrite (illustrative)")
        self.out.info("A chain can be recomputed if an attacker can rewrite every entry and hash.")

        entries = [
            {"id": index, "action": f"action_{index}", "user": "admin"} for index in range(1, 13)
        ]

        def compute_chain(items: list[dict]) -> list[str]:
            chain = []
            previous = b""
            for entry in items:
                digest = hashlib.sha3_512(
                    previous + json.dumps(entry, sort_keys=True).encode("utf-8")
                ).hexdigest()
                chain.append(digest)
                previous = digest.encode("ascii")
            return chain

        original_chain = compute_chain(entries)
        started = time.perf_counter()
        tampered_entries = [entry for entry in entries if entry["id"] != 7]
        tampered_chain = compute_chain(tampered_entries)
        elapsed_ms = (time.perf_counter() - started) * 1000
        recomputed = len(tampered_chain) == len(tampered_entries) and bool(tampered_chain[-1])

        self.out.warn(f"Recomputed a modified chain in {elapsed_ms:.3f} ms")
        self.out.info("This toy example has no independently trusted checkpoint or signature.")

        return {
            "attack": "Self-consistent SHA-3 hash-chain rewrite",
            "deleted_entry": 7,
            "elapsed_ms": round(elapsed_ms, 3),
            "original_entries": len(entries),
            "tampered_entries": len(tampered_entries),
            "sha3_chain_recomputed": recomputed,
            "original_checkpoint_changed": (
                bool(original_chain) and original_chain[-1] != tampered_chain[-1]
            ),
            "nexus_detection_executed": False,
            "nexus_detected": None,
            "countermeasure": (
                "Verify a receipt against a separately trusted signer key and "
                "checkpoint; this demonstration does not perform that verification."
            ),
            "cve_candidate": False,
            "note": (
                "Illustrative hash-chain behavior only. It does not establish impact "
                "against every SIEM or validate the production NEXUS receipt verifier."
            ),
        }

    def _security_posture_report(self) -> dict:
        """Generate a summary from the current session's available scan outputs."""
        posture: dict[str, Any] = {
            "session_id": self.session.id,
            "timestamp": datetime.now(UTC).isoformat(),
            "modules_run": [],
        }

        session_dir = self.session.session_dir
        for json_file in session_dir.glob("*.json"):
            if json_file.name == "meta.json":
                continue
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                posture["modules_run"].append(json_file.stem)
                if json_file.stem == "findings":
                    findings = data.get("findings", [])
                    posture["total_findings"] = len(findings)
                    posture["critical"] = sum(
                        1
                        for finding in findings
                        if finding.get("severity", "").upper() == "CRITICAL"
                    )
                    posture["high"] = sum(
                        1 for finding in findings if finding.get("severity", "").upper() == "HIGH"
                    )
                elif json_file.stem == "compliance":
                    posture["compliance_score"] = data.get("compliance_score", "N/A")
                elif json_file.stem == "quantum_report":
                    posture["quantum_findings"] = len(data.get("findings", []))
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "Skipping unreadable posture input %s: %s", json_file, exc
                )

        posture["ai_summary"] = self.kernel.ai.chat(
            "Generate a concise executive security posture summary based on these scan results. "
            "Include: overall risk rating (CRITICAL/HIGH/MEDIUM/LOW), top 3 priorities, "
            "and one-line recommendation for each. Keep under 200 words.",
            context=posture,
        )
        return posture
