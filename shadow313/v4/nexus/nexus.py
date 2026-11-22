from __future__ import annotations
"""
shadow313.v4.nexus.nexus  — v4 NEXUS
NEXUS orchestration layer: verifiable security intelligence platform.
Integrates 313 Temporal Binding with all modules for cryptographic provenance.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class NEXUSModule:
    """
    shadow313.v4.nexus — NEXUS platform orchestration. Registered: nexus

    NEXUS = Verifiable Security Intelligence
    Every finding is a cryptographic fact, not just a log entry.
    """

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
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
        """Return NEXUS platform status."""
        temporal_module = self.kernel.get_module("temporal")
        receipts = []
        if temporal_module:
            receipts = temporal_module.engine.list_receipts(limit=5)

        ai_status = self.kernel.ai_status()
        modules   = list(self.kernel._modules.keys())

        return {
            "version":          "4.0.0-NEXUS",
            "session_id":       self.session.id,
            "modules_loaded":   len(modules),
            "modules":          modules,
            "ai_backend":       ai_status.get("backend"),
            "ai_available":     ai_status.get("available"),
            "receipts_issued":  len(receipts),
            "latest_receipt":   receipts[0].get("receipt_id") if receipts else None,
            "temporal_binding": temporal_module is not None,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
        }

    def _bind_all_session_outputs(self) -> list[dict]:
        """Bind all session JSON outputs with 313 receipts."""
        temporal = self.kernel.get_module("temporal")
        if not temporal:
            self.out.warn("Temporal binding module not available")
            return []

        session_dir = self.session.session_dir
        bindings    = []
        for json_file in session_dir.glob("*.json"):
            try:
                content = json.loads(json_file.read_text())
                receipt = temporal.engine.bind(
                    content,
                    session_id=self.session.id,
                    module=json_file.stem,
                )
                bindings.append({
                    "file":       json_file.name,
                    "receipt_id": receipt.receipt_id,
                    "ipfs_cid":   receipt.ipfs_cid,
                })
                self.out.success(f"Bound {json_file.name} → {receipt.receipt_id}")
            except Exception as exc:
                self.out.warn(f"Could not bind {json_file.name}: {exc}")

        return bindings

    def _verify_audit_chain(self) -> dict:
        """Verify receipt hashes, signatures, and sequence continuity separately."""
        audit_path = self.session.session_dir / "audit.log"
        if not audit_path.exists():
            return {
                "valid": False,
                "status": "NOT_VERIFIED",
                "entries": 0,
                "note": "No audit log exists yet; no integrity conclusion is possible.",
            }

        entries = []
        try:
            for line in audit_path.read_text().splitlines():
                if line.strip():
                    entries.append(json.loads(line))
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

        temporal = self.kernel.get_module("temporal")
        receipts = temporal.engine.list_receipts(limit=100) if temporal else []
        gaps = []
        if receipts:
            indices = sorted(int(receipt.get("bind_index", 0)) for receipt in receipts)
            for left, right in zip(indices, indices[1:]):
                if right - left > 1:
                    gaps.append({"from": left, "to": right})

        verifications = []
        if temporal:
            for receipt in receipts:
                receipt_id = str(receipt.get("receipt_id", ""))
                if receipt_id:
                    verifications.append(temporal.engine.verify(receipt_id))

        verified = [item for item in verifications if item.get("valid") is True]
        unverified = [
            item.get("receipt_id", "unknown")
            for item in verifications
            if item.get("valid") is not True
        ]
        signature_count = sum(
            1 for item in verifications
            if item.get("checks", {}).get("signature_verified") is True
        )
        trusted_count = sum(
            1 for item in verifications
            if item.get("checks", {}).get("signer_trusted") is True
        )
        anchor_count = sum(
            1 for item in verifications
            if item.get("checks", {}).get("ipfs_anchor_recorded") is True
        )
        sequence_integrity = not gaps
        valid = bool(receipts) and sequence_integrity and len(verified) == len(receipts)

        return {
            "valid": valid,
            "audit_entries": len(entries),
            "receipts_checked": len(receipts),
            "signature_verified": signature_count,
            "trusted_signers": trusted_count,
            "ipfs_anchors_recorded": anchor_count,
            "unverified_receipts": unverified,
            "gaps_detected": gaps,
            "sequence_integrity": sequence_integrity,
            "cryptographic_integrity_verified": valid,
            "note": (
                "Receipt hashes and signatures verified. Embedded-key validity does not establish "
                "signer identity; configure SHADOW313_TRUSTED_SIGNER_IDS to trust key IDs. "
                "Recorded IPFS CIDs are not fetched during this local check."
            ),
        }

    def _demonstrate_insider_attack(self) -> dict:
        """
        Demonstrate why an unanchored hash chain can be rewritten by an attacker
        who controls the complete log, and show sequence-gap detection separately.
        """
        import hashlib
        import time

        self.out.warn("DEMONSTRATING: Unanchored Hash-Chain Rewrite (educational)")
        self.out.info(
            "A hash chain alone is not an authenticated signature or trusted external checkpoint."
        )

        entries = [
            {"id": index, "action": f"action_{index}", "user": "admin"}
            for index in range(1, 13)
        ]

        def compute_chain(items: list[dict]) -> list[str]:
            chain = []
            previous = b""
            for item in items:
                digest = hashlib.sha3_512(previous + json.dumps(item).encode()).hexdigest()
                chain.append(digest)
                previous = digest.encode()
            return chain

        original_chain = compute_chain(entries)
        start = time.perf_counter()
        tampered = [entry for entry in entries if entry["id"] != 7]
        recomputed_chain = compute_chain(tampered)
        elapsed_ms = (time.perf_counter() - start) * 1000

        tampered_indices = [entry["id"] for entry in tampered]
        sequence_gaps = [
            {"from": left, "to": right}
            for left, right in zip(tampered_indices, tampered_indices[1:])
            if right - left > 1
        ]
        sequence_gap_detected = bool(sequence_gaps)

        self.out.warn(f"Recomputed unanchored hash chain in {elapsed_ms:.3f}ms")
        self.out.info(
            f"Hash chain was recomputed: {len(recomputed_chain)} entries; "
            f"original chain had {len(original_chain)}."
        )
        if sequence_gap_detected:
            self.out.success("313-BIND sequence-gap check: DETECTED")
        else:
            self.out.warn("313-BIND sequence-gap check: NOT DETECTED")

        return {
            "attack": "Unanchored Hash-Chain Rewrite",
            "deleted_entry": 7,
            "elapsed_ms": round(elapsed_ms, 3),
            "hash_chain_recomputed": True,
            "sequence_gap_detected": sequence_gap_detected,
            "sequence_gaps": sequence_gaps,
            "original_entries": len(entries),
            "tampered_entries": len(tampered),
            "countermeasure": (
                "Sequence-gap checks plus per-receipt signature verification; "
                "trusted signer identity and external anchoring are separate requirements."
            ),
            "cve_candidate": False,
            "note": (
                "Educational demonstration only, not a CVE claim. A hash chain must be "
                "anchored to a trusted checkpoint or authenticated signer to resist full-log rewrites."
            ),
        }

    def _security_posture_report(self) -> dict:
        """Generate a comprehensive security posture report."""
        posture: dict[str, Any] = {
            "session_id":  self.session.id,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "modules_run": [],
        }

        # Collect all session outputs
        session_dir = self.session.session_dir
        for json_file in session_dir.glob("*.json"):
            if json_file.name == "meta.json":
                continue
            try:
                data = json.loads(json_file.read_text())
                posture["modules_run"].append(json_file.stem)
                # Extract key metrics
                if json_file.stem == "findings":
                    findings = data.get("findings", [])
                    posture["total_findings"] = len(findings)
                    posture["critical"] = sum(1 for f in findings if f.get("severity","").upper() == "CRITICAL")
                    posture["high"]     = sum(1 for f in findings if f.get("severity","").upper() == "HIGH")
                elif json_file.stem == "compliance":
                    posture["compliance_score"] = data.get("compliance_score", "N/A")
                elif json_file.stem == "quantum_report":
                    posture["quantum_findings"] = len(data.get("findings", []))
            except Exception as _exc:  # S01-fixed
                import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
                pass

        # AI posture summary
        posture["ai_summary"] = self.kernel.ai.chat(
            "Generate a concise executive security posture summary based on these scan results. "
            "Include: overall risk rating (CRITICAL/HIGH/MEDIUM/LOW), top 3 priorities, "
            "and one-line recommendation for each. Keep under 200 words.",
            context=posture,
        )

        return posture