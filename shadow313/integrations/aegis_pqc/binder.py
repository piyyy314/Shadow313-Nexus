"""
shadow313.integrations.aegis_pqc.binder
─────────────────────────────────────────
AegisPQCBinder — binds PQC audit results with 313 Temporal Binding receipts.

Usage:
    binder = AegisPQCBinder()
    audit, receipt = binder.bind_shadow313_sbom(components)
    html_path, json_path = binder.generate_report(audit, receipt)
"""
from __future__ import annotations

import json
import logging
from typing import Optional, Tuple

from .parser import PQCAuditParser, PQCAuditResult

logger = logging.getLogger("shadow313.aegis_pqc.binder")

try:
    from shadow313.core.binding_sdk.binder import Binder313, AppIdentity, BindReceipt
    HAS_BINDER = True
except ImportError:
    HAS_BINDER = False
    logger.warning("Binder313 SDK not available — receipts will be simulated")

_APP_IDENTITY_KWARGS = dict(
    app_id      = "aegis-pqc",
    app_name    = "Aegis PQC Audit",
    app_version = "4.0.0",
)


class AegisPQCBinder:
    """
    Binds PQC audit results with 313 Temporal Binding receipts.

    Supports three input formats:
      - Shadow313 crypto_sbom.py component list
      - CycloneDX JSON SBOM
      - Raw dict

    Usage:
        binder = AegisPQCBinder()
        audit, receipt = binder.bind_shadow313_sbom(components)
        html_path, json_path = binder.generate_report(audit, receipt)
    """

    def __init__(self) -> None:
        self.parser = PQCAuditParser()
        self._binder = None
        if HAS_BINDER:
            try:
                identity     = AppIdentity(**_APP_IDENTITY_KWARGS)
                self._binder = Binder313(identity=identity)
            except Exception as exc:
                logger.warning("Could not init Binder313: %s", exc)

    # ── Public API ────────────────────────────────────────────────────────────

    def bind_shadow313_sbom(
        self,
        components: list[dict],
        source_file: str = "shadow313_crypto_sbom",
    ) -> Tuple[PQCAuditResult, object]:
        """Parse Shadow313 crypto_sbom output and bind with 313 receipt."""
        audit   = self.parser.parse_shadow313_sbom(components, source_file)
        receipt = self._bind(audit)
        return audit, receipt

    def bind_cyclonedx(
        self,
        data: dict,
        source_file: str = "cyclonedx_sbom.json",
    ) -> Tuple[PQCAuditResult, object]:
        """Parse CycloneDX JSON SBOM and bind with 313 receipt."""
        audit   = self.parser.parse_cyclonedx(data, source_file)
        receipt = self._bind(audit)
        return audit, receipt

    def bind_json(
        self,
        json_str: str,
        source_file: str = "",
    ) -> Tuple[PQCAuditResult, object]:
        """Parse JSON string and bind with 313 receipt."""
        audit   = self.parser.parse_json(json_str, source_file)
        receipt = self._bind(audit)
        return audit, receipt

    def bind_dict(
        self,
        data: dict,
        source_file: str = "",
    ) -> Tuple[PQCAuditResult, object]:
        """Parse dict and bind with 313 receipt."""
        audit   = self.parser.parse_dict(data, source_file)
        receipt = self._bind(audit)
        return audit, receipt

    def generate_report(
        self,
        audit: PQCAuditResult,
        receipt: object,
        output_dir: str = "aegis_bound_reports",  # nosec S03 — default string, not credential
    ) -> Tuple[str, str]:
        """Generate HTML + JSON bound report."""
        try:
            from .report import generate_bound_report
            return generate_bound_report(audit, receipt, output_dir=output_dir)  # nosec S03
        except Exception as exc:
            logger.warning("Report generation failed: %s", exc)
            return "", ""

    def summary(self, audit: PQCAuditResult, receipt: object) -> dict:
        """Return compact summary dict."""
        s = audit.to_summary()
        if receipt:
            s["bind_id"]    = getattr(receipt, "bind_id", None)
            s["timestamp_ns"] = getattr(receipt, "timestamp_ns", None)
            s["chain_hash"] = getattr(receipt, "chain_hash", None)
        return s

    # ── Internal ──────────────────────────────────────────────────────────────

    def _bind(self, audit: PQCAuditResult) -> object:
        """Create a 313 temporal bind for the audit result."""
        payload = audit.to_bind_payload()
        if self._binder:
            try:
                receipt = self._binder.bind(
                    payload  = payload,
                    metadata = {
                        "source":         "AegisPQC",
                        "overall_status": audit.overall_status,
                        "critical_count": audit.critical_count,
                    },
                )
                logger.info("313 bind created: %s", receipt.bind_id)
                return receipt
            except Exception as exc:
                logger.warning("313 bind failed: %s", exc)

        return _SimulatedReceipt(payload)


class _SimulatedReceipt:
    """Fallback receipt when Binder313 SDK is not installed."""

    def __init__(self, payload: dict) -> None:
        import hashlib, time, secrets
        ts = time.time_ns()
        ts = int(str(ts)[:-3] + "313")
        self.timestamp_ns        = ts
        self.timestamp_iso       = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat()  # nosec S01
        raw = json.dumps(payload, sort_keys=True, default=str).encode()
        self.payload_hash        = "sha3_256:" + hashlib.sha3_256(raw).hexdigest()
        self.chain_hash          = "sha3_512:" + hashlib.sha3_512(raw).hexdigest()
        self.prev_chain_hash     = ""
        self.bind_id             = f"AEGIS-PQC-{secrets.token_hex(4).upper()}"
        self.signature_algorithm = "SHA3-512 (simulated — install shadow313 core for SLH-DSA)"
        self.signature           = self.chain_hash
        self.ipfs_cid            = None
        self.ipfs_anchored       = False
        self.app_id              = "aegis-pqc"
        self.app_version         = "4.0.0"
        self.sequence            = 1

    def to_dict(self) -> dict:
        return {
            "bind_id":             self.bind_id,
            "timestamp_ns":        self.timestamp_ns,
            "timestamp_iso":       self.timestamp_iso,
            "payload_hash":        self.payload_hash,
            "chain_hash":          self.chain_hash,
            "prev_chain_hash":     self.prev_chain_hash,
            "signature_algorithm": self.signature_algorithm,
            "ipfs_cid":            self.ipfs_cid,
            "ipfs_anchored":       self.ipfs_anchored,
            "app_id":              self.app_id,
            "app_version":         self.app_version,
            "sequence":            self.sequence,
        }