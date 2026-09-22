"""
shadow313.integrations.stia.binder
────────────────────────────────────
Binds STIA scan results with 313 Temporal Binding receipts
and feeds findings into the Shadow313 NEXUS detection pipeline.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from .parser import STIAScanResult, STIAParser

logger = logging.getLogger("shadow313.stia.binder")

try:
    from shadow313.core.binding_sdk.binder import Binder313, BindReceipt, AppIdentity
    HAS_BINDER = True
except ImportError:
    HAS_BINDER = False
    logger.warning("313 Binder SDK not available — receipts will be simulated")

_APP_IDENTITY_KWARGS = dict(
    app_id="aegis-nexus-vsat",
    app_name="Aegis Nexus VSAT",
    app_version="5.0.0",
)


class STIABinder:
    """
    Parses and 313-binds STIA scan results.

    Usage:
        binder = STIABinder()

        # From raw text (copy-paste from STIA UI)
        result, receipt = binder.bind_text(raw_stia_output)

        # From JSON string
        result, receipt = binder.bind_json(json_string)

        # From dict
        result, receipt = binder.bind_dict(data_dict)

        # Generate bound report
        html, json_path = binder.generate_report(result, receipt)
    """

    def __init__(self):
        self.parser = STIAParser()
        self._binder = None
        if HAS_BINDER:
            try:
                from shadow313.core.binding_sdk.binder import AppIdentity
                identity = AppIdentity(**_APP_IDENTITY_KWARGS)
                self._binder = Binder313(identity=identity)
            except Exception as exc:
                logger.warning("Could not init Binder313: %s", exc)

    # ── Public API ────────────────────────────────────────────────────────────

    def bind_text(self, text: str) -> Tuple[STIAScanResult, Optional[object]]:
        """Parse raw STIA text and bind with 313 receipt."""
        result = self.parser.parse_text(text)
        receipt = self._bind(result)
        return result, receipt

    def bind_json(self, json_str: str) -> Tuple[STIAScanResult, Optional[object]]:
        """Parse STIA JSON export and bind with 313 receipt."""
        result = self.parser.parse_json(json_str)
        receipt = self._bind(result)
        return result, receipt

    def bind_dict(self, data: dict) -> Tuple[STIAScanResult, Optional[object]]:
        """Parse STIA dict and bind with 313 receipt."""
        result = self.parser.parse_dict(data)
        receipt = self._bind(result)
        return result, receipt

    def generate_report(
        self,
        result: STIAScanResult,
        receipt: Optional[object],
        output_dir: str = "stia_bound_reports",
    ) -> Tuple[str, str]:
        """Generate HTML + JSON bound report."""
        try:
            from .report import generate_stia_report
            return generate_stia_report(result, receipt, output_dir=output_dir)
        except ImportError:
            logger.warning("STIA report module not available")
            return "", ""

    def to_nexus_findings(self, result: STIAScanResult) -> list:
        """Convert STIA result to NEXUS finding format."""
        return result.to_nexus_findings()

    def summary(self, result: STIAScanResult, receipt: Optional[object]) -> dict:
        """Return a compact summary dict."""
        s = {
            "target": result.target_name,
            "threat_profile": result.threat_profile,
            "risk_level": result.risk_level,
            "severity_score": result.severity_score,
            "status": result.status,
            "is_neutralized": result.is_neutralized,
            "cves": result.cve_list,
            "mitre_tactics": result.mitre_tactics,
            "artifact_count": len(result.forensic_artifacts),
            "mitigation_count": len(result.mitigations),
            "telemetry_events": len(result.telemetry_events),
            "ghost_stream": result.ghost_stream,
            "parsed_at": result.parsed_at,
        }
        if receipt:
            s["bind_id"] = getattr(receipt, "bind_id", None)
            s["timestamp_ns"] = getattr(receipt, "timestamp_ns", None)
            s["ipfs_cid"] = getattr(receipt, "ipfs_cid", None)
            s["chain_hash"] = getattr(receipt, "chain_hash", None)
        return s

    # ── Internal ──────────────────────────────────────────────────────────────

    def _bind(self, result: STIAScanResult) -> Optional[object]:
        """Create a 313 temporal bind for the scan result."""
        payload = result.to_bind_payload()
        if self._binder:
            try:
                receipt = self._binder.bind(
                    payload=payload,
                    metadata={
                        "source": "STIA",
                        "target_id": result.target_id,
                        "threat_profile": result.threat_profile,
                        "risk_level": result.risk_level,
                    },
                )
                logger.info(
                    "313 bind created for %s: %s",
                    result.target_id,
                    receipt.bind_id,
                )
                return receipt
            except Exception as exc:
                logger.warning("313 bind failed: %s", exc)

        # Simulated receipt when binder unavailable
        return _SimulatedReceipt(payload)


class _SimulatedReceipt:
    """Fallback receipt when 313 Binder SDK is not installed."""

    def __init__(self, payload: dict):
        import hashlib, time, secrets
        ts = time.time_ns()
        # Nudge to end in 313
        ts = int(str(ts)[:-3] + "313")
        self.timestamp_ns = ts
        self.timestamp_iso = datetime.now(timezone.utc).isoformat()
        raw = json.dumps(payload, sort_keys=True, default=str).encode()
        self.payload_hash = "sha3_256:" + hashlib.sha3_256(raw).hexdigest()
        self.chain_hash = "sha3_512:" + hashlib.sha3_512(raw).hexdigest()
        self.bind_id = f"313-STIA-{secrets.token_hex(4).upper()}"
        self.signature_algorithm = "SHA3-512 (simulated — install shadow313 core for SLH-DSA)"
        self.ipfs_cid = None
        self.ipfs_anchored = False
        self.app_id = "aegis-nexus-vsat"
        self.app_version = "5.0.0"

    def to_dict(self) -> dict:
        return {
            "bind_id": self.bind_id,
            "timestamp_ns": self.timestamp_ns,
            "timestamp_iso": self.timestamp_iso,
            "payload_hash": self.payload_hash,
            "chain_hash": self.chain_hash,
            "signature_algorithm": self.signature_algorithm,
            "ipfs_cid": self.ipfs_cid,
            "ipfs_anchored": self.ipfs_anchored,
            "app_id": self.app_id,
            "app_version": self.app_version,
        }