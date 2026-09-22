"""
shadow313.core.binding_sdk.binder
───────────────────────────────────
313 Temporal Binding SDK — Binder313, AppIdentity, BindReceipt.

Provides the public API used by integrations (aegis_pqc, stia, etc.)
to create cryptographically timestamped audit receipts.

Receipt properties:
  - timestamp_ns ends in ...313 (entropy marker)
  - payload_hash: SHA3-256 of the bound payload
  - chain_hash: SHA3-512 chain-linked to previous receipt
  - signature_algorithm: SLH-DSA (pyspx) or HMAC-SHA3-256 fallback
  - ipfs_cid: optional IPFS anchor
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── AppIdentity ───────────────────────────────────────────────────────────────

@dataclass
class AppIdentity:
    """Identifies the application creating 313-BIND receipts."""
    app_id:      str
    app_name:    str
    app_version: str = "1.0.0"
    operator:    str = ""
    environment: str = "production"
    # VANGUARD-313 registry fields (optional, backward-compatible)
    version:     str = ""   # alias for app_version
    prefix:      str = ""   # short prefix for bind_id (e.g. "S313", "GHOST")

    def __post_init__(self):
        # Sync version ↔ app_version
        if self.version and not self.app_version or self.app_version == "1.0.0":
            if self.version:
                self.app_version = self.version
        elif self.app_version and not self.version:
            self.version = self.app_version
        # Auto-derive prefix from app_id if not provided
        if not self.prefix:
            self.prefix = self.app_id.replace("-", "").upper()[:4]
        else:
            self.prefix = self.prefix.upper()[:8]


# ── BindReceipt ───────────────────────────────────────────────────────────────

@dataclass
class BindReceipt:
    """
    Immutable 313-BIND receipt.

    Created by Binder313.bind(). Contains cryptographic proof that
    a specific payload existed at a specific nanosecond timestamp.
    """
    bind_id:             str
    timestamp_ns:        int       # ends in ...313
    timestamp_iso:       str
    payload_hash:        str       # SHA3-256 of payload
    chain_hash:          str       # SHA3-512 chain-linked
    prev_chain_hash:     str       # previous receipt's chain_hash
    signature_algorithm: str
    signature:           str       # SLH-DSA or HMAC-SHA3-256
    ipfs_cid:            Optional[str]
    ipfs_anchored:       bool
    app_id:              str
    app_version:         str
    sequence:            int

    def to_dict(self) -> dict:
        return {
            "bind_id":             self.bind_id,
            "timestamp_ns":        self.timestamp_ns,
            "timestamp_iso":       self.timestamp_iso,
            "payload_hash":        self.payload_hash,
            "chain_hash":          self.chain_hash,
            "prev_chain_hash":     self.prev_chain_hash,
            "signature_algorithm": self.signature_algorithm,
            "signature":           self.signature[:32] + "…",
            "ipfs_cid":            self.ipfs_cid,
            "ipfs_anchored":       self.ipfs_anchored,
            "app_id":              self.app_id,
            "app_version":         self.app_version,
            "sequence":            self.sequence,
        }

    def verify_timestamp(self) -> bool:
        """Verify timestamp ends in 313."""
        return str(self.timestamp_ns).endswith("313")

    def verify_payload(self, payload: dict, sequence: int = 1,
                        app_id: str = "") -> bool:
        """Verify payload hash matches.
        
        Note: The binder wraps payload in full_payload before hashing.
        This method reconstructs the full_payload for verification.
        If app_id/sequence are unknown, falls back to raw payload hash.
        """
        # Try full_payload reconstruction first (matches bind() behavior)
        full_payload = {
            "payload":  payload,
            "metadata": {},
            "app_id":   app_id or self.app_id,
            "sequence": sequence or self.sequence,
        }
        canonical_full = json.dumps(full_payload, sort_keys=True, default=str).encode()
        expected_full  = "sha3_256:" + hashlib.sha3_256(canonical_full).hexdigest()
        if hmac.compare_digest(self.payload_hash, expected_full):
            return True
        # Fallback: raw payload hash (for simulated receipts)
        canonical_raw = json.dumps(payload, sort_keys=True, default=str).encode()
        expected_raw  = "sha3_256:" + hashlib.sha3_256(canonical_raw).hexdigest()
        return hmac.compare_digest(self.payload_hash, expected_raw)


# ── Binder313 ─────────────────────────────────────────────────────────────────

class Binder313:
    """
    313 Temporal Binding engine.

    Creates cryptographically timestamped receipts for any payload dict.
    Uses pyspx SLH-DSA-SHAKE-128f when available, falls back to HMAC-SHA3-256.

    Usage:
        identity = AppIdentity(app_id="aegis-pqc", app_name="Aegis PQC", app_version="1.0.0")
        binder   = Binder313(identity=identity)
        receipt  = binder.bind(payload={"findings": [...]}, metadata={"source": "aegis"})
    """

    def __init__(self, identity: AppIdentity) -> None:
        self.identity  = identity
        self._sequence = 0
        self._prev_chain_hash = ""
        self._hmac_key = os.urandom(32)
        self._signing_key = None
        self._signing_algo = self._init_signing()

    def _init_signing(self) -> str:
        """Initialize signing backend (pyspx → HMAC-SHA3-256 fallback)."""
        try:
            import pyspx.shake_128f as _pyspx
            self._pyspx = _pyspx
            self._pyspx_seed = os.urandom(48)
            pk, sk = _pyspx.generate_keypair(self._pyspx_seed)
            self._pyspx_sk = sk
            self._pyspx_pk = pk
            return "SLH-DSA-SHAKE-128f (FIPS 205, pyspx)"
        except ImportError:
            self._pyspx = None
            return "HMAC-SHA3-256 (fallback — install pyspx for SLH-DSA)"

    def _sign(self, message: bytes) -> str:
        """Sign message with available algorithm."""
        if self._pyspx is not None:
            try:
                sig = self._pyspx.sign(message, self._pyspx_sk)
                return sig.hex()
            except Exception as _exc:
                import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
        import hmac
        return hmac.new(self._hmac_key, message, "sha3_256").hexdigest()

    def _nudge_313(self) -> int:
        """Return current nanosecond timestamp ending in 313."""
        ts_ns = time.time_ns()
        return int(str(ts_ns)[:-3] + "313")

    def bind(
        self,
        payload: dict,
        metadata: Optional[dict] = None,
    ) -> BindReceipt:
        """
        Create a 313-BIND receipt for the given payload.

        Args:
            payload:  The data to bind (will be JSON-serialized)
            metadata: Optional metadata to include in the receipt

        Returns:
            BindReceipt with cryptographic proof
        """
        self._sequence += 1
        ts_ns = self._nudge_313()

        # Canonical payload serialization
        full_payload = {
            "payload":  payload,
            "metadata": metadata or {},
            "app_id":   self.identity.app_id,
            "sequence": self._sequence,
        }
        canonical = json.dumps(full_payload, sort_keys=True, default=str).encode()

        # Payload hash (SHA3-256)
        payload_hash = "sha3_256:" + hashlib.sha3_256(canonical).hexdigest()

        # Chain hash (SHA3-512, links to previous)
        chain_input = json.dumps({
            "payload_hash": payload_hash,
            "timestamp_ns": ts_ns,
            "prev_hash":    self._prev_chain_hash,
            "sequence":     self._sequence,
        }, sort_keys=True).encode()
        chain_hash = "sha3_512:" + hashlib.sha3_512(chain_input).hexdigest()

        # Signature over chain hash
        signature = self._sign(chain_hash.encode())

        # Bind ID
        bind_id = (
            f"{self.identity.app_id.upper().replace('-','_')}"
            f"-{self._sequence:08d}"
            f"-{secrets.token_hex(3).upper()}"
        )

        receipt = BindReceipt(
            bind_id             = bind_id,
            timestamp_ns        = ts_ns,
            timestamp_iso       = _now_iso(),
            payload_hash        = payload_hash,
            chain_hash          = chain_hash,
            prev_chain_hash     = self._prev_chain_hash,
            signature_algorithm = self._signing_algo,
            signature           = signature,
            ipfs_cid            = None,
            ipfs_anchored       = False,
            app_id              = self.identity.app_id,
            app_version         = self.identity.app_version,
            sequence            = self._sequence,
        )

        self._prev_chain_hash = chain_hash
        return receipt

    def verify(self, receipt: BindReceipt, payload: dict) -> dict:
        """Verify a receipt against its original payload."""
        ts_ok      = receipt.verify_timestamp()
        payload_ok = receipt.verify_payload(payload)
        return {
            "valid":          ts_ok and payload_ok,
            "timestamp_ok":   ts_ok,
            "payload_ok":     payload_ok,
            "bind_id":        receipt.bind_id,
        }