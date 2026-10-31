from __future__ import annotations
"""
shadow313.core.binding_sdk.binder
───────────────────────────────────
313 Temporal Binding SDK — Binder313, AppIdentity, BindReceipt.

Provides the public API used by integrations (aegis_pqc, stia, etc.)
to create cryptographically timestamped audit receipts.

Receipt properties:
  - timestamp_ns ends in ...313 (format marker, not trusted time or entropy)
  - payload_hash: SHA3-256 of the bound payload
  - chain_hash: SHA3-512 chain-linked to previous receipt
  - signature_algorithm: SPHINCS+ (pyspx) or explicitly labeled local HMAC
  - ipfs_cid: optional IPFS anchor
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
import time
import threading
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
    a specific payload was bound by a key holder; its local timestamp is not trusted time.
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
    metadata: dict = field(default_factory=dict)
    public_key: Optional[str] = None
    receipt_format: int = 2

    def to_dict(self) -> dict:
        return {
            "bind_id":             self.bind_id,
            "timestamp_ns":        self.timestamp_ns,
            "timestamp_iso":       self.timestamp_iso,
            "payload_hash":        self.payload_hash,
            "chain_hash":          self.chain_hash,
            "prev_chain_hash":     self.prev_chain_hash,
            "signature_algorithm": self.signature_algorithm,
            "signature":           self.signature,
            "ipfs_cid":            self.ipfs_cid,
            "ipfs_anchored":       self.ipfs_anchored,
            "app_id":              self.app_id,
            "app_version":         self.app_version,
            "sequence":            self.sequence,
            "metadata":            copy.deepcopy(self.metadata),
            "public_key":          self.public_key,
            "receipt_format":      self.receipt_format,
        }

    def verify_timestamp(self) -> bool:
        """Verify timestamp ends in 313."""
        return str(self.timestamp_ns).endswith("313")

    def verify_payload(self, payload: dict, sequence: int | None = None,
                       app_id: str = "") -> bool:
        """Verify the exact payload/metadata/sequence used by bind()."""
        full_payload = {
            "payload": payload,
            "metadata": self.metadata,
            "app_id": app_id or self.app_id,
            "sequence": self.sequence if sequence is None else sequence,
        }
        canonical = json.dumps(full_payload, sort_keys=True, default=str).encode()
        expected = "sha3_256:" + hashlib.sha3_256(canonical).hexdigest()
        return hmac.compare_digest(self.payload_hash, expected)

    def signing_bytes(self) -> bytes:
        """Versioned canonical envelope; all exported fields except signature."""
        data = self.to_dict()
        data.pop("signature")
        return json.dumps(data, sort_keys=True, default=str).encode()


# ── Binder313 ─────────────────────────────────────────────────────────────────

class Binder313:
    """
    313 Temporal Binding engine.

    Creates authenticated receipts with a local clock timestamp.
    Uses SPHINCS+ through pyspx when installed, otherwise explicitly labeled HMAC.

    Usage:
        identity = AppIdentity(app_id="aegis-pqc", app_name="Aegis PQC", app_version="1.0.0")
        binder   = Binder313(identity=identity)
        receipt  = binder.bind(payload={"findings": [...]}, metadata={"source": "aegis"})
    """

    def __init__(self, identity: AppIdentity) -> None:
        self.identity  = identity
        self._lock = threading.RLock()
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
            self._pyspx_seed = os.urandom(_pyspx.crypto_sign_SEEDBYTES)
            pk, sk = _pyspx.generate_keypair(self._pyspx_seed)
            self._pyspx_sk = sk
            self._pyspx_pk = pk
            return "SPHINCS+-SHAKE-128f"
        except ImportError:
            self._pyspx = None
            return "HMAC-SHA3-256 (local symmetric authentication)"

    def _sign(self, message: bytes) -> str:
        """Sign message with available algorithm."""
        if self._pyspx is not None:
            # A broken configured signer is an error, not permission to downgrade.
            return self._pyspx.sign(message, self._pyspx_sk).hex()
        return hmac.new(self._hmac_key, message, "sha3_256").hexdigest()

    def _nudge_313(self) -> int:
        """Return current nanosecond timestamp ending in 313."""
        ts_ns = time.time_ns()
        return int(str(ts_ns)[:-3] + "313")

    def bind(self, payload: dict, metadata: Optional[dict] = None) -> BindReceipt:
        """Create an authenticated receipt with this instance's ephemeral key.

        Not a trusted timestamp or IPFS proof. Persist/trust keys externally for
        cross-process verification. HMAC is not independently publicly verifiable.
        """
        with self._lock:
            return self._bind(payload, metadata)

    def _bind(
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
        next_sequence = self._sequence + 1
        metadata = copy.deepcopy(metadata or {})
        ts_ns = self._nudge_313()

        # Canonical payload serialization
        full_payload = {
            "payload":  payload,
            "metadata": metadata or {},
            "app_id":   self.identity.app_id,
            "sequence": next_sequence,
        }
        canonical = json.dumps(full_payload, sort_keys=True, default=str).encode()

        # Payload hash (SHA3-256)
        payload_hash = "sha3_256:" + hashlib.sha3_256(canonical).hexdigest()

        # Chain hash (SHA3-512, links to previous)
        chain_input = json.dumps({
            "payload_hash": payload_hash,
            "timestamp_ns": ts_ns,
            "prev_hash":    self._prev_chain_hash,
            "sequence":     next_sequence,
        }, sort_keys=True).encode()
        chain_hash = "sha3_512:" + hashlib.sha3_512(chain_input).hexdigest()

        # Signature over chain hash
        signature = ""

        # Bind ID
        bind_id = (
            f"{self.identity.app_id.upper().replace('-','_')}"
            f"-{next_sequence:08d}"
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
            sequence            = next_sequence,
            metadata            = metadata,
            public_key          = self._pyspx_pk.hex() if self._pyspx is not None else None,

        )

        receipt.signature = self._sign(receipt.signing_bytes())
        self._sequence = next_sequence
        self._prev_chain_hash = chain_hash
        return receipt

    def verify(self, receipt: BindReceipt, payload: dict) -> dict:
        """Verify a format-2 receipt with this binder's trusted instance key.

        Recomputes chain material, but verifying a complete history additionally
        requires validating every predecessor and its sequence. Legacy unsigned
        or truncated exports fail closed rather than acquire a verification claim.
        """
        ts_ok = payload_ok = chain_ok = signature_ok = False
        try:
            ts_ok = receipt.verify_timestamp()
            payload_ok = receipt.verify_payload(payload)
            chain_input = json.dumps({
                "payload_hash": receipt.payload_hash,
                "timestamp_ns": receipt.timestamp_ns,
                "prev_hash": receipt.prev_chain_hash,
                "sequence": receipt.sequence,
            }, sort_keys=True).encode()
            expected_chain = "sha3_512:" + hashlib.sha3_512(chain_input).hexdigest()
            chain_ok = hmac.compare_digest(receipt.chain_hash, expected_chain)
            expected_key = self._pyspx_pk.hex() if self._pyspx is not None else None
            compatible = (receipt.receipt_format == 2 and receipt.sequence > 0
                          and receipt.signature_algorithm == self._signing_algo
                          and receipt.public_key == expected_key
                          and receipt.app_id == self.identity.app_id)
            if compatible:
                signature = bytes.fromhex(receipt.signature)
                if self._pyspx is not None:
                    if len(signature) == self._pyspx.crypto_sign_BYTES:
                        signature_ok = bool(self._pyspx.verify(
                            receipt.signing_bytes(), signature, self._pyspx_pk))
                else:
                    expected = hmac.new(self._hmac_key, receipt.signing_bytes(), "sha3_256").digest()
                    signature_ok = hmac.compare_digest(expected, signature)
        except (ValueError, TypeError, AttributeError, OverflowError):
            signature_ok = False
        return {
            "valid": ts_ok and payload_ok and chain_ok and signature_ok,
            "timestamp_ok": ts_ok, "payload_ok": payload_ok,
            "chain_ok": chain_ok, "signature_ok": signature_ok,
            "bind_id": receipt.bind_id,
        }
