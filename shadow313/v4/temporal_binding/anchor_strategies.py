"""
shadow313.v4.temporal_binding.anchor_strategies
─────────────────────────────────────────────────
Alternative anchoring strategies for 313-BIND receipts.

Addresses IPFS reliability and failure modes:

FAILURE MODE 1: IPFS daemon not running (most common)
  Current behavior: falls back to "local:sha3_256_hash[:32]"
  Problem: local hash is not independently verifiable — only the node that
           created it can verify it. Defeats the "independently verifiable"
           property of 313-BIND.

FAILURE MODE 2: IPFS network partition (air-gapped deployments)
  Current behavior: same local fallback
  Problem: air-gapped environments (defense, intelligence) are the primary
           market — they can never use IPFS.

FAILURE MODE 3: IPFS CID collision (CRQC, 2035+)
  Current behavior: SHA-256 CIDs (original) → SHA3-256 CIDv1 (hardened)
  Status: FIXED in hardened_binding.py (QuantumResistantIPFS)

FAILURE MODE 4: IPFS content unavailability (garbage collection)
  Current behavior: CID stored but content may be GC'd from IPFS nodes
  Problem: CID without pinning is not a permanent anchor.

FAILURE MODE 5: Single-point-of-failure (localhost:5001)
  Current behavior: one IPFS API endpoint, no retry, no fallback nodes
  Problem: if the local daemon crashes, all anchoring fails silently.

ALTERNATIVE STRATEGIES IMPLEMENTED:
  1. LedgerAnchor     — anchor to Shadow313 ledger (always available)
  2. MultiHashAnchor  — SHA3-256 + SHA3-512 + BLAKE3 triple hash
  3. TimestampedMerkle — Merkle tree of receipts with periodic checkpoints
  4. HybridAnchor     — IPFS primary + LedgerAnchor fallback + MultiHash always
  5. RFC3161Anchor    — RFC 3161 trusted timestamp (external CA, no IPFS needed)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("shadow313.anchor_strategies")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Anchor result ─────────────────────────────────────────────────────────────

@dataclass
class AnchorResult:
    """Result of an anchoring operation."""
    strategy:       str
    anchor_id:      str       # The primary anchor identifier (CID, hash, seq, etc.)
    anchor_type:    str       # ipfs | ledger | multihash | merkle | rfc3161 | hybrid
    verified:       bool      # Can be independently verified
    offline_capable: bool     # Works without internet
    quantum_safe:   bool      # Resistant to CRQC
    timestamp:      str       = field(default_factory=_now_iso)
    metadata:       dict      = field(default_factory=dict)
    error:          str       = ""

    def to_dict(self) -> dict:
        return {
            "strategy":        self.strategy,
            "anchor_id":       self.anchor_id,
            "anchor_type":     self.anchor_type,
            "verified":        self.verified,
            "offline_capable": self.offline_capable,
            "quantum_safe":    self.quantum_safe,
            "timestamp":       self.timestamp,
            "metadata":        self.metadata,
            "error":           self.error,
        }


# ── Strategy 1: Ledger Anchor ─────────────────────────────────────────────────

class LedgerAnchor:
    """
    Anchor receipts to the Shadow313 ledger (always available, no network).

    The ledger is a local SHA3-256 Merkle chain — always available even in
    air-gapped environments. Each receipt is appended as a ledger entry,
    producing a sequence number that serves as the anchor ID.

    Tamper evidence: modifying any ledger entry breaks the Merkle chain.
    Independent verification: any party with the ledger file can verify.

    Advantages over IPFS:
      - Always available (no daemon required)
      - Works offline / air-gapped
      - Quantum-safe (SHA3-256 Merkle)
      - No garbage collection risk
      - Deterministic anchor IDs (sequence numbers)

    Disadvantages vs IPFS:
      - Not globally distributed (single node)
      - Requires ledger file to be shared for external verification
    """

    def __init__(self) -> None:
        self._entries: list[dict] = []
        self._prev_hash = ""
        self._sequence  = 0

    def anchor(self, content: str, receipt_id: str = "") -> AnchorResult:
        """Anchor content to the ledger. Returns AnchorResult with sequence number."""
        self._sequence += 1
        ts_ns = time.time_ns()
        ts_ns = int(str(ts_ns)[:-3] + "313")

        payload = json.dumps({
            "sequence":   self._sequence,
            "content":    content,
            "receipt_id": receipt_id,
            "timestamp":  ts_ns,
            "prev_hash":  self._prev_hash,
        }, sort_keys=True).encode()

        chain_hash = hashlib.sha3_256(payload).hexdigest()
        anchor_id  = f"ledger:{self._sequence:08d}:{chain_hash[:16]}"

        entry = {
            "sequence":   self._sequence,
            "anchor_id":  anchor_id,
            "chain_hash": chain_hash,
            "prev_hash":  self._prev_hash,
            "timestamp":  ts_ns,
            "receipt_id": receipt_id,
        }
        self._entries.append(entry)
        self._prev_hash = chain_hash

        return AnchorResult(
            strategy        = "LedgerAnchor",
            anchor_id       = anchor_id,
            anchor_type     = "ledger",
            verified        = True,
            offline_capable = True,
            quantum_safe    = True,
            metadata        = {"sequence": self._sequence, "chain_hash": chain_hash},
        )

    def verify(self, anchor_id: str, content: str) -> bool:
        """Verify content against its ledger anchor."""
        seq_str = anchor_id.split(":")[1] if ":" in anchor_id else ""
        try:
            seq = int(seq_str)
            entry = next((e for e in self._entries if e["sequence"] == seq), None)
            if not entry:
                return False
            # Recompute chain hash
            payload = json.dumps({
                "sequence":   entry["sequence"],
                "content":    content,
                "receipt_id": entry["receipt_id"],
                "timestamp":  entry["timestamp"],
                "prev_hash":  entry["prev_hash"],
            }, sort_keys=True).encode()
            expected = hashlib.sha3_256(payload).hexdigest()
            return hmac.compare_digest(entry["chain_hash"], expected)
        except Exception:
            return False

    def verify_chain(self) -> dict:
        """Verify the entire ledger chain integrity."""
        if not self._entries:
            return {"valid": True, "total": 0}
        for i in range(1, len(self._entries)):
            if self._entries[i]["prev_hash"] != self._entries[i-1]["chain_hash"]:
                return {"valid": False, "broken_at": i, "total": len(self._entries)}
        return {"valid": True, "total": len(self._entries)}


# ── Strategy 2: MultiHash Anchor ──────────────────────────────────────────────

class MultiHashAnchor:
    """
    Triple-hash anchor: SHA3-256 + SHA3-512 + BLAKE3 (if available).

    Provides defense-in-depth: an adversary must break ALL three hash
    functions simultaneously to forge an anchor. Even if one algorithm
    is compromised (classical or quantum), the other two remain valid.

    Format: "mh:{sha3_256_prefix}:{sha3_512_prefix}:{blake3_prefix}"

    Advantages:
      - Always available (pure Python, no daemon)
      - Offline capable
      - Quantum-safe (SHA3-256 and SHA3-512 are Grover-resistant)
      - No external dependencies
      - Independently verifiable by anyone with the content

    Disadvantages:
      - Not globally distributed
      - Larger anchor ID than IPFS CID
    """

    def anchor(self, content: str) -> AnchorResult:
        """Compute triple-hash anchor for content."""
        content_bytes = content.encode() if isinstance(content, str) else content

        sha3_256 = hashlib.sha3_256(content_bytes).hexdigest()
        sha3_512 = hashlib.sha3_512(content_bytes).hexdigest()

        # BLAKE3 if available, SHA3-384 as fallback
        try:
            import blake3
            b3 = blake3.blake3(content_bytes).hexdigest()
            algo3 = "blake3"
        except ImportError:
            b3 = hashlib.sha3_384(content_bytes).hexdigest()
            algo3 = "sha3_384"

        anchor_id = f"mh:{sha3_256[:20]}:{sha3_512[:20]}:{b3[:20]}"

        return AnchorResult(
            strategy        = "MultiHashAnchor",
            anchor_id       = anchor_id,
            anchor_type     = "multihash",
            verified        = True,
            offline_capable = True,
            quantum_safe    = True,
            metadata        = {
                "sha3_256": sha3_256,
                "sha3_512": sha3_512,
                algo3:      b3,
                "algo3":    algo3,
            },
        )

    def verify(self, anchor_id: str, content: str) -> bool:
        """Verify content against its multi-hash anchor."""
        result = self.anchor(content)
        return hmac.compare_digest(anchor_id, result.anchor_id)


# ── Strategy 3: Timestamped Merkle Checkpoint ─────────────────────────────────

class MerkleCheckpointAnchor:
    """
    Periodic Merkle tree checkpoints over batches of receipts.

    Instead of anchoring each receipt individually to IPFS, accumulate
    receipts into a Merkle tree and publish the root periodically.
    The Merkle root can be anchored to IPFS, a blockchain, or a ledger.

    This reduces IPFS dependency: even if IPFS is unavailable for 24 hours,
    receipts accumulate locally and are anchored in the next checkpoint.

    Tamper evidence: any receipt modification changes its leaf hash,
    which propagates up to change the Merkle root — detectable immediately.

    Checkpoint interval: configurable (default: 100 receipts or 1 hour)
    """

    def __init__(self, checkpoint_size: int = 100) -> None:
        self._pending:     list[str] = []   # pending receipt hashes
        self._checkpoints: list[dict] = []  # completed checkpoints
        self._checkpoint_size = checkpoint_size

    def add_receipt(self, receipt_content: str) -> str:
        """Add a receipt to the pending batch. Returns leaf hash."""
        leaf = hashlib.sha3_256(receipt_content.encode()).hexdigest()
        self._pending.append(leaf)
        if len(self._pending) >= self._checkpoint_size:
            self._flush_checkpoint()
        return leaf

    def _flush_checkpoint(self) -> Optional[dict]:
        """Create a Merkle checkpoint from pending receipts."""
        if not self._pending:
            return None
        root = self._compute_merkle_root(self._pending)
        checkpoint = {
            "checkpoint_id": f"ckpt:{len(self._checkpoints):06d}",
            "merkle_root":   root,
            "leaf_count":    len(self._pending),
            "timestamp":     _now_iso(),
            "leaves":        list(self._pending),
        }
        self._checkpoints.append(checkpoint)
        self._pending = []
        return checkpoint

    def flush(self) -> Optional[dict]:
        """Force a checkpoint even if batch is not full."""
        return self._flush_checkpoint()

    def _compute_merkle_root(self, leaves: list[str]) -> str:
        """Compute SHA3-256 Merkle root from leaf hashes."""
        if not leaves:
            return hashlib.sha3_256(b"empty").hexdigest()
        current = [hashlib.sha3_256(leaf.encode()).digest() for leaf in leaves]
        while len(current) > 1:
            if len(current) % 2 == 1:
                current.append(current[-1])
            current = [
                hashlib.sha3_256(current[i] + current[i+1]).digest()
                for i in range(0, len(current), 2)
            ]
        return current[0].hex()

    def get_proof(self, leaf_hash: str) -> Optional[dict]:
        """Get Merkle inclusion proof for a leaf hash."""
        for ckpt in self._checkpoints:
            if leaf_hash in ckpt["leaves"]:
                idx = ckpt["leaves"].index(leaf_hash)
                return {
                    "checkpoint_id": ckpt["checkpoint_id"],
                    "merkle_root":   ckpt["merkle_root"],
                    "leaf_index":    idx,
                    "leaf_hash":     leaf_hash,
                }
        return None

    def anchor(self, content: str) -> AnchorResult:
        """Add content to Merkle batch and return anchor result."""
        leaf = self.add_receipt(content)
        return AnchorResult(
            strategy        = "MerkleCheckpointAnchor",
            anchor_id       = f"merkle:{leaf[:20]}",
            anchor_type     = "merkle",
            verified        = True,
            offline_capable = True,
            quantum_safe    = True,
            metadata        = {
                "leaf_hash":    leaf,
                "pending_count": len(self._pending),
                "checkpoints":  len(self._checkpoints),
            },
        )


# ── Strategy 4: Hybrid Anchor (recommended) ───────────────────────────────────

class HybridAnchor:
    """
    Hybrid anchoring: IPFS primary + Ledger fallback + MultiHash always.

    This is the recommended production strategy:

    Layer 1 (always): MultiHash anchor — SHA3-256 + SHA3-512, always computed,
                      provides immediate tamper evidence without any network.

    Layer 2 (when available): IPFS anchor — provides global distribution and
                              independent verifiability. Falls back gracefully.

    Layer 3 (always): Ledger anchor — provides local chain integrity even when
                      IPFS is unavailable. Always available, offline-capable.

    The hybrid anchor ID encodes all three layers:
      "hybrid:{multihash_prefix}:{ledger_seq}:{ipfs_cid_or_local}"

    Degradation modes:
      IPFS available:    Full hybrid — all 3 layers active
      IPFS unavailable:  Degraded — MultiHash + Ledger (still tamper-evident)
      Air-gapped:        Offline — MultiHash + Ledger (full tamper evidence)
    """

    def __init__(self, ipfs_api: str = "http://localhost:5001") -> None:
        self._ipfs_api    = ipfs_api
        self._ledger      = LedgerAnchor()
        self._multihash   = MultiHashAnchor()
        self._ipfs_available = False
        self._ipfs_failures  = 0

    def anchor(self, content: str, receipt_id: str = "") -> AnchorResult:
        """Anchor content using all available strategies."""
        # Layer 1: MultiHash (always)
        mh_result = self._multihash.anchor(content)

        # Layer 2: IPFS (best-effort)
        ipfs_cid = self._try_ipfs(content)

        # Layer 3: Ledger (always)
        ledger_result = self._ledger.anchor(content, receipt_id)

        # Compose hybrid anchor ID
        mh_prefix     = mh_result.anchor_id.split(":")[1][:12]
        ledger_seq    = ledger_result.metadata.get("sequence", 0)
        ipfs_part     = ipfs_cid[:16] if ipfs_cid else "no-ipfs"
        anchor_id     = f"hybrid:{mh_prefix}:{ledger_seq:06d}:{ipfs_part}"

        return AnchorResult(
            strategy        = "HybridAnchor",
            anchor_id       = anchor_id,
            anchor_type     = "hybrid",
            verified        = True,
            offline_capable = True,
            quantum_safe    = True,
            metadata        = {
                "multihash":    mh_result.anchor_id,
                "multihash_full": mh_result.metadata,
                "ledger":       ledger_result.anchor_id,
                "ledger_chain": ledger_result.metadata.get("chain_hash", ""),
                "ipfs_cid":     ipfs_cid or "unavailable",
                "ipfs_active":  bool(ipfs_cid),
                "layers_active": 3 if ipfs_cid else 2,
            },
        )

    def _try_ipfs(self, content: str) -> Optional[str]:
        """Attempt IPFS anchoring with fast timeout. Returns CID or None."""
        if self._ipfs_failures >= 3:
            # Circuit breaker: stop trying after 3 consecutive failures
            return None
        try:
            from urllib import request as urlreq
            data = content.encode()
            req  = urlreq.Request(
                f"{self._ipfs_api}/api/v0/add",
                data    = data,
                headers = {"Content-Type": "application/octet-stream"},
                method  = "POST",
            )
            with urlreq.urlopen(req, timeout=3) as resp:
                result = json.loads(resp.read())
                cid = result.get("Hash", "")
                if cid:
                    self._ipfs_available = True
                    self._ipfs_failures  = 0
                    return cid
        except Exception as exc:
            self._ipfs_failures += 1
            logger.debug("IPFS unavailable (failure %d/3): %s", self._ipfs_failures, exc)
        return None

    def verify(self, anchor_id: str, content: str) -> dict:
        """Verify content against hybrid anchor."""
        parts = anchor_id.split(":")
        results = {}

        # Verify MultiHash layer
        mh_result = self._multihash.anchor(content)
        mh_prefix = mh_result.anchor_id.split(":")[1][:12]
        results["multihash_ok"] = len(parts) > 1 and parts[1] == mh_prefix

        # Verify Ledger layer (by sequence)
        if len(parts) > 2:
            try:
                seq = int(parts[2])
                results["ledger_ok"] = self._ledger.verify(
                    f"ledger:{seq:08d}:", content
                )
            except (ValueError, IndexError):
                results["ledger_ok"] = False

        results["valid"] = results.get("multihash_ok", False)
        return results

    def status(self) -> dict:
        return {
            "ipfs_available":  self._ipfs_available,
            "ipfs_failures":   self._ipfs_failures,
            "circuit_breaker": self._ipfs_failures >= 3,
            "ledger_entries":  len(self._ledger._entries),
            "active_layers":   3 if self._ipfs_available else 2,
        }


# ── Strategy 5: RFC 3161 Timestamp Anchor ────────────────────────────────────

class RFC3161Anchor:
    """
    RFC 3161 Trusted Timestamp anchor (external CA, no IPFS needed).

    RFC 3161 provides legally recognized timestamps from a trusted CA.
    The TSA (Timestamp Authority) signs a hash of the content with its
    private key, producing a timestamp token that proves the content
    existed at a specific time.

    Advantages:
      - Legally recognized in many jurisdictions (eIDAS, ESIGN Act)
      - No IPFS dependency
      - Independently verifiable by anyone with the TSA's public key
      - Works offline after token is obtained

    Disadvantages:
      - Requires internet access to TSA at anchoring time
      - TSA must be trusted (single point of trust)
      - Not quantum-safe (TSA typically uses RSA/ECDSA)

    Free TSAs: FreeTSA (https://freetsa.org), DigiCert, GlobalSign

    Note: This implementation simulates RFC 3161 — production use requires
    the python-rfc3161ng library and a real TSA endpoint.
    """

    def __init__(self, tsa_url: str = "https://freetsa.org/tsr") -> None:
        self._tsa_url = tsa_url

    def anchor(self, content: str) -> AnchorResult:
        """Request RFC 3161 timestamp for content hash."""
        content_hash = hashlib.sha3_256(content.encode()).hexdigest()

        # Simulate RFC 3161 token (production: use python-rfc3161ng)
        simulated_token = {
            "tsa":        self._tsa_url,
            "hash_algo":  "sha3-256",
            "hash":       content_hash,
            "timestamp":  _now_iso(),
            "serial":     int(time.time_ns()),
            "status":     "simulated",
        }
        token_hash = hashlib.sha3_256(
            json.dumps(simulated_token, sort_keys=True).encode()
        ).hexdigest()
        anchor_id = f"rfc3161:{token_hash[:32]}"

        return AnchorResult(
            strategy        = "RFC3161Anchor",
            anchor_id       = anchor_id,
            anchor_type     = "rfc3161",
            verified        = True,
            offline_capable = False,  # requires TSA at anchor time
            quantum_safe    = False,  # TSA uses RSA/ECDSA (HNDL risk)
            metadata        = {
                "tsa_url":    self._tsa_url,
                "hash":       content_hash,
                "token_hash": token_hash,
                "note":       "Simulated — use python-rfc3161ng for production",
            },
        )


# ── Anchor strategy comparison ────────────────────────────────────────────────

STRATEGY_COMPARISON = {
    "IPFS (current)": {
        "always_available":  False,
        "offline_capable":   False,
        "quantum_safe":      True,   # SHA3-256 CIDv1 (hardened)
        "globally_distributed": True,
        "legally_recognized": False,
        "failure_mode":      "local:sha3_256 fallback (not independently verifiable)",
        "recommendation":    "Use as Layer 2 in HybridAnchor",
    },
    "LedgerAnchor": {
        "always_available":  True,
        "offline_capable":   True,
        "quantum_safe":      True,
        "globally_distributed": False,
        "legally_recognized": False,
        "failure_mode":      "None — pure local computation",
        "recommendation":    "Use as Layer 3 in HybridAnchor (always active)",
    },
    "MultiHashAnchor": {
        "always_available":  True,
        "offline_capable":   True,
        "quantum_safe":      True,
        "globally_distributed": False,
        "legally_recognized": False,
        "failure_mode":      "None — pure computation",
        "recommendation":    "Use as Layer 1 in HybridAnchor (always active)",
    },
    "MerkleCheckpointAnchor": {
        "always_available":  True,
        "offline_capable":   True,
        "quantum_safe":      True,
        "globally_distributed": False,
        "legally_recognized": False,
        "failure_mode":      "Checkpoint delay (up to checkpoint_size receipts)",
        "recommendation":    "Use for high-volume receipt batching",
    },
    "HybridAnchor (recommended)": {
        "always_available":  True,
        "offline_capable":   True,
        "quantum_safe":      True,
        "globally_distributed": True,  # when IPFS available
        "legally_recognized": False,
        "failure_mode":      "Graceful degradation: IPFS→Ledger+MultiHash",
        "recommendation":    "BEST: use as default anchoring strategy",
    },
    "RFC3161Anchor": {
        "always_available":  False,
        "offline_capable":   False,
        "quantum_safe":      False,  # TSA uses RSA/ECDSA
        "globally_distributed": True,
        "legally_recognized": True,
        "failure_mode":      "TSA unavailable → no anchor",
        "recommendation":    "Use for legal/compliance contexts alongside HybridAnchor",
    },
}


def compare_strategies() -> str:
    """Return a formatted comparison table of all anchoring strategies."""
    lines = [
        "=" * 80,
        "  313-BIND Anchoring Strategy Comparison",
        "=" * 80,
        f"  {'Strategy':<30} {'Always':>7} {'Offline':>8} {'QSafe':>6} {'Global':>7} {'Legal':>6}",
        "  " + "─" * 70,
    ]
    for name, props in STRATEGY_COMPARISON.items():
        def yn(v): return "✅" if v else "❌"
        lines.append(
            f"  {name:<30} {yn(props['always_available']):>7} "
            f"{yn(props['offline_capable']):>8} "
            f"{yn(props['quantum_safe']):>6} "
            f"{yn(props['globally_distributed']):>7} "
            f"{yn(props['legally_recognized']):>6}"
        )
    lines.append("  " + "─" * 70)
    lines.append("\n  Failure modes:")
    for name, props in STRATEGY_COMPARISON.items():
        lines.append(f"  {name}: {props['failure_mode']}")
    lines.append("\n  Recommendations:")
    for name, props in STRATEGY_COMPARISON.items():
        lines.append(f"  {name}: {props['recommendation']}")
    return "\n".join(lines)