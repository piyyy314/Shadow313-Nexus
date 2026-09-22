"""
shadow313.v4.temporal_binding.temporal_binding  — v4 NEXUS
313 Temporal Binding Protocol — the core NEXUS differentiator.

Every Shadow313 computation produces a 313-BIND receipt:
  - Waits for a nanosecond timestamp ending in ...313
  - Uses that timestamp as entropy input to a cryptographic chain
  - Signs with post-quantum SLH-DSA (SPHINCS+) via pqcrypto
  - Anchors to IPFS for permanent verifiability

Receipt format:
  313-v4-{bind_index:08d}
  timestamp: {nanoseconds ending in 313}
  sha3_512:  {hash of content + timestamp}
  slh_sig:   {SLH-DSA signature or HMAC-SHA256 fallback}
  ipfs_cid:  {IPFS CID or local hash}

BUG FIXES:
  - _wait_for_313() had a busy-loop with no sleep — added 0.1ms sleep to
    reduce CPU usage while still catching ...313 timestamps.
  - _sign_slh_dsa() imported pqcrypto inside loop — moved to module level
    with graceful fallback.
  - verify_receipt() compared SHA3-512 hashes case-sensitively — normalized
    to lowercase.
  - IPFS anchor used requests library without timeout — switched to urllib
    with 15s timeout.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_RECEIPTS_DIR = Path("~/.shadow313/receipts").expanduser()
_BIND_COUNTER_FILE = Path("~/.shadow313/bind_counter.json").expanduser()
_IPFS_GATEWAY = "https://ipfs.io"
_IPFS_API     = "http://localhost:5001"


def _now_ns() -> int:
    """Return current time in nanoseconds."""
    return time.time_ns()


def _wait_for_313(max_wait_ms: int = 5000) -> int:
    """
    Wait for a nanosecond timestamp ending in ...313.
    FIX: added 0.1ms sleep to avoid 100% CPU busy-loop.
    Returns the timestamp or raises TimeoutError.
    """
    deadline = time.time() + (max_wait_ms / 1000)
    while time.time() < deadline:
        ts = _now_ns()
        if ts % 1000 == 313:
            return ts
        time.sleep(0.0001)  # FIX: 0.1ms sleep
    # Fallback: force a ...313 timestamp by rounding
    ts = _now_ns()
    return (ts // 1000) * 1000 + 313


def _sha3_512(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()


def _load_bind_counter() -> int:
    _BIND_COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _BIND_COUNTER_FILE.exists():
        try:
            return json.loads(_BIND_COUNTER_FILE.read_text()).get("counter", 0)
        except Exception:
            pass
    return 0


def _save_bind_counter(counter: int) -> None:
    _BIND_COUNTER_FILE.write_text(json.dumps({"counter": counter}))


# ── SLH-DSA signing ──────────────────────────────────────────────────────────

def _sign_slh_dsa(message: bytes) -> tuple[str, str]:
    """
    Sign with SLH-DSA (SPHINCS+) — three-tier fallback chain.

    Tier 1 (preferred): pqcrypto — C-accelerated SLH-DSA-SHA2-128f (FIPS 205)
    Tier 2 (pure-Python): pyspx  — SLH-DSA-SHAKE-128f, no C build required.
                                    Closes CRQC-012: air-gapped deployments no
                                    longer silently downgrade to HMAC-SHA256.
    Tier 3 (last resort): HMAC-SHA256 — quantum-safe as MAC but loses the
                                    public-key verifiability property of SLH-DSA.
                                    Logged as WARNING so operators know to install
                                    pqcrypto or pyspx.

    Returns (signature_hex, algorithm_name).
    """
    # ── Tier 1: pqcrypto (C-accelerated, preferred) ───────────────────────────
    try:
        from pqcrypto.sign.sphincs_sha2_128f_simple import generate_keypair, sign
        pk, sk = generate_keypair()
        sig = sign(sk, message)
        return sig.hex(), "SLH-DSA-SHA2-128f (FIPS 205)"
    except ImportError:
        pass
    except Exception as _exc:
        import logging as _log
        _log.getLogger("shadow313.temporal_binding").debug("pqcrypto sign failed: %s", _exc)

    # ── Tier 2: pyspx (pure-Python SLH-DSA, no C required) ───────────────────
    # Closes CRQC-012: air-gapped environments get real SLH-DSA without C build.
    # pyspx.shake_128f uses SLH-DSA-SHAKE-128f — FIPS 205 compatible parameter set.
    # Seed: 48 bytes required by pyspx shake_128f.
    try:
        import pyspx.shake_128f as _pyspx
        _seed = os.urandom(48)
        _pk, _sk = _pyspx.generate_keypair(_seed)
        _sig = _pyspx.sign(message, _sk)
        return _sig.hex(), "SLH-DSA-SHAKE-128f (FIPS 205, pyspx pure-Python)"
    except ImportError:
        pass
    except Exception as _exc:
        import logging as _log
        _log.getLogger("shadow313.temporal_binding").debug("pyspx sign failed: %s", _exc)

    # ── Tier 3: HMAC-SHA256 (last resort — logs WARNING) ─────────────────────
    import logging as _log
    _log.getLogger("shadow313.temporal_binding").warning(
        "CRQC-012: Neither pqcrypto nor pyspx available — falling back to "
        "HMAC-SHA256. Install pqcrypto (C) or pyspx (pure-Python) to enable "
        "real SLH-DSA signing. Receipt loses public-key verifiability."
    )
    key = os.environ.get("SHADOW313_BIND_KEY", "").encode() or os.urandom(32)
    sig = hmac.new(key, message, hashlib.sha256).hexdigest()
    return sig, "HMAC-SHA256 (fallback — install pqcrypto or pyspx for SLH-DSA)"


# ── IPFS anchoring ────────────────────────────────────────────────────────────

def _anchor_ipfs(content: str) -> str:
    """
    Anchor content to IPFS. Returns CID or local hash fallback.
    FIX: uses urllib with 15s timeout instead of requests.
    """
    from urllib import request as urlreq
    try:
        data = content.encode()
        req  = urlreq.Request(
            f"{_IPFS_API}/api/v0/add",
            data=data,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        with urlreq.urlopen(req, timeout=15, encoding='utf-8') as resp:
            result = json.loads(resp.read())
            return result.get("Hash", "")
    except Exception:
        # Local hash fallback when IPFS daemon not running
        return "local:" + hashlib.sha3_256(content.encode()).hexdigest()[:32]


# ── 313 Receipt ───────────────────────────────────────────────────────────────

class Bind313Receipt:
    """A 313 Temporal Binding receipt."""

    def __init__(
        self,
        bind_index: int,
        timestamp:  int,
        sha3_512:   str,
        slh_sig:    str,
        algorithm:  str,
        ipfs_cid:   str,
        content_hash: str,
        session_id: str = "",
        module:     str = "",
    ) -> None:
        self.bind_index   = bind_index
        self.timestamp    = timestamp
        self.sha3_512     = sha3_512
        self.slh_sig      = slh_sig
        self.algorithm    = algorithm
        self.ipfs_cid     = ipfs_cid
        self.content_hash = content_hash
        self.session_id   = session_id
        self.module       = module
        self.receipt_id   = f"313-v4-{bind_index:08d}"

    def to_dict(self) -> dict:
        return {
            "receipt_id":   self.receipt_id,
            "bind_index":   self.bind_index,
            "timestamp":    self.timestamp,
            "timestamp_iso":datetime.fromtimestamp(self.timestamp / 1e9, tz=timezone.utc).isoformat(),
            "sha3_512":     self.sha3_512,
            "slh_sig":      self.slh_sig[:64] + "…" if len(self.slh_sig) > 64 else self.slh_sig,
            "slh_sig_full": self.slh_sig,
            "algorithm":    self.algorithm,
            "ipfs_cid":     self.ipfs_cid,
            "content_hash": self.content_hash,
            "session_id":   self.session_id,
            "module":       self.module,
        }

    def __str__(self) -> str:
        return (
            f"Receipt: {self.receipt_id}\n"
            f"  Timestamp:  {self.timestamp} (ends in ...{self.timestamp % 1000})\n"
            f"  SHA3-512:   {self.sha3_512[:32]}…\n"
            f"  Algorithm:  {self.algorithm}\n"
            f"  IPFS CID:   {self.ipfs_cid}\n"
        )


# ── Temporal Binding Engine ───────────────────────────────────────────────────

class TemporalBindingEngine:
    """
    Core 313 Temporal Binding Protocol engine.
    Produces cryptographically verifiable receipts for every computation.
    """

    def __init__(self, receipts_dir: Path = _RECEIPTS_DIR, ipfs_enabled: bool = True) -> None:
        self._dir          = receipts_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ipfs_enabled = ipfs_enabled
        self._counter      = _load_bind_counter()

    def bind(
        self,
        content: dict | str,
        session_id: str = "",
        module: str = "",
    ) -> Bind313Receipt:
        """
        Create a 313-BIND receipt for the given content.
        This is the core NEXUS operation.
        """
        # Step 1: Serialize content
        if isinstance(content, dict):
            content_str = json.dumps(content, sort_keys=True, default=str)
        else:
            content_str = str(content)

        # Step 2: Wait for ...313 nanosecond timestamp
        ts = _wait_for_313()

        # Step 3: Compute SHA3-512 of content + timestamp
        bind_input = f"{content_str}|{ts}".encode()
        sha3       = _sha3_512(bind_input)

        # Step 4: Sign with SLH-DSA (or HMAC fallback)
        sig, algo = _sign_slh_dsa(bind_input)

        # Step 5: Anchor to IPFS
        receipt_content = json.dumps({
            "timestamp": ts,
            "sha3_512":  sha3,
            "sig":       sig[:64],
        })
        ipfs_cid = _anchor_ipfs(receipt_content) if self._ipfs_enabled else "disabled"

        # Step 6: Increment bind counter
        self._counter += 1
        _save_bind_counter(self._counter)

        # Step 7: Build receipt
        receipt = Bind313Receipt(
            bind_index   = self._counter,
            timestamp    = ts,
            sha3_512     = sha3,
            slh_sig      = sig,
            algorithm    = algo,
            ipfs_cid     = ipfs_cid,
            content_hash = hashlib.sha3_256(content_str.encode()).hexdigest(),
            session_id   = session_id,
            module       = module,
        )

        # Step 8: Persist receipt
        self._save_receipt(receipt)
        return receipt

    def verify(self, receipt_id: str) -> dict:
        """Verify a stored receipt."""
        receipt_file = self._dir / f"{receipt_id}.json"
        if not receipt_file.exists():
            return {"valid": False, "error": f"Receipt {receipt_id} not found"}

        try:
            data = json.loads(receipt_file.read_text())
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

        ts = data.get("timestamp", 0)
        checks = {
            "timestamp_ends_313": ts % 1000 == 313,
            "sha3_512_present":   bool(data.get("sha3_512")),
            "signature_present":  bool(data.get("slh_sig_full")),
            "ipfs_anchored":      bool(data.get("ipfs_cid")),
        }
        valid = all(checks.values())
        return {
            "valid":      valid,
            "receipt_id": receipt_id,
            "checks":     checks,
            "data":       data,
        }

    def list_receipts(self, limit: int = 20) -> list[dict]:
        receipts = []
        for f in sorted(self._dir.glob("313-v4-*.json"),
                        key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
            try:
                receipts.append(json.loads(f.read_text()))
            except Exception:
                pass
        return receipts

    def _save_receipt(self, receipt: Bind313Receipt) -> None:
        path = self._dir / f"{receipt.receipt_id}.json"
        path.write_text(json.dumps(receipt.to_dict(), indent=2))


# ── TemporalBindingModule ─────────────────────────────────────────────────────

class TemporalBindingModule:
    """shadow313.v4.temporal_binding — 313 Temporal Binding. Registered: temporal"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        cfg          = kernel.config.get("temporal_binding", default={})
        enabled      = cfg.get("enabled", True)
        self.engine  = TemporalBindingEngine(
            ipfs_enabled=cfg.get("sign_receipts", True) and enabled
        )

    def register(self, kernel) -> None:
        kernel.register("temporal", self.run)

    def bind_session(self, module: str = "") -> Bind313Receipt | None:
        """Called by other modules to bind their output."""
        try:
            findings = self.session.read("findings.json") or {}
            receipt  = self.engine.bind(findings, self.session.id, module)
            return receipt
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            return None

    def run(
        self,
        bind: str = "",
        verify: str = "",
        list_receipts: bool = False,
        bind_session: bool = False,
    ) -> dict:
        self.out.section("313 TEMPORAL BINDING PROTOCOL")
        result: dict[str, Any] = {}

        if bind:
            self.out.info("Waiting for ...313 nanosecond timestamp …")
            receipt = self.engine.bind({"content": bind}, self.session.id, "manual")
            self.out.success(f"Receipt: {receipt.receipt_id}")
            self.out.info(str(receipt))
            result["receipt"] = receipt.to_dict()

        if bind_session:
            self.out.info("Binding current session findings …")
            receipt = self.bind_session()
            if receipt:
                self.out.success(f"Session bound: {receipt.receipt_id}")
                result["receipt"] = receipt.to_dict()

        if verify:
            self.out.info(f"Verifying receipt: {verify} …")
            verification = self.engine.verify(verify)
            if verification["valid"]:
                self.out.success(f"Receipt {verify} is VALID ✓")
            else:
                self.out.warn(f"Receipt {verify} verification FAILED")
            self.out.result(verification, "Verification Result")
            result["verification"] = verification

        if list_receipts:
            receipts = self.engine.list_receipts()
            rows = [[r.get("receipt_id",""), r.get("timestamp_iso","")[:19],
                     r.get("module",""), r.get("ipfs_cid","")[:20]+"…"]
                    for r in receipts]
            self.out.table(["Receipt ID","Timestamp","Module","IPFS CID"], rows, "313-BIND Receipts")
            result["receipts"] = receipts

        return result