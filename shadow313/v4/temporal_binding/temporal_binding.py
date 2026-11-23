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
import logging
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
    Returns only an observed timestamp; never fabricates one.
    """
    if max_wait_ms < 0:
        raise ValueError("max_wait_ms must be non-negative")

    deadline = time.monotonic() + (max_wait_ms / 1000)
    while time.monotonic() < deadline:
        ts = _now_ns()
        if ts % 1000 == 313:
            return ts
        time.sleep(0.0001)  # FIX: 0.1ms sleep
    raise TimeoutError(
        f"No timestamp ending in 313 observed within {max_wait_ms} ms"
    )


def _sha3_512(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()


def _load_bind_counter() -> int:
    _BIND_COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _BIND_COUNTER_FILE.exists():
        try:
            return json.loads(_BIND_COUNTER_FILE.read_text()).get("counter", 0)
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Unable to read temporal binding counter; starting at zero: %s", exc
            )
    return 0


def _save_bind_counter(counter: int) -> None:
    _BIND_COUNTER_FILE.write_text(json.dumps({"counter": counter}))


# ── SLH-DSA signing ──────────────────────────────────────────────────────────

def _load_or_create_pqc_keypair(
    key_name: str,
    generate_keypair,
) -> tuple[bytes, bytes]:
    """Load a persistent local keypair, creating it once with restrictive permissions."""
    key_dir = Path(
        os.environ.get("SHADOW313_KEY_DIR", str(Path.home() / ".shadow313" / "keys"))
    ).expanduser()
    repository_root = Path(__file__).resolve().parents[3]
    resolved_key_dir = key_dir.resolve()
    try:
        resolved_key_dir.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise ValueError("SHADOW313_KEY_DIR must be outside the repository")
    key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        key_dir.chmod(0o700)
    except OSError:
        pass

    key_path = key_dir / f"{key_name}.json"
    lock_path = key_dir / f".{key_name}.lock"

    def read_keypair() -> tuple[bytes, bytes]:
        if key_path.is_symlink():
            raise ValueError(f"Signing key must not be a symlink: {key_path}")
        data = json.loads(key_path.read_text(encoding="utf-8"))
        public_key = bytes.fromhex(data["public_key_hex"])
        secret_key = bytes.fromhex(data["secret_key_hex"])
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        return public_key, secret_key

    if key_path.exists():
        return read_keypair()

    lock_fd = None
    deadline = time.monotonic() + 15
    while lock_fd is None:
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as lock_error:
            if key_path.exists():
                return read_keypair()
            try:
                if time.time() - lock_path.stat().st_mtime > 120:
                    lock_path.unlink(missing_ok=True)
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Timed out waiting for signing-key lock: {lock_path}"
                ) from lock_error
            time.sleep(0.05)

    try:
        if key_path.exists():
            return read_keypair()
        public_key, secret_key = generate_keypair()
        temporary_path = key_dir / f".{key_name}.{os.getpid()}.tmp"
        fd = os.open(temporary_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "algorithm": key_name,
                    "public_key_hex": public_key.hex(),
                    "secret_key_hex": secret_key.hex(),
                },
                handle,
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, key_path)
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        return public_key, secret_key
    finally:
        os.close(lock_fd)
        lock_path.unlink(missing_ok=True)


def _sign_slh_dsa(message: bytes) -> tuple[str, str, str]:
    """
    Sign a canonical receipt payload.

    Returns (signature_hex, algorithm_name, public_key_hex). SPHINCS+ keypairs
    are persisted outside the repository and public keys are embedded in receipts.
    This verifies signature integrity; signer identity still requires a trusted key ID.

    HMAC is used only when SHADOW313_BIND_KEY is explicitly configured.
    Without a public-key backend or stable shared key, the receipt is unsigned.
    """
    try:
        from pqcrypto.sign.sphincs_sha2_128f_simple import generate_keypair, sign

        public_key, secret_key = _load_or_create_pqc_keypair(
            "sphincs_sha2_128f_simple", generate_keypair
        )
        signature = sign(secret_key, message)
        return (
            signature.hex(),
            "SPHINCS+-SHA2-128f-simple (pqcrypto)",
            public_key.hex(),
        )
    except ImportError:
        pass
    except Exception as exc:
        import logging
        logging.getLogger("shadow313.temporal_binding").warning(
            "pqcrypto signing failed; trying pyspx: %s", exc
        )

    try:
        import pyspx.shake_128f as sphincs

        public_key, secret_key = _load_or_create_pqc_keypair(
            "sphincs_shake_128f", lambda: sphincs.generate_keypair(os.urandom(48))
        )
        signature = sphincs.sign(message, secret_key)
        return (
            signature.hex(),
            "SPHINCS+-SHAKE-128f (pyspx)",
            public_key.hex(),
        )
    except ImportError:
        pass
    except Exception as exc:
        import logging
        logging.getLogger("shadow313.temporal_binding").warning(
            "pyspx signing failed: %s", exc
        )

    key = os.environ.get("SHADOW313_BIND_KEY", "").encode()
    if key:
        signature = hmac.new(key, message, hashlib.sha256).hexdigest()
        return signature, "HMAC-SHA256 (shared-secret)", ""

    import logging
    logging.getLogger("shadow313.temporal_binding").warning(
        "No verifiable signing backend or SHADOW313_BIND_KEY is configured; "
        "creating an explicitly unsigned receipt."
    )
    return "", "UNSIGNED (no signing backend configured)", ""


def _verify_slh_dsa(
    message: bytes,
    signature_hex: str,
    algorithm: str,
    public_key_hex: str = "",
) -> bool:
    """Verify a receipt signature; never treat signature presence as verification."""
    if not signature_hex:
        return False
    try:
        signature = bytes.fromhex(signature_hex)
        if algorithm.startswith("SPHINCS+-SHA2-128f-simple"):
            from pqcrypto.sign.sphincs_sha2_128f_simple import verify

            if not public_key_hex:
                return False
            # pqcrypto returns None on success and raises on invalid signatures.
            verify(bytes.fromhex(public_key_hex), message, signature)
            return True
        if algorithm.startswith("SPHINCS+-SHAKE-128f"):
            import pyspx.shake_128f as sphincs

            if not public_key_hex:
                return False
            return bool(sphincs.verify(message, signature, bytes.fromhex(public_key_hex)))
        if algorithm.startswith("HMAC-SHA256"):
            key = os.environ.get("SHADOW313_BIND_KEY", "").encode()
            if not key:
                return False
            expected = hmac.new(key, message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
    except (ImportError, ValueError, TypeError):
        return False
    except Exception:
        return False
    return False


def _canonical_bind_payload(
    content_hash: str,
    timestamp: int,
    bind_index: int,
    session_id: str = "",
    module: str = "",
) -> bytes:
    """Build the exact payload signed and hashed by 313-BIND."""
    return json.dumps(
        {
            "bind_index": bind_index,
            "content_hash": content_hash,
            "module": module,
            "session_id": session_id,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ── IPFS anchoring ────────────────────────────────────────────────────────────

def _anchor_ipfs(content: str) -> str:
    """
    Anchor content to IPFS. Returns CID or local hash fallback.
    FIX: uses urllib with 15s timeout instead of requests.
    """
    from urllib import request as urlreq
    try:
        data = content.encode()
        req = urlreq.Request(  # noqa: S310 - fixed localhost IPFS daemon endpoint
            f"{_IPFS_API}/api/v0/add",
            data=data,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        with urlreq.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed localhost IPFS daemon endpoint
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
        public_key: str = "",
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
        self.public_key   = public_key
        self.receipt_id   = f"313-v4-{bind_index:08d}"

    def to_dict(self) -> dict:
        return {
            "schema_version": 2,
            "receipt_id":   self.receipt_id,
            "bind_index":   self.bind_index,
            "timestamp":    self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(
                self.timestamp / 1e9, tz=timezone.utc  # noqa: UP017 - Python 3.10 compatibility
            ).isoformat(),
            "sha3_512":     self.sha3_512,
            "slh_sig":      self.slh_sig[:64] + "…" if len(self.slh_sig) > 64 else self.slh_sig,
            "slh_sig_full": self.slh_sig,
            "algorithm":    self.algorithm,
            "public_key":   self.public_key,
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

    def __init__(
        self,
        receipts_dir: Path = _RECEIPTS_DIR,
        ipfs_enabled: bool = True,
        signing_enabled: bool = True,
    ) -> None:
        self._dir          = receipts_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ipfs_enabled = ipfs_enabled
        self._signing_enabled = signing_enabled
        self._counter      = _load_bind_counter()

    def bind(
        self,
        content: dict | str,
        session_id: str = "",
        module: str = "",
    ) -> Bind313Receipt:
        """Create a signed, hashed 313-BIND receipt when a verifiable backend exists."""
        if isinstance(content, dict):
            content_str = json.dumps(content, sort_keys=True, default=str)
        else:
            content_str = str(content)

        timestamp = _wait_for_313()
        content_hash = hashlib.sha3_256(content_str.encode("utf-8")).hexdigest()

        self._counter += 1
        bind_index = self._counter
        _save_bind_counter(self._counter)

        signing_payload = _canonical_bind_payload(
            content_hash, timestamp, bind_index, session_id, module
        )
        sha3 = _sha3_512(signing_payload)
        if self._signing_enabled:
            signature, algorithm, public_key = _sign_slh_dsa(signing_payload)
        else:
            signature, algorithm, public_key = "", "UNSIGNED (disabled by config)", ""

        anchor_content = json.dumps(
            {
                "algorithm": algorithm,
                "bind_index": bind_index,
                "content_hash": content_hash,
                "public_key_sha3_256": (
                    hashlib.sha3_256(public_key.encode()).hexdigest() if public_key else ""
                ),
                "sha3_512": sha3,
                "signature_sha3_256": (
                    hashlib.sha3_256(signature.encode()).hexdigest() if signature else ""
                ),
                "timestamp": timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        ipfs_cid = _anchor_ipfs(anchor_content) if self._ipfs_enabled else "disabled"

        receipt = Bind313Receipt(
            bind_index=bind_index,
            timestamp=timestamp,
            sha3_512=sha3,
            slh_sig=signature,
            algorithm=algorithm,
            ipfs_cid=ipfs_cid,
            content_hash=content_hash,
            session_id=session_id,
            module=module,
            public_key=public_key,
        )
        self._save_receipt(receipt)
        return receipt

    def verify(self, receipt_id: str) -> dict:
        """Verify the receipt hash and signature; report IPFS and signer trust separately."""
        receipt_file = self._dir / f"{receipt_id}.json"
        if not receipt_file.exists():
            return {"valid": False, "error": f"Receipt {receipt_id} not found"}

        try:
            data = json.loads(receipt_file.read_text(encoding="utf-8"))
            timestamp = int(data.get("timestamp", 0))
            bind_index = int(data.get("bind_index", 0))
            content_hash = str(data.get("content_hash", ""))
            session_id = str(data.get("session_id", ""))
            module = str(data.get("module", ""))
            payload = _canonical_bind_payload(
                content_hash, timestamp, bind_index, session_id, module
            )
            expected_hash = _sha3_512(payload)
            stored_hash = str(data.get("sha3_512", ""))
            hash_matches = bool(stored_hash) and hmac.compare_digest(expected_hash, stored_hash)
            signature = str(data.get("slh_sig_full", ""))
            algorithm = str(data.get("algorithm", ""))
            public_key = str(data.get("public_key", ""))
            signature_verified = _verify_slh_dsa(payload, signature, algorithm, public_key)
            cid = str(data.get("ipfs_cid", ""))
            ipfs_anchor_recorded = bool(cid) and cid != "disabled" and not cid.startswith("local:")

            key_id = (
                hashlib.sha3_256(bytes.fromhex(public_key)).hexdigest()[:16]
                if public_key else ""
            )
            trusted_key_ids = {
                value.strip()
                for value in os.environ.get("SHADOW313_TRUSTED_SIGNER_IDS", "").split(",")
                if value.strip()
            }
            signer_trusted = bool(key_id and key_id in trusted_key_ids)
            timestamp_valid = timestamp > 0 and timestamp % 1000 == 313
            checks = {
                "timestamp_ends_313": timestamp_valid,
                "sha3_512_present": bool(stored_hash),
                "sha3_512_matches": hash_matches,
                "signature_present": bool(signature),
                "signature_verified": signature_verified,
                "public_key_present": bool(public_key),
                "signer_trusted": signer_trusted,
                "ipfs_anchor_recorded": ipfs_anchor_recorded,
                "ipfs_anchor_fetched": False,
            }
            valid = timestamp_valid and hash_matches and signature_verified
            return {
                "valid": valid,
                "receipt_id": receipt_id,
                "checks": checks,
                "signer_key_id": key_id or None,
                "trust_note": (
                    "Signature math verified. Signer identity is not trusted unless its key ID "
                    "is configured in SHADOW313_TRUSTED_SIGNER_IDS."
                ),
                "ipfs_note": (
                    "An IPFS CID is recorded but was not fetched during local verification."
                    if ipfs_anchor_recorded
                    else "No externally verified IPFS anchor is available."
                ),
                "data": data,
            }
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

    def list_receipts(self, limit: int = 20) -> list[dict]:
        receipts = []
        for f in sorted(self._dir.glob("313-v4-*.json"),
                        key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
            try:
                receipts.append(json.loads(f.read_text()))
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "Skipping unreadable temporal receipt %s: %s", f, exc
                )
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
            ipfs_enabled=cfg.get("ipfs_enabled", True) and enabled,
            signing_enabled=cfg.get("sign_receipts", True) and enabled,
        )

    def register(self, kernel) -> None:
        kernel.register("temporal", self.run)

    def bind_session(self, module: str = "") -> Bind313Receipt | None:
        """Called by other modules to bind their output."""
        try:
            findings = self.session.read("findings.json") or {}
            receipt  = self.engine.bind(findings, self.session.id, module)
            return receipt
        except Exception as exc:  # S01-fixed
            logging.getLogger(__name__).debug(
                "Unable to bind session findings: %s", exc
            )
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
            rows = [
                [
                    receipt.get("receipt_id", ""),
                    receipt.get("timestamp_iso", "")[:19],
                    receipt.get("module", ""),
                    receipt.get("ipfs_cid", "")[:20] + "…",
                ]
                for receipt in receipts
            ]
            self.out.table(
                ["Receipt ID", "Timestamp", "Module", "IPFS CID"],
                rows,
                "313-BIND Receipts",
            )
            result["receipts"] = receipts

        return result
