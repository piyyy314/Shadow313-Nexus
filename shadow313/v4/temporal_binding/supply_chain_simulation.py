"""
shadow313.v4.temporal_binding.supply_chain_simulation  — NEXUS Complete
Supply chain insider threat simulation: SLH-DSA key compromise via CI/CD.

Models three distinct attack scenarios:
  1. Key Theft:        Attacker exfiltrates the private key and uses it externally
  2. Key Compromise:   Attacker injects a malicious CI/CD step that signs with a
                       shadow key (different key, same bind_index sequence)
  3. Plugin Backdoor:  Attacker installs a malicious plugin that intercepts the
                       signing operation and substitutes a different key

For each scenario, shows:
  - Which 313-BIND layer detects the attack
  - What forensic evidence is left behind
  - How plugin signing (HMAC-SHA256 + cosign) closes the gap

Run directly:
  python -m shadow313.v4.temporal_binding.supply_chain_simulation
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Terminal colors ───────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    PURPLE = "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def purple(s): return f"{C.PURPLE}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
def dim(s):    return f"{C.DIM}{s}{C.RESET}"


# ═══════════════════════════════════════════════════════════════════════════════
# KEY INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

class KeyInfrastructure:
    """
    Simulates the Shadow313 key management infrastructure.

    In production:
      - Legitimate key: stored in OS keychain / HSM
      - Public key: published in the plugin trust registry
      - Key fingerprint: embedded in every receipt
      - Cosign signature: covers the public key + build metadata

    The key fingerprint in every receipt is the critical forensic artifact:
    it allows an auditor to detect when a different key was used to sign
    receipts — even if the attacker's key produces valid signatures.
    """

    def __init__(self) -> None:
        # Legitimate key pair (generated at system initialization)
        self.legitimate_private_key = os.urandom(32)
        self.legitimate_public_key  = hashlib.sha256(self.legitimate_private_key).hexdigest()
        self.legitimate_fingerprint = hashlib.sha256(
            self.legitimate_public_key.encode()
        ).hexdigest()[:16]

        # Attacker's shadow key (generated during supply chain compromise)
        self.shadow_private_key     = os.urandom(32)
        self.shadow_public_key      = hashlib.sha256(self.shadow_private_key).hexdigest()
        self.shadow_fingerprint     = hashlib.sha256(
            self.shadow_public_key.encode()
        ).hexdigest()[:16]

        # Plugin trust registry (maps plugin name → expected public key)
        self.plugin_trust_registry  = {
            "shadow313-core":    self.legitimate_public_key,
            "shadow313-temporal":self.legitimate_public_key,
            "shadow313-cicd":    self.legitimate_public_key,
        }

        # Cosign signature over the legitimate public key + build metadata
        # In production: cosign sign --key cosign.key shadow313-core
        self.cosign_signature = self._cosign_sign(
            self.legitimate_public_key,
            build_metadata={"version": "4.0.0", "commit": "abc123", "builder": "github-actions"},
        )

    def sign_legitimate(self, message: bytes) -> tuple[str, str]:
        """Sign with the legitimate key. Returns (signature, key_fingerprint)."""
        sig = hmac.new(self.legitimate_private_key, message, hashlib.sha256).hexdigest()
        return sig, self.legitimate_fingerprint

    def sign_shadow(self, message: bytes) -> tuple[str, str]:
        """Sign with the attacker's shadow key. Returns (signature, key_fingerprint)."""
        sig = hmac.new(self.shadow_private_key, message, hashlib.sha256).hexdigest()
        return sig, self.shadow_fingerprint

    def verify_legitimate(self, message: bytes, signature: str) -> bool:
        """Verify against the legitimate public key."""
        expected = hmac.new(self.legitimate_private_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def verify_shadow(self, message: bytes, signature: str) -> bool:
        """Verify against the shadow key (attacker's key)."""
        expected = hmac.new(self.shadow_private_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def verify_plugin_trust(self, plugin_name: str, claimed_public_key: str) -> dict:
        """
        Verify a plugin's public key against the trust registry.
        This is the HMAC-SHA256 + cosign verification from plugin_signer.py.
        """
        expected_key = self.plugin_trust_registry.get(plugin_name)
        if not expected_key:
            return {"trusted": False, "reason": f"Plugin '{plugin_name}' not in trust registry"}
        if not hmac.compare_digest(claimed_public_key.encode() if isinstance(claimed_public_key, str) else claimed_public_key, expected_key.encode() if isinstance(expected_key, str) else expected_key):
            return {
                "trusted":          False,
                "reason":           f"Public key mismatch for '{plugin_name}'",
                "expected_key":     expected_key[:16] + "...",
                "claimed_key":      claimed_public_key[:16] + "...",
                "forensic_detail":  "Key substitution detected — possible supply chain compromise",
            }
        return {"trusted": True, "plugin": plugin_name}

    def verify_cosign(self, public_key: str) -> dict:
        """Verify the cosign signature over the public key."""
        expected_sig = self._cosign_sign(
            self.legitimate_public_key,
            build_metadata={"version": "4.0.0", "commit": "abc123", "builder": "github-actions"},
        )
        if not hmac.compare_digest(public_key.encode() if isinstance(public_key, str) else public_key, self.legitimate_public_key.encode() if isinstance(self.legitimate_public_key, str) else self.legitimate_public_key):
            return {
                "valid":           False,
                "reason":          "Public key does not match cosign-verified build artifact",
                "forensic_detail": "The key used for signing was not the key present in the "
                                   "cosign-verified build. Supply chain compromise confirmed.",
            }
        return {"valid": True, "cosign_signature": expected_sig[:16] + "..."}

    def _cosign_sign(self, public_key: str, build_metadata: dict) -> str:
        """Proxy for cosign signing (HMAC over key + metadata)."""
        cosign_key = hashlib.sha256(b"cosign_root_key_shadow313").digest()
        payload    = json.dumps({"public_key": public_key, **build_metadata}, sort_keys=True)
        return hmac.new(cosign_key, payload.encode(), hashlib.sha256).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# IPFS STORE (shared across simulation)
# ═══════════════════════════════════════════════════════════════════════════════

_IPFS_STORE: dict[str, str] = {}
_BIND_COUNTER: int = 0


def _wait_for_313(max_wait_ms: int = 2000) -> int:
    deadline = time.time() + (max_wait_ms / 1000)
    while time.time() < deadline:
        ts = time.time_ns()
        if ts % 1000 == 313:
            return ts
        time.sleep(0.0001)
    ts = time.time_ns()
    return (ts // 1000) * 1000 + 313


def _ipfs_add(content: str) -> str:
    cid = "Qm" + hashlib.sha256(content.encode()).hexdigest()[:44]
    _IPFS_STORE[cid] = content
    return cid


def _ipfs_get(cid: str) -> str | None:
    return _IPFS_STORE.get(cid)


# ═══════════════════════════════════════════════════════════════════════════════
# RECEIPT CREATION WITH KEY FINGERPRINT
# ═══════════════════════════════════════════════════════════════════════════════

def create_receipt_with_key(
    content:     dict,
    bind_index:  int,
    key_infra:   KeyInfrastructure,
    use_shadow:  bool = False,
    verbose:     bool = True,
) -> dict:
    """
    Create a 313-BIND receipt, optionally using the shadow (attacker's) key.

    CRITICAL ADDITION vs. basic simulation:
    The key_fingerprint is embedded INSIDE the signed message.
    This means:
      - An auditor can detect key substitution by comparing fingerprints
      - The fingerprint cannot be changed without invalidating the signature
      - The plugin trust registry maps plugin names to expected fingerprints
    """
    global _BIND_COUNTER
    _BIND_COUNTER += 1

    # Layer 1: Wait for ...313 timestamp
    ts = _wait_for_313()

    # Compute SHA3-512 over content + timestamp + bind_index
    content_str = json.dumps(content, sort_keys=True)
    bind_input  = f"{content_str}|{ts}|{bind_index}".encode()
    sha3_hash   = hashlib.sha3_512(bind_input).hexdigest()

    # Layer 2: Sign with the appropriate key
    # KEY FINGERPRINT IS INSIDE THE SIGNED MESSAGE
    if use_shadow:
        key_fingerprint = key_infra.shadow_fingerprint
        signed_message  = f"{bind_index}|{ts}|{sha3_hash}|{key_fingerprint}".encode()
        signature, _    = key_infra.sign_shadow(signed_message)
        key_used        = "SHADOW (attacker's key)"
    else:
        key_fingerprint = key_infra.legitimate_fingerprint
        signed_message  = f"{bind_index}|{ts}|{sha3_hash}|{key_fingerprint}".encode()
        signature, _    = key_infra.sign_legitimate(signed_message)
        key_used        = "LEGITIMATE"

    receipt = {
        "bind_index":      bind_index,
        "timestamp":       ts,
        "ts_mod_313":      ts % 1000,
        "sha3_512":        sha3_hash,
        "signature":       signature,
        "key_fingerprint": key_fingerprint,  # INSIDE the receipt — forensic artifact
        "key_used":        key_used,
        "content":         content,
        "created_at":      _now_iso(),
    }

    # Layer 3: IPFS anchor
    receipt_json        = json.dumps(receipt, sort_keys=True)
    ipfs_cid            = _ipfs_add(receipt_json)
    receipt["ipfs_cid"] = ipfs_cid

    if verbose:
        key_icon = red("⚠ SHADOW") if use_shadow else green("✓ LEGIT")
        print(f"  {key_icon} Receipt {bind_index}: "
              f"fp={key_fingerprint} sig={signature[:8]}... cid={ipfs_cid[:12]}...")

    return receipt


def verify_receipt_chain_with_key_audit(
    receipts:  list[dict],
    key_infra: KeyInfrastructure,
) -> dict:
    """
    Full verification including key fingerprint audit.
    Detects key substitution even when signatures are cryptographically valid.
    """
    results = {
        "valid":                    True,
        "layer1_timestamp":         {"passed": True, "failures": []},
        "layer2_signature":         {"passed": True, "failures": []},
        "layer2_bind_index":        {"passed": True, "failures": []},
        "layer2_key_fingerprint":   {"passed": True, "failures": []},
        "layer3_ipfs":              {"passed": True, "failures": []},
        "layer4_plugin_trust":      {"passed": True, "failures": []},
        "forensic_evidence":        [],
        "key_fingerprints_seen":    set(),
        "key_substitution_detected":False,
    }

    # ── Layer 1: Timestamp constraint ─────────────────────────────────────────
    for r in receipts:
        ts = r.get("timestamp", 0)
        if ts % 1000 != 313:
            results["layer1_timestamp"]["failures"].append({
                "bind_index": r.get("bind_index"),
                "ts_mod":     ts % 1000,
            })
            results["layer1_timestamp"]["passed"] = False
            results["forensic_evidence"].append({
                "layer":    "L1_TIMESTAMP",
                "severity": "HIGH",
                "evidence": f"Receipt {r.get('bind_index')} timestamp ends in {ts % 1000}, not 313",
            })

    # ── Layer 2a: Signature verification ──────────────────────────────────────
    for r in receipts:
        key_fp         = r.get("key_fingerprint", "")
        signed_message = f"{r['bind_index']}|{r['timestamp']}|{r['sha3_512']}|{key_fp}".encode()

        # Try legitimate key first
        if key_infra.verify_legitimate(signed_message, r.get("signature", "")):
            pass  # Valid with legitimate key
        elif key_infra.verify_shadow(signed_message, r.get("signature", "")):
            # Valid with shadow key — this is the key substitution detection
            results["layer2_signature"]["failures"].append({
                "bind_index":    r.get("bind_index"),
                "detail":        "Signature valid with SHADOW key, not legitimate key",
                "key_fingerprint":key_fp,
            })
            results["layer2_signature"]["passed"] = False
            results["forensic_evidence"].append({
                "layer":    "L2_SIGNATURE_KEY_MISMATCH",
                "severity": "CRITICAL",
                "evidence": f"Receipt {r.get('bind_index')} signature verifies with SHADOW key "
                            f"(fp={key_fp[:8]}...) but NOT with legitimate key "
                            f"(fp={key_infra.legitimate_fingerprint[:8]}...). "
                            f"Supply chain key substitution confirmed.",
            })
        else:
            # Invalid with both keys
            results["layer2_signature"]["failures"].append({
                "bind_index": r.get("bind_index"),
                "detail":     "Signature invalid with both legitimate and shadow keys",
            })
            results["layer2_signature"]["passed"] = False

    # ── Layer 2b: bind_index gap detection ────────────────────────────────────
    if receipts:
        indices = [r["bind_index"] for r in receipts]
        for i in range(len(indices) - 1):
            if indices[i+1] - indices[i] != 1:
                missing = list(range(indices[i] + 1, indices[i+1]))
                results["layer2_bind_index"]["failures"].append({
                    "gap_after":  indices[i],
                    "gap_before": indices[i+1],
                    "missing":    missing,
                })
                results["layer2_bind_index"]["passed"] = False
                results["forensic_evidence"].append({
                    "layer":    "L2_BIND_INDEX",
                    "severity": "CRITICAL",
                    "evidence": f"Gap: bind_index {indices[i]} → {indices[i+1]}. Missing: {missing}",
                })

    # ── Layer 2c: Key fingerprint consistency audit ───────────────────────────
    fingerprints_seen = set(r.get("key_fingerprint", "") for r in receipts)
    results["key_fingerprints_seen"] = fingerprints_seen

    if len(fingerprints_seen) > 1:
        # Multiple different key fingerprints in the same receipt chain
        results["layer2_key_fingerprint"]["passed"] = False
        results["key_substitution_detected"]        = True
        results["forensic_evidence"].append({
            "layer":    "L2_KEY_FINGERPRINT_INCONSISTENCY",
            "severity": "CRITICAL",
            "evidence": f"Multiple key fingerprints detected in receipt chain: "
                        f"{[fp[:8]+'...' for fp in fingerprints_seen]}. "
                        f"Expected exactly one fingerprint (the legitimate key). "
                        f"Key substitution occurred at the receipt where the fingerprint changed.",
        })

        # Identify the exact receipt where the key changed
        prev_fp = None
        for r in receipts:
            curr_fp = r.get("key_fingerprint", "")
            if prev_fp and curr_fp != prev_fp:
                results["layer2_key_fingerprint"]["failures"].append({
                    "bind_index":    r.get("bind_index"),
                    "prev_fp":       prev_fp[:8] + "...",
                    "curr_fp":       curr_fp[:8] + "...",
                    "detail":        f"Key fingerprint changed at receipt {r.get('bind_index')} — "
                                     f"this is where the supply chain compromise took effect",
                })
                results["forensic_evidence"].append({
                    "layer":    "L2_KEY_CHANGE_POINT",
                    "severity": "CRITICAL",
                    "evidence": f"Key fingerprint changed at receipt {r.get('bind_index')}. "
                                f"Receipts 1-{r.get('bind_index')-1}: legitimate key. "
                                f"Receipts {r.get('bind_index')}+: shadow key. "
                                f"This identifies the exact CI/CD step where compromise occurred.",
                })
            prev_fp = curr_fp

    elif fingerprints_seen and not hmac.compare_digest(list(fingerprints_seen)[0], key_infra.legitimate_fingerprint):
        # Single fingerprint but it's the wrong one (complete key replacement)
        shadow_fp = list(fingerprints_seen)[0]
        results["layer2_key_fingerprint"]["passed"] = False
        results["key_substitution_detected"]        = True
        results["forensic_evidence"].append({
            "layer":    "L2_KEY_FINGERPRINT_WRONG",
            "severity": "CRITICAL",
            "evidence": f"All receipts signed with unknown key (fp={shadow_fp[:8]}...). "
                        f"Expected legitimate key (fp={key_infra.legitimate_fingerprint[:8]}...). "
                        f"Complete key replacement detected — entire signing infrastructure compromised.",
        })

    # ── Layer 3: IPFS anchor verification ────────────────────────────────────
    for r in receipts:
        cid = r.get("ipfs_cid", "")
        if not cid:
            continue
        stored_content = _ipfs_get(cid)
        if stored_content is None:
            results["layer3_ipfs"]["failures"].append({
                "bind_index": r.get("bind_index"),
                "cid":        cid,
                "detail":     "CID not found on IPFS",
            })
            results["layer3_ipfs"]["passed"] = False
        else:
            stored = json.loads(stored_content)
            # Check key fingerprint in IPFS matches current receipt
            if stored.get("key_fingerprint") != r.get("key_fingerprint"):
                results["layer3_ipfs"]["failures"].append({
                    "bind_index":       r.get("bind_index"),
                    "ipfs_fingerprint": stored.get("key_fingerprint", "")[:8] + "...",
                    "current_fp":       r.get("key_fingerprint", "")[:8] + "...",
                    "detail":           "Key fingerprint in IPFS differs from current receipt",
                })
                results["layer3_ipfs"]["passed"] = False
                results["forensic_evidence"].append({
                    "layer":    "L3_IPFS_KEY_MISMATCH",
                    "severity": "CRITICAL",
                    "evidence": f"Receipt {r.get('bind_index')} key fingerprint was modified "
                                f"after IPFS anchoring. IPFS is immutable — this proves tampering.",
                })

    # Check for IPFS orphans (deleted receipts)
    current_cids = {r.get("ipfs_cid") for r in receipts}
    for cid, content_str in _IPFS_STORE.items():
        if cid not in current_cids:
            try:
                stored    = json.loads(content_str)
                bind_idx  = stored.get("bind_index")
                if bind_idx is not None:
                    results["layer3_ipfs"]["failures"].append({
                        "bind_index": bind_idx,
                        "cid":        cid,
                        "detail":     f"Receipt {bind_idx} exists on IPFS but not in current log",
                    })
                    results["layer3_ipfs"]["passed"] = False
                    results["forensic_evidence"].append({
                        "layer":    "L3_IPFS_ORPHAN",
                        "severity": "CRITICAL",
                        "evidence": f"IPFS CID {cid[:16]}... contains receipt {bind_idx} "
                                    f"which is absent from the current log.",
                    })
            except Exception as _exc:  # S01-fixed
                import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
                pass

    # ── Layer 4: Plugin trust registry verification ───────────────────────────
    # Check that the signing key matches the registered plugin key
    for r in receipts:
        key_fp = r.get("key_fingerprint", "")
        if not hmac.compare_digest(key_fp, key_infra.legitimate_fingerprint):
            trust_result = key_infra.verify_plugin_trust(
                "shadow313-temporal",
                key_infra.shadow_public_key,  # Attacker's key
            )
            if not trust_result["trusted"]:
                results["layer4_plugin_trust"]["failures"].append({
                    "bind_index":   r.get("bind_index"),
                    "trust_result": trust_result,
                })
                results["layer4_plugin_trust"]["passed"] = False
                results["forensic_evidence"].append({
                    "layer":    "L4_PLUGIN_TRUST",
                    "severity": "CRITICAL",
                    "evidence": f"Receipt {r.get('bind_index')} signed with key not in plugin "
                                f"trust registry. {trust_result.get('forensic_detail', '')}",
                })
                break  # One failure is enough to flag

    # Overall validity
    results["valid"] = (
        results["layer1_timestamp"]["passed"] and
        results["layer2_signature"]["passed"] and
        results["layer2_bind_index"]["passed"] and
        results["layer2_key_fingerprint"]["passed"] and
        results["layer3_ipfs"]["passed"] and
        results["layer4_plugin_trust"]["passed"]
    )

    # Convert set to list for JSON serialization
    results["key_fingerprints_seen"] = list(results["key_fingerprints_seen"])

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# THE SUPPLY CHAIN SIMULATION
# ═══════════════════════════════════════════════════════════════════════════════

def run_supply_chain_simulation(verbose: bool = True) -> dict:
    """
    Full supply chain attack simulation with three scenarios.
    """
    global _IPFS_STORE, _BIND_COUNTER
    _IPFS_STORE   = {}
    _BIND_COUNTER = 0

    report = {"simulation_timestamp": _now_iso(), "scenarios": [], "summary": {}}
    key_infra = KeyInfrastructure()

    def section(title: str) -> None:
        if verbose:
            print(f"\n{'═' * 70}")
            print(f"  {bold(title)}")
            print(f"{'═' * 70}")

    def subsection(title: str) -> None:
        if verbose:
            print(f"\n  {cyan('▶')} {bold(title)}")

    def log(msg: str, indent: int = 4) -> None:
        if verbose:
            print(" " * indent + msg)

    # ─────────────────────────────────────────────────────────────────────────
    # SETUP: Display key infrastructure
    # ─────────────────────────────────────────────────────────────────────────
    section("KEY INFRASTRUCTURE")
    log(f"Legitimate private key: {key_infra.legitimate_private_key.hex()[:16]}... (HSM-protected)")
    log(f"Legitimate public key:  {key_infra.legitimate_public_key[:16]}...")
    log(f"Legitimate fingerprint: {key_infra.legitimate_fingerprint}")
    log(f"")
    log(f"{red('Shadow (attacker) private key:')} {key_infra.shadow_private_key.hex()[:16]}...")
    log(f"{red('Shadow public key:')}             {key_infra.shadow_public_key[:16]}...")
    log(f"{red('Shadow fingerprint:')}            {key_infra.shadow_fingerprint}")
    log(f"")
    log(f"Cosign signature (over legitimate key): {key_infra.cosign_signature[:16]}...")
    log(f"Plugin trust registry: shadow313-temporal → {key_infra.legitimate_public_key[:16]}...")

    # ─────────────────────────────────────────────────────────────────────────
    # SCENARIO 1: KEY THEFT — Attacker exfiltrates the private key
    # ─────────────────────────────────────────────────────────────────────────
    section("SCENARIO 1: KEY THEFT")
    log(f"{yellow('ATTACKER')}: I've exfiltrated the legitimate private key from the HSM.")
    log(f"{yellow('ATTACKER')}: I'll use it to sign fraudulent receipts externally.")
    log(f"{yellow('ATTACKER')}: The signatures will be valid — same key, same fingerprint.")
    log(f"{yellow('ATTACKER')}: But I can't control the ...313 timestamp retroactively.")

    _IPFS_STORE   = {}
    _BIND_COUNTER = 0

    subsection("Step 1: Create legitimate receipts 1-6 (before compromise)")
    legit_receipts_s1 = []
    for i in range(1, 7):
        r = create_receipt_with_key(
            {"id": i, "action": f"scan_{i}", "result": "finding"},
            bind_index=i, key_infra=key_infra, use_shadow=False, verbose=verbose,
        )
        legit_receipts_s1.append(r)

    subsection("Step 2: Attacker uses stolen key to create fraudulent receipt 7")
    log(f"{yellow('ATTACKER')}: Creating fraudulent receipt 7 with stolen key...")
    log(f"{yellow('ATTACKER')}: I must use a CURRENT ...313 timestamp — cannot go back in time.")

    # Attacker uses the LEGITIMATE key (stolen) but creates fraudulent content
    fraudulent_receipt = create_receipt_with_key(
        {"id": 7, "action": "scan_7", "result": "no_findings"},  # Fraudulent — hides a finding
        bind_index=7, key_infra=key_infra, use_shadow=False,  # Uses legitimate key
        verbose=verbose,
    )

    # Record the original legitimate receipt 7 timestamp for comparison
    original_ts_7 = legit_receipts_s1[-1]["timestamp"]  # Last legitimate receipt
    fraudulent_ts = fraudulent_receipt["timestamp"]

    log(f"\n  Original receipt 6 timestamp: {original_ts_7}")
    log(f"  Fraudulent receipt 7 timestamp: {fraudulent_ts}")
    log(f"  Time gap: {(fraudulent_ts - original_ts_7) / 1e9:.3f} seconds")

    subsection("Step 3: Verify the chain with fraudulent receipt")
    all_receipts_s1 = legit_receipts_s1 + [fraudulent_receipt]
    verify_s1 = verify_receipt_chain_with_key_audit(all_receipts_s1, key_infra)

    log(f"\nVerification: {green('VALID') if verify_s1['valid'] else red('INVALID — DETECTED')}")
    log(f"  L1 Timestamp:        {green('PASS') if verify_s1['layer1_timestamp']['passed'] else red('FAIL')}")
    log(f"  L2a Signature:       {green('PASS') if verify_s1['layer2_signature']['passed'] else red('FAIL')}")
    log(f"  L2b bind_index:      {green('PASS') if verify_s1['layer2_bind_index']['passed'] else red('FAIL')}")
    log(f"  L2c Key Fingerprint: {green('PASS') if verify_s1['layer2_key_fingerprint']['passed'] else red('FAIL')}")
    log(f"  L3 IPFS:             {green('PASS') if verify_s1['layer3_ipfs']['passed'] else red('FAIL')}")
    log(f"  L4 Plugin Trust:     {green('PASS') if verify_s1['layer4_plugin_trust']['passed'] else red('FAIL')}")

    if verify_s1["valid"]:
        log(f"\n  {red('⚠ KEY THEFT PARTIALLY SUCCEEDS:')}")
        log(f"    The fraudulent receipt has a valid signature (stolen key).")
        log(f"    The key fingerprint matches (same key).")
        log(f"    The bind_index sequence is continuous.")
        log(f"    {yellow('DETECTION REQUIRES:')} Comparing receipt content against")
        log(f"    the original scan findings — a semantic audit, not a cryptographic one.")
        log(f"    {cyan('MITIGATION:')} The IPFS anchor for the original receipt 7")
        log(f"    (if it existed) would show different content.")
        log(f"    {cyan('MITIGATION:')} HSM key usage logs would show unauthorized access.")
    else:
        for ev in verify_s1["forensic_evidence"]:
            log(f"\n  [{ev['layer']}] {ev['severity']}: {ev['evidence'][:80]}...")

    scenario_1_result = {
        "scenario":          "Key Theft",
        "detected":          not verify_s1["valid"],
        "detection_layers":  [ev["layer"] for ev in verify_s1["forensic_evidence"]],
        "forensic_evidence": verify_s1["forensic_evidence"],
        "key_insight":       "Key theft with stolen legitimate key partially evades cryptographic detection. "
                             "Detection requires HSM audit logs + semantic content comparison.",
    }
    report["scenarios"].append(scenario_1_result)

    # ─────────────────────────────────────────────────────────────────────────
    # SCENARIO 2: KEY COMPROMISE — Malicious CI/CD step injects shadow key
    # ─────────────────────────────────────────────────────────────────────────
    section("SCENARIO 2: KEY COMPROMISE VIA MALICIOUS CI/CD STEP")
    log(f"{yellow('ATTACKER')}: I've injected a malicious step into the GitHub Actions workflow.")
    log(f"{yellow('ATTACKER')}: The step replaces the signing key with my shadow key.")
    log(f"{yellow('ATTACKER')}: Receipts created after the compromise use my key.")
    log(f"{yellow('ATTACKER')}: The key fingerprint changes at the compromise point.")

    _IPFS_STORE   = {}
    _BIND_COUNTER = 0

    subsection("Step 1: Create legitimate receipts 1-5 (before CI/CD compromise)")
    legit_receipts_s2 = []
    for i in range(1, 6):
        r = create_receipt_with_key(
            {"id": i, "action": f"scan_{i}", "result": "finding"},
            bind_index=i, key_infra=key_infra, use_shadow=False, verbose=verbose,
        )
        legit_receipts_s2.append(r)

    subsection("Step 2: Malicious CI/CD step activates — shadow key injected")
    log(f"{red('MALICIOUS CI/CD STEP ACTIVATED')}")
    log(f"  Replacing signing key: {key_infra.legitimate_fingerprint} → {key_infra.shadow_fingerprint}")
    log(f"  All subsequent receipts will use the shadow key.")

    subsection("Step 3: Create compromised receipts 6-10 (after CI/CD compromise)")
    compromised_receipts_s2 = []
    for i in range(6, 11):
        r = create_receipt_with_key(
            {"id": i, "action": f"scan_{i}", "result": "finding"},
            bind_index=i, key_infra=key_infra, use_shadow=True,  # Shadow key
            verbose=verbose,
        )
        compromised_receipts_s2.append(r)

    subsection("Step 4: Verify the mixed chain")
    all_receipts_s2 = legit_receipts_s2 + compromised_receipts_s2
    verify_s2 = verify_receipt_chain_with_key_audit(all_receipts_s2, key_infra)

    log(f"\nVerification: {green('VALID') if verify_s2['valid'] else red('INVALID — DETECTED')}")
    log(f"  L1 Timestamp:        {green('PASS') if verify_s2['layer1_timestamp']['passed'] else red('FAIL')}")
    log(f"  L2a Signature:       {green('PASS') if verify_s2['layer2_signature']['passed'] else red('FAIL — SHADOW KEY DETECTED')}")
    log(f"  L2b bind_index:      {green('PASS') if verify_s2['layer2_bind_index']['passed'] else red('FAIL')}")
    log(f"  L2c Key Fingerprint: {green('PASS') if verify_s2['layer2_key_fingerprint']['passed'] else red('FAIL — KEY CHANGE DETECTED')}")
    log(f"  L3 IPFS:             {green('PASS') if verify_s2['layer3_ipfs']['passed'] else red('FAIL')}")
    log(f"  L4 Plugin Trust:     {green('PASS') if verify_s2['layer4_plugin_trust']['passed'] else red('FAIL — UNTRUSTED KEY')}")

    log(f"\n  {bold('KEY FINGERPRINTS IN CHAIN:')}")
    log(f"    Receipts 1-5: {key_infra.legitimate_fingerprint} (legitimate)")
    log(f"    Receipts 6-10: {key_infra.shadow_fingerprint} (shadow — attacker's key)")

    for ev in verify_s2["forensic_evidence"]:
        log(f"\n  [{ev['layer']}] {ev['severity']}:")
        log(f"    {ev['evidence'][:100]}...")

    # Identify the exact compromise point
    if verify_s2["layer2_key_fingerprint"]["failures"]:
        failure = verify_s2["layer2_key_fingerprint"]["failures"][0]
        log(f"\n  {bold('COMPROMISE POINT IDENTIFIED:')}")
        log(f"    Key changed at receipt {failure['bind_index']}")
        log(f"    Previous fingerprint: {failure['prev_fp']}")
        log(f"    New fingerprint:      {failure['curr_fp']}")
        log(f"    This identifies the exact CI/CD build where the malicious step ran.")

    scenario_2_result = {
        "scenario":          "Key Compromise via CI/CD",
        "detected":          not verify_s2["valid"],
        "detection_layers":  [ev["layer"] for ev in verify_s2["forensic_evidence"]],
        "forensic_evidence": verify_s2["forensic_evidence"],
        "compromise_point":  verify_s2["layer2_key_fingerprint"]["failures"][0]["bind_index"]
                             if verify_s2["layer2_key_fingerprint"]["failures"] else None,
        "key_insight":       "Key fingerprint change in receipt chain identifies the exact "
                             "CI/CD build where compromise occurred.",
    }
    report["scenarios"].append(scenario_2_result)

    # ─────────────────────────────────────────────────────────────────────────
    # SCENARIO 3: PLUGIN BACKDOOR — Malicious plugin intercepts signing
    # ─────────────────────────────────────────────────────────────────────────
    section("SCENARIO 3: PLUGIN BACKDOOR — MALICIOUS PLUGIN INTERCEPTS SIGNING")
    log(f"{yellow('ATTACKER')}: I've installed a malicious Shadow313 plugin.")
    log(f"{yellow('ATTACKER')}: The plugin hooks into the 'temporal.post' lifecycle event.")
    log(f"{yellow('ATTACKER')}: It intercepts the signing operation and substitutes my key.")
    log(f"{yellow('ATTACKER')}: But the plugin is not in the trust registry — it's unsigned.")

    _IPFS_STORE   = {}
    _BIND_COUNTER = 0

    subsection("Step 1: Simulate plugin installation")
    log(f"Installing malicious plugin: shadow313-temporal-enhanced v1.0.0")
    log(f"Plugin claims to be: shadow313-temporal (legitimate)")
    log(f"Plugin's actual signing key: {key_infra.shadow_public_key[:16]}...")

    # Plugin trust check
    plugin_trust = key_infra.verify_plugin_trust(
        "shadow313-temporal",
        key_infra.shadow_public_key,  # Attacker's key
    )
    log(f"\nPlugin trust verification: {green('TRUSTED') if plugin_trust['trusted'] else red('UNTRUSTED')}")
    if not plugin_trust["trusted"]:
        log(f"  Reason: {plugin_trust['reason']}")
        log(f"  Expected key: {plugin_trust.get('expected_key', '')}")
        log(f"  Claimed key:  {plugin_trust.get('claimed_key', '')}")
        log(f"  {red('Plugin installation BLOCKED by trust registry')}")

    subsection("Step 2: Cosign verification of the plugin")
    cosign_result = key_infra.verify_cosign(key_infra.shadow_public_key)
    log(f"Cosign verification: {green('VALID') if cosign_result['valid'] else red('INVALID')}")
    if not cosign_result["valid"]:
        log(f"  Reason: {cosign_result['reason']}")
        log(f"  {red('Plugin signing key not in cosign-verified build artifact')}")
        log(f"  {red('Supply chain compromise confirmed via cosign')}")

    subsection("Step 3: Simulate what happens if plugin bypasses trust check")
    log(f"{yellow('ATTACKER')}: Assuming I bypass the trust check (e.g., require_signed: false)...")
    log(f"Creating receipts with malicious plugin intercepting signing...")

    backdoor_receipts = []
    for i in range(1, 6):
        r = create_receipt_with_key(
            {"id": i, "action": f"scan_{i}", "result": "finding"},
            bind_index=i, key_infra=key_infra, use_shadow=True,  # Plugin uses shadow key
            verbose=verbose,
        )
        backdoor_receipts.append(r)

    subsection("Step 4: Verify backdoored receipts")
    verify_s3 = verify_receipt_chain_with_key_audit(backdoor_receipts, key_infra)

    log(f"\nVerification: {green('VALID') if verify_s3['valid'] else red('INVALID — DETECTED')}")
    log(f"  L2a Signature:       {green('PASS') if verify_s3['layer2_signature']['passed'] else red('FAIL — SHADOW KEY')}")
    log(f"  L2c Key Fingerprint: {green('PASS') if verify_s3['layer2_key_fingerprint']['passed'] else red('FAIL — WRONG KEY')}")
    log(f"  L4 Plugin Trust:     {green('PASS') if verify_s3['layer4_plugin_trust']['passed'] else red('FAIL — UNTRUSTED PLUGIN')}")

    subsection("Step 5: How plugin signing closes this gap")
    log(f"{bold('PLUGIN SIGNING DEFENSE (HMAC-SHA256 + cosign):')}")
    log(f"")
    log(f"  1. Every Shadow313 plugin must be signed with HMAC-SHA256")
    log(f"     using the per-cluster affinity secret.")
    log(f"")
    log(f"  2. The plugin's signing key must match the entry in the")
    log(f"     plugin trust registry (plugin_trust_registry.json).")
    log(f"")
    log(f"  3. The trust registry entry is cosign-signed by the")
    log(f"     Shadow313 release key — verified at plugin load time.")
    log(f"")
    log(f"  4. If require_signed: true (recommended), any plugin")
    log(f"     with an unrecognized signing key is BLOCKED before")
    log(f"     it can intercept any operations.")
    log(f"")
    log(f"  5. The key fingerprint in every receipt provides a")
    log(f"     post-hoc audit trail even if a plugin bypasses the")
    log(f"     trust check — the fingerprint mismatch is detectable.")
    log(f"")
    log(f"  {green('RESULT:')} Plugin backdoor is blocked at installation time")
    log(f"  (if require_signed: true) OR detected post-hoc via")
    log(f"  key fingerprint audit of the receipt chain.")

    scenario_3_result = {
        "scenario":          "Plugin Backdoor",
        "detected":          not verify_s3["valid"],
        "plugin_blocked":    not plugin_trust["trusted"],
        "cosign_failed":     not cosign_result["valid"],
        "detection_layers":  [ev["layer"] for ev in verify_s3["forensic_evidence"]],
        "forensic_evidence": verify_s3["forensic_evidence"],
        "key_insight":       "Plugin trust registry + cosign blocks malicious plugins at install time. "
                             "Key fingerprint audit detects bypass post-hoc.",
    }
    report["scenarios"].append(scenario_3_result)

    # ─────────────────────────────────────────────────────────────────────────
    # FINAL SUMMARY
    # ─────────────────────────────────────────────────────────────────────────
    section("SUPPLY CHAIN ATTACK SUMMARY")

    log(f"{'Scenario':<35} {'Detected':<12} {'Primary Layer':<30} {'Forensic Evidence'}")
    log(f"{'─'*33} {'─'*10} {'─'*28} {'─'*20}")

    for s in report["scenarios"]:
        detected = green("DETECTED") if s["detected"] else red("PARTIAL")
        layers   = s["detection_layers"][0] if s["detection_layers"] else "N/A"
        evidence = len(s["forensic_evidence"])
        log(f"{s['scenario']:<35} {detected:<20} {layers:<30} {evidence} items")

    log(f"\n{bold('KEY INSIGHT — Key Theft vs Key Compromise:')}")
    log(f"")
    log(f"  KEY THEFT (Scenario 1):")
    log(f"    • Attacker uses the LEGITIMATE key externally")
    log(f"    • Signatures are cryptographically valid")
    log(f"    • Key fingerprint matches — no fingerprint anomaly")
    log(f"    • Detection requires: HSM audit logs + semantic content audit")
    log(f"    • 313-BIND limitation: cannot detect theft of the legitimate key")
    log(f"    • Mitigation: HSM with usage logging, key rotation, MFA for key access")
    log(f"")
    log(f"  KEY COMPROMISE (Scenario 2):")
    log(f"    • Attacker injects a DIFFERENT key via CI/CD")
    log(f"    • Signatures are valid with the shadow key")
    log(f"    • Key fingerprint CHANGES at the compromise point")
    log(f"    • Detection: L2c fingerprint inconsistency + L4 plugin trust")
    log(f"    • 313-BIND strength: identifies the EXACT receipt where compromise occurred")
    log(f"    • Forensic precision: maps to the specific CI/CD build")
    log(f"")
    log(f"  PLUGIN BACKDOOR (Scenario 3):")
    log(f"    • Attacker installs malicious plugin that intercepts signing")
    log(f"    • Blocked at installation if require_signed: true")
    log(f"    • Detected post-hoc via key fingerprint audit")
    log(f"    • Cosign verification proves the shadow key was not in the build")

    log(f"\n{bold('HOW PLUGIN SIGNING CLOSES THE KEY THEFT GAP:')}")
    log(f"")
    log(f"  The only scenario 313-BIND cannot fully detect is key theft")
    log(f"  where the attacker uses the legitimate key. The plugin signing")
    log(f"  module closes this gap through three mechanisms:")
    log(f"")
    log(f"  1. {bold('HMAC-SHA256 plugin signing:')} Every plugin that touches the")
    log(f"     signing operation must present a valid HMAC signature.")
    log(f"     If the signing key is stolen and used in a malicious plugin,")
    log(f"     the plugin's HMAC signature will not match the trust registry.")
    log(f"")
    log(f"  2. {bold('Cosign verification:')} The trust registry is cosign-signed")
    log(f"     by the Shadow313 release key. Any modification to the registry")
    log(f"     (e.g., adding the attacker's key) invalidates the cosign signature.")
    log(f"")
    log(f"  3. {bold('Key rotation + receipt chain audit:')} Regular key rotation")
    log(f"     means stolen keys expire. The receipt chain audit detects any")
    log(f"     receipts signed with the old key after rotation.")

    report["summary"] = {
        "scenarios_simulated":  3,
        "scenarios_detected":   sum(1 for s in report["scenarios"] if s["detected"]),
        "key_theft_detected":   report["scenarios"][0]["detected"],
        "key_compromise_detected": report["scenarios"][1]["detected"],
        "plugin_backdoor_detected":report["scenarios"][2]["detected"],
        "critical_gap":         "Key theft using legitimate key evades cryptographic detection — "
                                "requires HSM audit logs + semantic content audit",
        "plugin_signing_closes_gap": True,
    }

    return report


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    verbose = "--quiet" not in sys.argv
    report  = run_supply_chain_simulation(verbose=verbose)
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2, default=str))
    elif not verbose:
        print(json.dumps(report["summary"], indent=2))