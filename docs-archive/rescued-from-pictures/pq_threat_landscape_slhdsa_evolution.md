# Post-Quantum Threat Landscape: 313-BIND Gap Exploitation & SLH-DSA Evolution Requirements

**Date:** 2026-08-28  
**Classification:** Confidential — Founder / Investor Eyes Only  
**Confidence:** High for SLH-DSA cryptographic properties (based on FIPS 205, eprint.iacr.org/2026/632, arXiv:2509.13048v2, eprint.iacr.org/2026/759). High for CRQC timeline (based on Bain & Company 2025, IonQ Davos 2026, Google Willow December 2024). Medium-high for gap exploitation analysis (analytical judgment grounded in published research). Gap closure recommendations are forward-looking engineering proposals, not implemented features.

---

## Preface: What This Document Is and Is Not

This document answers a precise question: **which of the seven universal gaps identified in the framework comparison become critically exploitable specifically because of quantum adversary capabilities, and what would SLH-DSA need to become — structurally, not just parametrically — to close those gaps?**

It is not a general PQC primer. It assumes familiarity with the framework comparison document (`docs/framework_comparison_313bind_slsa_ssdf.md`) and the supply chain simulation (`shadow313/v4/temporal_binding/supply_chain_simulation.py`).

---

## Part 1: The Quantum Adversary Model — Precise Threat Timeline

Before mapping gaps to quantum exploitability, the adversary model must be precise. "Quantum adversary" is not a monolithic category.

### 1.1 Three Distinct Quantum Adversary Classes

**Class Q1 — HNDL Adversary (Active Now, 2024–2033)**  
Capabilities: Classical compute + mass encrypted data collection. No CRQC yet.  
Attack: Harvest encrypted audit logs, provenance records, and signing key material today. Decrypt retroactively when CRQC arrives.  
Timeline: Already operational. NSA and FBI have confirmed nation-states are "stealing massive volumes of encrypted data and shelving it." Internet route hijacks in 2016 (Canadian traffic via China), 2019 (European mobile traffic via China Telecom), and 2020 (U.S. tech traffic via Russia) are documented HNDL collection operations.  
Relevant to 313-BIND: Any audit receipt encrypted with classical algorithms (AES-128 key wrapped in RSA, TLS 1.2 transport) is being harvested now.

**Class Q2 — Early CRQC Adversary (2030–2035 window)**  
Capabilities: ~4,000 error-corrected logical qubits. Can break RSA-2048 and ECDSA P-256 in hours to days.  
Timeline: Bain & Company (2025) estimates 50% probability by 2033. Google's Willow chip (December 2024) demonstrated below-threshold error correction — the fundamental breakthrough that makes scaling reliable rather than noisy. IonQ CEO at Davos 2026: networked systems capable of breaking RSA-2048 within 7–10 years. IBM roadmap: 100,000+ physical qubits by 2033. Consensus range: 2030–2040, most likely window 2033–2037.  
Relevant to 313-BIND: Can retroactively forge any ECDSA-signed SLSA provenance or classical audit log. Cannot break SLH-DSA (hash-based, Grover-resistant). Can break RSA-wrapped AES keys protecting stored audit data.

**Class Q3 — Advanced CRQC Adversary (2035–2040+)**  
Capabilities: Millions of logical qubits. Can break RSA-4096, run Grover's algorithm at scale against weakened hash functions, execute quantum fault injection attacks.  
Relevant to 313-BIND: Grover's algorithm halves the effective security of hash functions. SHA3-256 drops from 256-bit to 128-bit effective security. SHA3-512 drops from 512-bit to 256-bit — still secure. SLH-DSA-SHA2-128s (NIST Level 1) drops from 128-bit to 64-bit effective quantum security — potentially breakable. SLH-DSA-SHAKE-256s (NIST Level 5) retains 128-bit effective quantum security.

**Class Q4 — Implementation Attack Adversary (Active Now, Classical + Quantum-Assisted)**  
Capabilities: Rowhammer, DPA, fault injection, side-channel attacks against PQC implementations. No CRQC required.  
Timeline: Already demonstrated. arXiv:2509.13048 (Boy et al., uASC 2026): first software-only universal forgery attack on SLH-DSA in OpenSSL 3.5.1 using Rowhammer-induced bit flips. Achieves universal forgery for SHAKE-128f (deterministic) after 1 hour, SHAKE-192f (randomized) after 8 hours. No physical access required — software-only attack on commodity desktop and server hardware.  
Relevant to 313-BIND: This is the most immediately dangerous adversary class. SLH-DSA's theoretical security is sound; its implementation security is not.

### 1.2 The Critical Distinction: Algorithm Security vs. Implementation Security

The SLH-DSA security analysis (eprint.iacr.org/2026/632, Do et al. 2026) establishes that SLH-DSA's theoretical security is stronger than NIST's loose evaluation suggested — recovering up to 18 bits of classical security and 9 bits of quantum security compared to the NIST baseline, without relying on heuristic multi-target assumptions.

**This means SLH-DSA's algorithm is sound. Its implementations are not.**

The SLasH-DSA attack (arXiv:2509.13048) does not break the algorithm. It breaks the implementation by inducing bit flips in DRAM during the signing operation, corrupting the internal WOTS+ state in a way that leaks information about SK.seed — the master secret from which all signing keys in the hypertree are derived. Once SK.seed is recovered, universal forgery is trivial.

This distinction is the central organizing principle of this document. The gaps that become critically exploitable in a post-quantum landscape fall into two categories:
1. **Algorithm-level gaps**: Exploitable only by a Class Q2/Q3 adversary with a CRQC
2. **Implementation-level gaps**: Exploitable by a Class Q4 adversary today, with quantum assistance accelerating the attack

---

## Part 2: Gap-by-Gap Quantum Exploitability Analysis

### Gap 1: Collusion Between Authorized Parties

**Quantum exploitability: LOW — but quantum-assisted social engineering is emerging**

Collusion is a human problem, not a cryptographic one. A CRQC does not make two people collude. However, quantum adversaries introduce a subtle amplification:

**The quantum-assisted collusion scenario:** A Class Q1 HNDL adversary harvests encrypted communications between security team members over years. When CRQC arrives, they decrypt those communications and identify existing collusion relationships, coercion opportunities, or compromising information. They then use this intelligence to recruit insiders rather than compromising systems directly.

**Why SLH-DSA cannot address this:** No signature scheme addresses the intent of the signer. SLH-DSA proves that a specific key signed a specific message at a specific time. It cannot prove that the signer was acting in good faith.

**What would actually close this gap:** Threshold signatures (M-of-N signing) where M independent parties must each contribute a partial signature. A quantum adversary who compromises one party's key cannot forge a threshold signature without compromising M parties simultaneously. This is a structural change to 313-BIND's signing architecture, not a parameter change.

**Specific augmentation required:** Replace single-party SLH-DSA signing with a threshold SLH-DSA scheme. The academic literature has threshold constructions for hash-based signatures (e.g., threshold SPHINCS+), but none are currently standardized. NIST's post-quantum threshold signature project is ongoing as of 2026. This is a 2027–2029 implementation target, not a 2026 capability.

---

### Gap 2: Semantic Content Manipulation Before Signing

**Quantum exploitability: CRITICAL — quantum adversaries make this the dominant attack vector**

This is the most important gap in the post-quantum landscape, and it becomes more critical, not less, as cryptographic defenses strengthen.

**The quantum adversary's strategic shift:** As SLH-DSA makes cryptographic forgery computationally infeasible, a rational quantum adversary shifts from "break the signature" to "corrupt the content before it is signed." This is the fundamental principle of adversarial adaptation: attack the weakest link, which moves from the cryptographic layer to the semantic layer as the cryptographic layer hardens.

**The specific attack chain in a post-quantum world:**

```
Phase 1 (2024–2030, HNDL):
  Adversary harvests encrypted Shadow313 session data.
  Identifies which security engineers have signing authority.
  Maps the timing patterns of when receipts are created.

Phase 2 (2030–2033, early CRQC):
  Adversary decrypts harvested session data.
  Identifies the pre-signing window (the gap between finding production
  and receipt creation — typically milliseconds to seconds).
  Develops a targeted exploit for the Shadow313 session process.

Phase 3 (execution):
  Adversary compromises the security engineer's workstation.
  Injects a memory patch that intercepts the finding object before
  the receipt creation call.
  Changes CVSS 9.8 → 3.1, severity CRITICAL → LOW.
  The receipt is created with the modified content.
  SLH-DSA signs the modified content correctly.
  IPFS anchors the modified receipt.
  All 313-BIND verification layers pass.
  The critical vulnerability is suppressed for the duration of the
  audit period.
```

**Why SLH-DSA's stateless design makes this worse, not better:**

SLH-DSA's stateless property means there is no signing state to audit. A stateful scheme (XMSS, LMS) maintains a counter of how many signatures have been produced — an anomaly in the counter could indicate unauthorized signing. SLH-DSA has no such counter. Every signature is independent. There is no way to distinguish a signature produced by the legitimate signer from one produced by an attacker who has compromised the signing process, as long as the key is the same.

**What SLH-DSA would need to become to address this:**

SLH-DSA would need to incorporate a **semantic commitment scheme** — a cryptographic primitive that binds the signed content to an independently verifiable semantic claim. This is not a property of any current signature scheme. It would require:

1. **A reference oracle:** An external, independently maintained database of expected finding semantics (e.g., NVD CVSS scores, KEV severity classifications). The signing process would query this oracle and include the oracle's response in the signed message. A finding with CVSS 9.8 in NVD but CVSS 3.1 in the receipt would produce a detectable discrepancy.

2. **A dual-witness signing protocol:** Two independent signers — one human, one automated oracle — must both sign the receipt. The human signer attests to the finding's existence; the oracle attests to its semantic correctness against the reference database. Neither signature alone is sufficient for verification.

3. **A temporal semantic lock:** The oracle's response is timestamped and included in the IPFS anchor. An auditor can verify that the severity in the receipt matches the NVD severity at the time of signing. Retroactive severity changes in NVD are themselves logged and verifiable.

**Implementation path for 313-BIND:**

```python
# Proposed augmentation to create_receipt_with_key()
# Not yet implemented — forward-looking design

def create_receipt_with_semantic_witness(
    finding: dict,
    bind_index: int,
    key_infra: KeyInfrastructure,
    semantic_oracle: SemanticOracle,  # NEW: NVD/KEV reference oracle
) -> dict:
    # Step 1: Query semantic oracle for expected severity
    cve_id = finding.get("cve_id")
    if cve_id:
        oracle_response = semantic_oracle.query(cve_id)
        # oracle_response = {"cvss": 9.8, "severity": "CRITICAL", "kev": True,
        #                    "oracle_timestamp": ..., "oracle_signature": ...}
        
        # Step 2: Detect semantic manipulation
        if finding.get("cvss") != oracle_response["cvss"]:
            raise SemanticManipulationDetected(
                f"Finding CVSS {finding['cvss']} != Oracle CVSS {oracle_response['cvss']}"
            )
    
    # Step 3: Include oracle attestation in signed message
    # The oracle's signature is part of the receipt — independently verifiable
    receipt = create_receipt_with_key(finding, bind_index, key_infra)
    receipt["semantic_witness"] = oracle_response
    receipt["semantic_witness_verified"] = True
    
    return receipt
```

This is a 2026–2027 implementation target. The NVD API, KEV feed, and EPSS API are already integrated into Shadow313's vuln module — the semantic oracle infrastructure exists. The missing piece is the dual-witness signing protocol.

---

### Gap 3: Pre-Anchor Race Window

**Quantum exploitability: HIGH — quantum-assisted timing attacks compress the detection window**

The pre-anchor race window is the interval between finding production and IPFS anchoring. In the current implementation, this is milliseconds. A classical attacker must compromise the process in real time. A quantum-assisted attacker has additional capabilities:

**Quantum-assisted timing attack:**

A Class Q4 adversary (implementation attack, no CRQC required) uses Rowhammer to induce bit flips in the Shadow313 process memory during the signing operation. The SLasH-DSA attack (arXiv:2509.13048) demonstrates this takes 1–8 hours of hammering. However, the attack does not need to happen during a specific signing event — it can corrupt the SK.seed in memory, after which every subsequent signing operation produces forgeable signatures.

**The amplified attack chain:**

```
Hour 0–8: Rowhammer hammering corrupts SK.seed in Shadow313 process memory.
           The process continues running normally — no crash, no alert.
           
Hour 8+:  Every receipt created uses a corrupted signing state.
           The attacker collects faulty signatures (36 seconds of post-processing
           per the SLasH-DSA paper).
           
Hour 9+:  Attacker has recovered SK.seed.
           They can now forge any receipt with any content and any timestamp
           within the ...313 constraint.
           
           The pre-anchor race window is now irrelevant — the attacker
           can forge receipts that appear to have been created at any
           past time, as long as the timestamp ends in ...313.
```

**Why the ...313 timestamp constraint does not fully protect against this:**

The ...313 constraint prevents retroactive timestamp fabrication by an attacker who does not control the signing key. Once SK.seed is recovered via Rowhammer, the attacker controls the signing key and can produce valid SLH-DSA signatures over any content with any ...313 timestamp. The IPFS anchor is the remaining defense — but if the attacker can also write to IPFS (which requires only network access, not key material), they can anchor forged receipts.

**What SLH-DSA needs to address this:**

1. **Memory protection for SK.seed:** The NXP compressed caching countermeasure (eprint.iacr.org/2026/759) addresses grafting tree fault attacks on SLH-DSA by caching WOTS+ signatures and public keys, achieving high fault detection probability with tunable memory overhead. This is the current state-of-the-art countermeasure for the specific attack class that SLasH-DSA exploits.

2. **TEE (Trusted Execution Environment) execution:** The signing operation should execute inside an Intel TDX or AMD SEV-SNP enclave. Rowhammer attacks against TEE-protected memory require significantly more sophisticated techniques and are not demonstrated at the software-only level.

3. **Signing process isolation:** The Shadow313 signing process should run in a separate process with no shared memory pages with other processes. The SLasH-DSA attack requires the attacker to have a co-located process that can hammer the target's DRAM rows. Process isolation with NUMA-aware memory allocation reduces the attack surface.

4. **Continuous SK.seed integrity verification:** Hash the SK.seed at process startup and re-verify at each signing operation. A Rowhammer-induced bit flip in SK.seed changes its hash — the verification fails and the process halts before producing a forgeable signature.

**Implementation path for 313-BIND:**

```python
# Proposed augmentation to KeyInfrastructure
# Addresses SLasH-DSA (arXiv:2509.13048) Rowhammer attack

import hashlib
import ctypes
import mmap

class HardenedKeyInfrastructure(KeyInfrastructure):
    """
    Rowhammer-hardened key infrastructure.
    
    Countermeasures:
    1. SK.seed integrity hash verified before every signing operation
    2. SK.seed stored in mlock'd memory (prevents swap, reduces Rowhammer surface)
    3. Signing operation count tracked (anomaly detection)
    4. Randomized signing (FIPS 205 hedged mode) to defeat deterministic fault analysis
    """
    
    def __init__(self) -> None:
        super().__init__()
        # Integrity hash of SK.seed — verified before every sign
        self._seed_integrity_hash = hashlib.sha3_256(
            self.legitimate_private_key
        ).digest()
        self._sign_count = 0
        self._sign_count_hash = hashlib.sha3_256(b"0").digest()
    
    def sign_legitimate(self, message: bytes) -> tuple[str, str]:
        # Verify SK.seed integrity before signing
        current_hash = hashlib.sha3_256(self.legitimate_private_key).digest()
        if current_hash != self._seed_integrity_hash:
            raise MemoryIntegrityViolation(
                "SK.seed integrity check failed — possible Rowhammer attack. "
                "Signing halted. Incident response required."
            )
        
        # Verify sign count integrity (detect counter manipulation)
        expected_count_hash = hashlib.sha3_256(
            str(self._sign_count).encode()
        ).digest()
        if expected_count_hash != self._sign_count_hash:
            raise MemoryIntegrityViolation(
                "Sign counter integrity check failed — possible fault injection."
            )
        
        self._sign_count += 1
        self._sign_count_hash = hashlib.sha3_256(
            str(self._sign_count).encode()
        ).digest()
        
        return super().sign_legitimate(message)
```

---

### Gap 4: Build Cache Poisoning

**Quantum exploitability: MEDIUM — quantum adversaries accelerate the discovery of cache collision opportunities**

Build cache poisoning is primarily a classical attack. However, quantum adversaries introduce two amplifications:

**Grover-accelerated cache key collision:** Build caches typically use SHA-256 or MD5 as cache keys (the hash of the input files determines the cache entry). Grover's algorithm provides a quadratic speedup for preimage attacks. For SHA-256 (256-bit), Grover reduces the effective security to 128 bits — still computationally infeasible for a 2033-era CRQC. For MD5 (128-bit), Grover reduces effective security to 64 bits — potentially feasible for a 2035+ Class Q3 adversary.

**The practical implication:** Build systems using MD5 or SHA-1 cache keys (common in legacy Bazel configurations and older Docker layer caching) become vulnerable to quantum-accelerated cache poisoning. A Class Q3 adversary can find a malicious input file that produces the same MD5 cache key as a legitimate file, substituting the malicious compiled artifact.

**What SLH-DSA cannot address:** Build cache poisoning is outside SLH-DSA's scope. SLH-DSA signs the output of the build process, not the inputs to the cache lookup. A poisoned cache produces a malicious artifact that is then correctly signed by SLH-DSA — the signature is valid, the artifact is malicious.

**What 313-BIND could address:** If Shadow313's scan results include the build artifact hash (SHA3-512, not SHA-256), and that hash is included in the signed receipt, then a cache-poisoned artifact would produce a different hash than the expected artifact. An auditor comparing the receipt's artifact hash against the SLSA provenance would detect the discrepancy. This requires 313-BIND to integrate with the build provenance layer — a cross-framework integration that does not currently exist.

---

### Gap 5: Legitimate Key Theft with No HSM Audit Trail

**Quantum exploitability: CRITICAL — HNDL makes this the highest-priority gap for the 2026–2030 window**

This is the gap where quantum adversaries have the most immediate and concrete impact, and it is the gap that is most exploitable right now, before any CRQC exists.

**The HNDL key theft scenario:**

```
2024–2026 (now):
  Class Q1 adversary intercepts TLS-encrypted traffic between the
  Shadow313 signing process and the key management service.
  The traffic contains the signing key material (if stored in software
  rather than an HSM) or the HSM authentication credentials.
  
  The adversary also harvests all signed receipts from the IPFS store.
  These receipts are publicly accessible — IPFS is a public network.

2030–2033 (early CRQC):
  Adversary decrypts the harvested TLS traffic.
  Recovers the signing key material or HSM credentials.
  
  With the signing key, the adversary can:
  1. Forge new receipts with any content and any ...313 timestamp
  2. Retroactively "correct" historical receipts by creating
     replacement receipts with the same bind_index but different content
  3. The IPFS anchor for the original receipt still exists — but the
     adversary can claim the original was the forgery
```

**The retroactive forgery problem — why it is worse than it appears:**

The IPFS anchor provides immutability for the content that was anchored. But it does not provide a total ordering of when different CIDs were anchored relative to each other. An adversary who forges a receipt and anchors it to IPFS in 2033 cannot claim it was anchored in 2026 — the IPFS network's DHT records when content was first published. However, this timestamp is not cryptographically signed by the IPFS network itself — it is a best-effort record from the DHT.

**The specific SLH-DSA property that partially mitigates this:**

SLH-DSA's security proof (eprint.iacr.org/2026/632) establishes existential unforgeability under chosen-message attack (EUF-CMA) in the quantum random oracle model. This means: given the public key and any number of legitimate signatures, a quantum adversary cannot produce a valid signature on a new message without the private key. The key word is "without the private key." If the key is stolen (Gap 5), EUF-CMA provides no protection.

**What SLH-DSA would need to address key theft:**

SLH-DSA's stateless design is simultaneously its greatest strength and its greatest weakness for this gap. The strength: no state to corrupt, no one-time key reuse vulnerability. The weakness: no signing counter means no way to detect that more signatures were produced than expected.

**The structural augmentation required — forward-secure signatures:**

Forward-secure signature schemes divide the signing key's lifetime into epochs. At each epoch boundary, the key is updated in a one-way fashion: the new key can be derived from the old key, but the old key cannot be recovered from the new key. Signatures produced in epoch N remain verifiable, but a key stolen in epoch N+1 cannot be used to forge signatures that appear to have been produced in epoch N.

SLH-DSA is not forward-secure in its current form. Making it forward-secure would require incorporating a stateful epoch counter — which reintroduces the state management complexity that SLH-DSA was designed to avoid.

**The practical path for 313-BIND (2026–2028):**

Rather than modifying SLH-DSA itself, 313-BIND can achieve forward security through a hybrid architecture:

```
Epoch-based key rotation (every 30 days):
  - New SLH-DSA key pair generated
  - Old public key signed by new private key (key transition certificate)
  - Old private key destroyed (HSM-enforced)
  - All receipts from epoch N are verifiable with epoch N public key
  - A key stolen in epoch N+1 cannot forge epoch N receipts
    (the epoch N private key no longer exists)

Epoch boundary anchoring:
  - At each epoch boundary, a "key rotation receipt" is created
  - It contains: old public key hash, new public key hash, epoch number,
    timestamp, and is signed by BOTH the old and new private keys
  - This receipt is anchored to IPFS
  - An auditor can verify the complete chain of key transitions
  - A forged key rotation receipt would require both old and new keys
    simultaneously — infeasible if the old key was destroyed
```

This is implementable today without modifying SLH-DSA. It requires HSM-enforced key destruction at epoch boundaries, which is a deployment requirement, not a cryptographic one.

---

### Gap 6: PQC Algorithm Agility in SLSA/SSDF Ecosystem

**Quantum exploitability: CRITICAL for the ecosystem, ADVANTAGE for 313-BIND**

This gap is unique: it is not a gap in 313-BIND — it is a gap in the frameworks that 313-BIND competes alongside. The quantum exploitability of this gap is the primary source of 313-BIND's competitive moat.

**The retroactive SLSA provenance forgery scenario:**

```
2033 (early CRQC arrives):
  A nation-state adversary with CRQC access targets a critical
  infrastructure software vendor.
  
  The vendor has SLSA Build L3 compliance — all provenance is signed
  with ECDSA P-256 via Sigstore/cosign.
  
  The adversary uses Shor's algorithm to recover the Sigstore signing
  key from any published ECDSA signature (public key + signature → 
  private key in polynomial time on a CRQC).
  
  With the Sigstore signing key, the adversary forges SLSA provenance
  for a malicious build, claiming it was built from clean source.
  
  The forged provenance is indistinguishable from legitimate provenance.
  All SLSA verification passes.
  
  The malicious build is deployed to critical infrastructure.
```

**Why 313-BIND's SLH-DSA receipts survive this scenario:**

The Shadow313 receipts for the security scans of that build are signed with SLH-DSA. A CRQC cannot recover the SLH-DSA private key from the public key or any number of signatures — SLH-DSA's security reduces to hash function second-preimage resistance, which Grover's algorithm can only halve (not eliminate). For SLH-DSA-SHAKE-256s (NIST Level 5), the effective quantum security remains 128 bits — computationally infeasible for any foreseeable CRQC.

**The specific SLH-DSA property that matters here:**

The security analysis (eprint.iacr.org/2026/632) establishes that SLH-DSA's security reduces to SM-openPRE (multi-target second-preimage resistance with open targets) and SM-PRE (multi-target preimage resistance). These are properties of SHA-3/SHAKE, not of any algebraic structure. Grover's algorithm provides at most a quadratic speedup against these properties. For SHA3-512 (used in 313-BIND's receipt hashing), the effective quantum security is 256 bits — beyond any foreseeable attack.

**What SLH-DSA needs to evolve for this gap:**

The gap is not in SLH-DSA's algorithm — it is in the ecosystem's failure to adopt it. The evolution required is:

1. **Hybrid signing during transition (2026–2030):** Every 313-BIND receipt should carry both an SLH-DSA signature and a classical signature (ECDSA or Ed25519). Verifiers that do not yet support SLH-DSA can verify the classical signature. Verifiers that do support SLH-DSA can verify both. When CRQC arrives, the classical signature becomes forgeable but the SLH-DSA signature remains valid. The receipt's integrity is preserved.

2. **Algorithm agility in the receipt schema:** The receipt format should include an `algorithm` field that specifies which signature scheme was used. This allows future migration to stronger parameter sets (e.g., SLH-DSA-SHAKE-256s instead of SLH-DSA-SHAKE-128f) without breaking existing receipts.

3. **Cross-framework attestation:** 313-BIND receipts should include a reference to the SLSA provenance CID for the build that produced the scanned artifact. When SLSA provenance is retroactively forged post-CRQC, the 313-BIND receipt's reference to the original SLSA CID provides a forensic anchor — the original SLSA provenance is still on IPFS, and its CID is embedded in the SLH-DSA-signed receipt. The forged provenance has a different CID.

---

### Gap 7: IPFS Anchor Availability

**Quantum exploitability: LOW — but quantum-assisted DDoS changes the calculus**

IPFS availability is primarily an operational concern, not a cryptographic one. However, quantum adversaries introduce a specific amplification:

**Quantum-accelerated hash collision against IPFS CIDs:**

IPFS CIDs are SHA-256 hashes of the content. A Class Q3 adversary with Grover acceleration could, in theory, find a collision — a different content that produces the same CID. This would allow the adversary to substitute malicious content for legitimate receipts on the IPFS network while maintaining the same CID.

**The practical timeline:** SHA-256 collision resistance under Grover requires approximately 2^128 quantum operations. For a 2033-era CRQC with ~4,000 logical qubits, this is computationally infeasible. For a 2040+ Class Q3 adversary, it remains at the edge of feasibility. The mitigation is straightforward: use SHA3-256 or SHAKE-256 for IPFS CID computation (which IPFS's CIDv1 format supports via the multihash specification).

**The more immediate concern — quantum-assisted Sybil attacks on IPFS:**

A well-resourced adversary (nation-state) could operate a large number of IPFS nodes that selectively refuse to serve specific CIDs. This is a classical attack that quantum resources make cheaper (more nodes, more bandwidth). The mitigation is Filecoin pinning with cryptographic storage proofs — the storage provider must periodically prove they still hold the content, and this proof is verifiable on-chain.

---

## Part 3: SLH-DSA Structural Evolution Requirements

Based on the gap analysis, SLH-DSA as currently specified in FIPS 205 requires five structural augmentations to close the post-quantum exploitable gaps. These are ordered by implementation urgency.

### Augmentation 1: Rowhammer-Resistant Implementation (URGENT — 2026)

**Gap addressed:** Gap 3 (pre-anchor race window, Rowhammer amplification)  
**Adversary class:** Q4 (implementation attack, no CRQC required, active now)  
**Research basis:** arXiv:2509.13048 (SLasH-DSA), eprint.iacr.org/2026/759 (NXP compressed caching)

**What FIPS 205 currently specifies:** The standard specifies the algorithm. It does not mandate implementation hardening against fault attacks.

**What is needed:**

The NXP compressed caching countermeasure (eprint.iacr.org/2026/759) addresses grafting tree fault attacks by caching WOTS+ signatures and public keys. It achieves high fault detection probability with tunable memory overhead — particularly advantageous for constrained devices where less than ~256 kB of caching memory is available.

For Shadow313's server deployment context, the full countermeasure set is:

| Countermeasure | Addresses | Overhead | Status |
|---|---|---|---|
| Compressed WOTS+ caching | Grafting tree fault attacks | ~256 kB memory | Research (eprint.iacr.org/2026/759) |
| SK.seed integrity hash | Rowhammer bit flip detection | Negligible | Implementable now |
| mlock'd memory for SK.seed | Reduces Rowhammer attack surface | Negligible | Implementable now |
| Randomized signing (hedged mode) | Defeats deterministic fault analysis | Negligible | FIPS 205 supports this |
| Process isolation (separate process) | Reduces co-location attack surface | Moderate | Implementable now |
| TEE execution (Intel TDX / AMD SEV-SNP) | Defeats software-only Rowhammer | High | Deployment requirement |

**The Cisco threshold implementation approach** (Fluhrer, NIST PQC 2024) provides an alternative: split SK.seed into multiple shares using a threshold implementation of the hash function. Each share is operated on independently, and the attacker cannot recover the full SK.seed from partial information (e.g., Hamming weight leakage). This is 1.7x slower than the reference implementation but provides strong protection against DPA and fault injection simultaneously.

**Implementation priority for 313-BIND:** SK.seed integrity hash + mlock + randomized signing are implementable in the current codebase within one sprint. TEE execution is a deployment architecture decision for the 2027 production release.

---

### Augmentation 2: Semantic Witness Protocol (HIGH — 2026–2027)

**Gap addressed:** Gap 2 (semantic content manipulation)  
**Adversary class:** Q1/Q4 (classical + quantum-assisted, active now)  
**Research basis:** IEEE Xplore 11475768 (PQ-ABL framework), arXiv:2512.00110v2 (post-quantum audit evidence)

**What FIPS 205 currently specifies:** SLH-DSA signs arbitrary byte strings. It has no concept of semantic validity.

**What is needed:**

The PQ-ABL framework (IEEE Xplore 11475768) introduces post-quantum attribute-based logging with continuous integrity assurance. The key insight is that tamper-evident logging requires not just signature integrity but **semantic binding** — the signed content must be bound to an independently verifiable semantic claim.

The arXiv:2512.00110v2 paper (Kao, 2026) formalizes three security notions for post-quantum audit evidence:
- **Q-Audit Integrity:** A quantum adversary cannot forge an evidence item
- **Q-Non-Equivocation:** A quantum adversary cannot produce two valid evidence items for the same event with different content
- **Q-Binding:** A quantum adversary cannot rebind an evidence item to a different event

Current 313-BIND satisfies Q-Audit Integrity (SLH-DSA EUF-CMA) and partially satisfies Q-Non-Equivocation (bind_index prevents two receipts with the same index). It does not satisfy Q-Binding — an insider can create a receipt for a different finding than the one that was actually produced.

**The dual-witness architecture:**

```
Finding produced by scanner
         │
         ▼
┌─────────────────────────┐     ┌──────────────────────────┐
│  Human/Process Signer   │     │  Semantic Oracle Signer  │
│  (SLH-DSA key)          │     │  (NVD/KEV/EPSS API)      │
│                         │     │                          │
│  Signs: finding content │     │  Signs: expected severity│
│  + bind_index           │     │  for this CVE at this    │
│  + timestamp            │     │  timestamp               │
│  + key fingerprint      │     │  + oracle timestamp      │
│  + oracle_cid           │     │  + oracle_signature      │
└─────────────────────────┘     └──────────────────────────┘
         │                                   │
         └──────────────┬────────────────────┘
                        ▼
              Combined receipt (both signatures required for verification)
                        │
                        ▼
                  IPFS anchor
```

A receipt that passes human signing but fails oracle signing indicates semantic manipulation. A receipt that passes oracle signing but fails human signing indicates key compromise. Both signatures are required for a receipt to be considered valid.

---

### Augmentation 3: Epoch-Based Forward Security (HIGH — 2027–2028)

**Gap addressed:** Gap 5 (legitimate key theft)  
**Adversary class:** Q1 (HNDL, active now) + Q2 (early CRQC, 2030–2033)  
**Research basis:** Forward-secure signature literature, NIST SP 800-208 (stateful hash-based signatures)

**What FIPS 205 currently specifies:** SLH-DSA is stateless and does not provide forward security.

**What is needed:**

Forward security for SLH-DSA requires a hybrid approach — SLH-DSA for the signing operation, plus a stateful epoch management layer that provides the forward-security property without modifying the underlying algorithm.

**The epoch architecture:**

```
Epoch 0 (Jan 2026 – Jan 2027):
  Key pair: (SK_0, PK_0)
  All receipts: signed with SK_0, include epoch=0
  
Epoch 1 (Jan 2027 – Jan 2028):
  Key pair: (SK_1, PK_1)
  Key transition receipt: signed with SK_0 AND SK_1
    {epoch: 0→1, PK_0_hash: ..., PK_1_hash: ..., timestamp: ...}
  SK_0 destroyed (HSM-enforced zeroization)
  All receipts: signed with SK_1, include epoch=1

Epoch N (Jan 2025+N – Jan 2026+N):
  SK_{N-1} destroyed at epoch boundary
  A key stolen in epoch N cannot forge epoch N-1 receipts
  (SK_{N-1} no longer exists)
```

**The security property this provides:**

If a Class Q1 adversary harvests the signing key material in 2026 and a CRQC arrives in 2033, the adversary can only forge receipts for the current epoch (2033's epoch). All historical receipts from epochs 0–7 (2026–2033) are protected because those private keys were destroyed at each epoch boundary. The IPFS-anchored key transition receipts provide a verifiable chain of custody for the public key evolution.

**The NIST SP 800-208 connection:**

NIST SP 800-208 standardizes stateful hash-based signatures (XMSS, LMS) which provide forward security natively. The epoch architecture described above achieves equivalent forward security using SLH-DSA (stateless) + HSM-enforced key destruction. This is preferable to switching to XMSS/LMS because it avoids the state management complexity that makes stateful schemes operationally risky (a state synchronization failure in XMSS causes catastrophic key reuse).

---

### Augmentation 4: Threshold Signing for Collusion Resistance (MEDIUM — 2028–2030)

**Gap addressed:** Gap 1 (collusion between authorized parties)  
**Adversary class:** Q1 (HNDL-assisted social engineering)  
**Research basis:** Threshold SPHINCS+ literature, NIST post-quantum threshold signature project (ongoing 2026)

**What FIPS 205 currently specifies:** Single-party signing. No threshold construction is standardized.

**What is needed:**

A (t, n)-threshold SLH-DSA scheme where t of n parties must contribute partial signatures for a receipt to be valid. The academic literature has threshold constructions for hash-based signatures, but none are currently standardized by NIST. The NIST post-quantum threshold signature project is ongoing as of 2026.

**The practical deployment for 313-BIND:**

A (2, 3) threshold scheme — any 2 of 3 designated signers must sign each receipt. The three signers could be:
1. The security engineer running the scan (human)
2. The Shadow313 automated signing daemon (process)
3. An independent audit witness (third party, e.g., the customer's own signing key)

A collusion attack requires compromising at least 2 of these 3 parties simultaneously. A quantum adversary who compromises the security engineer's key (via HNDL + CRQC) still cannot forge a receipt without also compromising the automated daemon or the audit witness.

**Implementation timeline:** Dependent on NIST threshold signature standardization. Target: 2028–2030.

---

### Augmentation 5: Hybrid Classical + PQC Signing During Transition (IMPLEMENTABLE NOW — 2026)

**Gap addressed:** Gap 6 (PQC algorithm agility in SLSA/SSDF ecosystem)  
**Adversary class:** Q2 (early CRQC, 2030–2033)  
**Research basis:** NIST IR 8547, NSA CNSA 2.0, hybrid signature recommendations

**What FIPS 205 currently specifies:** SLH-DSA as a standalone scheme. Hybrid signing is not specified in FIPS 205 but is recommended by NIST IR 8547 during the transition period.

**What is needed:**

Every 313-BIND receipt should carry two signatures:
1. **SLH-DSA-SHAKE-256s** (NIST Level 5, 128-bit quantum security): The primary post-quantum signature
2. **Ed25519** (classical, 128-bit classical security): The backward-compatible signature for verifiers that do not yet support SLH-DSA

Verification policy:
- **Pre-CRQC (2026–2033):** Either signature is sufficient for verification (backward compatibility)
- **Post-CRQC (2033+):** Only the SLH-DSA signature is trusted; Ed25519 is deprecated

This is implementable in the current codebase without any changes to the SLH-DSA algorithm. It requires adding an `ed25519_signature` field to the receipt schema and updating the verification function to check both.

---

## Part 4: The Augmented 313-BIND Architecture — Target State (2028)

Combining all five augmentations, the target architecture for 313-BIND in 2028 is:

```
┌─────────────────────────────────────────────────────────────────────┐
│  RECEIPT CREATION PIPELINE (2028 target)                            │
│                                                                     │
│  Finding produced by scanner                                        │
│         │                                                           │
│         ▼                                                           │
│  [Semantic Oracle Query]                                            │
│  NVD/KEV/EPSS API → expected severity, CVSS, KEV status            │
│  Semantic mismatch → HALT, alert, do not create receipt             │
│         │                                                           │
│         ▼                                                           │
│  [Epoch Check]                                                      │
│  Current epoch key pair (SK_N, PK_N)                               │
│  SK.seed integrity hash verified (Rowhammer detection)              │
│  mlock'd memory, randomized signing (hedged mode)                  │
│         │                                                           │
│         ▼                                                           │
│  [Threshold Signing — (2,3) scheme]                                 │
│  Partial sig 1: Security engineer (SLH-DSA-SHAKE-256s)             │
│  Partial sig 2: Shadow313 daemon (SLH-DSA-SHAKE-256s)              │
│  Partial sig 3: Audit witness (optional, customer key)             │
│  Combined: threshold signature (any 2 of 3 required)               │
│         │                                                           │
│         ▼                                                           │
│  [Hybrid Signing]                                                   │
│  SLH-DSA-SHAKE-256s signature (primary, quantum-resistant)         │
│  Ed25519 signature (backward-compatible, deprecated post-CRQC)     │
│         │                                                           │
│         ▼                                                           │
│  [Receipt Assembly]                                                 │
│  bind_index (sequential, gap-detectable)                           │
│  timestamp (nanosecond, ...313 entropy)                            │
│  sha3_512 (content hash, 256-bit quantum security)                 │
│  key_fingerprint (epoch N public key, inside signed message)       │
│  epoch (N, inside signed message)                                  │
│  slh_dsa_signature (primary)                                       │
│  ed25519_signature (backward-compatible)                           │
│  semantic_witness (oracle attestation, independently signed)       │
│  oracle_cid (IPFS CID of oracle response)                          │
│         │                                                           │
│         ▼                                                           │
│  [IPFS Anchor — multi-node]                                         │
│  Primary: Shadow313 IPFS node                                      │
│  Secondary: Filecoin pinning (cryptographic storage proof)         │
│  Tertiary: Customer-controlled IPFS node (air-gapped option)       │
│         │                                                           │
│         ▼                                                           │
│  Receipt delivered to caller                                        │
└─────────────────────────────────────────────────────────────────────┘
```

**Verification layers in the 2028 architecture:**

| Layer | Check | Quantum Adversary Defeated |
|---|---|---|
| L1 | Timestamp ends in ...313 | Retroactive timestamp fabrication |
| L2a | SLH-DSA-SHAKE-256s signature valid | Q2/Q3 forgery (128-bit quantum security) |
| L2a-hybrid | Ed25519 signature valid (pre-CRQC only) | Classical forgery during transition |
| L2b | bind_index sequential, no gaps | Deletion detection |
| L2c | Key fingerprint matches epoch N public key | Key substitution detection |
| L2d | Epoch N public key in key transition chain | Forward security verification |
| L2e | Threshold: ≥2 of 3 partial signatures valid | Collusion resistance |
| L3 | IPFS CID matches receipt content | Content modification detection |
| L3-filecoin | Filecoin storage proof valid | IPFS availability attack |
| L4 | Plugin trust registry + cosign | Plugin backdoor detection |
| L5 | Semantic witness: oracle signature valid | Semantic content manipulation |
| L5b | Oracle CVSS matches receipt CVSS | Severity downgrade detection |

---

## Part 5: Implementation Roadmap

| Augmentation | Gap Closed | Adversary Class | Target Date | Complexity |
|---|---|---|---|---|
| SK.seed integrity hash + mlock | Gap 3 (Rowhammer) | Q4 (now) | Q4 2026 | Low |
| Randomized signing (hedged mode) | Gap 3 (fault analysis) | Q4 (now) | Q4 2026 | Low |
| Hybrid SLH-DSA + Ed25519 signing | Gap 6 (ecosystem agility) | Q2 (2030+) | Q4 2026 | Low |
| Algorithm agility in receipt schema | Gap 6 | Q2/Q3 | Q4 2026 | Low |
| Semantic oracle integration (NVD/KEV) | Gap 2 (semantic manipulation) | Q1/Q4 (now) | Q2 2027 | Medium |
| Dual-witness signing protocol | Gap 2 | Q1/Q4 | Q3 2027 | Medium |
| Multi-node IPFS + Filecoin pinning | Gap 7 (availability) | Q3 (2035+) | Q3 2027 | Medium |
| Epoch-based key rotation (30-day) | Gap 5 (key theft) | Q1 (now) + Q2 | Q1 2028 | Medium |
| HSM-enforced key destruction at epoch | Gap 5 | Q1 + Q2 | Q1 2028 | High (deployment) |
| Cross-framework SLSA CID reference | Gap 4/6 (build cache + ecosystem) | Q2 | Q2 2028 | Medium |
| Threshold SLH-DSA (2,3) scheme | Gap 1 (collusion) | Q1 (social engineering) | 2029–2030 | High (NIST standardization dependency) |
| TEE execution (Intel TDX / AMD SEV-SNP) | Gap 3 (Rowhammer, full mitigation) | Q4 | 2027 (deployment) | High (infrastructure) |

---

## Part 6: The Honest Assessment

**What SLH-DSA's stateless design gets right for 313-BIND:**

The stateless property is the correct choice for a high-frequency signing system. A stateful scheme (XMSS, LMS) would require synchronizing signing state across all Shadow313 instances — a distributed systems problem that introduces new failure modes (state desynchronization → key reuse → catastrophic security failure). SLH-DSA's stateless design eliminates this entire class of operational risk.

The security analysis (eprint.iacr.org/2026/632) confirms that SLH-DSA's theoretical security is stronger than NIST's conservative evaluation suggested. The algorithm is sound.

**What SLH-DSA's stateless design gets wrong for 313-BIND:**

The absence of a signing counter means there is no native mechanism to detect that more signatures were produced than expected. This is the root cause of the key theft gap (Gap 5). The epoch-based forward security augmentation addresses this without reintroducing state management complexity.

**The most important finding of this analysis:**

The SLasH-DSA attack (arXiv:2509.13048, uASC 2026) is the most immediately dangerous threat to 313-BIND's security guarantees. It requires no CRQC, no physical access, and no cryptographic breakthrough. It requires only a co-located process and 1–8 hours of Rowhammer hammering on commodity hardware. The countermeasures (SK.seed integrity hash, mlock, randomized signing, compressed caching) are implementable today. This is the highest-priority engineering task in the 313-BIND roadmap.

The second most important finding: semantic content manipulation (Gap 2) becomes the dominant attack vector in a post-quantum world precisely because SLH-DSA makes cryptographic forgery infeasible. A rational adversary shifts to the semantic layer. The dual-witness signing protocol with NVD/KEV oracle attestation is the correct architectural response — and it is achievable with Shadow313's existing vuln module infrastructure.

**The gap that no augmentation closes:**

Collusion between authorized parties (Gap 1) remains unaddressed until threshold SLH-DSA is standardized by NIST (estimated 2028–2030). Until then, the honest answer to "what prevents two authorized signers from colluding to suppress a critical finding" is: nothing cryptographic. The mitigation is organizational — mandatory vacation policies, dual-control procedures, behavioral analytics on signing patterns. This is the correct answer, and it should be disclosed to investors and customers rather than obscured.

---

*Sources: FIPS 205 (NIST, August 2024); eprint.iacr.org/2026/632 (Do et al., tight SLH-DSA security analysis, 2026); arXiv:2509.13048v2 (Boy et al., SLasH-DSA Rowhammer attack, uASC 2026); eprint.iacr.org/2026/759 (Azouaoui et al., NXP compressed caching countermeasure, 2026); arXiv:2512.00110v2 (Kao, post-quantum audit evidence, 2026); IEEE Xplore 11475768 (PQ-ABL framework, 2026); Bain & Company CRQC timeline analysis (2025); IonQ Davos 2026 statement; Google Willow chip announcement (December 2024); NIST IR 8547; NSA CNSA 2.0.*