# Shadow313 313-BIND vs. SLSA v1.2 vs. NIST SSDF v1.1 — Supply Chain Security Framework Comparison

**Date:** 2026-08-28  
**Classification:** Confidential — Founder / Investor Eyes Only  
**Confidence:** High for SLSA and SSDF (based on official published specifications as of SLSA v1.2, November 2025, and NIST SP 800-218 v1.1 final). Medium-high for 313-BIND coverage claims (based on implemented simulation code and architecture documents in this repository). Gap analysis is analytical judgment, not third-party audit.

---

## 1. Framework Definitions — What Each One Actually Is

Before comparing, it is essential to be precise about what each framework is and is not. Conflating them is the most common analytical error.

### SLSA v1.2 (Supply-chain Levels for Software Artifacts)
**What it is:** A graduated attestation framework for proving that a software artifact was built from a specific, unmodified source using a specific, unmodified build process. It is organized into two tracks (Build and Source) with three levels each.

**What it is not:** A runtime security framework. A cryptographic algorithm standard. A tamper-evidence system for operational audit logs. A post-quantum security specification.

**Current version:** v1.2, approved November 2025. The Source Track was promoted from experimental to normative in this release. v1.1 (April 2025) added verifier metadata to VSAs. v1.0 (2023) established the Build Track.

**Signing approach:** SLSA is algorithm-agnostic. It requires that provenance be signed (Build L2+) but does not mandate a specific algorithm. In practice, the ecosystem uses ECDSA P-256 via Sigstore/cosign. No SLSA level requires or recommends post-quantum algorithms. The specification explicitly defers algorithm selection to the ecosystem.

**Trust model:** SLSA trusts the build platform (GitHub Actions, GitLab CI, etc.) as the root of trust. The build platform signs the provenance. The consumer verifies the provenance against the platform's public key. The platform's key is the single point of cryptographic trust.

### NIST SSDF v1.1 (Secure Software Development Framework, SP 800-218)
**What it is:** A process framework — a set of outcome-based practices organized into four groups (PO, PS, PW, RV) that describe what a software producer should do to develop software securely. It is the reference standard behind U.S. federal software attestation requirements (EO 14028 Section 4e). SSDF v1.2 (SP 800-218 Rev. 1) was published as an initial public draft in December 2025; v1.1 remains the operative standard.

**What it is not:** A technical specification. It does not mandate specific tools, algorithms, or architectures. It describes outcomes and leaves implementation to the producer.

**Four practice groups:**
- **PO (Prepare the Organization):** Security requirements, roles, toolchain readiness
- **PS (Protect the Software):** Protect code and artifacts from tampering (PS.1: access control; PS.2: integrity verification mechanism; PS.3: archive and protect releases)
- **PW (Produce Well-Secured Software):** Secure design, code review, component management (PW.4: third-party components/SBOM), secure build config (PW.6), SAST (PW.7), testing (PW.8)
- **RV (Respond to Vulnerabilities):** Ongoing identification (RV.1), remediation (RV.2), root cause analysis (RV.3)

**Signing approach:** PS.2 requires "a mechanism for verifying software integrity" — this is intentionally vague. It can be satisfied by a hash, a signature, or a more sophisticated provenance system. No algorithm is mandated.

**Trust model:** Process-based. SSDF trusts that the producer follows documented practices. Evidence is producer-generated and producer-attested. There is no independent cryptographic verifier in the SSDF model — the framework relies on audit and attestation, not cryptographic proof.

### Shadow313 313-BIND
**What it is:** A runtime cryptographic audit provenance system. It creates tamper-evident, independently verifiable receipts for security scan findings at the moment they are produced. It is not a build-time framework — it operates during the execution of security tools, not during software compilation.

**What it is not:** A build provenance system. It does not attest to how Shadow313 itself was built. It does not replace SLSA or SSDF for the build pipeline.

**Four defense layers (as implemented):**
- **L1 — Nanosecond timestamp entropy:** Every receipt timestamp must end in ...313 nanoseconds. This is a temporal specificity constraint that makes retroactive fabrication require controlling nanosecond-precision system time.
- **L2a — SLH-DSA (FIPS 205) signature:** The SHA3-512 hash of the finding, the bind_index, the timestamp, and the key fingerprint are signed with a post-quantum signature scheme. The key fingerprint is embedded inside the signed message — it cannot be changed without invalidating the signature.
- **L2b — bind_index sequential integrity:** Receipts are numbered sequentially. Any deletion creates a detectable gap. Any renumbering invalidates the SLH-DSA signature (which covers the bind_index).
- **L2c — Key fingerprint consistency audit:** The key fingerprint embedded in every receipt allows detection of key substitution at any point in the chain, with receipt-level precision identifying the exact compromise point.
- **L3 — IPFS anchor:** The complete receipt is anchored to IPFS at creation time. The CID is content-addressed and immutable. Retroactive modification of the receipt produces a different CID, exposing the tampering.
- **L4 — Plugin trust registry (HMAC-SHA256 + cosign):** Every plugin that touches the signing operation must be registered in a cosign-signed trust registry. The plugin's signing key must match the registry entry.

**Signing approach:** SLH-DSA (FIPS 205), a NIST-standardized post-quantum signature scheme. This is the only framework of the three that specifies a post-quantum algorithm.

**Trust model:** Local-first, independently verifiable. The verifier does not need to trust Shadow313, the build platform, or any third party. The IPFS anchor is publicly verifiable. The SLH-DSA public key can be published independently.

---

## 2. Attack Vector Coverage Matrix

The following matrix maps 28 specific supply chain attack vectors against each framework's coverage. Coverage ratings:

- **✅ Full** — The framework explicitly addresses this vector with a specific requirement or control
- **⚠️ Partial** — The framework addresses the category but not this specific vector, or the control is process-based rather than cryptographic
- **❌ None** — The framework does not address this vector
- **🔬 Unique** — Only this framework addresses this vector among the three

### 2.1 Source Integrity Threats

| Attack Vector | SLSA v1.2 | NIST SSDF | 313-BIND | Notes |
|---|---|---|---|---|
| Unauthorized commit to source repo | ✅ Source L3 | ⚠️ PS.1 (process) | ❌ | SLSA Source L3 requires technically enforced branch protection and two-party review. SSDF PS.1 requires access controls but is process-based. 313-BIND operates post-build. |
| Force-push erasing git history | ✅ Source L2 | ❌ | ❌ | SLSA Source L2 requires history preservation attestation. Neither SSDF nor 313-BIND addresses this. |
| Single-maintainer takeover | ✅ Source L3 | ⚠️ PO.2 (roles) | ❌ | SLSA Source L3 requires two-party review enforcement. SSDF PO.2 requires role assignment but is not technically enforced. |
| Sock puppet / colluding reviewers | ❌ (out of scope) | ❌ | ❌ | **Universal gap.** All three frameworks explicitly exclude collusion between authorized parties. |
| Typosquatting / dependency confusion | ❌ | ⚠️ PW.4 (component review) | ❌ | SSDF PW.4 requires component inventory and review. SLSA explicitly marks typosquatting as out of scope. 313-BIND does not address dependency selection. |

### 2.2 Build Integrity Threats

| Attack Vector | SLSA v1.2 | NIST SSDF | 313-BIND | Notes |
|---|---|---|---|---|
| Build from modified source (not matching repo) | ✅ Build L3 | ⚠️ PS.2 | ❌ | SLSA Build L3 provenance identifies actual sources used. SSDF PS.2 requires integrity verification but is not specific. |
| Malicious CI/CD step injecting code | ✅ Build L3 | ⚠️ PW.6 | 🔬 L2c + L4 | SLSA Build L3 isolates build steps. SSDF PW.6 requires secure build config. **313-BIND uniquely detects key substitution at the exact CI/CD step via fingerprint change point.** |
| Compromised build platform (SolarWinds pattern) | ✅ Build L3 | ⚠️ PS.1 | ❌ | SLSA Build L3 requires hardened, isolated builder. SSDF PS.1 requires access controls. 313-BIND does not attest to the build platform. |
| Stolen build signing credentials | ⚠️ Build L2 (deters) | ⚠️ PO.3 (toolchain) | 🔬 L2c (key theft gap documented) | SLSA Build L2 deters but does not prevent credential theft. SSDF PO.3 requires secure toolchain. **313-BIND explicitly models and documents the key theft limitation — the only framework to do so with forensic precision.** |
| Poisoned build cache | ❌ (TBD in spec) | ❌ | ❌ | **Universal gap.** SLSA marks this as TBD. Neither SSDF nor 313-BIND addresses build cache poisoning. |
| Malicious plugin intercepting signing | ❌ | ❌ | 🔬 L4 (plugin trust registry) | **313-BIND uniquely addresses this.** SLSA and SSDF have no mechanism for plugin-level signing interception detection. |
| Parallel build tampering | ✅ Build L3 | ❌ | ❌ | SLSA Build L3 prevents runs from influencing one another. |
| Build parameter injection | ✅ Build L3 | ⚠️ PW.6 | ❌ | SLSA Build L3 prevents user-defined build steps from accessing signing secrets. |

### 2.3 Artifact and Distribution Threats

| Attack Vector | SLSA v1.2 | NIST SSDF | 313-BIND | Notes |
|---|---|---|---|---|
| Upload modified package (CodeCov pattern) | ✅ Build L1+ | ⚠️ PS.2 | ❌ | SLSA provenance shows artifact was not built as expected. SSDF PS.2 requires integrity mechanism. |
| Tamper with artifact after CI/CD | ✅ Build L1 | ⚠️ PS.2 | ❌ | SLSA provenance detects post-build modification. |
| Compromise package repository | ✅ Build L1+ | ⚠️ PS.3 | ❌ | SLSA provenance shows artifact not built as expected. SSDF PS.3 requires archiving. |
| Tamper with provenance/attestation | ✅ Build L2 (signed) | ❌ | ❌ | SLSA Build L2 signs provenance. SSDF has no provenance concept. |

### 2.4 Runtime Audit Log Threats (313-BIND's Primary Domain)

| Attack Vector | SLSA v1.2 | NIST SSDF | 313-BIND | Notes |
|---|---|---|---|---|
| Delete a security finding from audit log | ❌ | ⚠️ PS.3 (archive) | 🔬 L2b (bind_index gap) + L3 (IPFS orphan) | **313-BIND uniquely detects deletion with dual evidence: sequential gap + IPFS orphan.** SSDF PS.3 requires archiving but provides no tamper detection. SLSA does not address runtime audit logs. |
| Modify a finding after the fact | ❌ | ⚠️ PS.3 | 🔬 L2a (SLH-DSA) + L3 (IPFS CID mismatch) | **313-BIND uniquely detects modification.** The SLH-DSA signature covers the content; the IPFS CID is content-addressed. Any modification invalidates both. |
| Renumber receipts to close a deletion gap | ❌ | ❌ | 🔬 L2a (bind_index in signed message) | **313-BIND uniquely prevents this.** The bind_index is inside the signed message — renumbering invalidates the signature. |
| SHA-3 chain bypass (recompute hash chain) | ❌ | ❌ | 🔬 L2a (SLH-DSA defeats recomputation) | **313-BIND uniquely addresses this.** SHA-3 chain bypass completes in <1ms and is undetected by hash-only verification. SLH-DSA requires the private key — recomputation without the key produces an invalid signature. |
| Retroactive timestamp forgery | ❌ | ❌ | 🔬 L1 (...313 entropy) + L3 (IPFS timestamp) | **313-BIND uniquely addresses this.** The ...313 nanosecond constraint and IPFS anchor timestamp make retroactive timestamp fabrication detectable. |
| Insider deletes findings before IPFS anchor | ❌ | ❌ | ⚠️ Partial (race window) | **Universal gap for this specific timing attack.** If an insider deletes a finding before the IPFS anchor is written, no framework detects it. 313-BIND minimizes the window but cannot eliminate it. |

### 2.5 Cryptographic Threats

| Attack Vector | SLSA v1.2 | NIST SSDF | 313-BIND | Notes |
|---|---|---|---|---|
| CRQC breaks RSA/ECDSA signing key | ❌ (algorithm-agnostic, ecosystem uses ECDSA) | ❌ (no algorithm mandate) | 🔬 L2a (SLH-DSA FIPS 205) | **313-BIND is the only framework with a post-quantum signing requirement.** SLSA's ecosystem (Sigstore/cosign) uses ECDSA P-256, which is retroactively forgeable post-CRQC. SSDF has no algorithm mandate. |
| Harvest-now-decrypt-later (HNDL) on audit logs | ❌ | ❌ | 🔬 Quantum NEXUS module | **313-BIND uniquely addresses HNDL.** Neither SLSA nor SSDF considers the threat of adversaries harvesting encrypted audit data today for future decryption. |
| Hash collision attack on SHA-256 provenance | ❌ (TBD in SLSA spec) | ❌ | 🔬 SHA3-512 (collision resistance) | **313-BIND uses SHA3-512** (512-bit output, no known collision attacks). SLSA provenance uses SHA-256 (256-bit, theoretically vulnerable to birthday attacks at quantum scale). SSDF has no hash algorithm mandate. |
| Key compromise via supply chain (different key injected) | ❌ | ❌ | 🔬 L2c (fingerprint change point) + L4 (plugin trust) | **313-BIND uniquely detects key substitution with receipt-level precision.** Neither SLSA nor SSDF has a mechanism to detect that a different signing key was used at a specific point in the audit chain. |
| Key theft (legitimate key used externally) | ❌ | ⚠️ PO.3 (HSM recommendation) | ⚠️ Documented gap + HSM mitigation | **All three frameworks have this gap.** SSDF PO.3 recommends HSM use. 313-BIND explicitly documents the limitation and the mitigation path. SLSA Build L3 reduces the attack surface but does not prevent key theft. |

### 2.6 Dependency and Component Threats

| Attack Vector | SLSA v1.2 | NIST SSDF | 313-BIND | Notes |
|---|---|---|---|---|
| Compromised dependency (event-stream pattern) | ⚠️ Build L3 (recursive SLSA) | ✅ PW.4 (component inventory + review) | ❌ | SSDF PW.4 is the strongest control here. SLSA addresses this recursively but requires all dependencies to also be SLSA-compliant. 313-BIND does not address dependency selection. |
| Dependency becomes unavailable | ❌ (out of scope) | ❌ | ❌ | **Universal gap.** All three frameworks explicitly exclude availability threats from their scope. |
| Unsigned/unverified SBOM | ❌ | ⚠️ PW.4 | ❌ | SSDF PW.4 requires component inventory. Neither SLSA nor 313-BIND mandates SBOM signing (though SLSA provenance can reference an SBOM digest). |

---

## 3. Unique Coverage — What Each Framework Owns Exclusively

### 3.1 What SLSA v1.2 Covers That Neither SSDF Nor 313-BIND Does

1. **Source history preservation (Source L2):** Cryptographic attestation that git history has not been rewritten or force-pushed. No other framework addresses this.
2. **Technically enforced two-party review (Source L3):** Attestation that branch protection and code review were mechanically enforced for every commit, not just declared as policy. SSDF PO.2 requires role assignment but is process-based.
3. **Build platform isolation (Build L3):** The requirement that build steps cannot influence one another and cannot access signing secrets. This is a structural control against SolarWinds-pattern compromises.
4. **Provenance as a first-class artifact:** SLSA's VSA (Verification Summary Attestation) is a machine-readable, signed, distributable artifact that consumers can verify independently. Neither SSDF nor 313-BIND produces an equivalent artifact for the build pipeline.
5. **Parallel build tampering prevention (Build L3):** Isolation between concurrent builds on the same platform.

### 3.2 What NIST SSDF Covers That Neither SLSA Nor 313-BIND Does

1. **Organizational process governance (PO group):** Security requirements definition, role assignment, training, toolchain readiness. SLSA and 313-BIND are technical frameworks; SSDF is the only one that addresses the human and organizational layer.
2. **Third-party component management (PW.4):** Explicit requirement to inventory, review, and track third-party components and their vulnerabilities. This is the SBOM mandate in practice.
3. **Secure design and architecture review (PW.1, PW.2):** Requirements to design software to meet security requirements and review the design. Neither SLSA nor 313-BIND addresses pre-code security.
4. **Ongoing vulnerability response (RV group):** The requirement to continuously identify, assess, and remediate vulnerabilities in released software. SLSA and 313-BIND are point-in-time attestation systems; SSDF is the only framework with a continuous post-release obligation.
5. **Root cause analysis (RV.3):** Requirement to analyze vulnerabilities to prevent recurrence. No other framework addresses this.
6. **Federal procurement compliance:** SSDF is the reference standard for EO 14028 Section 4e attestations. SLSA and 313-BIND do not satisfy federal procurement requirements on their own.

### 3.3 What 313-BIND Covers That Neither SLSA Nor SSDF Does

1. **Runtime audit log tamper detection:** The ability to detect deletion, modification, or renumbering of security findings after they are produced. SLSA and SSDF address build-time and process-time integrity; neither addresses the integrity of operational security scan results.
2. **Post-quantum signing of audit evidence (SLH-DSA FIPS 205):** The only framework with a NIST-standardized post-quantum signature requirement. SLSA's ecosystem uses ECDSA P-256 (retroactively forgeable post-CRQC). SSDF has no algorithm mandate.
3. **Nanosecond temporal specificity as entropy:** The ...313 timestamp constraint creates a temporal proof-of-work that makes retroactive fabrication require nanosecond-precision time control. No other framework uses timestamp entropy as a cryptographic primitive.
4. **IPFS-anchored immutability:** Receipts are anchored to a content-addressed, decentralized store. The CID is independently verifiable without trusting Shadow313. No other framework uses decentralized immutable storage for audit evidence.
5. **Key fingerprint chain audit:** The ability to detect key substitution at the exact receipt where it occurred, with forensic precision mapping to the specific CI/CD build. No other framework has this capability.
6. **Plugin signing interception detection (L4):** The plugin trust registry + cosign mechanism detects malicious plugins that intercept the signing operation. No other framework addresses this attack vector.
7. **SHA-3 chain bypass detection:** The simulation demonstrates that SHA-3 hash chains (used by Burp Suite Enterprise and others) are bypassable in <1ms. SLH-DSA defeats this because recomputation requires the private key. No other framework addresses this specific attack.
8. **HNDL (Harvest-Now-Decrypt-Later) prioritization:** The Quantum NEXUS module identifies which encrypted audit data is at highest risk of future decryption by a CRQC. No other framework addresses this threat.
9. **Retroactive forgery window documentation:** 313-BIND explicitly quantifies which historical audit evidence becomes retroactively forgeable post-CRQC (any evidence signed with RSA/ECDSA before key compromise). No other framework addresses the retroactive forgery problem.

---

## 4. Overlap Analysis — Where All Three Frameworks Agree

The following areas are addressed by all three frameworks, though with different mechanisms and specificity:

| Concern | SLSA Mechanism | SSDF Mechanism | 313-BIND Mechanism |
|---|---|---|---|
| Artifact signing | Signed provenance (Build L2+) | PS.2 (integrity mechanism) | SLH-DSA receipt signing |
| Access control on signing keys | Build L3 (secrets not accessible to build steps) | PO.3 (secure toolchain) | Plugin trust registry |
| Tamper evidence for released artifacts | Provenance + VSA | PS.2 + PS.3 | IPFS anchor + bind_index |
| Key management | Build L3 (implicit) | PO.3 (HSM recommendation) | Key fingerprint in signed message |
| Insider threat deterrence | Build L3 (isolation) | PS.1 (access control) | L2c (fingerprint change point) |

**The critical observation:** Where all three frameworks overlap, they use fundamentally different mechanisms. SLSA uses build platform isolation. SSDF uses process controls and access management. 313-BIND uses cryptographic embedding of the key fingerprint inside the signed message. These are complementary, not redundant — an attacker who defeats one mechanism does not automatically defeat the others.

---

## 5. Gap Analysis — What No Framework Addresses

These are attack vectors that remain unaddressed by SLSA v1.2, NIST SSDF v1.1, and 313-BIND collectively. They represent the true frontier of supply chain security.

### Gap 1: Collusion Between Authorized Parties
**Description:** Two or more authorized developers, reviewers, or administrators cooperate to introduce malicious code or suppress findings.

**Why no framework addresses it:** All three frameworks explicitly exclude this. SLSA marks it as "out of scope." SSDF's process controls assume good-faith actors. 313-BIND's cryptographic controls prove what was signed, not whether the signer was acting in good faith.

**Realistic attack:** A senior engineer and a security reviewer collude to approve a backdoor commit. The commit passes two-party review (satisfying SLSA Source L3), is built by a hardened builder (satisfying SLSA Build L3), and the resulting scan findings are properly signed (satisfying 313-BIND). The backdoor is invisible to all three frameworks.

**Potential mitigation (not in any framework):** Behavioral analytics on commit patterns, anomaly detection on review approval timing, mandatory vacation policies that force code exposure to other reviewers.

### Gap 2: Pre-Anchor Race Window
**Description:** An insider deletes or modifies a security finding in the interval between when it is produced and when it is anchored to IPFS.

**Why no framework addresses it:** 313-BIND minimizes this window (the anchor is written immediately after receipt creation) but cannot eliminate it. SLSA and SSDF do not address runtime audit logs at all.

**Realistic attack:** An insider with access to the Shadow313 process intercepts the receipt object in memory before the IPFS write and modifies the finding severity from CRITICAL to LOW. The modified receipt is then anchored — the IPFS CID reflects the modified content, not the original.

**Potential mitigation (not in any framework):** Hardware-enforced memory isolation for the signing process, TEE (Trusted Execution Environment) execution of the receipt creation and anchoring pipeline, dual-write to two independent IPFS nodes with cross-verification.

### Gap 3: Build Cache Poisoning
**Description:** An attacker poisons a shared build cache so that a cached artifact (a compiled dependency, a Docker layer, a compiled object file) is substituted for the legitimate one during a subsequent build.

**Why no framework addresses it:** SLSA explicitly marks this as "TBD." SSDF does not address build caches. 313-BIND operates post-build.

**Realistic attack:** An attacker with write access to a shared Bazel or Docker layer cache substitutes a malicious compiled library. The build system uses the cached artifact without recompiling. The SLSA provenance records the correct source inputs but the actual binary contains the malicious library. The provenance is technically accurate but misleading.

**Potential mitigation (not in any framework):** Hermetic builds (no network access, no shared cache), reproducible builds with independent verification, cache entry signing with provenance linkage.

### Gap 4: Legitimate Key Theft with No HSM Audit Trail
**Description:** An attacker exfiltrates the legitimate signing private key and uses it to sign fraudulent receipts or provenance. The key is stored in software (not an HSM), so there is no usage audit log.

**Why no framework fully addresses it:** SSDF PO.3 recommends HSM use but does not mandate it. SLSA Build L3 requires that signing secrets not be accessible to build steps but does not mandate HSM storage. 313-BIND explicitly documents this as its primary limitation (Scenario 1 in the supply chain simulation).

**Realistic attack:** A developer with access to the CI/CD environment extracts the private key from an environment variable or a secrets manager with insufficient access controls. They use the key to sign fraudulent receipts that suppress critical findings. All cryptographic checks pass.

**Potential mitigation:** Mandatory HSM storage with per-operation audit logging, key usage anomaly detection (signing outside of normal build hours, signing from unexpected IP addresses), threshold signing (require M-of-N key shares to produce a valid signature).

### Gap 5: Semantic Content Manipulation Within Valid Signatures
**Description:** An attacker with legitimate signing authority changes the semantic content of a finding (e.g., changes the CVSS score from 9.8 to 3.1, or changes the affected component from "production" to "test") without changing the cryptographic structure.

**Why no framework addresses it:** All three frameworks verify that content has not been modified after signing. None verifies that the content was accurate before signing. The semantic correctness of the signed content is outside the scope of all three frameworks.

**Realistic attack:** A security engineer with signing authority runs a scan, receives a CRITICAL finding, manually edits the finding severity to LOW in the Shadow313 session before the receipt is created, then creates the receipt. The receipt is cryptographically valid. The IPFS anchor is correct. The bind_index is sequential. All 313-BIND checks pass. The finding is suppressed.

**Potential mitigation (not in any framework):** Dual-control signing (two independent signers must sign each receipt), automated severity validation against a reference database (CVSS scores must match NVD), anomaly detection on finding severity distributions.

### Gap 6: Post-Quantum Algorithm Agility in SLSA and SSDF
**Description:** Neither SLSA nor SSDF mandates post-quantum signing algorithms. As CRQC timelines compress (current estimates: 2030-2035 for cryptographically relevant quantum computers), all historical SLSA provenance and SSDF-compliant audit evidence signed with RSA/ECDSA becomes retroactively forgeable.

**Why no framework addresses it:** SLSA is explicitly algorithm-agnostic. SSDF has no algorithm mandate. 313-BIND uses SLH-DSA but only for its own receipts — it does not address the broader ecosystem.

**Realistic attack (2031 scenario):** A nation-state actor with CRQC access retroactively forges SLSA provenance for a critical infrastructure software package, claiming it was built from a clean source when it was actually built from a compromised source. The forged provenance is indistinguishable from the original because the ECDSA signature is now forgeable. Historical audit evidence is retroactively invalidated.

**Potential mitigation:** Mandatory PQC algorithm migration timeline in SLSA and SSDF (analogous to NIST's PQC migration guidance in SP 800-131A). Dual-signing with both classical and PQC algorithms during the transition period.

### Gap 7: Availability and Continuity of IPFS Anchors
**Description:** IPFS content is only available as long as at least one node is pinning it. If Shadow313's IPFS infrastructure goes offline and no other node has pinned the receipts, the L3 anchor becomes unverifiable.

**Why no framework addresses it:** SLSA and SSDF do not address decentralized storage availability. 313-BIND relies on IPFS availability for L3 verification but does not mandate pinning redundancy.

**Realistic attack:** An attacker who cannot forge the receipts instead takes down the IPFS infrastructure, making L3 verification impossible. An auditor cannot verify the IPFS anchors and must fall back to L1/L2 verification only.

**Potential mitigation:** Mandatory multi-node pinning (Filecoin, Pinata, self-hosted), periodic anchor re-verification with alerting, fallback to a secondary immutable store (e.g., Ethereum OP_RETURN, Sigstore Rekor) for critical receipts.

---

## 6. Framework Positioning — The Three-Layer Model

The correct mental model is not "which framework is best" but "which layer of the supply chain does each framework protect." They are complementary, not competing.

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 3: RUNTIME AUDIT INTEGRITY                               │
│  "Were the security findings accurately recorded and preserved?" │
│  Framework: 313-BIND                                            │
│  Mechanism: SLH-DSA + IPFS + bind_index + key fingerprint       │
│  Unique coverage: Post-quantum, tamper-evident, independently   │
│  verifiable, runtime audit log integrity                        │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: BUILD AND ARTIFACT INTEGRITY                          │
│  "Was the software built from the correct source?"              │
│  Framework: SLSA v1.2                                           │
│  Mechanism: Signed provenance, hardened builder, source VSA     │
│  Unique coverage: Source history, build isolation, provenance   │
│  as a distributable artifact                                    │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1: PROCESS AND ORGANIZATIONAL INTEGRITY                  │
│  "Does the organization follow secure development practices?"   │
│  Framework: NIST SSDF v1.1                                      │
│  Mechanism: Practice groups (PO, PS, PW, RV), attestation       │
│  Unique coverage: Organizational governance, component          │
│  management, ongoing vulnerability response, federal compliance │
└─────────────────────────────────────────────────────────────────┘
```

A fully defended supply chain requires all three layers. An organization with SLSA Build L3 and SSDF compliance but no 313-BIND equivalent has no tamper-evident audit trail for its security findings — an insider can suppress critical vulnerabilities after the build is complete. An organization with 313-BIND but no SLSA has tamper-evident scan results but no proof that the scanner itself was built from unmodified source. An organization with SSDF compliance but no SLSA or 313-BIND has documented processes but no cryptographic proof that those processes were followed.

---

## 7. Investor Implications

### 7.1 The Regulatory Tailwind
NIST SSDF v1.1 is already mandatory for federal software suppliers (EO 14028). SLSA is increasingly required in federal procurement. Neither framework addresses post-quantum audit integrity. As NIST's PQC migration timeline becomes enforceable (NIST IR 8547 sets 2030 as the deprecation deadline for RSA/ECDSA in new systems), regulated enterprises will need a solution that 313-BIND already provides.

**The gap 313-BIND fills is not currently addressed by any mandatory framework.** This is both the opportunity and the risk: the market for post-quantum audit provenance does not fully exist yet, but it is the fastest-growing segment of the compliance market between 2027 and 2032.

### 7.2 The Complementarity Argument
313-BIND is not a replacement for SLSA or SSDF — it is the missing third layer. This is a sales advantage, not a weakness. A CISO who has already invested in SLSA compliance and SSDF attestation has a clear gap: their runtime audit logs are not tamper-evident and are not post-quantum resistant. 313-BIND fills that gap without requiring them to replace their existing investments.

**The correct go-to-market framing:** "You have SLSA for your build pipeline and SSDF for your development process. 313-BIND is the missing layer for your runtime audit evidence."

### 7.3 The Post-Quantum Timing Advantage
SLSA's ecosystem (Sigstore/cosign) uses ECDSA P-256. Migrating Sigstore to a post-quantum algorithm requires changes to the Rekor transparency log, the cosign client, and every build platform that generates SLSA provenance. This is a multi-year ecosystem migration. Shadow313 is already using SLH-DSA (FIPS 205) in production. The window of advantage is 2026-2030 — after which the ecosystem will likely have migrated, but by then Shadow313 will have established the reference implementation and the customer relationships.

### 7.4 The Gap That Matters Most for Investors
Of the seven universal gaps identified in Section 5, **Gap 5 (semantic content manipulation)** is the most commercially significant and the most underappreciated. It is the attack that a sophisticated insider would actually use — not a cryptographic attack, but a semantic one. The finding is suppressed before the receipt is created, so all cryptographic checks pass. No framework addresses this. The mitigation (dual-control signing, automated severity validation) is a product roadmap item that would further differentiate 313-BIND from any competitor.

---

## 8. Summary Tables

### 8.1 Coverage by Attack Category

| Attack Category | SLSA v1.2 | NIST SSDF | 313-BIND |
|---|---|---|---|
| Source code integrity | ✅ Strong (Source Track) | ⚠️ Process-based | ❌ |
| Build pipeline integrity | ✅ Strong (Build Track) | ⚠️ Process-based | ❌ |
| Artifact distribution integrity | ✅ Strong | ⚠️ Process-based | ❌ |
| Runtime audit log integrity | ❌ | ⚠️ Archive only | ✅ Strong |
| Post-quantum cryptographic resistance | ❌ | ❌ | ✅ Strong |
| Key substitution detection | ❌ | ❌ | ✅ Strong |
| Plugin signing interception | ❌ | ❌ | ✅ Strong |
| Organizational process governance | ❌ | ✅ Strong | ❌ |
| Ongoing vulnerability response | ❌ | ✅ Strong | ❌ |
| Component/dependency management | ⚠️ Recursive SLSA | ✅ Strong (PW.4) | ❌ |
| Federal compliance attestation | ⚠️ Partial | ✅ Strong | ❌ |

### 8.2 Universal Gaps (No Framework Addresses)

| Gap | Severity | Mitigation Path |
|---|---|---|
| Collusion between authorized parties | Critical | Behavioral analytics, mandatory vacation |
| Pre-anchor race window | High | TEE execution, dual-write IPFS |
| Build cache poisoning | High | Hermetic builds, cache signing |
| Legitimate key theft (no HSM audit) | High | Mandatory HSM + usage logging |
| Semantic content manipulation before signing | Critical | Dual-control signing, automated validation |
| PQC algorithm agility in SLSA/SSDF ecosystem | High (2030+) | Ecosystem PQC migration |
| IPFS anchor availability | Medium | Multi-node pinning, secondary anchor |

---

*This document is based on SLSA v1.2 (approved November 2025), NIST SP 800-218 v1.1 (final), and the Shadow313 NEXUS v4 codebase as of 2026-08-28. The gap analysis reflects the author's analytical judgment and has not been independently audited.*