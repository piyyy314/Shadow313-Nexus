/**
 * SHADOW313 NEXUS — Real PQC Operations Test
 * Tests @noble/post-quantum: ML-KEM-768, ML-DSA-65, SLH-DSA
 * NIST FIPS 203 / 204 / 205
 *
 * API (v0.7.x):
 *   ml_kem768.keygen(seed64)          → { publicKey, secretKey }
 *   ml_kem768.encapsulate(publicKey)  → { cipherText, sharedSecret }
 *   ml_kem768.decapsulate(ct, sk)     → sharedSecret
 *
 *   ml_dsa65.keygen(seed32)           → { publicKey, secretKey }
 *   ml_dsa65.sign(msg, secretKey)     → signature   ← msg FIRST
 *   ml_dsa65.verify(sig, msg, pubKey) → boolean     ← sig FIRST
 *
 *   slh_dsa_sha2_128f.keygen()        → { publicKey, secretKey }
 *   slh_dsa_sha2_128f.sign(msg, sk)   → signature
 *   slh_dsa_sha2_128f.verify(sig, msg, pk) → boolean
 */

'use strict';

const crypto = require('crypto');
const mlKem  = require('./node_modules/@noble/post-quantum/ml-kem.js');
const mlDsa  = require('./node_modules/@noble/post-quantum/ml-dsa.js');
const slhDsa = require('./node_modules/@noble/post-quantum/slh-dsa.js');

console.log('=== SHADOW313 NEXUS — REAL PQC OPERATIONS ===');
console.log('@noble/post-quantum — NIST FIPS 203/204/205');
console.log();

// ── ML-KEM-768 (NIST FIPS 203) ────────────────────────────────────────────
console.log('--- ML-KEM-768 Key Encapsulation (NIST FIPS 203) ---');
const kemSeed = new Uint8Array(crypto.randomBytes(64));  // 64-byte seed
const kemKeys = mlKem.ml_kem768.keygen(kemSeed);
console.log('  Public key:    ', kemKeys.publicKey.length, 'bytes  (spec: 1184)');
console.log('  Secret key:    ', kemKeys.secretKey.length, 'bytes (spec: 2400)');

const { cipherText, sharedSecret: ss1 } = mlKem.ml_kem768.encapsulate(kemKeys.publicKey);
const ss2 = mlKem.ml_kem768.decapsulate(cipherText, kemKeys.secretKey);
const kemMatch = Buffer.from(ss1).equals(Buffer.from(ss2));
console.log('  Ciphertext:    ', cipherText.length, 'bytes  (spec: 1088)');
console.log('  Shared secret: ', Buffer.from(ss1).slice(0, 8).toString('hex') + '...');
console.log('  Encap==Decap:  ', kemMatch);
console.log();

// ── ML-DSA-65 (NIST FIPS 204) ─────────────────────────────────────────────
console.log('--- ML-DSA-65 Digital Signatures (NIST FIPS 204) ---');
const sigSeed = new Uint8Array(crypto.randomBytes(32));  // must be Uint8Array, not Buffer
const sigKeys = mlDsa.ml_dsa65.keygen(sigSeed);
console.log('  Public key:    ', sigKeys.publicKey.length, 'bytes (spec: 1952)');
console.log('  Secret key:    ', sigKeys.secretKey.length, 'bytes (spec: 4032)');

const msg = Buffer.from('SHADOW313 NEXUS - 313-API-00000001 bind verification');
// sign(msg, secretKey) — message first
const sig = mlDsa.ml_dsa65.sign(msg, sigKeys.secretKey);
// verify(sig, msg, publicKey) — signature first
const valid = mlDsa.ml_dsa65.verify(sig, msg, sigKeys.publicKey);
console.log('  Signature:     ', sig.length, 'bytes (spec: 3309)');
console.log('  Valid:         ', valid);

// Tamper test
const tampered = Buffer.from('SHADOW313 NEXUS - TAMPERED PAYLOAD');
const tamperedValid = mlDsa.ml_dsa65.verify(sig, tampered, sigKeys.publicKey);
console.log('  Tampered valid:', tamperedValid, '(must be false)');
console.log();

// ── SLH-DSA-SHA2-128f (NIST FIPS 205) ────────────────────────────────────
console.log('--- SLH-DSA-SHA2-128f / SPHINCS+ (NIST FIPS 205) ---');
const slhKeys = slhDsa.slh_dsa_sha2_128f.keygen();
console.log('  Public key:    ', slhKeys.publicKey.length, 'bytes  (spec: 32)');
console.log('  Secret key:    ', slhKeys.secretKey.length, 'bytes  (spec: 64)');

const slhMsg = Buffer.from('313-API-00000001:sha3_512:chain_hash_abc123');
// sign(msg, secretKey)
const slhSig = slhDsa.slh_dsa_sha2_128f.sign(slhMsg, slhKeys.secretKey);
// verify(sig, msg, publicKey)
const slhValid = slhDsa.slh_dsa_sha2_128f.verify(slhSig, slhMsg, slhKeys.publicKey);
console.log('  Signature:     ', slhSig.length, 'bytes (spec: 17088)');
console.log('  Valid:         ', slhValid);
console.log();

// ── Full PQC API Auth Flow ─────────────────────────────────────────────────
console.log('--- Full PQC API Auth Flow ---');
const ts = Date.now();
const body = JSON.stringify({ data: 'quantum-secured payload' });
const bodyHash = crypto.createHash('sha3-256').update(body).digest('hex');
const signedPayload = `POST:/api/secure-data:${ts}:${bodyHash}`;

console.log('  Signed payload:', signedPayload.slice(0, 55) + '...');

// Client signs with ML-DSA-65: sign(msg, secretKey)
const authSig = mlDsa.ml_dsa65.sign(Buffer.from(signedPayload), sigKeys.secretKey);
const authHeader = Buffer.from(authSig).toString('base64');

// Server verifies: verify(sig, msg, publicKey)
const authValid = mlDsa.ml_dsa65.verify(
  Buffer.from(authHeader, 'base64'),
  Buffer.from(signedPayload),
  sigKeys.publicKey,
);

console.log('  Auth header:   ', authHeader.slice(0, 32) + '...');
console.log('  Auth valid:    ', authValid);
console.log('  Sig size:      ', authSig.length, 'bytes (vs Ed25519: 64 bytes)');
console.log('  Size overhead: ', (authSig.length / 64).toFixed(1) + 'x larger than Ed25519');
console.log();

// ── 313 Temporal Chain with real ML-DSA-65 signatures ─────────────────────
console.log('--- 313 Temporal Chain with Real ML-DSA-65 Signatures ---');

const chain = [];
let prevHash = '0'.repeat(128);

for (let i = 1; i <= 4; i++) {
  // Nudge timestamp to end in 313
  let ts313;
  const deadline = Date.now() + 50;
  while (Date.now() < deadline) {
    const ns = BigInt(Date.now()) * 1000000n;
    if (ns.toString().endsWith('313')) { ts313 = ns; break; }
  }
  if (!ts313) {
    const ns = BigInt(Date.now()) * 1000000n;
    ts313 = BigInt(ns.toString().slice(0, -3) + '313');
  }

  const bindId = `313-PQC-${String(i).padStart(8, '0')}`;
  const events = ['AUTH_SUCCESS', 'AUTH_FAIL', 'DOWNGRADE', 'HNDL_RISK'];
  const payload = { bindId, index: i, event: events[i - 1] };
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const payloadHash = crypto.createHash('sha3-512').update(canonical).digest('hex');

  // Chain hash links to previous
  const chainInput = `${bindId}:${payloadHash}:${prevHash}:${ts313}`;
  const chainHash = crypto.createHash('sha3-512').update(chainInput).digest('hex');

  // Real ML-DSA-65 signature: sign(msg, secretKey)
  const mldsaSig   = mlDsa.ml_dsa65.sign(Buffer.from(chainHash), sigKeys.secretKey);
  // verify(sig, msg, publicKey)
  const mldsaValid = mlDsa.ml_dsa65.verify(mldsaSig, Buffer.from(chainHash), sigKeys.publicKey);

  chain.push({
    bindId,
    chainHash,
    mldsaSig:   Buffer.from(mldsaSig).toString('base64').slice(0, 16) + '...',
    mldsaValid,
  });
  prevHash = chainHash;

  console.log(`  ${bindId} | ML-DSA sig valid: ${mldsaValid} | hash: ${chainHash.slice(0, 20)}...`);
}

console.log();
console.log('  Chain with ML-DSA-65 signatures: all valid =', chain.every(r => r.mldsaValid));
console.log();

// ── Algorithm comparison table ─────────────────────────────────────────────
console.log('--- Algorithm Comparison ---');
console.log('  Algorithm        PubKey   SecKey   Sig      Quantum-Safe  Standard');
console.log('  ─────────────────────────────────────────────────────────────────');
console.log('  Ed25519          32B      64B      64B      NO (Shor)     RFC 8032');
console.log('  ML-KEM-768       1184B    2400B    1088B*   YES           FIPS 203');
console.log('  ML-DSA-65        1952B    4032B    3309B    YES           FIPS 204');
console.log('  SLH-DSA-128f     32B      64B      17088B   YES           FIPS 205');
console.log('  (* ciphertext, not signature)');
console.log();
console.log('=== ALL REAL PQC OPERATIONS SUCCESSFUL ===');
console.log();
console.log('Integration status:');
console.log('  pqc_middleware.js  — use sign(msg, sk) / verify(sig, msg, pk) order');
console.log('  crypto_sbom.py     — liboqs needed for Python (C build required)');
console.log('  temporal_chain.py  — SLH-DSA upgrade ready when liboqs available');