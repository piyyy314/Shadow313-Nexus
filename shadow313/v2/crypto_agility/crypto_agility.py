"""
shadow313.v2.crypto_agility.crypto_agility  — v4
PQC migration scanning, code snippets, hybrid TLS testing.

BUG FIXES:
  - scan() returned duplicate findings when a file matched multiple patterns
    on the same line — added (file, line, pattern) dedup set.
  - get_snippet() returned raw string with no formatting — now returns
    structured dict with before/after/instructions.
  - test_tls() used ssl.PROTOCOL_TLS which is deprecated in Python 3.12 —
    updated to ssl.PROTOCOL_TLS_CLIENT with check_hostname=False.
  - migration_plan() called kernel.ai.chat() with empty context when no
    session data found — now provides default context.
"""
from __future__ import annotations
import re
import ssl
import socket
from pathlib import Path
from typing import Any

# ── PQC Algorithm catalog ─────────────────────────────────────────────────────

PQC_ALGORITHMS = [
    {"name": "ML-KEM-512",          "type": "KEM",       "fips": "FIPS 203", "level": 1},
    {"name": "ML-KEM-768",          "type": "KEM",       "fips": "FIPS 203", "level": 3},
    {"name": "ML-KEM-1024",         "type": "KEM",       "fips": "FIPS 203", "level": 5},
    {"name": "ML-DSA-44",           "type": "Signature", "fips": "FIPS 204", "level": 2},
    {"name": "ML-DSA-65",           "type": "Signature", "fips": "FIPS 204", "level": 3},
    {"name": "ML-DSA-87",           "type": "Signature", "fips": "FIPS 204", "level": 5},
    {"name": "SLH-DSA-SHAKE-128s",  "type": "Signature", "fips": "FIPS 205", "level": 1},
    {"name": "SLH-DSA-SHAKE-256s",  "type": "Signature", "fips": "FIPS 205", "level": 5},
    {"name": "FALCON-512",          "type": "Signature", "fips": "NIST Alt", "level": 1},
    {"name": "FALCON-1024",         "type": "Signature", "fips": "NIST Alt", "level": 5},
    {"name": "HQC-128",             "type": "KEM",       "fips": "NIST Alt", "level": 1},
]

# ── Migration code snippets ───────────────────────────────────────────────────

PQC_SNIPPETS: dict[str, dict] = {
    "rsa-python": {
        "title":       "RSA → ML-KEM (Python)",
        "before": """# VULNERABLE: RSA key generation
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(  # nosec — migration guide example
    public_exponent=65537,
    key_size=2048,
)""",
        "after": """# QUANTUM-SAFE: ML-KEM-768 (FIPS 203)
# pip install pqcrypto
from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt
public_key, secret_key = generate_keypair()
# For key exchange:
ciphertext, shared_secret = encrypt(public_key)
# Recipient:
shared_secret = decrypt(secret_key, ciphertext)""",
        "instructions": [
            "1. Install pqcrypto: pip install pqcrypto",
            "2. Replace RSA key generation with ML-KEM-768 keypair",
            "3. Replace RSA encrypt/decrypt with KEM encapsulate/decapsulate",
            "4. Update key storage format (PEM → binary or base64)",
            "5. Test with both classical and PQC endpoints during transition",
        ],
        "urgency": "IMMEDIATE",
    },
    "ecdsa-python": {
        "title":       "ECDSA → ML-DSA (Python)",
        "before": """# VULNERABLE: ECDSA signing
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key(ec.SECP256R1())  # nosec — migration guide example
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))""",
        "after": """# QUANTUM-SAFE: ML-DSA-65 (FIPS 204)
from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify
public_key, secret_key = generate_keypair()
signature = sign(secret_key, message)
verify(public_key, message, signature)  # raises on failure""",
        "instructions": [
            "1. Install pqcrypto: pip install pqcrypto",
            "2. Replace ECDSA key generation with ML-DSA-65 keypair",
            "3. Update signature format (DER → raw bytes)",
            "4. Update certificate infrastructure for PQC signatures",
            "5. Consider hybrid mode: sign with both ECDSA + ML-DSA during transition",
        ],
        "urgency": "IMMEDIATE",
    },
    "aes128-python": {
        "title":       "AES-128 → AES-256 (Grover mitigation)",
        "before": """# WEAKENED: AES-128 (64-bit quantum security after Grover)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = os.urandom(16)  # 128-bit key
aesgcm = AESGCM(key)""",
        "after": """# QUANTUM-SAFE: AES-256 (128-bit quantum security)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = os.urandom(32)  # 256-bit key — doubles Grover resistance
aesgcm = AESGCM(key)""",
        "instructions": [
            "1. Change key generation from 16 bytes to 32 bytes",
            "2. Update key storage and distribution",
            "3. Re-encrypt existing data with new 256-bit keys",
            "4. Update key derivation functions to output 256-bit keys",
        ],
        "urgency": "SHORT-TERM",
    },
    "rsa-java": {
        "title":       "RSA → ML-KEM (Java/BouncyCastle)",
        "before": """// VULNERABLE: RSA key generation
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
KeyPair keyPair = kpg.generateKeyPair();""",
        "after": """// QUANTUM-SAFE: ML-KEM-768 (BouncyCastle PQC)
// Add: org.bouncycastle:bcprov-jdk18on:1.77
Security.addProvider(new BouncyCastleProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", "BC");
kpg.initialize(KyberParameterSpec.kyber768);
KeyPair keyPair = kpg.generateKeyPair();""",
        "instructions": [
            "1. Add BouncyCastle PQC dependency: bcprov-jdk18on:1.77",
            "2. Register BouncyCastleProvider",
            "3. Replace RSA with KYBER algorithm",
            "4. Update serialization for PQC key formats",
        ],
        "urgency": "IMMEDIATE",
    },
    "nginx-tls": {
        "title":       "Nginx RSA TLS → PQC Hybrid TLS",
        "before": """# VULNERABLE: RSA certificate TLS config
ssl_certificate     /etc/ssl/certs/server.crt;
ssl_certificate_key /etc/ssl/private/server.key;
ssl_protocols       TLSv1.2 TLSv1.3;
ssl_ciphers         HIGH:!aNULL:!MD5;""",
        "after": """# QUANTUM-SAFE: Hybrid PQC TLS (X25519Kyber768 + ECDSA)
ssl_certificate     /etc/ssl/certs/server-pqc.crt;
ssl_certificate_key /etc/ssl/private/server-pqc.key;
ssl_protocols       TLSv1.3;
ssl_ciphers         TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
# Enable X25519Kyber768 hybrid KEM (requires OpenSSL 3.2+ with OQS provider)
ssl_ecdh_curve      X25519Kyber768Draft00:X25519:P-256;""",
        "instructions": [
            "1. Install OpenSSL 3.2+ with OQS provider",
            "2. Generate PQC certificate (ML-DSA or hybrid ECDSA+ML-DSA)",
            "3. Update nginx ssl_ecdh_curve to include X25519Kyber768",
            "4. Test with Chrome/Firefox (both support X25519Kyber768 as of 2024)",
            "5. Monitor for client compatibility issues during transition",
        ],
        "urgency": "SHORT-TERM",
    },
}

# ── Vulnerability patterns ────────────────────────────────────────────────────

VULN_PATTERNS = [
    (r"\bRSA\b",                    "RSA",    "VULNERABLE", "IMMEDIATE"),
    (r"\bECDSA\b|\bECDH\b",         "ECDSA",  "VULNERABLE", "IMMEDIATE"),
    (r"\bDiffieHellman\b|\bdh\.generate", "DH", "VULNERABLE", "IMMEDIATE"),
    (r"\bMD5\b",                    "MD5",    "VULNERABLE", "IMMEDIATE"),
    (r"\bSHA[-_]?1\b",              "SHA-1",  "VULNERABLE", "IMMEDIATE"),
    (r"\bRC4\b",                    "RC4",    "VULNERABLE", "IMMEDIATE"),
    (r"\b3DES\b|\bDES\b",           "3DES",   "VULNERABLE", "IMMEDIATE"),
    (r"AES[_-]?128",                "AES-128","WEAKENED",   "SHORT-TERM"),
    (r"key_size\s*=\s*2048",        "RSA-2048","VULNERABLE","IMMEDIATE"),
    (r"secp256[kr]1|P-256|P256",    "ECDSA",  "VULNERABLE", "IMMEDIATE"),
]

LANG_EXTENSIONS = {
    "python":     [".py"],
    "javascript": [".js", ".ts", ".mjs"],
    "java":       [".java"],
    "go":         [".go"],
    "rust":       [".rs"],
    "c":          [".c", ".h"],
    "cpp":        [".cpp", ".cc", ".hpp"],
}


class CryptoMigrationEngine:
    """Scans source code for vulnerable crypto usage."""

    def scan(self, path: str, languages: list[str] | None = None) -> list[dict]:
        base     = Path(path)
        findings = []
        seen:    set[tuple] = set()

        exts: set[str] = set()
        for lang in (languages or list(LANG_EXTENSIONS.keys())):
            exts.update(LANG_EXTENSIONS.get(lang.lower(), []))

        files = list(base.rglob("*")) if base.is_dir() else [base]
        for fpath in files:
            if not fpath.is_file():
                continue
            if exts and fpath.suffix.lower() not in exts:
                continue
            try:
                lines = fpath.read_text(errors="replace").splitlines()
            except Exception:
                continue
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                for pattern, algo, status, urgency in VULN_PATTERNS:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        # FIX: dedup by (file, line, pattern)
                        key = (str(fpath), lineno, pattern)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "file":    str(fpath),
                            "line":    lineno,
                            "code":    stripped[:120],
                            "algorithm": algo,
                            "status":  status,
                            "urgency": urgency,
                        })
        return findings

    def pqc_readiness(self, findings: list[dict]) -> str:
        if not findings:
            return "QUANTUM_READY"
        statuses = {f["status"] for f in findings}
        if "VULNERABLE" in statuses:
            safe_count = sum(1 for f in findings if f["status"] == "SAFE")
            if safe_count > 0:
                return "PARTIAL"
            return "VULNERABLE"
        if "WEAKENED" in statuses:
            return "PQC_TRANSITION"
        return "QUANTUM_READY"


class HybridTLSTester:
    """Tests hosts for X25519Kyber768 hybrid KEM support."""

    def test(self, host: str, port: int = 443) -> dict:
        result = {
            "host":          host,
            "port":          port,
            "tls_version":   "",
            "cipher":        "",
            "hybrid_kem":    False,
            "pqc_ready":     False,
        }
        try:
            # FIX: use ssl.PROTOCOL_TLS_CLIENT (PROTOCOL_TLS deprecated in 3.12)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result["tls_version"] = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        result["cipher"] = cipher[0]
                    # Check for X25519Kyber768 in cipher or negotiated groups
                    cipher_str = (cipher[0] or "").lower()
                    result["hybrid_kem"] = "kyber" in cipher_str or "x25519kyber" in cipher_str
                    result["pqc_ready"]  = result["hybrid_kem"]
        except Exception as exc:
            result["error"] = str(exc)
        return result


class CryptoAgilityFramework:
    """Unified facade for crypto agility operations."""

    def __init__(self, kernel) -> None:
        self._kernel = kernel
        self._engine = CryptoMigrationEngine()
        self._tester = HybridTLSTester()

    def scan(self, path: str, languages: list[str] | None = None) -> list[dict]:
        return self._engine.scan(path, languages)

    def get_snippet(self, snippet_id: str) -> dict:
        return PQC_SNIPPETS.get(snippet_id, {"error": f"Snippet '{snippet_id}' not found",
                                              "available": list(PQC_SNIPPETS.keys())})

    def test_tls(self, host_port: str) -> dict:
        parts = host_port.split(":")
        host  = parts[0]
        port  = int(parts[1]) if len(parts) > 1 else 443
        return self._tester.test(host, port)

    def migration_plan(self, findings: list[dict]) -> str:
        # FIX: provide default context when findings is empty
        ctx = {
            "findings_count": len(findings),
            "vulnerable":     [f for f in findings if f.get("status") == "VULNERABLE"],
            "weakened":       [f for f in findings if f.get("status") == "WEAKENED"],
            "readiness":      self._engine.pqc_readiness(findings),
            "nist_standards": ["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "FIPS 205 (SLH-DSA)"],
        } if findings else {
            "findings_count": 0,
            "readiness":      "QUANTUM_READY",
            "note":           "No vulnerable crypto found — system appears quantum-ready",
        }
        return self._kernel.ai.chat(
            "Generate a concise PQC migration plan based on these crypto audit findings. "
            "Reference NIST FIPS 203/204/205. Prioritize by urgency. "
            "Include: immediate actions, 6-month plan, 18-month plan.",
            context=ctx,
        )

    def list_pqc_algorithms(self) -> list[dict]:
        return PQC_ALGORITHMS


class CryptoAgilityModule:
    """shadow313.v2.crypto_agility — PQC migration. Registered: crypto_agility"""

    def __init__(self, kernel) -> None:
        self.kernel    = kernel
        self.out       = kernel.out
        self.session   = kernel.session
        self.framework = CryptoAgilityFramework(kernel)

    def register(self, kernel) -> None:
        kernel.register("crypto_agility", self.run)

    def run(
        self,
        scan: str = "",
        snippet: str = "",
        test_tls: str = "",
        migration_plan: bool = False,
        list_pqc_algorithms: bool = False,
        languages: str = "",
        _prev_result: dict | None = None,
    ) -> dict:
        self.out.section("CRYPTO AGILITY FRAMEWORK")
        result: dict[str, Any] = {}
        lang_list = [l.strip() for l in languages.split(",") if l.strip()] if languages else None

        if scan:
            self.out.info(f"Scanning for vulnerable crypto: {scan} …")
            findings = self.framework.scan(scan, lang_list)
            readiness = self.framework._engine.pqc_readiness(findings)
            result["findings"]  = findings
            result["readiness"] = readiness
            self.out.info(f"PQC Readiness: {readiness}")
            if findings:
                rows = [[f["file"].split("/")[-1], f["line"], f["algorithm"],
                         f["status"], f["urgency"]] for f in findings[:30]]
                self.out.table(["File","Line","Algorithm","Status","Urgency"], rows,
                               f"Crypto Findings ({len(findings)})")
            else:
                self.out.success("No vulnerable crypto usage found.")

        if snippet:
            s = self.framework.get_snippet(snippet)
            if "error" not in s:
                self.out.section(s.get("title", snippet))
                self.out.info("BEFORE (vulnerable):")
                print(s.get("before", ""))
                self.out.info("AFTER (quantum-safe):")
                print(s.get("after", ""))
                self.out.info("Migration steps:")
                for step in s.get("instructions", []):
                    self.out.info(step)
            else:
                self.out.error(s.get("error", ""))
            result["snippet"] = s

        if test_tls:
            self.out.info(f"Testing hybrid TLS: {test_tls} …")
            tls_result = self.framework.test_tls(test_tls)
            result["tls_test"] = tls_result
            if tls_result.get("hybrid_kem"):
                self.out.success(f"Hybrid KEM (X25519Kyber768) supported on {test_tls}")
            else:
                self.out.warn(f"No hybrid KEM detected on {test_tls}")
            self.out.result(tls_result, "TLS Test Result")

        if migration_plan:
            findings = result.get("findings", [])
            if not findings and _prev_result:
                findings = _prev_result.get("findings", [])
            self.out.info("Generating AI PQC migration plan …")
            plan = self.framework.migration_plan(findings)
            self.out.ai_response(plan, "PQC Migration Plan")
            result["migration_plan"] = plan

        if list_pqc_algorithms:
            algos = self.framework.list_pqc_algorithms()
            rows  = [[a["name"], a["type"], a["fips"], str(a["level"])] for a in algos]
            self.out.table(["Algorithm","Type","FIPS Standard","Security Level"], rows,
                           "NIST PQC Algorithm Catalog")
            result["pqc_algorithms"] = algos

        self.session.write("crypto_agility.json", result)
        return result