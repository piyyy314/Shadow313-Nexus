"""shadow313.modules.quantum.quantum_data — NIST PQC reference data and vulnerability tables."""
from __future__ import annotations

NIST_PQC_STANDARDS = {
    "CRYSTALS-Kyber": {
        "fips": "FIPS 203", "purpose": "Key Encapsulation (KEM) — replaces RSA/DH/ECDH",
        "variants": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "strength": "128/192/256-bit quantum security",
    },
    "CRYSTALS-Dilithium": {
        "fips": "FIPS 204", "purpose": "Digital Signatures — replaces RSA/ECDSA",
        "variants": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        "strength": "128/192/256-bit quantum security",
    },
    "SPHINCS+": {
        "fips": "FIPS 205", "purpose": "Hash-based Digital Signatures — stateless, conservative",
        "variants": ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s"],
        "strength": "128/192/256-bit quantum security",
    },
    "FALCON": {
        "fips": "NIST Round 3 Alternate", "purpose": "Compact Digital Signatures (lattice-based)",
        "variants": ["FALCON-512", "FALCON-1024"],
        "strength": "128/256-bit quantum security",
    },
}

QUANTUM_VULN_TABLE: dict[str, dict] = {
    "RSA":           {"vuln": "VULNERABLE", "reason": "Shor's algorithm breaks RSA factoring", "replace": "CRYSTALS-Kyber (FIPS 203)"},
    "RSA-2048":      {"vuln": "VULNERABLE", "reason": "2048-bit RSA broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "RSA-4096":      {"vuln": "VULNERABLE", "reason": "4096-bit RSA broken by Shor's algorithm", "replace": "ML-KEM-1024"},
    "DH":            {"vuln": "VULNERABLE", "reason": "Diffie-Hellman broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "DHE":           {"vuln": "VULNERABLE", "reason": "Ephemeral DH broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "ECDH":          {"vuln": "VULNERABLE", "reason": "Elliptic Curve DH broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "ECDHE":         {"vuln": "VULNERABLE", "reason": "Ephemeral ECDH broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "ECDSA":         {"vuln": "VULNERABLE", "reason": "EC signatures broken by Shor's algorithm", "replace": "ML-DSA-65 (FIPS 204)"},
    "DSA":           {"vuln": "VULNERABLE", "reason": "DSA broken by Shor's algorithm", "replace": "ML-DSA-44 (FIPS 204)"},
    "ED25519":       {"vuln": "VULNERABLE", "reason": "Edwards curve broken by Shor's algorithm", "replace": "ML-DSA-44 (FIPS 204)"},
    "ED448":         {"vuln": "VULNERABLE", "reason": "Edwards curve broken by Shor's algorithm", "replace": "ML-DSA-65 (FIPS 204)"},
    "AES-128":       {"vuln": "WEAKENED",   "reason": "Grover's algorithm halves effective key strength to 64-bit", "replace": "AES-256"},
    "AES-192":       {"vuln": "WEAKENED",   "reason": "Grover reduces to ~96-bit effective security", "replace": "AES-256"},
    "AES-256":       {"vuln": "SAFE",       "reason": "256-bit AES remains secure against Grover's attack", "replace": ""},
    "3DES":          {"vuln": "VULNERABLE", "reason": "3DES is deprecated and weak", "replace": "AES-256-GCM"},
    "DES":           {"vuln": "VULNERABLE", "reason": "DES is cryptographically broken", "replace": "AES-256-GCM"},
    "RC4":           {"vuln": "VULNERABLE", "reason": "RC4 is cryptographically broken", "replace": "AES-256-GCM"},
    "MD5":           {"vuln": "VULNERABLE", "reason": "MD5 is classically broken (collision attacks)", "replace": "SHA-256 or SHA-3"},
    "SHA-1":         {"vuln": "VULNERABLE", "reason": "SHA-1 is classically broken (SHAttered)", "replace": "SHA-256"},
    "SHA-256":       {"vuln": "WEAKENED",   "reason": "Grover's halves collision resistance to 128-bit", "replace": "SHA-384 or SHA-3-256"},
    "SHA-384":       {"vuln": "SAFE",       "reason": "SHA-384 provides 192-bit quantum resistance", "replace": ""},
    "SHA-512":       {"vuln": "SAFE",       "reason": "SHA-512 provides 256-bit quantum resistance", "replace": ""},
    "SHA3-256":      {"vuln": "SAFE",       "reason": "SHA3-256 quantum-resistant at 128-bit level", "replace": ""},
    "SHA3-512":      {"vuln": "SAFE",       "reason": "SHA3-512 quantum-resistant at 256-bit level", "replace": ""},
    "CRYSTALS-KYBER":    {"vuln": "SAFE", "reason": "NIST FIPS 203 quantum-resistant KEM", "replace": ""},
    "CRYSTALS-DILITHIUM":{"vuln": "SAFE", "reason": "NIST FIPS 204 quantum-resistant signatures", "replace": ""},
    "SPHINCS+":          {"vuln": "SAFE", "reason": "NIST FIPS 205 hash-based quantum-resistant signatures", "replace": ""},
    "FALCON":            {"vuln": "SAFE", "reason": "NIST alternate quantum-resistant signatures", "replace": ""},

    # ── FIPS 205 — SLH-DSA (standardised name for SPHINCS+) ──────────────────
    "SLH-DSA":              {"vuln": "SAFE", "assumption": "CONSERVATIVE", "archival": "EXCELLENT",
                             "reason": "NIST FIPS 205 — hash-based, most conservative PQC assumption (SHA-3/SHAKE only)", "replace": ""},
    "SLH-DSA-SHAKE-128s":   {"vuln": "SAFE", "assumption": "CONSERVATIVE", "archival": "EXCELLENT",
                             "reason": "FIPS 205 Level 1 — 128-bit quantum security, 32-byte public key", "replace": ""},
    "SLH-DSA-SHAKE-128f":   {"vuln": "SAFE", "assumption": "CONSERVATIVE", "archival": "EXCELLENT",
                             "reason": "FIPS 205 Level 1 fast variant — larger signatures, faster signing", "replace": ""},
    "SLH-DSA-SHAKE-192s":   {"vuln": "SAFE", "assumption": "CONSERVATIVE", "archival": "EXCELLENT",
                             "reason": "FIPS 205 Level 3 — 192-bit quantum security", "replace": ""},
    "SLH-DSA-SHAKE-256s":   {"vuln": "SAFE", "assumption": "CONSERVATIVE", "archival": "EXCELLENT",
                             "reason": "FIPS 205 Level 5 — 256-bit quantum security", "replace": ""},
    "SLH-DSA-SHA2-128s":    {"vuln": "SAFE", "assumption": "CONSERVATIVE", "archival": "EXCELLENT",
                             "reason": "FIPS 205 Level 1 SHA-2 variant — FIPS-compliant environments", "replace": ""},
    "SLH-DSA-SHA2-256s":    {"vuln": "SAFE", "assumption": "CONSERVATIVE", "archival": "EXCELLENT",
                             "reason": "FIPS 205 Level 5 SHA-2 variant — maximum security", "replace": ""},

    # ── FIPS 204 — ML-DSA (standardised name for CRYSTALS-Dilithium) ─────────
    "ML-DSA":               {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "NIST FIPS 204 — lattice-based digital signatures (ML-DSA)", "replace": ""},
    "ML-DSA-44":            {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "FIPS 204 Level 2 — 128-bit quantum security", "replace": ""},
    "ML-DSA-65":            {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "FIPS 204 Level 3 — 192-bit quantum security", "replace": ""},
    "ML-DSA-87":            {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "FIPS 204 Level 5 — 256-bit quantum security", "replace": ""},

    # ── FIPS 203 — ML-KEM (standardised name for CRYSTALS-Kyber) ─────────────
    "ML-KEM":               {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "NIST FIPS 203 — lattice-based key encapsulation (ML-KEM)", "replace": ""},
    "ML-KEM-512":           {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "FIPS 203 Level 1 — 128-bit quantum security", "replace": ""},
    "ML-KEM-768":           {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "FIPS 203 Level 3 — 192-bit quantum security", "replace": ""},
    "ML-KEM-1024":          {"vuln": "SAFE", "assumption": "STANDARD", "archival": "GOOD",
                             "reason": "FIPS 203 Level 5 — 256-bit quantum security", "replace": ""},
}

TLS_CIPHER_PATTERNS: dict[str, str] = {
    r"ECDHE[-_]RSA":   "ECDHE+RSA",
    r"ECDHE[-_]ECDSA": "ECDHE+ECDSA",
    r"DHE[-_]RSA":     "DHE+RSA",
    r"RSA[-_]WITH":    "RSA key exchange",
    r"AES[_-]128":     "AES-128",
    r"AES[_-]256":     "AES-256",
    r"3DES":           "3DES",
    r"RC4":            "RC4",
    r"MD5":            "MD5",
    r"SHA1\b|SHA[-_]1\b": "SHA-1",
    r"TLS_AES":        "TLS 1.3 (modern)",
    r"CHACHA20":       "ChaCha20 (safe)",
    r"X25519":         "X25519 (ECDH — quantum vulnerable)",
    r"P[-_]256":       "P-256 ECDH (quantum vulnerable)",
}

CODE_CRYPTO_PATTERNS: dict[str, dict] = {
    "Python": {
        "RSA":   ["from Crypto.PublicKey import RSA", "rsa.generate", "RSA.generate",
                  "from cryptography.hazmat.primitives.asymmetric import rsa"],
        "ECDSA": ["from cryptography.hazmat.primitives.asymmetric import ec",
                  "from Crypto.PublicKey import ECC", "SECP256K1", "SECP384R1"],
        "DH":    ["from cryptography.hazmat.primitives.asymmetric import dh",
                  "DiffieHellman", "dh.generate_parameters"],
        "MD5":   ["hashlib.md5", "md5(", "from hashlib import md5"],
        "SHA-1": ["hashlib.sha1", "sha1(", "from hashlib import sha1"],
    },
    "JavaScript": {
        "RSA":   ["crypto.generateKeyPair('rsa'", "new NodeRSA", "RSA.generate"],
        "ECDSA": ["crypto.createECDH", "new EC('p256'", "elliptic"],
        "MD5":   ["require('md5'", "createHash('md5'"],
        "SHA-1": ["createHash('sha1'", "require('sha1'"],
    },
    "Java": {
        "RSA":   ['KeyPairGenerator.getInstance("RSA"', "new RSAKeyGenParameterSpec"],
        "DH":    ['KeyPairGenerator.getInstance("DH"', "DHParameterSpec"],
        "ECDSA": ['KeyPairGenerator.getInstance("EC"', "ECGenParameterSpec"],
        "MD5":   ['MessageDigest.getInstance("MD5"'],
        "SHA-1": ['MessageDigest.getInstance("SHA-1"'],
    },
    "Go": {
        "RSA":   ["rsa.GenerateKey", "x509.ParsePKCS1"],
        "ECDSA": ["ecdsa.GenerateKey", "elliptic.P256"],
        "MD5":   ["crypto/md5", "md5.New()"],
        "SHA-1": ["crypto/sha1", "sha1.New()"],
    },
}

LANG_EXTENSIONS: dict[str, list[str]] = {
    "Python":     [".py"],
    "JavaScript": [".js", ".ts", ".mjs"],
    "Java":       [".java"],
    "Go":         [".go"],
    "C":          [".c", ".h"],
    "CPP":        [".cpp", ".cc", ".cxx", ".hpp"],
    "Rust":       [".rs"],
}


def classify_algorithm(name: str) -> dict:
    """
    Look up an algorithm in the vulnerability table (case-insensitive).
    Priority order:
      1. Exact normalised match (e.g. 'DSA' -> 'DSA', not 'ML-DSA')
      2. Longest substring match (e.g. 'SLH-DSA-SHAKE-128s' beats 'DSA')
    This prevents short keys like 'DSA' from matching 'SLH-DSA' queries,
    and prevents 'ML-DSA' from matching a bare 'DSA' query.
    """
    name_upper = name.upper().replace("-", "").replace("_", "")

    # Pass 1: exact normalised match
    for key, info in QUANTUM_VULN_TABLE.items():
        norm = key.upper().replace("-", "").replace("_", "")
        if norm == name_upper:
            return {**info, "algorithm": key}

    # Pass 2: longest substring match (query contains key OR key contains query)
    best_match: dict | None = None
    best_key:   str         = ""
    best_len:   int         = 0

    for key, info in QUANTUM_VULN_TABLE.items():
        norm = key.upper().replace("-", "").replace("_", "")
        if norm in name_upper or name_upper in norm:
            if len(norm) > best_len:
                best_len   = len(norm)
                best_key   = key
                best_match = info

    if best_match is not None:
        return {**best_match, "algorithm": best_key}
    return {"algorithm": name, "vuln": "UNKNOWN",
            "reason": "Not in quantum vulnerability database", "replace": ""}