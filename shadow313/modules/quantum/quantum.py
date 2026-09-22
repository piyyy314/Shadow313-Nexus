"""
shadow313.modules.quantum
Post-quantum cryptography audit — detect quantum-vulnerable algorithms in TLS,
certificates, source code, and configuration files. Generate NIST PQC migration roadmaps.
NOTE: This module assesses CLASSICAL systems for quantum readiness.
      It does NOT perform quantum computing.
"""
from __future__ import annotations
import json
import re
import socket
import ssl
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── NIST PQC reference data (FIPS 203/204/205) ───────────────────────────────

NIST_PQC_STANDARDS = {
    "CRYSTALS-Kyber":  {
        "fips":    "FIPS 203",
        "purpose": "Key Encapsulation (KEM) — replaces RSA/DH/ECDH",
        "variants":["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "strength": "128/192/256-bit quantum security",
    },
    "CRYSTALS-Dilithium": {
        "fips":    "FIPS 204",
        "purpose": "Digital Signatures — replaces RSA/ECDSA",
        "variants":["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        "strength": "128/192/256-bit quantum security",
    },
    "SPHINCS+": {
        "fips":    "FIPS 205",
        "purpose": "Hash-based Digital Signatures — stateless, conservative",
        "variants":["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s"],
        "strength": "128/192/256-bit quantum security",
    },
    "FALCON": {
        "fips":    "NIST Round 3 Alternate",
        "purpose": "Compact Digital Signatures (lattice-based)",
        "variants":["FALCON-512", "FALCON-1024"],
        "strength": "128/256-bit quantum security",
    },
}

# Quantum vulnerability classification
QUANTUM_VULN_TABLE: dict[str, dict] = {
    # Key exchange / encryption
    "RSA":           {"vuln": "VULNERABLE", "reason": "Shor's algorithm breaks RSA factoring", "replace": "CRYSTALS-Kyber (FIPS 203)"},
    "RSA-2048":      {"vuln": "VULNERABLE", "reason": "2048-bit RSA — broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "RSA-4096":      {"vuln": "VULNERABLE", "reason": "4096-bit RSA — broken by Shor's algorithm (more time)", "replace": "ML-KEM-1024"},
    "DH":            {"vuln": "VULNERABLE", "reason": "Diffie-Hellman — broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "DHE":           {"vuln": "VULNERABLE", "reason": "Ephemeral DH — broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "ECDH":          {"vuln": "VULNERABLE", "reason": "Elliptic Curve DH — broken by Shor's algorithm", "replace": "ML-KEM-768"},
    "ECDHE":         {"vuln": "VULNERABLE", "reason": "Ephemeral ECDH — broken by Shor's algorithm", "replace": "ML-KEM-768"},
    # Signatures
    "ECDSA":         {"vuln": "VULNERABLE", "reason": "EC signatures — broken by Shor's algorithm", "replace": "ML-DSA-65 (FIPS 204)"},
    "DSA":           {"vuln": "VULNERABLE", "reason": "DSA — broken by Shor's algorithm", "replace": "ML-DSA-44 (FIPS 204)"},
    "ED25519":       {"vuln": "VULNERABLE", "reason": "Edwards curve — broken by Shor's algorithm", "replace": "ML-DSA-44 (FIPS 204)"},
    "ED448":         {"vuln": "VULNERABLE", "reason": "Edwards curve — broken by Shor's algorithm", "replace": "ML-DSA-65 (FIPS 204)"},
    # Symmetric (weakened, not broken)
    "AES-128":       {"vuln": "WEAKENED",   "reason": "Grover's algorithm halves effective key strength → 64-bit", "replace": "AES-256"},
    "AES-192":       {"vuln": "WEAKENED",   "reason": "Grover reduces to ~96-bit effective security", "replace": "AES-256"},
    "AES-256":       {"vuln": "SAFE",       "reason": "256-bit AES remains secure against Grover's attack (128-bit effective)", "replace": ""},
    "3DES":          {"vuln": "VULNERABLE", "reason": "3DES is deprecated and weak regardless of quantum", "replace": "AES-256-GCM"},
    "DES":           {"vuln": "VULNERABLE", "reason": "DES is cryptographically broken (classical + quantum)", "replace": "AES-256-GCM"},
    "RC4":           {"vuln": "VULNERABLE", "reason": "RC4 is cryptographically broken", "replace": "AES-256-GCM"},
    # Hash functions
    "MD5":           {"vuln": "VULNERABLE", "reason": "MD5 is classically broken (collision attacks)", "replace": "SHA-256 or SHA-3"},
    "SHA-1":         {"vuln": "VULNERABLE", "reason": "SHA-1 is classically broken (SHAttered)", "replace": "SHA-256"},
    "SHA-256":       {"vuln": "WEAKENED",   "reason": "Grover's halves collision resistance → 128-bit", "replace": "SHA-384 or SHA-3-256"},
    "SHA-384":       {"vuln": "SAFE",       "reason": "SHA-384 provides 192-bit quantum resistance", "replace": ""},
    "SHA-512":       {"vuln": "SAFE",       "reason": "SHA-512 provides 256-bit quantum resistance", "replace": ""},
    "SHA3-256":      {"vuln": "SAFE",       "reason": "SHA3-256 — quantum-resistant at 128-bit level", "replace": ""},
    "SHA3-512":      {"vuln": "SAFE",       "reason": "SHA3-512 — quantum-resistant at 256-bit level", "replace": ""},
    # PQC algorithms (already safe)
    "CRYSTALS-KYBER":    {"vuln": "SAFE", "reason": "NIST FIPS 203 — quantum-resistant KEM", "replace": ""},
    "CRYSTALS-DILITHIUM":{"vuln": "SAFE", "reason": "NIST FIPS 204 — quantum-resistant signatures", "replace": ""},
    "SPHINCS+":          {"vuln": "SAFE", "reason": "NIST FIPS 205 — hash-based quantum-resistant signatures", "replace": ""},
    "FALCON":            {"vuln": "SAFE", "reason": "NIST alternate — quantum-resistant signatures", "replace": ""},
    "ML-KEM-768":        {"vuln": "SAFE", "reason": "NIST FIPS 203 ML-KEM-768 — quantum-resistant KEM", "replace": ""},
    "ML-DSA-65":         {"vuln": "SAFE", "reason": "NIST FIPS 204 ML-DSA-65 — quantum-resistant signatures", "replace": ""},
    "SLH-DSA":           {"vuln": "SAFE", "reason": "NIST FIPS 205 SLH-DSA — hash-based quantum-resistant signatures", "replace": ""},
}

# TLS cipher suite patterns
TLS_CIPHER_PATTERNS: dict[str, str] = {
    r"ECDHE[-_]RSA":     "ECDHE+RSA",
    r"ECDHE[-_]ECDSA":   "ECDHE+ECDSA",
    r"DHE[-_]RSA":       "DHE+RSA",
    r"RSA[-_]WITH":      "RSA key exchange",
    r"ECDH[-_]":         "ECDH key exchange",
    r"AES[_-]128":       "AES-128",
    r"AES[_-]256":       "AES-256",
    r"3DES":             "3DES",
    r"RC4":              "RC4",
    r"MD5":              "MD5",
    r"SHA1\b|SHA[-_]1\b":"SHA-1",
    r"TLS_AES":          "TLS 1.3 (modern)",
    r"CHACHA20":         "ChaCha20 (safe)",
    r"X25519":           "X25519 (ECDH — quantum vulnerable)",
    r"P[-_]256":         "P-256 ECDH (quantum vulnerable)",
    r"P[-_]384":         "P-384 ECDH (quantum vulnerable)",
}

# Source code crypto patterns
CODE_CRYPTO_PATTERNS: dict[str, dict] = {
    "Python": {
        "RSA":       ["from Crypto.PublicKey import RSA", "rsa.generate", "RSA.generate",
                      "from cryptography.hazmat.primitives.asymmetric import rsa"],
        "ECDSA":     ["from cryptography.hazmat.primitives.asymmetric import ec",
                      "from Crypto.PublicKey import ECC", "SECP256K1", "SECP384R1"],
        "DH":        ["from cryptography.hazmat.primitives.asymmetric import dh",
                      "DiffieHellman", "dh.generate_parameters"],
        "MD5":       ["hashlib.md5", "md5(", "from hashlib import md5"],
        "SHA-1":     ["hashlib.sha1", "sha1(", "from hashlib import sha1"],
        "AES-128":   ["AES.new(key,", "algorithms.AES(key)"],
    },
    "JavaScript": {
        "RSA":       ["crypto.generateKeyPair('rsa'", "new NodeRSA", "RSA.generate"],
        "ECDSA":     ["crypto.createECDH", "new EC('p256'", "elliptic"],
        "MD5":       ["require('md5'", "createHash('md5'"],
        "SHA-1":     ["createHash('sha1'", "require('sha1'"],
    },
    "Java": {
        "RSA":       ['KeyPairGenerator.getInstance("RSA"', "new RSAKeyGenParameterSpec"],
        "DH":        ['KeyPairGenerator.getInstance("DH"', "DHParameterSpec"],
        "ECDSA":     ['KeyPairGenerator.getInstance("EC"', "ECGenParameterSpec"],
        "MD5":       ['MessageDigest.getInstance("MD5"'],
        "SHA-1":     ['MessageDigest.getInstance("SHA-1"'],
    },
    "Go": {
        "RSA":       ["rsa.GenerateKey", "x509.ParsePKCS1"],
        "ECDSA":     ["ecdsa.GenerateKey", "elliptic.P256"],
        "DH":        ["crypto/dh"],
        "MD5":       ["crypto/md5", "md5.New()"],
        "SHA-1":     ["crypto/sha1", "sha1.New()"],
    },
}

LANG_EXTENSIONS: dict[str, list[str]] = {
    "Python":      [".py"],
    "JavaScript":  [".js", ".ts", ".mjs"],
    "Java":        [".java"],
    "Go":          [".go"],
    "C":           [".c", ".h"],
    "CPP":         [".cpp", ".cc", ".cxx", ".hpp"],
    "Rust":        [".rs"],
}


def classify_algorithm(name: str) -> dict:
    """Look up an algorithm in the vulnerability table (case-insensitive)."""
    name_upper = name.upper().replace("-", "").replace("_", "")
    for key, info in QUANTUM_VULN_TABLE.items():
        norm = key.upper().replace("-", "").replace("_", "")
        if norm in name_upper or name_upper in norm:
            return {**info, "algorithm": key}
    return {"algorithm": name, "vuln": "UNKNOWN",
            "reason": "Not in quantum vulnerability database", "replace": ""}


# ── TLS scanner ───────────────────────────────────────────────────────────────

class TLSScanner:
    """Probe a TLS endpoint and extract cipher suite + certificate info."""

    def __init__(self, host: str, port: int = 443, timeout: int = 10) -> None:
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def scan(self) -> dict:
        result: dict[str, Any] = {
            "host":   self.host,
            "port":   self.port,
            "tls_version": "",
            "cipher_suite": "",
            "cert_info":   {},
            "findings":    [],
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_OPTIONAL
            with socket.create_connection((self.host, self.port),
                                          timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    result["tls_version"] = ssock.version() or ""
                    cipher               = ssock.cipher()
                    if cipher:
                        result["cipher_suite"]     = cipher[0]
                        result["cipher_protocol"]  = cipher[1]
                        result["cipher_bits"]      = cipher[2]
                    cert = ssock.getpeercert()
                    result["cert_info"] = self._parse_cert(cert)
                    result["findings"]  = self._analyse_cipher(result["cipher_suite"],
                                                                result["tls_version"])
        except ssl.SSLError as exc:
            result["error"] = f"SSL error: {exc}"
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            result["error"] = f"Connection error: {exc}"
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def _parse_cert(self, cert: dict | None) -> dict:
        if not cert:
            return {}
        subject   = dict(x[0] for x in cert.get("subject", []))
        issuer    = dict(x[0] for x in cert.get("issuer", []))
        san       = [v for _, v in cert.get("subjectAltName", [])]
        not_after = cert.get("notAfter", "")
        try:
            from datetime import datetime as dt
            expires = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expires - dt.utcnow()).days
        except Exception:
            days_left = -1
        return {
            "subject":   subject.get("commonName", ""),
            "issuer":    issuer.get("organizationName", ""),
            "san":       san[:10],
            "not_after": not_after,
            "days_left": days_left,
            "serial":    str(cert.get("serialNumber", "")),
        }

    def _analyse_cipher(self, cipher: str, tls_ver: str) -> list[dict]:
        findings = []
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append({
                "type":     "DEPRECATED_TLS",
                "severity": "CRITICAL",
                "detail":   f"TLS version {tls_ver} is deprecated and insecure",
                "quantum":  "VULNERABLE",
                "replace":  "TLS 1.3",
            })
        for pattern, description in TLS_CIPHER_PATTERNS.items():
            if re.search(pattern, cipher, re.IGNORECASE):
                info = classify_algorithm(description)
                if info["vuln"] != "SAFE":
                    findings.append({
                        "type":     "CIPHER_SUITE",
                        "severity": "HIGH" if info["vuln"] == "VULNERABLE" else "MEDIUM",
                        "detail":   f"Cipher uses {description} — {info['reason']}",
                        "quantum":  info["vuln"],
                        "replace":  info.get("replace", ""),
                        "cipher":   cipher,
                    })
        return findings


# ── Source code scanner ───────────────────────────────────────────────────────

class SourceCodeScanner:
    """Scan source code for quantum-vulnerable cryptographic usage."""

    def __init__(self, lang: str | None = None) -> None:
        self.lang = lang

    def scan_directory(self, dir_path: str) -> list[dict]:
        findings = []
        p = Path(dir_path)
        for lang, exts in LANG_EXTENSIONS.items():
            if self.lang and lang.lower() != self.lang.lower():
                continue
            for ext in exts:
                for fpath in p.rglob(f"*{ext}"):
                    findings.extend(self._scan_file(fpath, lang))
        return findings

    def scan_file(self, file_path: str) -> list[dict]:
        p    = Path(file_path)
        lang = self._detect_lang(p)
        return self._scan_file(p, lang)

    def _scan_file(self, path: Path, lang: str) -> list[dict]:
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except Exception:
            return []

        findings = []
        patterns = CODE_CRYPTO_PATTERNS.get(lang, {})
        for algo, sigs in patterns.items():
            for sig in sigs:
                for lineno, line in enumerate(lines, 1):
                    if sig in line:
                        info = classify_algorithm(algo)
                        findings.append({
                            "file":      str(path),
                            "line":      lineno,
                            "code":      line.strip()[:120],
                            "algorithm": algo,
                            "quantum":   info["vuln"],
                            "reason":    info["reason"],
                            "replace":   info["replace"],
                            "language":  lang,
                        })

        # Generic grep for raw algorithm names
        generic_patterns = [
            (r'\bMD5\b',             "MD5"),
            (r'\bSHA[-_]?1\b',       "SHA-1"),
            (r'\bRC4\b',             "RC4"),
            (r'\bDES\b',             "DES"),
            (r'RSA[_-]?\d{3,4}',     "RSA"),
            (r'\bsecp256k1\b',       "ECDSA"),
            (r'\bP-256\b',           "ECDSA"),
        ]
        for pattern, algo in generic_patterns:
            for lineno, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    info = classify_algorithm(algo)
                    if info["vuln"] != "SAFE":
                        findings.append({
                            "file":      str(path),
                            "line":      lineno,
                            "code":      line.strip()[:120],
                            "algorithm": algo,
                            "quantum":   info["vuln"],
                            "reason":    info["reason"],
                            "replace":   info["replace"],
                            "language":  lang,
                        })

        # Deduplicate by (file, line, algorithm)
        seen = set()
        unique = []
        for f in findings:
            key = (f["file"], f["line"], f["algorithm"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _detect_lang(path: Path) -> str:
        for lang, exts in LANG_EXTENSIONS.items():
            if path.suffix in exts:
                return lang
        return "Unknown"


# ── Risk timeline estimator ───────────────────────────────────────────────────

def estimate_threat_timeline(algorithms: list[str]) -> dict:
    """
    Estimate the 'harvest now, decrypt later' threat window.
    Based on current consensus for CRQC availability estimates.
    """
    has_rsa      = any("RSA" in a.upper() for a in algorithms)
    has_ecc      = any(k in " ".join(algorithms).upper()
                       for k in ("ECDH", "ECDSA", "ED25519", "P-256", "P-384"))
    has_sym_weak = any(a.upper() in ("AES-128", "3DES", "DES", "RC4") for a in algorithms)

    risk_level = "LOW"
    if has_rsa or has_ecc:
        risk_level = "CRITICAL"
    elif has_sym_weak:
        risk_level = "HIGH"

    return {
        "risk_level":             risk_level,
        "crqc_estimated_arrival": "2030–2035 (community consensus, IBM/Google roadmaps)",
        "harvest_now_threat":     "Active — state actors may already be harvesting encrypted data",
        "migration_urgency":      "HIGH" if risk_level in ("CRITICAL", "HIGH") else "MEDIUM",
        "recommended_action":     (
            "Begin PQC migration NOW for long-lived data. "
            "Prioritise key exchange algorithms first (TLS, VPN, SSH)."
            if risk_level == "CRITICAL"
            else "Plan PQC migration within 2 years."
        ),
        "vulnerable_algorithms":  [a for a in algorithms
                                   if classify_algorithm(a)["vuln"] == "VULNERABLE"],
    }


# ── QuantumModule ─────────────────────────────────────────────────────────────

class QuantumModule:
    """
    shadow313.quantum — Post-quantum cryptography audit.
    Registered commands: quantum
    """

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("quantum", self.run)

    def run(self, scan_host: str = "", audit_certs: str = "",
            scan_code: str = "", lang: str = "",
            report: bool = False, output: str = "rich") -> dict:
        self.out.section("QUANTUM CRYPTOGRAPHY AUDIT")
        self.session.audit("quantum", "start")

        result: dict[str, Any] = {
            "timestamp": _now(),
            "findings":  [],
            "algorithms_found": [],
        }

        # 1. TLS endpoint scan
        if scan_host:
            host_str = scan_host.split(":")[0]
            port_str = scan_host.split(":")[-1] if ":" in scan_host else "443"
            try:
                port = int(port_str)
            except ValueError:
                port = 443
            self.out.info(f"Scanning TLS endpoint {host_str}:{port} …")
            tls_result = TLSScanner(host_str, port).scan()
            result["tls"] = tls_result

            if tls_result.get("error"):
                self.out.warn(f"TLS scan: {tls_result['error']}")
            else:
                tls_findings = tls_result.get("findings", [])
                result["findings"].extend(tls_findings)
                for finding in tls_findings:
                    result["algorithms_found"].append(
                        finding.get("cipher", scan_host).split("-")[0]
                    )

        # 2. Source code scan
        if scan_code:
            self.out.info(f"Scanning source code: {scan_code} …")
            scanner  = SourceCodeScanner(lang=lang or None)
            code_findings = (
                scanner.scan_directory(scan_code)
                if Path(scan_code).is_dir()
                else scanner.scan_file(scan_code)
            )
            result["code_findings"] = code_findings
            result["findings"].extend(code_findings)
            result["algorithms_found"].extend(
                [f.get("algorithm", "") for f in code_findings]
            )

        # 3. Risk timeline
        algos_unique = list(set(result["algorithms_found"]))
        if algos_unique:
            result["threat_timeline"] = estimate_threat_timeline(algos_unique)

        # 4. PQC migration map
        result["pqc_mapping"] = self._build_pqc_mapping(result["findings"])

        # 5. NIST PQC reference
        if report:
            result["nist_pqc_standards"] = NIST_PQC_STANDARDS

        path = self.session.write("quantum_report.json", result)
        self.out.success(f"Quantum audit saved → {path}")
        self.session.audit("quantum", "complete", str(path))
        return result

    def _build_pqc_mapping(self, findings: list[dict]) -> list[dict]:
        mapping = []
        seen    = set()
        priority_map = {"VULNERABLE": "IMMEDIATE", "WEAKENED": "SHORT-TERM", "UNKNOWN": "ASSESS"}
        for f in findings:
            algo  = f.get("algorithm", "")
            repl  = f.get("replace", "")
            vuln  = f.get("quantum", "UNKNOWN")
            if algo and repl and algo not in seen:
                seen.add(algo)
                pqc_info = {}
                for name, info in NIST_PQC_STANDARDS.items():
                    if name.upper().replace("-", "") in repl.upper().replace("-", "").replace("_", ""):
                        pqc_info = info
                        break
                mapping.append({
                    "from":     algo,
                    "to":       repl,
                    "fips":     pqc_info.get("fips", "See NIST PQC"),
                    "priority": priority_map.get(vuln, "ASSESS"),
                })
        return mapping

    def _ai_roadmap(self, data: dict) -> str:
        vuln_count = sum(1 for f in data.get("findings", [])
                         if f.get("quantum") == "VULNERABLE")
        ctx = {
            "vulnerable_algorithms":  list({f.get("algorithm", "") for f in data.get("findings", [])
                                            if f.get("quantum") == "VULNERABLE"}),
            "total_findings":         len(data.get("findings", [])),
            "vulnerable_count":       vuln_count,
            "pqc_mapping":            data.get("pqc_mapping", []),
            "threat_timeline":        data.get("threat_timeline", {}),
            "nist_standards":         list(NIST_PQC_STANDARDS.keys()),
        }
        return self.ai.chat(
            "You are a post-quantum cryptography migration expert. "
            "Based on this quantum audit, generate a 3-phase PQC migration roadmap: "
            "Phase 1 (0-6 months): Immediate actions for CRITICAL findings. "
            "Phase 2 (6-18 months): Systematic algorithm replacement with NIST FIPS 203/204/205. "
            "Phase 3 (18-36 months): Full PQC posture validation and crypto-agility implementation. "
            "For each phase: list specific actions, tools, and success criteria. "
            "Reference NIST SP 800-208 and FIPS 203/204/205 where applicable.",
            context=ctx,
        )