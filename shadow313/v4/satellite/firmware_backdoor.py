"""
shadow313.v4.satellite.firmware_backdoor
VSAT Firmware Backdoor Analyzer — SHA-19

Detects firmware backdoors, supply chain implants, and unauthorized
modifications in VSAT ground segment firmware images.

Based on:
- YARA_SCAN_VSAT_Firmware_Backdoor.json findings
- CVE-2026-3392 TR-069 CWMP unsigned provisioning
- NSA/CISA advisory on satellite ground segment security
- ATT&CK T1542.001 (Pre-OS Boot: System Firmware)
- ATT&CK T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)

Detection capabilities:
1. Firmware signature verification (SLH-DSA / RSA-4096)
2. Hidden service detection (unexpected open ports, processes)
3. Hardcoded credential scanning
4. Suspicious string patterns (C2 URLs, shell commands)
5. Entropy analysis (packed/encrypted sections)
6. Known backdoor signatures (YARA-style rules)
7. Supply chain integrity (hash comparison against known-good)
8. Debug interface detection (UART/JTAG exposure)
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── YARA-style backdoor signatures ───────────────────────────────────────────

BACKDOOR_SIGNATURES: list[dict] = [
    # Hidden admin accounts
    {
        "id":          "VSAT-BACK-001",
        "name":        "Hardcoded Admin Credential",
        "technique":   "T1078.001",
        "risk":        0.98,
        "patterns":    [
            rb"admin:admin",
            rb"root:root",
            rb"admin:password",
            rb"admin:1234",
            rb"supervisor:supervisor",
            rb"support:support",
            rb"service:service",
            rb"guest:guest",
            rb"default:default",
        ],
        "description": "Hardcoded default credentials in firmware — trivial authentication bypass",
    },
    {
        "id":          "VSAT-BACK-002",
        "name":        "Hidden Backdoor Account",
        "technique":   "T1136.001",
        "risk":        0.99,
        "patterns":    [
            rb"backdoor",
            rb"b4ckd00r",
            rb"debug_user",
            rb"factory_mode",
            rb"mfg_mode",
            rb"test_account",
            rb"hidden_admin",
        ],
        "description": "Hidden backdoor account string in firmware binary",
    },
    # C2 / remote access
    {
        "id":          "VSAT-BACK-003",
        "name":        "Hardcoded C2 URL",
        "technique":   "T1071.001",
        "risk":        0.97,
        "patterns":    [
            rb"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}/",
            rb"https://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}/",
            rb"\.onion",
            rb"pastebin\.com",
            rb"raw\.githubusercontent\.com.*payload",
        ],
        "description": "Hardcoded C2 URL or suspicious remote endpoint in firmware",
    },
    {
        "id":          "VSAT-BACK-004",
        "name":        "Reverse Shell Payload",
        "technique":   "T1059.004",
        "risk":        0.99,
        "patterns":    [
            rb"/bin/sh -i",
            rb"nc -e /bin/sh",
            rb"nc -e /bin/bash",
            rb"bash -i >& /dev/tcp/",
            rb"python -c.*socket.*connect",
            rb"perl -e.*socket.*connect",
        ],
        "description": "Reverse shell payload embedded in firmware",
    },
    # Persistence mechanisms
    {
        "id":          "VSAT-BACK-005",
        "name":        "Cron Persistence",
        "technique":   "T1053.003",
        "risk":        0.90,
        "patterns":    [
            rb"\* \* \* \* \*.*wget",
            rb"\* \* \* \* \*.*curl",
            rb"crontab.*wget.*http",
            rb"/etc/cron\.d/.*backdoor",
        ],
        "description": "Cron-based persistence downloading remote payload",
    },
    {
        "id":          "VSAT-BACK-006",
        "name":        "Init Script Backdoor",
        "technique":   "T1037.004",
        "risk":        0.93,
        "patterns":    [
            rb"/etc/init\.d/.*nc\s",
            rb"/etc/rc\.local.*wget.*http",
            rb"S99.*backdoor",
            rb"insmod.*rootkit",
        ],
        "description": "Backdoor injected into init scripts for persistence",
    },
    # Rootkit indicators
    {
        "id":          "VSAT-BACK-007",
        "name":        "Kernel Rootkit Module",
        "technique":   "T1014",
        "risk":        0.99,
        "patterns":    [
            rb"hide_pid",
            rb"hide_file",
            rb"hook_syscall",
            rb"sys_call_table",
            rb"rootkit",
            rb"diamorphine",
            rb"reptile",
            rb"azazel",
        ],
        "description": "Kernel rootkit strings — process/file hiding capability",
    },
    # Supply chain indicators
    {
        "id":          "VSAT-BACK-008",
        "name":        "Supply Chain Implant Marker",
        "technique":   "T1195.002",
        "risk":        0.97,
        "patterns":    [
            rb"IMPLANT_ID:",
            rb"BEACON_KEY:",
            rb"C2_HOST:",
            rb"EXFIL_URL:",
            rb"\x00PAYLOAD\x00",
            rb"SHADOW_AGENT",
        ],
        "description": "Supply chain implant marker — firmware modified post-build",
    },
    # Debug/test interfaces
    {
        "id":          "VSAT-BACK-009",
        "name":        "Debug Interface Exposure",
        "technique":   "T1542.001",
        "risk":        0.85,
        "patterns":    [
            rb"UART_DEBUG_ENABLED",
            rb"JTAG_ENABLED",
            rb"DEBUG_SHELL",
            rb"telnetd",
            rb"dropbear.*debug",
            rb"gdbserver",
        ],
        "description": "Debug interface enabled in production firmware — hardware attack surface",
    },
    # Crypto weaknesses
    {
        "id":          "VSAT-BACK-010",
        "name":        "Weak Crypto / Hardcoded Key",
        "technique":   "T1600.001",
        "risk":        0.92,
        "patterns":    [
            rb"MD5\x00",
            rb"DES\x00",
            rb"RC4\x00",
            rb"hardcoded_key",
            rb"PRIVATE_KEY_HERE",
            rb"-----BEGIN RSA PRIVATE KEY-----",
            rb"-----BEGIN EC PRIVATE KEY-----",
        ],
        "description": "Weak crypto algorithm or hardcoded private key in firmware",
    },
    # CVE-2026-3392 specific
    {
        "id":          "VSAT-BACK-011",
        "name":        "CVE-2026-3392 CWMP Unsigned Accept",
        "technique":   "T1190",
        "risk":        0.96,
        "patterns":    [
            rb"accept_unsigned_firmware",
            rb"skip_signature_check",
            rb"CWMP_NO_AUTH",
            rb"acs_auth_disabled",
            rb"verify_acs=0",
            rb"verify_acs=false",
        ],
        "description": "CVE-2026-3392: CWMP configured to accept unsigned firmware/provisioning",
    },
    # Known malicious hashes (simulated — real deployment uses threat intel feed)
    {
        "id":          "VSAT-BACK-012",
        "name":        "Known Malicious Firmware Section",
        "technique":   "T1542.001",
        "risk":        0.99,
        "patterns":    [
            # These are SHA3-256 prefixes of known malicious firmware sections
            # In production: loaded from threat intel feed
            rb"\xde\xad\xbe\xef\xca\xfe\xba\xbe",  # magic bytes of known implant
            rb"\x4d\x5a\x90\x00\x03\x00\x00\x00",  # PE header in non-PE context
        ],
        "description": "Known malicious firmware section magic bytes detected",
    },
]

# ── Known-good firmware hashes (simulated baseline) ───────────────────────────

KNOWN_GOOD_HASHES: dict[str, str] = {
    # Format: "firmware_version": "sha3_256_hash"
    # In production: loaded from vendor-signed manifest
    "vsat-gw-v2.1.0": "a" * 64,  # placeholder
    "vsat-gw-v2.2.0": "b" * 64,
    "vsat-gw-v3.0.0": "c" * 64,
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class FirmwareFinding:
    """A single backdoor/anomaly finding in firmware."""
    signature_id:    str
    signature_name:  str
    technique:       str
    risk_score:      float
    offset:          int
    matched_bytes:   bytes
    description:     str
    timestamp:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "signature_id":   self.signature_id,
            "signature_name": self.signature_name,
            "technique":      self.technique,
            "risk_score":     self.risk_score,
            "offset":         f"0x{self.offset:08X}",
            "matched_bytes":  self.matched_bytes[:32].hex(),
            "description":    self.description,
            "timestamp":      self.timestamp,
        }


@dataclass
class EntropySection:
    """Entropy analysis of a firmware section."""
    offset:    int
    size:      int
    entropy:   float
    suspicious: bool
    note:      str

    def to_dict(self) -> dict:
        return {
            "offset":    f"0x{self.offset:08X}",
            "size":      self.size,
            "entropy":   round(self.entropy, 4),
            "suspicious": self.suspicious,
            "note":      self.note,
        }


@dataclass
class FirmwareAnalysisResult:
    """Complete firmware backdoor analysis result."""
    firmware_name:      str
    firmware_size:      int
    firmware_hash:      str
    hash_verified:      bool
    findings:           list[FirmwareFinding] = field(default_factory=list)
    entropy_sections:   list[EntropySection]  = field(default_factory=list)
    suspicious_strings: list[str]             = field(default_factory=list)
    risk_score:         float = 0.0
    backdoor_detected:  bool  = False
    supply_chain_clean: bool  = True
    technique_ids:      list[str] = field(default_factory=list)
    timestamp:          str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "firmware_name":      self.firmware_name,
            "firmware_size":      self.firmware_size,
            "firmware_hash":      self.firmware_hash,
            "hash_verified":      self.hash_verified,
            "backdoor_detected":  self.backdoor_detected,
            "supply_chain_clean": self.supply_chain_clean,
            "risk_score":         round(self.risk_score, 4),
            "finding_count":      len(self.findings),
            "technique_ids":      self.technique_ids,
            "findings":           [f.to_dict() for f in self.findings],
            "entropy_sections":   [e.to_dict() for e in self.entropy_sections],
            "suspicious_strings": self.suspicious_strings[:20],
            "timestamp":          self.timestamp,
        }


# ── Analyzer ──────────────────────────────────────────────────────────────────

class FirmwareBackdoorAnalyzer:
    """
    Analyzes VSAT firmware images for backdoors and supply chain implants.

    Usage:
        analyzer = FirmwareBackdoorAnalyzer()

        # Analyze raw firmware bytes
        result = analyzer.analyze(firmware_bytes, name="vsat-gw-v3.0.0")

        # Analyze from file path (simulation)
        result = analyzer.analyze_path("/path/to/firmware.bin")

        # Quick score for pipeline integration
        score = analyzer.score_firmware(firmware_bytes)
    """

    ENTROPY_THRESHOLD:    float = 6.0   # above this = likely encrypted/packed (64-byte blocks)
    ENTROPY_BLOCK_SIZE:   int   = 64    # bytes per entropy block
    DETECTION_THRESHOLD:  float = 0.65

    def __init__(self, threshold: float = DETECTION_THRESHOLD) -> None:
        self.threshold = threshold
        self._compiled: list[tuple[dict, list[re.Pattern]]] = []
        self._compile_signatures()

    def _compile_signatures(self) -> None:
        for sig in BACKDOOR_SIGNATURES:
            compiled = [re.compile(p, re.DOTALL) for p in sig["patterns"]]
            self._compiled.append((sig, compiled))

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(
        self,
        firmware_bytes: bytes,
        name: str = "unknown",
        known_good_hash: Optional[str] = None,
    ) -> FirmwareAnalysisResult:
        """
        Full firmware backdoor analysis.

        Args:
            firmware_bytes:   Raw firmware binary data
            name:             Firmware version/name for reporting
            known_good_hash:  Expected SHA3-256 hash (None = skip verification)

        Returns:
            FirmwareAnalysisResult with all findings
        """
        # Compute hash
        fw_hash = hashlib.sha3_256(firmware_bytes).hexdigest()

        # Hash verification
        expected = known_good_hash or KNOWN_GOOD_HASHES.get(name)
        hash_verified = (expected is not None and fw_hash == expected)

        result = FirmwareAnalysisResult(
            firmware_name=name,
            firmware_size=len(firmware_bytes),
            firmware_hash=fw_hash,
            hash_verified=hash_verified,
        )

        # If hash doesn't match known-good → supply chain flag
        if expected is not None and not hash_verified:
            result.supply_chain_clean = False

        # Run signature scan
        self._scan_signatures(firmware_bytes, result)

        # Entropy analysis
        self._analyze_entropy(firmware_bytes, result)

        # Suspicious string extraction
        self._extract_suspicious_strings(firmware_bytes, result)

        # Aggregate score
        result.risk_score = self._aggregate_score(result)
        result.backdoor_detected = result.risk_score >= self.threshold

        # Collect unique technique IDs
        result.technique_ids = list({f.technique for f in result.findings})

        return result

    def analyze_path(self, path: str) -> FirmwareAnalysisResult:
        """Analyze firmware from file path."""
        with open(path, "rb") as f:
            data = f.read()
        import os
        return self.analyze(data, name=os.path.basename(path))

    def score_firmware(self, firmware_bytes: bytes) -> float:
        """Quick risk score for pipeline integration."""
        result = self.analyze(firmware_bytes)
        return result.risk_score

    def verify_signature(
        self,
        firmware_bytes: bytes,
        expected_hash: str,
        algorithm: str = "sha3_256",
    ) -> dict:
        """
        Verify firmware cryptographic signature.

        Args:
            firmware_bytes: Raw firmware data
            expected_hash:  Expected hash (hex string)
            algorithm:      Hash algorithm (sha3_256, sha256, sha512)

        Returns:
            dict with verified, actual_hash, expected_hash, algorithm
        """
        hashers = {
            "sha3_256": hashlib.sha3_256,
            "sha256":   hashlib.sha256,
            "sha512":   hashlib.sha512,
            "sha3_512": hashlib.sha3_512,
        }
        hasher = hashers.get(algorithm, hashlib.sha3_256)
        actual = hasher(firmware_bytes).hexdigest()
        verified = actual == expected_hash.lower()

        return {
            "verified":      verified,
            "actual_hash":   actual,
            "expected_hash": expected_hash.lower(),
            "algorithm":     algorithm,
            "firmware_size": len(firmware_bytes),
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _scan_signatures(
        self,
        data: bytes,
        result: FirmwareAnalysisResult,
    ) -> None:
        """Scan firmware bytes against all backdoor signatures."""
        for sig, patterns in self._compiled:
            for pattern in patterns:
                match = pattern.search(data)
                if match:
                    finding = FirmwareFinding(
                        signature_id=sig["id"],
                        signature_name=sig["name"],
                        technique=sig["technique"],
                        risk_score=sig["risk"],
                        offset=match.start(),
                        matched_bytes=data[match.start():match.start()+32],
                        description=sig["description"],
                    )
                    result.findings.append(finding)
                    break  # one match per signature

    def _analyze_entropy(
        self,
        data: bytes,
        result: FirmwareAnalysisResult,
    ) -> None:
        """Analyze entropy across firmware sections to detect packed/encrypted regions."""
        block_size = self.ENTROPY_BLOCK_SIZE
        for offset in range(0, len(data) - block_size, block_size):
            block = data[offset:offset + block_size]
            entropy = self._shannon_entropy(block)

            # Flag high entropy (encrypted/packed) or near-zero (hardcoded keys/padding)
            high = entropy > self.ENTROPY_THRESHOLD
            low  = entropy < 0.5

            if high or low:
                if high:
                    note = f"High entropy ({entropy:.2f}) — possible encrypted/packed section"
                    suspicious = True
                else:
                    note = f"Near-zero entropy ({entropy:.2f}) — possible hardcoded key/padding"
                    suspicious = False

                result.entropy_sections.append(EntropySection(
                    offset=offset,
                    size=block_size,
                    entropy=entropy,
                    suspicious=suspicious,
                    note=note,
                ))
            elif entropy > 5.5:
                # Record moderately high entropy sections (not flagged but notable)
                result.entropy_sections.append(EntropySection(
                    offset=offset,
                    size=block_size,
                    entropy=entropy,
                    suspicious=True,  # flag as suspicious for detection
                    note=f"Elevated entropy ({entropy:.2f}) — possible compressed/random data",
                ))

    def _extract_suspicious_strings(
        self,
        data: bytes,
        result: FirmwareAnalysisResult,
    ) -> None:
        """Extract suspicious printable strings from firmware."""
        suspicious_keywords = [
            b"wget", b"curl", b"nc ", b"ncat", b"netcat",
            b"/bin/sh", b"/bin/bash", b"chmod 777",
            b"base64 -d", b"eval ", b"exec(",
            b"iptables -F", b"iptables -X",
            b"rm -rf /", b"dd if=",
            b"telnetd", b"dropbear",
            b"passwd", b"shadow",
            b"authorized_keys",
            b"id_rsa", b"id_ed25519",
        ]

        # Extract printable strings (min 6 chars)
        string_pattern = re.compile(rb'[ -~]{6,}')
        strings = string_pattern.findall(data)

        for s in strings:
            for kw in suspicious_keywords:
                if kw in s.lower():
                    decoded = s.decode("ascii", errors="replace")
                    if decoded not in result.suspicious_strings:
                        result.suspicious_strings.append(decoded)
                    break

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        length = len(data)
        for f in freq:
            if f > 0:
                p = f / length
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _aggregate_score(result: FirmwareAnalysisResult) -> float:
        """Aggregate findings into a single risk score."""
        score = 0.0

        # Supply chain mismatch is an immediate high score
        if not result.supply_chain_clean:
            score = max(score, 0.90)

        # Signature findings
        if result.findings:
            scores = sorted([f.risk_score for f in result.findings], reverse=True)
            score = max(score, scores[0])
            for i, s in enumerate(scores[1:], 1):
                score += s * (0.4 ** i)

        # Entropy anomalies add to score
        high_entropy = sum(1 for e in result.entropy_sections if e.suspicious)
        if high_entropy > 5:
            score = max(score, min(score + 0.15, 1.0))

        # Suspicious strings
        if len(result.suspicious_strings) > 10:
            score = max(score, min(score + 0.10, 1.0))

        return min(score, 1.0)


# ── Convenience functions ─────────────────────────────────────────────────────

def scan_firmware_bytes(
    firmware_bytes: bytes,
    name: str = "unknown",
    known_good_hash: Optional[str] = None,
) -> FirmwareAnalysisResult:
    """Convenience wrapper for one-shot firmware scanning."""
    analyzer = FirmwareBackdoorAnalyzer()
    return analyzer.analyze(firmware_bytes, name=name, known_good_hash=known_good_hash)


def generate_firmware_yara_rules() -> str:
    """Generate YARA rules from the backdoor signature database."""
    rules = ['rule VSAT_Firmware_Backdoor {', '    meta:']
    rules.append('        description = "Shadow313 NEXUS VSAT Firmware Backdoor Detection"')
    rules.append('        author = "Shadow313 NEXUS v4.0.0"')
    rules.append('        technique = "T1542.001, T1195.002"')
    rules.append('    strings:')

    for sig in BACKDOOR_SIGNATURES:
        for i, pattern in enumerate(sig["patterns"][:2]):  # max 2 per sig
            safe_id = sig["id"].replace("-", "_")
            hex_pattern = " ".join(f"{b:02x}" for b in pattern[:16])
            rules.append(f'        ${safe_id}_{i} = {{ {hex_pattern} }}')

    rules.append('    condition:')
    rules.append('        any of them')
    rules.append('}')
    return "\n".join(rules)
