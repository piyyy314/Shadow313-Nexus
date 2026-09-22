"""
shadow313.integrations.aegis_pqc.parser
─────────────────────────────────────────
Parses PQC (Post-Quantum Cryptography) audit results from multiple formats:
  - CycloneDX JSON SBOM (crypto components)
  - Shadow313 crypto_sbom.py output
  - Raw dict / programmatic input

Produces PQCAuditResult objects for binding and reporting.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Component model ───────────────────────────────────────────────────────────

@dataclass
class PQCComponent:
    """A single cryptographic component in the audit."""
    name:             str
    algorithm:        str
    crypto_type:      str       # signing | encryption | hashing | kdf | mac
    key_size_bits:    int
    is_quantum_safe:  bool
    pqc_readiness:    str       # QUANTUM_SAFE | HNDL_RISK | VULNERABLE | DEPRECATED
    risk_level:       str       # CRITICAL | HIGH | MEDIUM | LOW | ACCEPTABLE
    hndl_window:      str       # e.g. "2030-2033" or "N/A"
    pqc_replacement:  str       # e.g. "ML-DSA-65 (FIPS 204)"
    action_plan:      str       # migration action
    failure_channel:  str       # how it fails under CRQC
    target_code_line: str       # file:line reference
    fips_standard:    str       # FIPS 203 | FIPS 204 | FIPS 205 | N/A
    status:           str       # ACTIVE | DEPRECATED | MIGRATED

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ── Audit result ──────────────────────────────────────────────────────────────

@dataclass
class PQCAuditResult:
    """Complete PQC audit result ready for 313-BIND."""
    source_file:          str
    source_format:        str       # cyclonedx | shadow313_sbom | dict
    tool_name:            str       = "Shadow313 Aegis PQC"
    tool_version:         str       = "4.0.0"
    generated_at:         str       = field(default_factory=_now_iso)
    components:           list[PQCComponent] = field(default_factory=list)
    overall_status:       str       = "UNKNOWN"   # VULNERABLE | DEGRADED | SECURE
    overall_risk_score:   int       = 0           # 0-100 (higher = more risk)
    parse_warnings:       list[str] = field(default_factory=list)

    # ── Derived properties ────────────────────────────────────────────────────

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.components if c.risk_level == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for c in self.components if c.risk_level == "HIGH")

    @property
    def quantum_safe_count(self) -> int:
        return sum(1 for c in self.components if c.is_quantum_safe)

    @property
    def quantum_readiness_pct(self) -> int:
        if not self.components:
            return 0
        return int(self.quantum_safe_count / len(self.components) * 100)

    def to_bind_payload(self) -> dict:
        """Serialize for 313-BIND."""
        return {
            "source_file":        self.source_file,
            "source_format":      self.source_format,
            "tool_name":          self.tool_name,
            "tool_version":       self.tool_version,
            "generated_at":       self.generated_at,
            "overall_status":     self.overall_status,
            "overall_risk_score": self.overall_risk_score,
            "critical_count":     self.critical_count,
            "high_count":         self.high_count,
            "quantum_safe_count": self.quantum_safe_count,
            "quantum_readiness_pct": self.quantum_readiness_pct,
            "total_components":   len(self.components),
            "components":         [c.to_dict() for c in self.components],
        }

    def to_summary(self) -> dict:
        return {
            "overall_status":        self.overall_status,
            "overall_risk_score":    self.overall_risk_score,
            "critical_count":        self.critical_count,
            "high_count":            self.high_count,
            "quantum_safe_count":    self.quantum_safe_count,
            "quantum_readiness_pct": self.quantum_readiness_pct,
            "total_components":      len(self.components),
        }


# ── Parser ────────────────────────────────────────────────────────────────────

# Risk classification for known algorithms
_ALGO_RISK = {
    # Quantum-safe
    "SLH-DSA":      ("ACCEPTABLE", True,  "N/A",       "Already post-quantum"),
    "ML-DSA":       ("ACCEPTABLE", True,  "N/A",       "Already post-quantum"),
    "ML-KEM":       ("ACCEPTABLE", True,  "N/A",       "Already post-quantum"),
    "Argon2id":     ("ACCEPTABLE", True,  "N/A",       "Already post-quantum"),
    "AES-256":      ("ACCEPTABLE", True,  "N/A",       "Already post-quantum"),
    "SHA3-256":     ("ACCEPTABLE", True,  "N/A",       "Already post-quantum"),
    "SHA3-512":     ("ACCEPTABLE", True,  "N/A",       "Already post-quantum"),
    "HMAC-SHA256":  ("ACCEPTABLE", True,  "N/A",       "Symmetric — quantum-safe"),
    "HMAC-SHA3":    ("ACCEPTABLE", True,  "N/A",       "Symmetric — quantum-safe"),
    # HNDL risk
    "ECDSA":        ("CRITICAL",   False, "2030-2033", "ML-DSA-65 (FIPS 204)"),
    "ECDH":         ("CRITICAL",   False, "2030-2033", "ML-KEM-768 (FIPS 203)"),
    "RSA":          ("CRITICAL",   False, "2030-2033", "ML-KEM-768 (FIPS 203)"),
    "Ed25519":      ("CRITICAL",   False, "2030-2033", "ML-DSA-65 (FIPS 204)"),
    "DH":           ("CRITICAL",   False, "2030-2033", "ML-KEM-768 (FIPS 203)"),
    # Weakened
    "SHA-256":      ("HIGH",       False, "2035+",     "SHA3-256 (FIPS 202)"),
    "SHA-384":      ("HIGH",       False, "2035+",     "SHA3-384 (FIPS 202)"),
    "AES-128":      ("HIGH",       False, "2035+",     "AES-256-GCM"),
    "PBKDF2":       ("HIGH",       False, "2033-2037", "Argon2id (RFC 9106)"),
    # Broken
    "MD5":          ("CRITICAL",   False, "NOW",       "SHA3-256 (FIPS 202)"),
    "SHA-1":        ("CRITICAL",   False, "NOW",       "SHA3-256 (FIPS 202)"),
    "DES":          ("CRITICAL",   False, "NOW",       "AES-256-GCM"),
    "3DES":         ("CRITICAL",   False, "NOW",       "AES-256-GCM"),
    "RC4":          ("CRITICAL",   False, "NOW",       "AES-256-GCM"),
}

_FAILURE_CHANNELS = {
    "ECDSA":   "Shor's algorithm recovers private key from public key in O(n³) quantum gates",
    "RSA":     "Shor's algorithm factors RSA modulus — all key sizes broken",
    "ECDH":    "Shor's algorithm solves ECDLP — session keys recoverable retroactively (HNDL)",
    "SHA-256": "Grover's algorithm halves collision resistance: 256-bit → 128-bit effective",
    "PBKDF2":  "Grover's algorithm accelerates brute-force: effective security halved",
    "MD5":     "Classically broken (collision attacks) — no quantum needed",
    "SHA-1":   "Classically broken (SHAttered) — no quantum needed",
}


def _classify_algorithm(algo: str) -> tuple:
    """Return (risk_level, is_quantum_safe, hndl_window, replacement) for an algorithm."""
    algo_upper = algo.upper()
    for key, vals in _ALGO_RISK.items():
        if key.upper() in algo_upper:
            return vals
    return ("LOW", True, "N/A", "Review manually")


class PQCAuditParser:
    """
    Parses PQC audit data from multiple input formats.

    Supported formats:
      - CycloneDX JSON SBOM (bomFormat: "CycloneDX")
      - Shadow313 crypto_sbom.py output (list of CryptoComponent dicts)
      - Raw dict with 'components' key
      - Plain list of algorithm dicts
    """

    def parse_cyclonedx(self, data: dict, source_file: str = "") -> PQCAuditResult:
        """Parse a CycloneDX JSON SBOM."""
        result = PQCAuditResult(
            source_file   = source_file,
            source_format = "cyclonedx",
        )

        components_raw = data.get("components", [])
        for comp_raw in components_raw:
            if comp_raw.get("type") != "cryptographic-asset":
                continue
            comp = self._parse_cyclonedx_component(comp_raw)
            if comp:
                result.components.append(comp)

        result = self._compute_overall(result)
        return result

    def parse_shadow313_sbom(self, components: list[dict], source_file: str = "") -> PQCAuditResult:
        """Parse Shadow313 crypto_sbom.py output."""
        result = PQCAuditResult(
            source_file   = source_file,
            source_format = "shadow313_sbom",
        )

        for comp_raw in components:
            algo = comp_raw.get("algorithm", "")
            risk, is_safe, hndl, replacement = _classify_algorithm(algo)
            status = comp_raw.get("status", "ACTIVE")

            # Override with explicit fields if present
            if not comp_raw.get("quantum_safe", is_safe):
                is_safe = False
                if risk == "ACCEPTABLE":
                    risk = "HIGH"

            pqc_readiness = "QUANTUM_SAFE" if is_safe else (
                "HNDL_RISK" if hndl != "N/A" and hndl != "NOW" else "VULNERABLE"
            )

            comp = PQCComponent(
                name             = comp_raw.get("component_id", algo),
                algorithm        = algo,
                crypto_type      = comp_raw.get("purpose", "unknown"),
                key_size_bits    = comp_raw.get("key_size_bits", 0),
                is_quantum_safe  = is_safe,
                pqc_readiness    = pqc_readiness,
                risk_level       = risk,
                hndl_window      = hndl,
                pqc_replacement  = comp_raw.get("migration_path", replacement),
                action_plan      = f"Migrate to {replacement}" if not is_safe else "",
                failure_channel  = _FAILURE_CHANNELS.get(algo.split()[0], ""),
                target_code_line = ", ".join(comp_raw.get("files", [])[:2]),
                fips_standard    = comp_raw.get("fips_standard", "N/A"),
                status           = status,
            )
            result.components.append(comp)

        result = self._compute_overall(result)
        return result

    def parse_dict(self, data: dict, source_file: str = "") -> PQCAuditResult:
        """Parse a generic dict with algorithm information."""
        # Detect format
        if data.get("bomFormat") == "CycloneDX":
            return self.parse_cyclonedx(data, source_file)

        components_raw = data.get("components", [])
        if components_raw and isinstance(components_raw[0], dict):
            if "algorithm" in components_raw[0]:
                return self.parse_shadow313_sbom(components_raw, source_file)

        # Fallback: treat as list of algorithm names
        result = PQCAuditResult(source_file=source_file, source_format="dict")
        for item in components_raw:
            algo = item.get("algorithm", item.get("name", str(item)))
            risk, is_safe, hndl, replacement = _classify_algorithm(algo)
            comp = PQCComponent(
                name=algo, algorithm=algo, crypto_type="unknown",
                key_size_bits=0, is_quantum_safe=is_safe,
                pqc_readiness="QUANTUM_SAFE" if is_safe else "VULNERABLE",
                risk_level=risk, hndl_window=hndl,
                pqc_replacement=replacement, action_plan="",
                failure_channel=_FAILURE_CHANNELS.get(algo.split()[0], ""),
                target_code_line="", fips_standard="N/A", status="ACTIVE",
            )
            result.components.append(comp)
        return self._compute_overall(result)

    def parse_json(self, json_str: str, source_file: str = "") -> PQCAuditResult:
        """Parse JSON string."""
        try:
            data = json.loads(json_str)
            return self.parse_dict(data, source_file)
        except json.JSONDecodeError as exc:
            result = PQCAuditResult(source_file=source_file, source_format="json")
            result.parse_warnings.append(f"JSON parse error: {exc}")
            return result

    # ── Internal ──────────────────────────────────────────────────────────────

    def _parse_cyclonedx_component(self, comp_raw: dict) -> Optional[PQCComponent]:
        """Parse a single CycloneDX cryptographic-asset component."""
        name  = comp_raw.get("name", "")
        props = {p["name"]: p["value"] for p in comp_raw.get("properties", [])}
        algo  = name

        risk, is_safe, hndl, replacement = _classify_algorithm(algo)

        # Override with explicit properties
        if props.get("quantum_safe", "").lower() == "false":
            is_safe = False
        if props.get("hndl_window"):
            hndl = props["hndl_window"]
        if props.get("migration_path"):
            replacement = props["migration_path"]

        pqc_readiness = "QUANTUM_SAFE" if is_safe else (
            "HNDL_RISK" if hndl not in ("N/A", "NOW") else "VULNERABLE"
        )

        crypto_props = comp_raw.get("cryptoProperties", {})
        algo_props   = crypto_props.get("algorithmProperties", {})

        return PQCComponent(
            name             = comp_raw.get("bom-ref", name),
            algorithm        = algo,
            crypto_type      = crypto_props.get("assetType", "unknown"),
            key_size_bits    = int(algo_props.get("classicalSecurityLevel", 0)),
            is_quantum_safe  = is_safe,
            pqc_readiness    = pqc_readiness,
            risk_level       = risk,
            hndl_window      = hndl,
            pqc_replacement  = replacement,
            action_plan      = f"Migrate to {replacement}" if not is_safe else "",
            failure_channel  = _FAILURE_CHANNELS.get(algo.split()[0], ""),
            target_code_line = props.get("files", ""),
            fips_standard    = "N/A",
            status           = props.get("status", "ACTIVE"),
        )

    def _compute_overall(self, result: PQCAuditResult) -> PQCAuditResult:
        """Compute overall status and risk score."""
        if not result.components:
            result.overall_status = "UNKNOWN"
            result.overall_risk_score = 0
            return result

        critical = result.critical_count
        high     = result.high_count
        total    = len(result.components)

        # Risk score: weighted sum
        risk_score = min(100, int(
            (critical * 25 + high * 10) / max(total, 1) * 4
        ))
        result.overall_risk_score = risk_score

        if critical > 0:
            result.overall_status = "VULNERABLE"
        elif high > 0:
            result.overall_status = "DEGRADED"
        else:
            result.overall_status = "SECURE"

        return result