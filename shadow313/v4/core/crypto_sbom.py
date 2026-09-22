"""
shadow313.v4.core.crypto_sbom
───────────────────────────────
Crypto Software Bill of Materials (SBOM) for Shadow313 NEXUS v4 core.

Catalogs all cryptographic primitives in use across the codebase:
  - Algorithm name, key size, FIPS standard
  - Quantum safety status and HNDL exposure window
  - Migration path to post-quantum equivalent
  - Current deployment status

Exports to CycloneDX JSON format for compliance reporting.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CryptoComponent:
    """A single cryptographic primitive in the SBOM."""
    component_id:   str
    algorithm:      str
    key_size_bits:  int
    purpose:        str       # signing | encryption | hashing | kdf | mac
    fips_standard:  str       # FIPS 140-3 | FIPS 203 | FIPS 204 | FIPS 205 | N/A
    quantum_safe:   bool
    hndl_risk:      bool
    hndl_window:    str       # e.g. "2030-2033" or "N/A"
    migration_path: str
    status:         str       # ACTIVE | DEPRECATED | MIGRATED | PLANNED
    files:          list[str] = field(default_factory=list)
    notes:          str = ""

    def to_cyclonedx(self) -> dict:
        return {
            "type":        "cryptographic-asset",
            "bom-ref":     self.component_id,
            "name":        self.algorithm,
            "cryptoProperties": {
                "assetType":      self.purpose,
                "algorithmProperties": {
                    "primitive":      self.algorithm,
                    "parameterSetIdentifier": str(self.key_size_bits),
                    "executionEnvironment": "software",
                    "implementationPlatform": "python",
                    "certificationLevel": [self.fips_standard] if self.fips_standard != "N/A" else [],
                    "cryptoFunctions": [self.purpose],
                    "classicalSecurityLevel": self.key_size_bits,
                    "nistQuantumSecurityLevel": 5 if self.quantum_safe else 0,
                },
            },
            "properties": [
                {"name": "quantum_safe",   "value": str(self.quantum_safe)},
                {"name": "hndl_risk",      "value": str(self.hndl_risk)},
                {"name": "hndl_window",    "value": self.hndl_window},
                {"name": "migration_path", "value": self.migration_path},
                {"name": "status",         "value": self.status},
                {"name": "files",          "value": ", ".join(self.files)},
            ],
        }


# ── Shadow313 v4 Crypto SBOM ──────────────────────────────────────────────────

SHADOW313_CRYPTO_SBOM: list[CryptoComponent] = [
    CryptoComponent(
        component_id   = "CS-001",
        algorithm      = "SLH-DSA-SHAKE-128f",
        key_size_bits  = 256,
        purpose        = "signing",
        fips_standard  = "FIPS 205",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Already post-quantum",
        status         = "ACTIVE",
        files          = ["shadow313/v4/temporal_binding/temporal_binding.py"],
        notes          = "pyspx pure-Python fallback; pqcrypto C-accelerated preferred",
    ),
    CryptoComponent(
        component_id   = "CS-002",
        algorithm      = "ML-DSA-65 (HMAC-SHA3-256 proxy)",
        key_size_bits  = 256,
        purpose        = "signing",
        fips_standard  = "FIPS 204",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Replace proxy with liboqs real ML-DSA-65 (DW-1)",
        status         = "ACTIVE",
        files          = [
            "shadow313/v4/temporal_binding/hardened_binding.py",
            "shadow313/v4/ledger/ledger_engine.py",
            "shadow313/v2/plugin_signing/plugin_signer.py",
        ],
        notes          = "HMAC-SHA3-256 proxy — production needs liboqs",
    ),
    CryptoComponent(
        component_id   = "CS-003",
        algorithm      = "AES-256-GCM",
        key_size_bits  = 256,
        purpose        = "encryption",
        fips_standard  = "FIPS 140-3",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Already quantum-safe (symmetric)",
        status         = "ACTIVE",
        files          = ["shadow313/core/crypto_store.py"],
        notes          = "Session data encryption",
    ),
    CryptoComponent(
        component_id   = "CS-004",
        algorithm      = "Argon2id",
        key_size_bits  = 256,
        purpose        = "kdf",
        fips_standard  = "RFC 9106",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Already quantum-safe (memory-hard)",
        status         = "ACTIVE",
        files          = ["shadow313/core/crypto_store.py"],
        notes          = "64MB memory cost, time_cost=3, parallelism=4",
    ),
    CryptoComponent(
        component_id   = "CS-005",
        algorithm      = "SHA3-256",
        key_size_bits  = 256,
        purpose        = "hashing",
        fips_standard  = "FIPS 202",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Already quantum-safe",
        status         = "ACTIVE",
        files          = [
            "shadow313/v4/ledger/ledger_engine.py",
            "shadow313/v4/temporal_binding/temporal_binding.py",
            "shadow313/v4/ghost_watch/ghost_watch.py",
            "shadow313/v4/workflow/workflow_engine.py",
        ],
        notes          = "Primary hash function across all security-critical paths",
    ),
    CryptoComponent(
        component_id   = "CS-006",
        algorithm      = "SHA3-512",
        key_size_bits  = 512,
        purpose        = "hashing",
        fips_standard  = "FIPS 202",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Already quantum-safe",
        status         = "ACTIVE",
        files          = ["shadow313/v4/temporal_binding/temporal_binding.py"],
        notes          = "313-BIND receipt chain hash",
    ),
    CryptoComponent(
        component_id   = "CS-007",
        algorithm      = "HMAC-SHA256",
        key_size_bits  = 256,
        purpose        = "mac",
        fips_standard  = "FIPS 198-1",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Quantum-safe (symmetric) — no migration needed",
        status         = "ACTIVE",
        files          = [
            "shadow313/v2/plugin_signing/plugin_signer.py",
            "shadow313/v4/nexus_router/nexus_router.py",
            "shadow313/v4/workflow/workflow_engine.py",
        ],
        notes          = "Ephemeral MACs — symmetric, Grover gives √2 speedup only",
    ),
    CryptoComponent(
        component_id   = "CS-008",
        algorithm      = "ECDSA P-256 (cosign — LEGACY)",
        key_size_bits  = 256,
        purpose        = "signing",
        fips_standard  = "FIPS 186-5",
        quantum_safe   = False,
        hndl_risk      = True,
        hndl_window    = "2030-2033",
        migration_path = "MIGRATED → MLDSATrustRegistry (ML-DSA-65) as primary",
        status         = "DEPRECATED",
        files          = ["shadow313/v2/plugin_signing/plugin_signer.py"],
        notes          = "cosign binary fallback only — ML-DSA-65 is now primary",
    ),
    CryptoComponent(
        component_id   = "CS-009",
        algorithm      = "ML-KEM-1024",
        key_size_bits  = 1024,
        purpose        = "encryption",
        fips_standard  = "FIPS 203",
        quantum_safe   = True,
        hndl_risk      = False,
        hndl_window    = "N/A",
        migration_path = "Already post-quantum",
        status         = "ACTIVE",
        files          = ["shadow313/v4/tools/blueteam/crypto_sbom.py"],
        notes          = "Key encapsulation for quantum-safe key exchange",
    ),
]


class CryptoSBOM:
    """Crypto SBOM manager for Shadow313 NEXUS v4."""

    def __init__(self, components: Optional[list[CryptoComponent]] = None) -> None:
        self.components = components or SHADOW313_CRYPTO_SBOM
        self.generated_at = _now_iso()

    def get_vulnerable(self) -> list[CryptoComponent]:
        """Return components with HNDL risk or not quantum-safe."""
        return [c for c in self.components if not c.quantum_safe or c.hndl_risk]

    def get_active(self) -> list[CryptoComponent]:
        return [c for c in self.components if c.status == "ACTIVE"]

    def get_by_purpose(self, purpose: str) -> list[CryptoComponent]:
        return [c for c in self.components if c.purpose == purpose]

    def summary(self) -> dict:
        total     = len(self.components)
        safe      = sum(1 for c in self.components if c.quantum_safe)
        hndl_risk = sum(1 for c in self.components if c.hndl_risk)
        active    = sum(1 for c in self.components if c.status == "ACTIVE")
        return {
            "total":          total,
            "quantum_safe":   safe,
            "not_safe":       total - safe,
            "hndl_risk":      hndl_risk,
            "active":         active,
            "deprecated":     sum(1 for c in self.components if c.status == "DEPRECATED"),
            "generated_at":   self.generated_at,
        }

    def to_cyclonedx(self) -> dict:
        """Export as CycloneDX JSON SBOM."""
        return {
            "bomFormat":   "CycloneDX",
            "specVersion": "1.5",
            "version":     1,
            "metadata": {
                "timestamp": self.generated_at,
                "component": {
                    "type":    "application",
                    "name":    "Shadow313 NEXUS v4",
                    "version": "4.0.0",
                },
            },
            "components": [c.to_cyclonedx() for c in self.components],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_cyclonedx(), indent=2)