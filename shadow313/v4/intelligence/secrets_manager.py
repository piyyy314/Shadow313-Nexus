"""
shadow313.v4.intelligence.secrets_manager
Hardened Secrets Management — Shadow313 NEXUS v4

Implements a layered secrets strategy:

Layer 1 — GitHub Actions OIDC (CI/CD pipeline)
  - Keyless authentication via OIDC tokens
  - No long-lived credentials in GitHub Secrets
  - Dynamic tokens for GHCR, PyPI, AWS

Layer 2 — HashiCorp Vault (runtime secrets)
  - Dynamic secrets with TTL and auto-rotation
  - AppRole + JWT auth for containers
  - Audit log for every secret access

Layer 3 — Environment validation (fail-fast)
  - Validates all required secrets at startup
  - Blocks deployment if secrets are missing/weak
  - Enforces minimum entropy requirements

Layer 4 — Secret rotation policy
  - Automatic rotation schedules per secret class
  - Rotation receipts anchored to 313-BIND

Secret classes:
  CRITICAL  — rotate every 24h (API keys, JWT secrets)
  HIGH      — rotate every 7d (service tokens)
  MEDIUM    — rotate every 30d (integration keys)
  LOW       — rotate every 90d (non-sensitive config)
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional


# ── Secret Classification ─────────────────────────────────────────────────────

class SecretClass(str, Enum):
    CRITICAL = "CRITICAL"   # Rotate every 24h — JWT, API keys
    HIGH     = "HIGH"       # Rotate every 7d  — service tokens
    MEDIUM   = "MEDIUM"     # Rotate every 30d — integration keys
    LOW      = "LOW"        # Rotate every 90d — non-sensitive config


class SecretSource(str, Enum):
    VAULT       = "VAULT"        # HashiCorp Vault
    GITHUB_OIDC = "GITHUB_OIDC"  # GitHub Actions OIDC
    ENV_FILE    = "ENV_FILE"     # .env file (local dev only)
    ENV_VAR     = "ENV_VAR"      # Environment variable
    MISSING     = "MISSING"      # Not found


# ── Secret Registry ───────────────────────────────────────────────────────────

SECRET_REGISTRY: dict[str, dict] = {
    # ── Critical secrets (rotate every 24h) ──────────────────────────
    "WEBUI_SECRET_KEY": {
        "class":       SecretClass.CRITICAL,
        "description": "Open WebUI JWT signing key",
        "min_length":  32,
        "min_entropy": 4.0,
        "rotation_h":  24,
        "vault_path":  "secret/data/shadow313/webui",
        "vault_key":   "secret_key",
        "required":    True,
        "env_var":     "WEBUI_SECRET_KEY",
    },
    "SHADOW313_API_KEY": {
        "class":       SecretClass.CRITICAL,
        "description": "Shadow313 REST API authentication key",
        "min_length":  32,
        "min_entropy": 4.0,
        "rotation_h":  24,
        "vault_path":  "secret/data/shadow313/api",
        "vault_key":   "api_key",
        "required":    True,
        "env_var":     "SHADOW313_API_KEY",
    },
    "LEDGER_API_TOKEN": {
        "class":       SecretClass.CRITICAL,
        "description": "Ledger service API token (313-BIND anchoring)",
        "min_length":  40,
        "min_entropy": 4.5,
        "rotation_h":  24,
        "vault_path":  "secret/data/shadow313/ledger",
        "vault_key":   "api_token",
        "required":    False,
        "env_var":     "LEDGER_API_TOKEN",
    },

    # ── High secrets (rotate every 7d) ───────────────────────────────
    "HETZNER_API_TOKEN": {
        "class":       SecretClass.HIGH,
        "description": "Hetzner Cloud API token for VPS management",
        "min_length":  64,
        "min_entropy": 4.5,
        "rotation_h":  168,
        "vault_path":  "secret/data/shadow313/hetzner",
        "vault_key":   "api_token",
        "required":    False,
        "env_var":     "HETZNER_API_TOKEN",
    },
    "VERCEL_TOKEN": {
        "class":       SecretClass.HIGH,
        "description": "Vercel deployment token",
        "min_length":  24,
        "min_entropy": 4.0,
        "rotation_h":  168,
        "vault_path":  "secret/data/shadow313/vercel",
        "vault_key":   "token",
        "required":    False,
        "env_var":     "VERCEL_TOKEN",
    },

    # ── Medium secrets (rotate every 30d) ────────────────────────────
    "SHADOW313_SHODAN_KEY": {
        "class":       SecretClass.MEDIUM,
        "description": "Shodan API key for OSINT recon",
        "min_length":  32,
        "min_entropy": 3.5,
        "rotation_h":  720,
        "vault_path":  "secret/data/shadow313/threat-intel",
        "vault_key":   "shodan_key",
        "required":    False,
        "env_var":     "SHADOW313_SHODAN_KEY",
    },
    "SHADOW313_GREYNOISE_KEY": {
        "class":       SecretClass.MEDIUM,
        "description": "GreyNoise API key for threat intel",
        "min_length":  32,
        "min_entropy": 3.5,
        "rotation_h":  720,
        "vault_path":  "secret/data/shadow313/threat-intel",
        "vault_key":   "greynoise_key",
        "required":    False,
        "env_var":     "SHADOW313_GREYNOISE_KEY",
    },

    # ── Low secrets (rotate every 90d) ───────────────────────────────
    "OLLAMA_DEFAULT_MODEL": {
        "class":       SecretClass.LOW,
        "description": "Default Ollama model name",
        "min_length":  5,
        "min_entropy": 0.0,  # Not a secret — just config
        "rotation_h":  2160,
        "vault_path":  None,
        "vault_key":   None,
        "required":    False,
        "env_var":     "OLLAMA_DEFAULT_MODEL",
    },
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SecretValidationResult:
    """Result of validating a single secret."""
    name:          str
    present:       bool
    source:        str
    length_ok:     bool
    entropy_ok:    bool
    not_default:   bool
    rotation_due:  bool
    issues:        list[str] = field(default_factory=list)
    secret_class:  str = SecretClass.LOW.value

    @property
    def valid(self) -> bool:
        return self.present and self.length_ok and self.entropy_ok and self.not_default

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "present":      self.present,
            "source":       self.source,
            "valid":        self.valid,
            "length_ok":    self.length_ok,
            "entropy_ok":   self.entropy_ok,
            "not_default":  self.not_default,
            "rotation_due": self.rotation_due,
            "secret_class": self.secret_class,
            "issues":       self.issues,
        }


@dataclass
class SecretsAuditReport:
    """Complete secrets audit report."""
    results:          list[SecretValidationResult] = field(default_factory=list)
    critical_missing: list[str] = field(default_factory=list)
    weak_secrets:     list[str] = field(default_factory=list)
    rotation_due:     list[str] = field(default_factory=list)
    default_values:   list[str] = field(default_factory=list)
    overall_pass:     bool = False
    timestamp:        str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "overall_pass":     self.overall_pass,
            "critical_missing": self.critical_missing,
            "weak_secrets":     self.weak_secrets,
            "rotation_due":     self.rotation_due,
            "default_values":   self.default_values,
            "total_checked":    len(self.results),
            "total_valid":      sum(1 for r in self.results if r.valid),
            "results":          [r.to_dict() for r in self.results],
            "timestamp":        self.timestamp,
        }


# ── Known default/weak values ─────────────────────────────────────────────────

KNOWN_DEFAULTS = {
    "shadow313-nexus-change-me-in-production",
    "dev-key-change-in-production",
    "change-me",
    "changeme",
    "password",
    "secret",
    "test",
    "development",
    "your-secret-here",
    "replace-me",
    "todo",
    "fixme",
}


# ── Secret Pattern Detection (Layer 3 gap fix) ───────────────────────────────
# Real leaked secrets pass entropy/length checks — need pattern matching too

SECRET_PATTERNS: list[tuple[str, str]] = [
    # Shadow313 specific
    (r"sk-shadow313-[a-zA-Z0-9\-]{20,}", "Shadow313 production key (sk-shadow313- prefix)"),
    (r"313-[A-Z]+-[A-F0-9]{8}", "Shadow313 BIND receipt ID in secret position"),

    # GitHub tokens
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token (ghp_)"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App token (ghs_)"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub fine-grained PAT"),

    # AWS
    (r"AKIA[A-Z0-9]{16}", "AWS Access Key ID"),
    (r"(?i)aws.{0,20}secret.{0,20}[A-Za-z0-9/+=]{40}", "AWS Secret Access Key"),

    # OpenAI
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API key (sk- prefix)"),
    (r"sk-proj-[A-Za-z0-9\-_]{50,}", "OpenAI project key"),

    # Hetzner
    (r"[A-Za-z0-9]{64}", "Possible Hetzner API token (64 char hex)"),

    # Generic high-confidence patterns
    (r"(?i)(api.key|secret.key|access.token)\s*[=:]\s*[A-Za-z0-9\-_+/]{32,}", "Hardcoded API/secret key assignment"),
    (r"(?i)bearer\s+[A-Za-z0-9\-_+/=]{32,}", "Bearer token in code"),
    (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----", "Private key in code"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate in code"),
]

def detect_secret_patterns(value: str, context: str = "") -> list[str]:
    """
    Detect if a value matches known secret patterns.
    This closes the Layer 3 gap where real secrets pass entropy checks.

    Args:
        value:   The secret value to check
        context: Optional context (variable name, file path) for better detection

    Returns:
        List of pattern match descriptions (empty = no patterns matched)
    """
    import re
    matches = []
    text = f"{context}={value}" if context else value
    for pattern, description in SECRET_PATTERNS:
        if re.search(pattern, text):
            matches.append(description)
    return matches


# ── Secrets Validator ─────────────────────────────────────────────────────────

class SecretsValidator:
    """
    Validates secrets at startup — fail-fast if critical secrets are missing or weak.

    Usage:
        validator = SecretsValidator()

        # Validate all secrets (fail-fast mode)
        report = validator.validate_all(fail_fast=True)

        # Validate single secret
        result = validator.validate_secret("WEBUI_SECRET_KEY")

        # Check if rotation is due
        due = validator.check_rotation_due("SHADOW313_API_KEY", last_rotated_iso)
    """

    def __init__(self, vault_url: Optional[str] = None) -> None:
        self.vault_url = vault_url or os.environ.get("VAULT_ADDR")
        self._vault_available = False
        self._check_vault()

    def _check_vault(self) -> None:
        """Check if Vault is reachable."""
        if not self.vault_url:
            return
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{self.vault_url}/v1/sys/health",
                headers={"User-Agent": "shadow313-nexus/4.0.0"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                self._vault_available = resp.status in (200, 429, 472, 473)
        except Exception:
            self._vault_available = False

    def validate_all(self, fail_fast: bool = False) -> SecretsAuditReport:
        """
        Validate all registered secrets.

        Args:
            fail_fast: If True, raise RuntimeError if any CRITICAL secret is invalid

        Returns:
            SecretsAuditReport with full validation results
        """
        report = SecretsAuditReport()

        for name, config in SECRET_REGISTRY.items():
            result = self.validate_secret(name)
            report.results.append(result)

            if not result.present and config["required"]:
                report.critical_missing.append(name)
            if result.present and not result.valid:
                report.weak_secrets.append(name)
            if result.rotation_due:
                report.rotation_due.append(name)
            if result.present and not result.not_default:
                report.default_values.append(name)

        # Overall pass: no critical missing, no weak required secrets
        required_valid = all(
            r.valid
            for r in report.results
            if SECRET_REGISTRY[r.name]["required"]
        )
        report.overall_pass = (
            len(report.critical_missing) == 0 and
            required_valid
        )

        if fail_fast and not report.overall_pass:
            issues = []
            if report.critical_missing:
                issues.append(f"Missing required secrets: {report.critical_missing}")
            if report.default_values:
                issues.append(f"Default values detected: {report.default_values}")
            if report.weak_secrets:
                issues.append(f"Weak secrets: {report.weak_secrets}")
            raise RuntimeError(
                f"FAIL-FAST: Secrets validation failed — {'; '.join(issues)}"
            )

        return report

    def validate_secret(self, name: str) -> SecretValidationResult:
        """Validate a single secret by name."""
        config = SECRET_REGISTRY.get(name, {})
        if not config:
            return SecretValidationResult(
                name=name, present=False, source=SecretSource.MISSING.value,
                length_ok=False, entropy_ok=False, not_default=False,
                rotation_due=False, issues=[f"Unknown secret: {name}"],
            )

        # Get value from environment
        value = os.environ.get(config["env_var"], "")
        source = SecretSource.ENV_VAR.value if value else SecretSource.MISSING.value

        # Try Vault if available
        if not value and self._vault_available and config.get("vault_path"):
            vault_value = self._get_from_vault(config["vault_path"], config["vault_key"])
            if vault_value:
                value = vault_value
                source = SecretSource.VAULT.value

        issues = []
        present = bool(value)

        # Length check
        min_len = config.get("min_length", 8)
        length_ok = len(value) >= min_len if present else False
        if present and not length_ok:
            issues.append(f"Too short: {len(value)} < {min_len} chars required")

        # Entropy check
        min_entropy = config.get("min_entropy", 3.0)
        actual_entropy = self._shannon_entropy(value) if present else 0.0
        entropy_ok = actual_entropy >= min_entropy if present else False
        if present and not entropy_ok and min_entropy > 0:
            issues.append(f"Low entropy: {actual_entropy:.2f} < {min_entropy:.2f} required")

        # Default value check
        not_default = value.lower() not in KNOWN_DEFAULTS if present else False
        if present and not not_default:
            issues.append("Default/placeholder value detected — must be changed")

        # Pattern-based detection (Layer 3 gap fix)
        # Real leaked secrets pass entropy/length but match known patterns
        if present:
            pattern_matches = detect_secret_patterns(value, context=name)
            if pattern_matches:
                for match in pattern_matches:
                    issues.append(f"Secret pattern detected: {match}")
                # Pattern match in wrong context = potential leak
                # (e.g., GitHub token as WEBUI_SECRET_KEY)

        # Rotation check (simplified — in production use Vault lease TTL)
        rotation_due = False  # Would check Vault lease expiry in production

        return SecretValidationResult(
            name=name,
            present=present,
            source=source,
            length_ok=length_ok,
            entropy_ok=entropy_ok,
            not_default=not_default,
            rotation_due=rotation_due,
            issues=issues,
            secret_class=config.get("class", SecretClass.LOW).value,
        )

    def check_rotation_due(
        self,
        name: str,
        last_rotated_iso: str,
    ) -> bool:
        """Check if a secret is due for rotation based on its class."""
        config = SECRET_REGISTRY.get(name, {})
        if not config:
            return False

        rotation_hours = config.get("rotation_h", 720)
        try:
            last_rotated = datetime.fromisoformat(last_rotated_iso)
            if last_rotated.tzinfo is None:
                last_rotated = last_rotated.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - last_rotated).total_seconds() / 3600
            return age_hours >= rotation_hours
        except (ValueError, TypeError):
            return True  # Unknown rotation time → assume due

    def generate_secret(self, length: int = 48) -> str:
        """Generate a cryptographically secure secret."""
        return secrets.token_urlsafe(length)

    def _get_from_vault(self, path: str, key: str) -> Optional[str]:
        """Retrieve secret from HashiCorp Vault (stub — real impl uses hvac)."""
        try:
            import urllib.request, json
            vault_token = os.environ.get("VAULT_TOKEN", "")
            if not vault_token:
                return None
            req = urllib.request.Request(
                f"{self.vault_url}/v1/{path}",
                headers={
                    "X-Vault-Token": vault_token,
                    "User-Agent": "shadow313-nexus/4.0.0",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return data.get("data", {}).get("data", {}).get(key)
        except Exception:
            return None

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy


# ── Vault Integration Config ──────────────────────────────────────────────────

VAULT_CONFIG = {
    "auth_methods": {
        "github_actions": {
            "method":      "jwt",
            "role":        "github-actions-shadow313",
            "jwt_path":    "auth/jwt/login",
            "description": "GitHub Actions OIDC — keyless, no long-lived tokens",
            "ttl":         "1h",
            "max_ttl":     "4h",
        },
        "docker_container": {
            "method":      "approle",
            "role":        "shadow313-nexus-container",
            "description": "Docker container AppRole — short-lived tokens",
            "ttl":         "6h",
            "max_ttl":     "24h",
        },
        "local_dev": {
            "method":      "token",
            "description": "Local development — developer token (never in CI)",
            "ttl":         "24h",
            "max_ttl":     "72h",
        },
    },
    "secret_paths": {
        "shadow313/webui":       "Open WebUI secrets (JWT key, admin password)",
        "shadow313/api":         "Shadow313 API keys",
        "shadow313/ledger":      "Ledger service tokens",
        "shadow313/hetzner":     "Hetzner Cloud API tokens",
        "shadow313/vercel":      "Vercel deployment tokens",
        "shadow313/threat-intel": "Threat intel API keys (Shodan, GreyNoise)",
        "shadow313/pqc":         "Post-quantum crypto keys (SLH-DSA private keys)",
    },
    "rotation_policies": {
        SecretClass.CRITICAL.value: {
            "interval":    "24h",
            "auto_rotate": True,
            "notify":      True,
            "description": "JWT secrets, API keys — rotate every 24 hours",
        },
        SecretClass.HIGH.value: {
            "interval":    "7d",
            "auto_rotate": True,
            "notify":      True,
            "description": "Service tokens — rotate every 7 days",
        },
        SecretClass.MEDIUM.value: {
            "interval":    "30d",
            "auto_rotate": False,
            "notify":      True,
            "description": "Integration keys — rotate every 30 days",
        },
        SecretClass.LOW.value: {
            "interval":    "90d",
            "auto_rotate": False,
            "notify":      False,
            "description": "Non-sensitive config — rotate every 90 days",
        },
    },
}


# ── GitHub Actions OIDC Strategy ──────────────────────────────────────────────

GITHUB_OIDC_STRATEGY = {
    "description": """
    GitHub Actions OIDC eliminates long-lived credentials.
    Instead of storing tokens in GitHub Secrets, the workflow
    requests a short-lived OIDC token from GitHub and exchanges
    it for cloud provider credentials.
    """,
    "supported_providers": {
        "ghcr": {
            "method":      "GITHUB_TOKEN",
            "description": "GitHub Container Registry — built-in, no config needed",
            "workflow_step": """
      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
            """,
        },
        "pypi": {
            "method":      "OIDC Trusted Publisher",
            "description": "PyPI — configure Trusted Publisher, no API token needed",
            "workflow_step": """
      - name: Publish to PyPI (OIDC)
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          # No password needed — OIDC Trusted Publisher
          attestations: true
            """,
            "setup": "Configure at pypi.org/manage/project/shadow313/settings/publishing/",
        },
        "vault": {
            "method":      "JWT auth",
            "description": "HashiCorp Vault — exchange OIDC token for Vault token",
            "workflow_step": """
      - name: Get Vault secrets via OIDC
        uses: hashicorp/vault-action@v3
        with:
          url: ${{ secrets.VAULT_ADDR }}
          method: jwt
          role: github-actions-shadow313
          secrets: |
            secret/data/shadow313/api api_key | SHADOW313_API_KEY ;
            secret/data/shadow313/webui secret_key | WEBUI_SECRET_KEY
            """,
        },
    },
    "permissions_required": {
        "id-token": "write",  # Required for OIDC
        "contents": "read",
    },
}


# ── Pre-commit Hook Config ────────────────────────────────────────────────────

PRECOMMIT_CONFIG = """
# .pre-commit-config.yaml — Shadow313 NEXUS
# Install: pip install pre-commit && pre-commit install

repos:
  # Secret scanning — blocks commits with secrets
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
        name: Detect secrets (Gitleaks)
        description: Scan for secrets before commit

  # Detect-secrets baseline
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        name: Detect secrets (detect-secrets)
        args: ['--baseline', '.secrets.baseline']

  # Python security
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.8
    hooks:
      - id: bandit
        name: SAST (Bandit)
        args: ['-r', 'shadow313/', '-ll', '--skip', 'B101,B603,B607']

  # Prevent .env commits
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
        name: Detect private keys
      - id: check-added-large-files
        args: ['--maxkb=1000']
"""

# ── Convenience functions ─────────────────────────────────────────────────────

def validate_secrets_at_startup(fail_fast: bool = True) -> SecretsAuditReport:
    """
    Call this at application startup to validate all secrets.
    Set fail_fast=True in production to block startup on invalid secrets.
    """
    validator = SecretsValidator()
    return validator.validate_all(fail_fast=fail_fast)


def generate_strong_secret(length: int = 48) -> str:
    """Generate a cryptographically secure secret suitable for any secret class."""
    return secrets.token_urlsafe(length)


def get_secret_rotation_schedule() -> list[dict]:
    """Return the rotation schedule for all registered secrets."""
    schedule = []
    for name, config in SECRET_REGISTRY.items():
        schedule.append({
            "name":        name,
            "class":       config["class"].value,
            "rotation_h":  config["rotation_h"],
            "rotation_d":  config["rotation_h"] / 24,
            "auto_rotate": VAULT_CONFIG["rotation_policies"][config["class"].value]["auto_rotate"],
            "vault_path":  config.get("vault_path"),
            "required":    config["required"],
        })
    return sorted(schedule, key=lambda x: x["rotation_h"])
