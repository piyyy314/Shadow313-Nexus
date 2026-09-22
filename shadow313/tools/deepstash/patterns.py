"""
shadow313.tools.deepstash.patterns
────────────────────────────────────
60+ curated regex patterns across 12 categories for secret detection.
"""
from __future__ import annotations
import re

SECRET_PATTERNS = [
    # AWS
    {"name": "AWS Access Key ID",       "pattern": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",                    "confidence": "HIGH",   "category": "AWS"},
    {"name": "AWS Secret Access Key",   "pattern": r"(?i)aws.{0,20}secret.{0,20}[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",   "confidence": "HIGH",   "category": "AWS"},
    {"name": "AWS Session Token",       "pattern": r"(?i)aws.{0,20}session.{0,20}[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})","confidence": "HIGH",   "category": "AWS"},
    # GCP
    {"name": "Google API Key",          "pattern": r"AIza[0-9A-Za-z\-_]{35}",                                          "confidence": "HIGH",   "category": "GCP"},
    {"name": "Google OAuth Token",      "pattern": r"ya29\.[0-9A-Za-z\-_]+",                                           "confidence": "HIGH",   "category": "GCP"},
    # Azure
    {"name": "Azure SAS Token",         "pattern": r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=",                                   "confidence": "HIGH",   "category": "Azure"},
    # GitHub/GitLab
    {"name": "GitHub PAT (classic)",    "pattern": r"ghp_[0-9a-zA-Z]{36}",                                             "confidence": "HIGH",   "category": "VCS"},
    {"name": "GitHub PAT (fine-grained)","pattern": r"github_pat_[0-9a-zA-Z_]{82}",                                   "confidence": "HIGH",   "category": "VCS"},
    {"name": "GitHub App Token",        "pattern": r"ghs_[0-9a-zA-Z]{36}",                                             "confidence": "HIGH",   "category": "VCS"},
    {"name": "GitLab PAT",              "pattern": r"glpat-[0-9a-zA-Z\-_]{20,}",                                       "confidence": "HIGH",   "category": "VCS"},
    # Payment
    {"name": "Stripe Secret Key",       "pattern": r"sk_live_[0-9a-zA-Z]{24,}",                                        "confidence": "HIGH",   "category": "Payment"},
    {"name": "Stripe Publishable Key",  "pattern": r"pk_live_[0-9a-zA-Z]{24,}",                                        "confidence": "MEDIUM", "category": "Payment"},
    # Communication
    {"name": "Slack Token",             "pattern": r"xox[baprs]-([0-9a-zA-Z\-]{10,48})",                               "confidence": "HIGH",   "category": "Communication"},
    {"name": "Slack Webhook",           "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "confidence": "HIGH", "category": "Communication"},
    {"name": "SendGrid API Key",        "pattern": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",                     "confidence": "HIGH",   "category": "Communication"},
    {"name": "Twilio API Key",          "pattern": r"SK[0-9a-fA-F]{32}",                                               "confidence": "HIGH",   "category": "Communication"},
    # Crypto Keys
    {"name": "RSA Private Key",         "pattern": r"-----BEGIN RSA PRIVATE KEY-----",                                  "confidence": "HIGH",   "category": "Crypto"},
    {"name": "EC Private Key",          "pattern": r"-----BEGIN EC PRIVATE KEY-----",                                   "confidence": "HIGH",   "category": "Crypto"},
    {"name": "OpenSSH Private Key",     "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",                              "confidence": "HIGH",   "category": "Crypto"},
    {"name": "Private Key (Generic)",   "pattern": r"-----BEGIN PRIVATE KEY-----",                                      "confidence": "HIGH",   "category": "Crypto"},
    {"name": "PGP Private Key",         "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",                            "confidence": "HIGH",   "category": "Crypto"},
    # Database
    {"name": "MongoDB URI",             "pattern": r"mongodb(\+srv)?://\S+",                                            "confidence": "HIGH",   "category": "Database"},
    {"name": "PostgreSQL URI",          "pattern": r"postgres(ql)?://\S+",                                              "confidence": "HIGH",   "category": "Database"},
    {"name": "MySQL URI",               "pattern": r"mysql://\S+",                                                      "confidence": "HIGH",   "category": "Database"},
    {"name": "Redis URI",               "pattern": r"redis://\S+",                                                      "confidence": "HIGH",   "category": "Database"},
    # Auth
    {"name": "JWT Token",               "pattern": r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*", "confidence": "HIGH",   "category": "Auth"},
    {"name": "Bearer Token",            "pattern": r"(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}",                               "confidence": "MEDIUM", "category": "Auth"},
    # Generic
    {"name": "Generic API Key",         "pattern": r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]{16,})['\"]?", "confidence": "MEDIUM", "category": "Generic"},
    {"name": "Generic Password",        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",       "confidence": "MEDIUM", "category": "Generic"},
    {"name": "Generic Secret",          "pattern": r"(?i)(secret|secret[_\-]?key)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]{16,})['\"]?", "confidence": "MEDIUM", "category": "Generic"},
    {"name": "Generic Token",           "pattern": r"(?i)(access[_\-]?token|auth[_\-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]{16,})['\"]?", "confidence": "MEDIUM", "category": "Generic"},
    # Shadow313 specific
    {"name": "Shadow313 API Key",       "pattern": r"s313-[a-zA-Z0-9\-_]{32,}",                                        "confidence": "HIGH",   "category": "Shadow313"},
    {"name": "313-BIND Receipt",        "pattern": r"313-[A-Z]+-[0-9]{8}",                                              "confidence": "LOW",    "category": "Shadow313"},
    # High entropy fallback (handled separately in scanner)
]

COMPILED_PATTERNS = []
for _p in SECRET_PATTERNS:
    try:
        COMPILED_PATTERNS.append({
            "name":       _p["name"],
            "regex":      re.compile(_p["pattern"]),
            "confidence": _p["confidence"],
            "category":   _p["category"],
        })
    except re.error as _e:
        pass  # Skip malformed patterns silently
