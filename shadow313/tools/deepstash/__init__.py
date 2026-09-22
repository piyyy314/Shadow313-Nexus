"""
shadow313.tools.deepstash
─────────────────────────
DeepStash — Filesystem & Git History Secret Scanner
Production-ready secret detection for offensive & defensive security.

Features:
  - 60+ regex patterns across 12 categories
  - Shannon entropy detection for unknown secret formats
  - Recursive directory scanning with smart exclusions
  - Git history scanning (commits, stashes, branches)
  - Multi-format output: console, JSON, CSV
  - Thread-pooled parallel scanning
  - CI/CD-friendly exit codes

Author: Mohamad | License: MIT | Version: 1.0.0
"""
from .scanner import DeepStashScanner, ScanResult, FindingRecord, SkippedRecord
from .patterns import SECRET_PATTERNS, COMPILED_PATTERNS

__all__ = [
    "DeepStashScanner",
    "ScanResult", 
    "FindingRecord",
    "SkippedRecord",
    "SECRET_PATTERNS",
    "COMPILED_PATTERNS",
]
