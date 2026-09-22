"""
shadow313.tools.deepstash.scanner
───────────────────────────────────
Core scanning engine for DeepStash.
Typed result objects, policy evaluation, and parallel scanning.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Literal, Optional

from .patterns import COMPILED_PATTERNS

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
ENTROPY_THRESHOLD = 4.5
MIN_SECRET_LENGTH = 8
MAX_SECRET_LENGTH = 500
MAX_LINE_LENGTH = 2000
MAX_FILE_SIZE_MB = 10

NOISE_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv",
    "env", ".env", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".coverage", "htmlcov",
    "site-packages", ".idea", ".vscode",
}

Confidence = Literal["HIGH", "MEDIUM", "LOW"]
DecisionStatus = Literal["pass", "review", "fail"]


# ── Types ─────────────────────────────────────────────────────────────────────

@dataclass
class FindingRecord:
    file: str
    line: int
    type: str
    category: str
    confidence: Confidence
    redacted_value: str
    value_hash: str
    context: str
    entropy: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SkippedRecord:
    file: str
    reason: str
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class PolicyDecision:
    mode: str
    status: DecisionStatus
    reasons: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Aggregated scanner output."""
    findings: List[FindingRecord] = field(default_factory=list)
    skipped: List[SkippedRecord] = field(default_factory=list)
    errors: List[SkippedRecord] = field(default_factory=list)
    scanner: str = "DeepStash"
    tool_version: str = VERSION
    schema_version: str = "1.1"
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    policy_decision: Optional[PolicyDecision] = None

    def merge(self, other: "ScanResult") -> None:
        self.findings.extend(other.findings)
        self.skipped.extend(other.skipped)
        self.errors.extend(other.errors)

    def summary_by_confidence(self) -> Dict[str, int]:
        return {
            "high":   sum(1 for f in self.findings if f.confidence == "HIGH"),
            "medium": sum(1 for f in self.findings if f.confidence == "MEDIUM"),
            "low":    sum(1 for f in self.findings if f.confidence == "LOW"),
        }

    def skipped_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in self.skipped:
            counts[item.reason] = counts.get(item.reason, 0) + 1
        return counts

    def to_report(self) -> Dict:
        report = {
            "scanner":        self.scanner,
            "tool_version":   self.tool_version,
            "schema_version": self.schema_version,
            "scan_time":      self.scan_time,
            "total_findings": len(self.findings),
            "summary":        self.summary_by_confidence(),
            "total_skipped":  len(self.skipped),
            "skipped_summary":self.skipped_summary(),
            "total_errors":   len(self.errors),
            "findings":       [asdict(f) for f in self.findings],
            "skipped_files":  [asdict(s) for s in self.skipped],
            "scanner_errors": [asdict(e) for e in self.errors],
        }
        if self.policy_decision:
            report["policy_decision"] = asdict(self.policy_decision)
        return report

    def is_clean(self) -> bool:
        return not self.findings and not self.skipped and not self.errors


# ── Entropy ───────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for char in data:
        freq[char] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def find_high_entropy_strings(line: str,
                               threshold: float = ENTROPY_THRESHOLD) -> list:
    findings = []
    candidates = re.findall(r'["\']([A-Za-z0-9+/=\-_]{16,})["\']', line)
    candidates += re.findall(r'=\s*([A-Za-z0-9+/=\-_]{20,})\s', line)
    for candidate in candidates:
        ent = shannon_entropy(candidate)
        if ent >= threshold and len(candidate) >= MIN_SECRET_LENGTH:
            findings.append({"value": candidate, "entropy": round(ent, 2)})
    return findings


# ── File Scanner ──────────────────────────────────────────────────────────────

def _redact(value: str, show_chars: int = 6) -> str:
    if len(value) <= show_chars + 4:
        return value[:3] + "***" + value[-2:]
    return value[:show_chars] + "***" + value[-4:]


def scan_file(file_path: str,
              patterns: list,
              entropy_threshold: float = ENTROPY_THRESHOLD,
              confidence_filter: set | None = None) -> tuple[list, list]:
    """Scan one file. Returns (findings, skipped)."""
    if confidence_filter is None:
        confidence_filter = {"HIGH", "MEDIUM", "LOW"}

    findings: list[FindingRecord] = []
    skipped: list[SkippedRecord] = []

    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            skipped.append(SkippedRecord(
                file_path, "file_too_large",
                f"{size_mb:.2f} MB exceeds {MAX_FILE_SIZE_MB} MB"
            ))
            return findings, skipped

        skipped_long = 0
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                if len(line) > MAX_LINE_LENGTH:
                    skipped_long += 1
                    continue

                for pat in patterns:
                    if pat["confidence"] not in confidence_filter:
                        continue
                    match = pat["regex"].search(line)
                    if not match:
                        continue
                    val = match.group(0)
                    if MIN_SECRET_LENGTH <= len(val) <= MAX_SECRET_LENGTH:
                        findings.append(FindingRecord(
                            file=file_path,
                            line=line_num,
                            type=pat["name"],
                            category=pat["category"],
                            confidence=pat["confidence"],
                            redacted_value=_redact(val),
                            value_hash=hashlib.sha256(val.encode()).hexdigest()[:16],
                            context=line.strip()[:200],
                        ))

                for hit in find_high_entropy_strings(line, entropy_threshold):
                    findings.append(FindingRecord(
                        file=file_path,
                        line=line_num,
                        type="High Entropy String",
                        category="Entropy",
                        confidence="MEDIUM",
                        redacted_value=_redact(hit["value"]),
                        value_hash=hashlib.sha256(
                            hit["value"].encode()).hexdigest()[:16],
                        context=line.strip()[:200],
                        entropy=hit["entropy"],
                    ))

        if skipped_long:
            skipped.append(SkippedRecord(
                file_path, "long_lines_skipped",
                f"{skipped_long} line(s) exceeded {MAX_LINE_LENGTH} chars"
            ))

    except PermissionError as e:
        skipped.append(SkippedRecord(file_path, "permission_denied", str(e)))
    except UnicodeError as e:
        skipped.append(SkippedRecord(file_path, "decode_error", str(e)))
    except OSError as e:
        skipped.append(SkippedRecord(file_path, "os_error", str(e)))

    return findings, skipped


# ── Directory Scanner ─────────────────────────────────────────────────────────

class DeepStashScanner:
    """
    Production-ready filesystem secret scanner.

    Usage:
        scanner = DeepStashScanner()
        result = scanner.scan("/path/to/project")
        report = result.to_report()
    """

    def __init__(self,
                 patterns: list | None = None,
                 entropy_threshold: float = ENTROPY_THRESHOLD,
                 confidence_filter: set | None = None,
                 workers: int = 8,
                 extensions: set | None = None):
        self.patterns = patterns or COMPILED_PATTERNS
        self.entropy_threshold = entropy_threshold
        self.confidence_filter = confidence_filter or {"HIGH", "MEDIUM", "LOW"}
        self.workers = workers
        self.extensions = extensions  # None = all text files

    def _collect_files(self, root: str) -> list[str]:
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune noise directories
            dirnames[:] = [d for d in dirnames if d not in NOISE_DIRS]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                if self.extensions:
                    if not any(fname.endswith(ext) for ext in self.extensions):
                        continue
                files.append(fpath)
        return files

    def scan(self, path: str) -> ScanResult:
        """Scan a directory or file recursively."""
        result = ScanResult()
        root = str(Path(path).resolve())

        if os.path.isfile(root):
            files = [root]
        else:
            files = self._collect_files(root)

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {
                executor.submit(
                    scan_file, f, self.patterns,
                    self.entropy_threshold, self.confidence_filter
                ): f
                for f in files
            }
            for future in as_completed(futures):
                fpath = futures[future]
                try:
                    findings, skipped = future.result()
                    result.findings.extend(findings)
                    result.skipped.extend(skipped)
                except Exception as e:
                    result.errors.append(
                        SkippedRecord(fpath, "scanner_exception", str(e)[:100])
                    )

        return result


# ── Policy Evaluation ─────────────────────────────────────────────────────────

def evaluate_policy(result: ScanResult,
                    mode: str = "balanced") -> PolicyDecision:
    """Return a CI/review decision from scan results."""
    high   = [f for f in result.findings if f.confidence == "HIGH"]
    medium = [f for f in result.findings if f.confidence == "MEDIUM"]
    skipped = len(result.skipped)
    errors  = len(result.errors)

    status: DecisionStatus = "pass"
    reasons: List[str] = []

    if high or medium:
        status = "fail"
        reasons.append("Findings require remediation or approved exception.")

    if mode == "strict" and skipped:
        status = "fail"
        reasons.append("Skipped content is not allowed in strict mode.")
    elif mode == "balanced" and skipped and status == "pass":
        status = "review"
        reasons.append("Skipped content requires reviewer approval.")

    if errors:
        status = "fail"
        reasons.append("Scanner errors must be resolved before approval.")

    return PolicyDecision(mode=mode, status=status, reasons=reasons)
