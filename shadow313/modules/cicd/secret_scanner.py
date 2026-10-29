"""shadow313.modules.cicd.secret_scanner — 13-pattern secret scanner with entropy detection."""
from __future__ import annotations
import math
import re
from pathlib import Path

PATTERNS: list[tuple[str, str, str]] = [
    ("SECRET-AWS-KEY",      "AWS Access Key ID",           r"AKIA[0-9A-Z]{16}"),
    ("SECRET-AWS-SECRET",   "AWS Secret Access Key",       r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    ("SECRET-GITHUB-TOKEN", "GitHub Personal Access Token",r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
    ("SECRET-SLACK-TOKEN",  "Slack Token",                 r"xox[baprs]-[A-Za-z0-9\-]{10,48}"),
    ("SECRET-PRIVATE-KEY",  "Private Key Material",        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
    ("SECRET-GENERIC-KEY",  "Generic API Key",             r"(?i)(api[_\-]?key|apikey|secret[_\-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9]{20,}"),
    ("SECRET-DB-PASSWORD",  "Database Password",           r"(?i)(db_password|database_password|mysql_password|postgres_password)\s*[=:]\s*['\"]?\S{8,}"),
    ("SECRET-GOOGLE-KEY",   "Google API Key",              r"AIza[0-9A-Za-z\-_]{35}"),
    ("SECRET-STRIPE-KEY",   "Stripe Secret Key",           r"sk_live_[A-Za-z0-9]{24,}"),
    ("SECRET-JWT",          "JSON Web Token",              r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    ("SECRET-SENDGRID",     "SendGrid API Key",            r"SG\.[A-Za-z0-9\-._]{22,}\.[A-Za-z0-9\-._]{43,}"),
    ("SECRET-HARDCODED-PW", "Hardcoded Password",          r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]"),
    ("SECRET-OTX-KEY",      "AlienVault OTX API Key",      r"[0-9a-f]{64}"),
]

HIGH_ENTROPY_THRESHOLD = 4.5
HIGH_ENTROPY_MIN_LEN   = 20

IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                     ".woff", ".woff2", ".ttf", ".eot", ".map", ".lock",
                     ".min.js", ".min.css", ".pdf", ".zip", ".tar", ".gz"}
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv",
               "venv", "env", "dist", "build", ".mypy_cache"}


def _shannon_entropy(s: str) -> float:
    """Return character entropy in bits, or zero for an empty string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


class SecretScanner:
    def scan_directory(self, path: str, max_file_size: int = 1_000_000) -> list[dict]:
        """Return secret findings from eligible files recursively below path.

        Skip ignored directories, extensions, and files larger than
        max_file_size bytes. File read failures yield no findings; filesystem
        errors during traversal or size checks can propagate.
        """
        findings = []
        base = Path(path)
        for fpath in base.rglob("*"):
            if fpath.is_file():
                if any(part in self.IGNORE_DIRS for part in fpath.parts):
                    continue
                if fpath.suffix.lower() in IGNORE_EXTENSIONS:
                    continue
                if fpath.stat().st_size > max_file_size:
                    continue
                findings.extend(self._scan_file(fpath))
        return findings

    def scan_diff(self, diff_text: str) -> list[dict]:
        """Return pattern and entropy findings from added lines in a unified diff.

        Line numbers refer to the diff text, starting at one. Finding content
        is truncated and partially redacted, so it may still contain secrets.
        """
        findings = []
        lines    = diff_text.splitlines()
        current_file = ""
        for lineno, line in enumerate(lines, 1):
            if line.startswith("--- ") or line.startswith("+++ "):
                current_file = line[4:].strip().lstrip("b/")
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                for rule_id, desc, pattern in PATTERNS:
                    if re.search(pattern, content):
                        findings.append({
                            "rule_id":  rule_id, "desc": desc,
                            "file":     current_file, "line": lineno,
                            "content":  self._redact(content.strip()[:120]),
                            "severity": "critical", "source": "git_diff",
                        })
                # High entropy check
                for token in re.findall(r"[A-Za-z0-9+/=_\-]{20,}", content):
                    if _shannon_entropy(token) >= HIGH_ENTROPY_THRESHOLD:
                        findings.append({
                            "rule_id":  "SECRET-HIGH-ENTROPY",
                            "desc":     "High-entropy string detected",
                            "file":     current_file, "line": lineno,
                            "content":  self._redact(token[:40]),
                            "severity": "high", "source": "git_diff",
                        })
                        break
        return findings

    def _scan_file(self, path: Path) -> list[dict]:
        """Return findings with one-based source line numbers, or [] on read failure.

        Content is truncated and partially redacted; some secrets may remain.
        """
        findings = []
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except Exception:
            return []
        for lineno, line in enumerate(lines, 1):
            for rule_id, desc, pattern in PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "rule_id":  rule_id, "desc": desc,
                        "file":     str(path), "line": lineno,
                        "content":  self._redact(line.strip()[:120]),
                        "severity": "critical", "source": "file_scan",
                    })
            for token in re.findall(r"[A-Za-z0-9+/=_\-]{20,}", line):
                if _shannon_entropy(token) >= HIGH_ENTROPY_THRESHOLD:
                    findings.append({
                        "rule_id":  "SECRET-HIGH-ENTROPY",
                        "desc":     "High-entropy string detected",
                        "file":     str(path), "line": lineno,
                        "content":  self._redact(token[:40]),
                        "severity": "high", "source": "file_scan",
                    })
                    break
        return findings

    @staticmethod
    def _redact(text: str) -> str:
        """Mask supported AWS keys, GitHub tokens, and quoted assignments in text."""
        patterns = [
            (r"(AKIA[0-9A-Z]{4})[0-9A-Z]{12}", r"\1************"),
            (r"(ghp_[A-Za-z0-9]{6})[A-Za-z0-9]{30}", r"\1****...****"),
            (r"=['\"]([A-Za-z0-9+/=]{20,})['\"]", r"='***REDACTED***'"),
        ]
        for pat, repl in patterns:
            try:
                text = re.sub(pat, repl, text)
            except re.error:
                pass
        return text

    # Expose IGNORE_DIRS as class attribute for external use
    IGNORE_DIRS = IGNORE_DIRS