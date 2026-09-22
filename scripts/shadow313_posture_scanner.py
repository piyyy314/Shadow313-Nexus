#!/usr/bin/env python3
"""
shadow313_posture_scanner.py — Security Posture Measurement Scanner

Computes all Tier 1 (lagging) and Tier 2 (leading) metrics from the
current codebase state. Outputs a human-readable report and optional JSON.

Metrics:
  L-01  Security Debt Score (SDS)
  P-01  Exception-Without-Log Density (EWLD)
  P-05  Memory Budget Compliance Rate (MBCR)
  R-02  New-Code Violation Rate (NCVR)
  R-03  Gate Bypass Detection (GBD)
  R-05  Canary Test Failure Rate (CTFR)

Usage:
  python scripts/shadow313_posture_scanner.py
  python scripts/shadow313_posture_scanner.py --json
  python scripts/shadow313_posture_scanner.py --output report.json

Exit codes:
  0 = All metrics GREEN
  1 = One or more metrics YELLOW
  2 = One or more metrics RED
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

BOLD = "\033[1m"
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
C    = "\033[96m"
DIM  = "\033[2m"
RST  = "\033[0m"


class MetricResult(NamedTuple):
    name:             str
    code:             str
    value:            float
    unit:             str
    status:           str   # GREEN | YELLOW | RED
    threshold_green:  str
    threshold_yellow: str
    threshold_red:    str
    detail:           str


# ── Skip dirs ─────────────────────────────────────────────────────────────────

_SKIP = {"test", "skills/", ".git", "venv", "scripts/", "__pycache__"}


def _py_files(root: Path) -> list[Path]:
    return [f for f in root.rglob("*.py") if not any(p in str(f) for p in _SKIP)]


# ── Compiled patterns ─────────────────────────────────────────────────────────

_PAT_SILENT = re.compile(
    r"except\s+(Exception|BaseException)\s*:\s*\n\s*(pass|return\s+None)\s*$",
    re.MULTILINE,
)
_PAT_BARE = re.compile(r"^\s*except\s*:\s*$", re.MULTILINE)
_PAT_TIMING = re.compile(
    r"(token|secret|password|hash|sig(?:nature)?|key|auth)\s*==\s*"
    r"|==\s*(token|secret|password|hash|sig(?:nature)?|key|auth)",
    re.IGNORECASE,
)
_PAT_HARDCODED = re.compile(
    r"""(?i)(password|secret|api_key|token)\s*=\s*["'][^"'\\s]{6,}["']"""
)
_PAT_NO_TIMEOUT = re.compile(
    r"requests\.(get|post|put|delete|patch)\s*\([^)]*\)(?!.*timeout)",
    re.DOTALL,
)


# ── L-01: Security Debt Score ─────────────────────────────────────────────────

def compute_sds(root: Path) -> MetricResult:
    counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    details: list[str] = []

    for f in _py_files(root):
        try:
            src = f.read_text(errors="replace")
        except Exception:
            continue

        for m in _PAT_SILENT.finditer(src):
            line = src[: m.start()].count("\n") + 1
            # Get context to classify acceptable patterns
            ctx_start = max(0, line - 7)
            ctx = "\n".join(src.splitlines()[ctx_start:line])
            # Skip acceptable silent-except patterns:
            # network I/O (timeouts, banner grabs), optional library fallbacks,
            # file-read with safe default, callback isolation, parse fallbacks
            if any(kw in ctx for kw in [
                "asyncio", "socket", "connect", "banner", "wait_for",
                "urlopen", "urlreq", "urllib",
            ]):
                continue  # network I/O — silence is correct
            if any(kw in ctx for kw in ["import ", "ImportError"]):
                continue  # optional library fallback
            if any(kw in ctx for kw in [
                "read_text", "read_bytes", "json.loads", "json.load", "open(",
            ]):
                continue  # file read with safe default return
            if any(kw in ctx for kw in ["callback", "cb(", "_callbacks", "_hooks"]):
                continue  # callback isolation — caller errors must not propagate
            if any(kw in ctx for kw in ["parse", "fromstring", "loads", "decode"]):
                continue  # parse fallback
            # S01-fixed lines already have logging — skip them
            if "S01-fixed" in src.splitlines()[line - 1] if line <= len(src.splitlines()) else False:
                continue
            counts["HIGH"] += 1
            details.append(f"S01-SILENT-EXCEPT: {f.name}:{line}")

        for m in _PAT_BARE.finditer(src):
            counts["HIGH"] += 1
            line = src[: m.start()].count("\n") + 1
            details.append(f"S01-BARE-EXCEPT: {f.name}:{line}")

        for m in _PAT_TIMING.finditer(src):
            line = src[: m.start()].count("\n") + 1
            lines = src.splitlines()
            content = lines[line - 1].strip() if line <= len(lines) else ""
            # Skip: comment lines, nosec annotations, HTML event handlers,
            # dictionary/dataclass key lookups (e.key, entry.key, etc.)
            if content.startswith("#"):
                continue
            if "nosec" in content:
                continue
            if any(html in content for html in ["onkeydown", "onclick", "onchange", "oninput", "<input", "<button"]):
                continue
            if re.search(r'\b\w+\.key\s*==', content):
                continue  # dict/dataclass key lookup, not credential comparison
            counts["CRITICAL"] += 1
            details.append(f"S03-TIMING: {f.name}:{line}")

        for m in _PAT_HARDCODED.finditer(src):
            counts["CRITICAL"] += 1
            line = src[: m.start()].count("\n") + 1
            details.append(f"S06-HARDCODED: {f.name}:{line}")

        for _ in _PAT_NO_TIMEOUT.finditer(src):
            counts["MEDIUM"] += 1

    sds = (
        counts["CRITICAL"] * 100
        + counts["HIGH"]   * 10
        + counts["MEDIUM"] * 1
        + counts["LOW"]    * 0.1
    )

    status = "GREEN" if sds < 50 else ("YELLOW" if sds < 200 else "RED")

    detail = (
        f"CRIT={counts['CRITICAL']} HIGH={counts['HIGH']} "
        f"MED={counts['MEDIUM']} LOW={counts['LOW']}"
    )
    if details:
        detail += " | " + "; ".join(details[:5])
        if len(details) > 5:
            detail += f" ... +{len(details) - 5} more"

    return MetricResult(
        name="Security Debt Score", code="L-01",
        value=round(sds, 1), unit="points", status=status,
        threshold_green="< 50", threshold_yellow="50–200", threshold_red="≥ 200",
        detail=detail,
    )


# ── P-01: Exception-Without-Log Density ───────────────────────────────────────

def compute_ewld(root: Path) -> MetricResult:
    total_except  = 0
    silent_except = 0
    _any = re.compile(r"\bexcept\b", re.MULTILINE)

    _ACCEPTABLE_CTX = [
        "asyncio", "socket", "connect", "banner", "wait_for", "urlopen", "urlreq", "urllib",
        "import ", "ImportError",
        "read_text", "read_bytes", "json.loads", "json.load", "open(",
        "callback", "cb(", "_callbacks", "_hooks",
        "parse", "fromstring", "loads", "decode",
    ]

    for f in _py_files(root):
        try:
            src = f.read_text(errors="replace")
        except Exception:
            continue
        total_except += len(_any.findall(src))
        lines = src.splitlines()
        for m in _PAT_SILENT.finditer(src):
            line = src[: m.start()].count("\n") + 1
            ctx  = "\n".join(lines[max(0, line - 7): line])
            # Skip acceptable patterns — same logic as SDS
            if any(kw in ctx for kw in _ACCEPTABLE_CTX):
                continue
            # Skip already-fixed lines (have S01-fixed marker)
            if line <= len(lines) and "S01-fixed" in lines[line - 1]:
                continue
            silent_except += 1

    ewld   = (silent_except / total_except * 100) if total_except > 0 else 0.0
    status = "GREEN" if ewld == 0 else ("YELLOW" if ewld <= 5 else "RED")

    return MetricResult(
        name="Exception-Without-Log Density", code="P-01",
        value=round(ewld, 2), unit="%", status=status,
        threshold_green="0%", threshold_yellow="1–5%", threshold_red="> 5%",
        detail=f"{silent_except} silent / {total_except} total except clauses",
    )


# ── P-05: Memory Budget Compliance Rate ───────────────────────────────────────

def compute_mbcr(root: Path) -> MetricResult:
    classes_with_lists = 0
    classes_with_max   = 0
    violations: list[str] = []

    for f in _py_files(root):
        try:
            src  = f.read_text(errors="replace")
            tree = ast.parse(src)
        except Exception:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            has_list = False
            for child in ast.walk(node):
                if isinstance(child, ast.FunctionDef) and child.name == "__init__":
                    for stmt in ast.walk(child):
                        if isinstance(stmt, ast.Assign):
                            for tgt in stmt.targets:
                                if (
                                    isinstance(tgt, ast.Attribute)
                                    and isinstance(tgt.value, ast.Name)
                                    and tgt.value.id == "self"
                                    and isinstance(stmt.value, ast.List)
                                    and not stmt.value.elts
                                ):
                                    has_list = True

            if not has_list:
                continue

            classes_with_lists += 1
            has_max = any(
                isinstance(n, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id.startswith("_MAX_")
                    for t in n.targets
                )
                for n in ast.walk(node)
            )
            if has_max:
                classes_with_max += 1
            else:
                violations.append(f"{f.name}:{node.name}")

    mbcr   = (classes_with_max / classes_with_lists * 100) if classes_with_lists > 0 else 100.0
    status = "GREEN" if mbcr == 100 else ("YELLOW" if mbcr >= 90 else "RED")

    detail = f"{classes_with_max}/{classes_with_lists} classes compliant"
    if violations:
        detail += " | Missing _MAX_*: " + ", ".join(violations[:5])
        if len(violations) > 5:
            detail += f" +{len(violations) - 5} more"

    return MetricResult(
        name="Memory Budget Compliance Rate", code="P-05",
        value=round(mbcr, 1), unit="%", status=status,
        threshold_green="100%", threshold_yellow="90–99%", threshold_red="< 90%",
        detail=detail,
    )


# ── R-02: New-Code Violation Rate ─────────────────────────────────────────────

def compute_ncvr(root: Path) -> MetricResult:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=AM", "HEAD~14", "HEAD"],
            capture_output=True, text=True, cwd=str(root), timeout=10,
        )
        changed = [f for f in result.stdout.strip().split("\n") if f.endswith(".py") and f]
    except Exception:
        changed = []

    if not changed:
        return MetricResult(
            name="New-Code Violation Rate", code="R-02",
            value=0.0, unit="violations/1kLOC", status="GREEN",
            threshold_green="0", threshold_yellow="1–3", threshold_red="> 3",
            detail="No changed Python files in git history (or not a git repo)",
        )

    violations = 0
    new_lines   = 0
    _timing2    = re.compile(
        r"(token|secret|password|hash|sig(?:nature)?)\s*==\s*", re.IGNORECASE
    )

    for fname in changed:
        fpath = root / fname
        if not fpath.exists():
            continue
        try:
            src = fpath.read_text(errors="replace")
            new_lines  += len(src.splitlines())
            violations += len(_PAT_SILENT.findall(src))
            violations += len(_timing2.findall(src))
        except Exception:
            continue

    ncvr   = (violations / new_lines * 1000) if new_lines > 0 else 0.0
    status = "GREEN" if ncvr == 0 else ("YELLOW" if ncvr <= 3 else "RED")

    return MetricResult(
        name="New-Code Violation Rate", code="R-02",
        value=round(ncvr, 2), unit="violations/1kLOC", status=status,
        threshold_green="0", threshold_yellow="1–3", threshold_red="> 3",
        detail=f"{violations} violations in {new_lines} new lines across {len(changed)} files",
    )


# ── R-03: Gate Bypass Detection ───────────────────────────────────────────────

def compute_gbd(root: Path) -> MetricResult:
    try:
        reflog = subprocess.run(
            ["git", "reflog", "--format=%gs", "-200"],
            capture_output=True, text=True, cwd=str(root), timeout=10,
        )
        log = subprocess.run(
            ["git", "log", "--oneline", "-200"],
            capture_output=True, text=True, cwd=str(root), timeout=10,
        )
        bypasses = sum(
            1 for line in reflog.stdout.split("\n")
            if "no-verify" in line.lower()
        )
        total = max(len([l for l in log.stdout.split("\n") if l.strip()]), 1)
        gbd   = bypasses / total * 100
    except Exception:
        bypasses, total, gbd = 0, 0, 0.0

    status = "GREEN" if gbd == 0 else ("YELLOW" if gbd <= 1 else "RED")

    return MetricResult(
        name="Gate Bypass Detection", code="R-03",
        value=round(gbd, 2), unit="%", status=status,
        threshold_green="0%", threshold_yellow="0–1%", threshold_red="> 1%",
        detail=f"{bypasses} bypasses detected in last {total} commits",
    )


# ── R-05: Canary Test Failure Rate ────────────────────────────────────────────

def compute_canary(root: Path) -> MetricResult:
    failures: list[str] = []

    # Canary 1: silent exception pattern must be detectable
    canary1 = root / "scripts" / "_canary1.py"
    try:
        canary1.write_text(
            "def bad():\n"
            "    try:\n"
            "        x = 1\n"
            "    except Exception:\n"
            "        pass\n"
        )
        src = canary1.read_text()
        if not _PAT_SILENT.search(src):
            failures.append("Silent exception pattern not detectable by scanner regex")
    except Exception as e:
        failures.append(f"Canary 1 error: {e}")
    finally:
        canary1.unlink(missing_ok=True)

    # Canary 2: unbounded list pattern must be detectable via AST
    canary2 = root / "scripts" / "_canary2.py"
    try:
        canary2.write_text(
            "class Unbounded:\n"
            "    def __init__(self):\n"
            "        self._data = []\n"
        )
        src  = canary2.read_text()
        tree = ast.parse(src)
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for child in ast.walk(node):
                    if isinstance(child, ast.FunctionDef) and child.name == "__init__":
                        for stmt in ast.walk(child):
                            if isinstance(stmt, ast.Assign):
                                for tgt in stmt.targets:
                                    if (
                                        isinstance(tgt, ast.Attribute)
                                        and isinstance(tgt.value, ast.Name)
                                        and tgt.value.id == "self"
                                        and isinstance(stmt.value, ast.List)
                                        and not stmt.value.elts
                                    ):
                                        found = True
        if not found:
            failures.append("Unbounded list pattern not detectable by AST scanner")
    except Exception as e:
        failures.append(f"Canary 2 error: {e}")
    finally:
        canary2.unlink(missing_ok=True)

    # Canary 3: pytest importable and test files exist
    try:
        import pytest  # noqa: F401
        test_count = len(list((root / "tests").rglob("test_*.py")))
        if test_count == 0:
            failures.append("No test files found — test suite may be missing")
        else:
            pass  # healthy
    except ImportError:
        failures.append("pytest not importable — test infrastructure broken")

    ctfr   = len(failures) / 3 * 100
    status = "GREEN" if ctfr == 0 else "RED"

    return MetricResult(
        name="Canary Test Failure Rate", code="R-05",
        value=round(ctfr, 1), unit="%", status=status,
        threshold_green="0%", threshold_yellow="N/A", threshold_red="> 0%",
        detail=(
            "; ".join(failures) if failures
            else "All 3 enforcement canaries verified working"
        ),
    )


# ── Report printer ────────────────────────────────────────────────────────────

STATUS_COLORS = {"GREEN": G, "YELLOW": Y, "RED": R}
STATUS_ICONS  = {"GREEN": "●", "YELLOW": "◐", "RED": "○"}
TIER_LABELS   = {
    "L": "LAGGING INDICATORS  (Outcomes — confirm improvement happened)",
    "P": "LEADING INDICATORS  (Predictors — warn before regression)",
    "R": "REGRESSION DETECTORS (Fire before production)",
}


def print_report(metrics: list[MetricResult], scan_time: str) -> str:
    worst = "GREEN"
    for m in metrics:
        if m.status == "RED":
            worst = "RED"
        elif m.status == "YELLOW" and worst != "RED":
            worst = "YELLOW"

    overall_col = STATUS_COLORS[worst]

    print(f"\n{BOLD}{C}{'=' * 72}{RST}")
    print(f"{BOLD}{C}  Shadow313 NEXUS — Security Posture Report{RST}")
    print(f"  {DIM}Scanned: {scan_time}{RST}")
    print(f"{BOLD}{C}{'=' * 72}{RST}")
    print(f"\n  {BOLD}Overall Posture: {overall_col}{worst}{RST}\n")

    current_tier = None
    for m in metrics:
        tier = m.code[0]
        if tier != current_tier:
            current_tier = tier
            label = TIER_LABELS.get(tier, tier)
            print(f"  {BOLD}{Y}-- {label} --{RST}")

        col  = STATUS_COLORS[m.status]
        icon = STATUS_ICONS[m.status]
        print(f"\n  {col}{icon} [{m.code}]{RST} {BOLD}{m.name}{RST}")
        print(
            f"      Value:  {BOLD}{m.value} {m.unit}{RST}   "
            f"({G}GREEN{RST}: {m.threshold_green}  "
            f"{Y}YELLOW{RST}: {m.threshold_yellow}  "
            f"{R}RED{RST}: {m.threshold_red})"
        )
        print(f"      Detail: {DIM}{m.detail}{RST}")

    print(f"\n{BOLD}{C}{'=' * 72}{RST}\n")
    return worst


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Shadow313 Security Posture Scanner")
    parser.add_argument("--json",   action="store_true", help="Output JSON report")
    parser.add_argument("--output", default=None,        help="Save JSON report to file")
    parser.add_argument("--root",   default=".",         help="Repository root path")
    args = parser.parse_args()

    root      = Path(args.root).resolve()
    scan_time = datetime.utcnow().isoformat() + "Z"

    print(f"Scanning {root} ...")

    metrics = [
        compute_sds(root),
        compute_ewld(root),
        compute_mbcr(root),
        compute_ncvr(root),
        compute_gbd(root),
        compute_canary(root),
    ]

    if args.json or args.output:
        report = {
            "scan_time": scan_time,
            "root":      str(root),
            "overall":   max(
                (m.status for m in metrics),
                key=lambda s: {"GREEN": 0, "YELLOW": 1, "RED": 2}[s],
            ),
            "metrics": [m._asdict() for m in metrics],
        }
        json_str = json.dumps(report, indent=2)
        if args.output:
            Path(args.output).write_text(json_str)
            print(f"Report saved to {args.output}")
        if args.json:
            print(json_str)
            return {"GREEN": 0, "YELLOW": 1, "RED": 2}[report["overall"]]

    worst = print_report(metrics, scan_time)
    return {"GREEN": 0, "YELLOW": 1, "RED": 2}[worst]


if __name__ == "__main__":
    sys.exit(main())