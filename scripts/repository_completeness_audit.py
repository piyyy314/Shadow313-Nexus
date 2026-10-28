#!/usr/bin/env python3
"""Shadow313 NEXUS repository completeness auditor.

Static, read-only audit that inventories Python modules, tests, API routes,
CLI surfaces, detectors, Sigma rules, CI workflows, packaging, containers,
version references, markers, imports, and test traceability.

Exit codes: 0=PASS, 1=WARNING, 2=FAIL, 3=tool/configuration error.
Python: 3.11+
"""
from __future__ import annotations

import argparse
import ast
import csv
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

TOOL_VERSION = "1.0.0"
DEFAULT_SOURCE_ROOTS = (
    "shadow313", "nexus_toolkit", "shadow313_platform", "shadow313_sdk",
    "sentinelos", "api", "cyber_lab",
)
DEFAULT_EXCLUDES = (
    ".git/*", ".venv/*", "venv/*", "env/*", "__pycache__/*", ".pytest_cache/*",
    ".mypy_cache/*", ".ruff_cache/*", "node_modules/*", "dist/*", "build/*",
    "site-packages/*", "docs-archive/*", "audit-results/*",
)
ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "websocket", "route", "api_route"}
TEST_NAME_RE = re.compile(r"(^test_.*\.py$|.*_test\.py$)", re.I)
MARKER_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|STUB|NOT_IMPLEMENTED)\b", re.I)
VERSION_RE = re.compile(r"(?<!\d)(?:v)?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)(?!\d)", re.I)
SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"
)
PLACEHOLDER_SECRET_RE = re.compile(r"(?i)^(changeme|example|placeholder|replace[_-]?me|your[_-]?.*|test|dummy|none|null|\*+)$")
FAIL_OPEN_RE = re.compile(r"(?:\|\|\s*true|continue-on-error\s*:\s*true)", re.I)

@dataclass
class Finding:
    id: str
    severity: str
    category: str
    message: str
    path: str = ""
    line: int | None = None
    evidence: str = ""
    remediation: str = ""

@dataclass
class Route:
    method: str
    path: str
    handler: str
    file: str
    line: int
    framework: str
    auth_hint: bool
    test_matches: list[str] = field(default_factory=list)

@dataclass
class CliSurface:
    name: str
    handler: str
    file: str
    line: int
    framework: str
    test_matches: list[str] = field(default_factory=list)

@dataclass
class ModuleRecord:
    module: str
    path: str
    package: str
    has_test: bool
    test_matches: list[str]
    parse_error: str = ""

@dataclass
class AuditState:
    root: Path
    out: Path
    files: list[Path] = field(default_factory=list)
    python_files: list[Path] = field(default_factory=list)
    test_files: list[Path] = field(default_factory=list)
    source_files: list[Path] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    cli: list[CliSurface] = field(default_factory=list)
    modules: list[ModuleRecord] = field(default_factory=list)
    imports: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    versions: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    markers: list[dict[str, Any]] = field(default_factory=list)
    detector_files: list[str] = field(default_factory=list)
    sigma_files: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def excluded(path: Path, root: Path, patterns: tuple[str, ...]) -> bool:
    value = rel(path, root)
    return any(fnmatch.fnmatch(value, p) or fnmatch.fnmatch(value + "/", p) for p in patterns)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def add_finding(state: AuditState, severity: str, category: str, message: str,
                path: str = "", line: int | None = None, evidence: str = "",
                remediation: str = "") -> None:
    digest = hashlib.sha1(f"{category}|{path}|{line}|{message}".encode()).hexdigest()[:10]
    state.findings.append(Finding(f"S313-{digest}", severity, category, message, path, line, evidence[:500], remediation))


def discover(state: AuditState, excludes: tuple[str, ...], source_roots: tuple[str, ...]) -> None:
    state.files = sorted(p for p in state.root.rglob("*") if p.is_file() and not excluded(p, state.root, excludes))
    state.python_files = [p for p in state.files if p.suffix == ".py"]
    state.test_files = [p for p in state.python_files if "tests" in p.parts or TEST_NAME_RE.match(p.name)]
    roots = {state.root / x for x in source_roots}
    state.source_files = [p for p in state.python_files if any(r == p or r in p.parents for r in roots) and p not in state.test_files]
    state.metadata.update({
        "tool": "Shadow313 Repository Completeness Auditor",
        "tool_version": TOOL_VERSION,
        "root": str(state.root),
        "generated_epoch": int(time.time()),
        "source_roots": list(source_roots),
        "file_count": len(state.files),
        "python_file_count": len(state.python_files),
        "source_file_count": len(state.source_files),
        "test_file_count": len(state.test_files),
    })


def dotted_module(path: Path, root: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def get_decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = get_decorator_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    if isinstance(node, ast.Call):
        return get_decorator_name(node.func)
    return ""


def literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return "<dynamic>"


def scan_ast(state: AuditState, source_roots: tuple[str, ...]) -> None:
    test_blob = "\n".join(read_text(p) for p in state.test_files)
    test_names = {rel(p, state.root): read_text(p) for p in state.test_files}
    top_packages = {x for x in source_roots if (state.root / x).exists()}

    for path in state.source_files:
        rp = rel(path, state.root)
        text = read_text(path)
        module = dotted_module(path, state.root)
        likely = path.stem if path.stem != "__init__" else path.parent.name
        matches = [name for name, body in test_names.items() if likely.lower() in name.lower() or module in body or likely in body]
        record = ModuleRecord(module, rp, module.split(".")[0] if module else "", bool(matches), matches[:20])
        try:
            tree = ast.parse(text, filename=rp)
        except SyntaxError as exc:
            record.parse_error = f"{exc.msg} at line {exc.lineno}"
            add_finding(state, "FAIL", "syntax", "Python source cannot be parsed", rp, exc.lineno, exc.msg,
                        "Fix the syntax error before running deeper checks.")
            state.modules.append(record)
            continue
        state.modules.append(record)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    state.imports[module].add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    state.imports[module].add(node.module)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dname = get_decorator_name(dec)
                    tail = dname.split(".")[-1].lower()
                    if tail in ROUTE_METHODS and isinstance(dec, ast.Call):
                        route_path = literal_string(dec.args[0] if dec.args else None)
                        method = tail.upper()
                        if tail in {"route", "api_route"}:
                            for kw in dec.keywords:
                                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                    vals = [literal_string(x).upper() for x in kw.value.elts]
                                    method = ",".join(vals) or "ROUTE"
                        auth = any(x in text[max(0, node.lineno-25)*1:] for x in ("Depends(", "Security(", "@require_auth", "current_user"))
                        tokens = [node.name, route_path.strip("/").replace("/", "_")]
                        tm = [n for n, body in test_names.items() if any(t and (t in body or t in n) for t in tokens)]
                        framework = "FastAPI/Starlette" if tail in ROUTE_METHODS else "unknown"
                        state.routes.append(Route(method, route_path, node.name, rp, node.lineno, framework, auth, tm[:20]))
                    if tail in {"command", "callback"}:
                        name = node.name
                        if isinstance(dec, ast.Call) and dec.args:
                            name = literal_string(dec.args[0])
                        tm = [n for n, body in test_names.items() if name in body or name in n]
                        state.cli.append(CliSurface(name, node.name, rp, node.lineno, "click/typer", tm[:20]))
            if isinstance(node, ast.Call):
                call_name = get_decorator_name(node.func)
                if call_name.endswith("add_parser") or call_name.endswith("add_command"):
                    name = literal_string(node.args[0] if node.args else None)
                    tm = [n for n, body in test_names.items() if name != "<dynamic>" and (name in body or name in n)]
                    state.cli.append(CliSurface(name, "<registration>", rp, getattr(node, "lineno", 0), "argparse/click", tm[:20]))

        if not record.has_test and path.name != "__init__.py":
            add_finding(state, "WARN", "test-coverage", "No traceable test found for source module", rp,
                        remediation="Add a behavioral unit or integration test and reference the module directly.")

        for imported in state.imports[module]:
            top = imported.split(".")[0]
            if top in top_packages:
                candidate = state.root.joinpath(*imported.split("."))
                if not (candidate.with_suffix(".py").exists() or candidate.is_dir()):
                    add_finding(state, "FAIL", "imports", f"Local import target appears missing: {imported}", rp,
                                remediation="Correct the import or restore the missing module/package.")

    for route in state.routes:
        if not route.test_matches:
            add_finding(state, "FAIL", "api", f"API route lacks a traceable test: {route.method} {route.path}",
                        route.file, route.line, route.handler,
                        "Add happy-path, validation, auth, error, and schema tests for this route.")
    for item in state.cli:
        if not item.test_matches and item.name != "<dynamic>":
            add_finding(state, "WARN", "cli", f"CLI command lacks a traceable test: {item.name}", item.file, item.line,
                        remediation="Add --help, valid invocation, invalid argument, and failure-path tests.")


def scan_structure(state: AuditState, source_roots: tuple[str, ...]) -> None:
    for root_name in source_roots:
        base = state.root / root_name
        if not base.exists():
            add_finding(state, "WARN", "structure", f"Expected source root is missing: {root_name}", remediation="Confirm the component is required or remove it from the audit configuration.")
            continue
        for directory in [p for p in base.rglob("*") if p.is_dir()]:
            if excluded(directory, state.root, DEFAULT_EXCLUDES):
                continue
            has_py = any(x.suffix == ".py" for x in directory.iterdir() if x.is_file())
            if has_py and not (directory / "__init__.py").exists():
                add_finding(state, "INFO", "structure", "Python directory has no __init__.py (namespace package or omission)", rel(directory, state.root),
                            remediation="Confirm namespace-package intent; otherwise add __init__.py.")

    required = ["README.md", "pyproject.toml", "LICENSE", "SECURITY.md", "CHANGELOG.md", ".gitignore"]
    for name in required:
        if not (state.root / name).exists():
            add_finding(state, "FAIL", "required-files", f"Required repository file missing: {name}", remediation="Add and maintain this project-governance file.")


def scan_text(state: AuditState) -> None:
    text_exts = {".py", ".md", ".toml", ".yml", ".yaml", ".json", ".txt", ".ini", ".cfg", ".html", ".ps1", ".sh", ".xml"}
    for path in state.files:
        if path.suffix.lower() not in text_exts and path.name not in {"Dockerfile"}:
            continue
        rp = rel(path, state.root)
        text = read_text(path)
        for idx, line in enumerate(text.splitlines(), 1):
            m = MARKER_RE.search(line)
            if m:
                item = {"marker": m.group(1).upper(), "path": rp, "line": idx, "text": line.strip()[:300]}
                state.markers.append(item)
                sev = "WARN" if m.group(1).upper() in {"FIXME", "STUB", "NOT_IMPLEMENTED"} else "INFO"
                add_finding(state, sev, "markers", f"{m.group(1).upper()} marker found", rp, idx, line.strip(), "Resolve or link to a tracked issue before release.")
            for vm in VERSION_RE.finditer(line):
                state.versions[vm.group(1)].append({"path": rp, "line": idx, "text": line.strip()[:250]})
            sm = SECRET_RE.search(line)
            if sm and not PLACEHOLDER_SECRET_RE.match(sm.group(2).strip()):
                add_finding(state, "FAIL", "secrets", f"Possible hard-coded secret assigned to {sm.group(1)}", rp, idx,
                            f"{sm.group(1)}=<redacted>", "Remove it, rotate if real, and use environment or secret-manager injection.")
        if rp.startswith(".github/workflows/") and FAIL_OPEN_RE.search(text):
            for idx, line in enumerate(text.splitlines(), 1):
                if FAIL_OPEN_RE.search(line):
                    add_finding(state, "FAIL", "ci", "Fail-open CI instruction found", rp, idx, line.strip(), "Remove fail-open behavior from release-blocking validation.")

    current_versions = {v: refs for v, refs in state.versions.items() if any(not r["path"].startswith(("docs-archive/", "CHANGELOG")) for r in refs)}
    semvers = [v for v in current_versions if re.fullmatch(r"\d+\.\d+\.\d+", v)]
    if len(semvers) > 1:
        add_finding(state, "WARN", "versioning", f"Multiple active semantic versions found: {', '.join(sorted(semvers))}",
                    remediation="Use one canonical version source and generate other current-version references.")


def scan_detectors_and_rules(state: AuditState) -> None:
    for path in state.source_files:
        rp = rel(path, state.root)
        text = read_text(path).lower()
        if "detector" in path.name.lower() or "class " in text and "detector" in text:
            state.detector_files.append(rp)
            stem = path.stem
            matches = [rel(t, state.root) for t in state.test_files if stem in t.name or stem in read_text(t)]
            if not matches:
                add_finding(state, "FAIL", "detectors", "Detector implementation lacks a traceable test", rp,
                            remediation="Add known-positive, known-negative, malformed, empty, and boundary fixtures.")
    sigma_root = state.root / "sigma" / "rules"
    if sigma_root.exists():
        for path in sigma_root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
                rp = rel(path, state.root)
                state.sigma_files.append(rp)
                text = read_text(path)
                for key in ("title:", "id:", "status:", "logsource:", "detection:", "condition:"):
                    if key not in text:
                        add_finding(state, "FAIL", "sigma", f"Sigma rule missing required field: {key[:-1]}", rp,
                                    remediation="Complete the rule and validate it with a Sigma validator.")


def scan_packaging(state: AuditState) -> None:
    pyproject = state.root / "pyproject.toml"
    text = read_text(pyproject)
    if pyproject.exists():
        if "[project.scripts]" not in text:
            add_finding(state, "WARN", "packaging", "No [project.scripts] entry found", "pyproject.toml")
        urls = re.findall(r"https://github\.com/[^\s\"']+", text)
        for url in urls:
            if "piyyy314/Shadow313-Nexus" not in url:
                add_finding(state, "WARN", "metadata", f"Potential non-canonical GitHub URL in package metadata: {url}", "pyproject.toml",
                            remediation="Point active package metadata to the canonical repository and issue tracker.")
    if (state.root / "conftest.py").exists() and "sys.path" in read_text(state.root / "conftest.py"):
        add_finding(state, "WARN", "packaging", "Root conftest.py modifies sys.path and may mask wheel omissions", "conftest.py",
                    remediation="Add a clean-wheel test in an isolated environment outside the repository.")


def scan_containers(state: AuditState) -> None:
    dockerfile = state.root / "Dockerfile"
    if dockerfile.exists():
        text = read_text(dockerfile)
        images = re.findall(r"(?im)^FROM\s+([^\s]+)", text)
        state.metadata["docker_base_images"] = images
        if not re.search(r"(?im)^USER\s+(?!root\b)\S+", text):
            add_finding(state, "WARN", "container", "Dockerfile does not clearly switch to a non-root USER", "Dockerfile")
        if "HEALTHCHECK" not in text.upper():
            add_finding(state, "WARN", "container", "Dockerfile has no HEALTHCHECK", "Dockerfile")
    else:
        add_finding(state, "FAIL", "container", "Dockerfile is missing")
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = state.root / name
        if p.exists():
            text = read_text(p)
            if "seccomp:unconfined" in text.replace(" ", ""):
                add_finding(state, "FAIL", "container", "Compose uses seccomp:unconfined", name,
                            remediation="Use the runtime default or a reviewed custom seccomp profile for production.")
            if "healthcheck:" not in text.lower():
                add_finding(state, "WARN", "container", "Compose file has no healthcheck declarations", name)


def git_metadata(state: AuditState) -> None:
    def run(*args: str) -> str:
        try:
            return subprocess.check_output(args, cwd=state.root, stderr=subprocess.DEVNULL, text=True, timeout=5).strip()
        except Exception:
            return ""
    state.metadata["git_commit"] = run("git", "rev-parse", "HEAD")
    state.metadata["git_branch"] = run("git", "branch", "--show-current")
    status = run("git", "status", "--porcelain")
    state.metadata["git_dirty"] = bool(status)


def summarize(state: AuditState) -> dict[str, Any]:
    counts = Counter(f.severity for f in state.findings)
    categories = Counter(f.category for f in state.findings)
    status = "FAIL" if counts["FAIL"] else "WARNING" if counts["WARN"] else "PASS"
    return {
        "status": status,
        "severity_counts": dict(counts),
        "category_counts": dict(categories),
        "route_count": len(state.routes),
        "untested_route_count": sum(not x.test_matches for x in state.routes),
        "cli_surface_count": len(state.cli),
        "untested_cli_count": sum(not x.test_matches for x in state.cli),
        "module_count": len(state.modules),
        "untested_module_count": sum(not x.has_test and not x.path.endswith("/__init__.py") for x in state.modules),
        "detector_file_count": len(set(state.detector_files)),
        "sigma_rule_count": len(state.sigma_files),
        "marker_count": len(state.markers),
        "version_count": len(state.versions),
    }


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(state: AuditState) -> dict[str, Any]:
    state.out.mkdir(parents=True, exist_ok=True)
    summary = summarize(state)
    report = {
        "metadata": state.metadata,
        "summary": summary,
        "findings": [asdict(x) for x in state.findings],
        "modules": [asdict(x) for x in state.modules],
        "api_routes": [asdict(x) for x in state.routes],
        "cli_surfaces": [asdict(x) for x in state.cli],
        "versions": state.versions,
        "markers": state.markers,
        "detector_files": sorted(set(state.detector_files)),
        "sigma_files": sorted(state.sigma_files),
        "imports": {k: sorted(v) for k, v in sorted(state.imports.items())},
    }
    (state.out / "repository-audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_csv(state.out / "findings.csv", [asdict(x) for x in state.findings], list(Finding.__dataclass_fields__))
    write_csv(state.out / "api-endpoints.csv", [asdict(x) | {"test_matches": ";".join(x.test_matches)} for x in state.routes], list(Route.__dataclass_fields__))
    write_csv(state.out / "cli-surfaces.csv", [asdict(x) | {"test_matches": ";".join(x.test_matches)} for x in state.cli], list(CliSurface.__dataclass_fields__))
    write_csv(state.out / "module-inventory.csv", [asdict(x) | {"test_matches": ";".join(x.test_matches)} for x in state.modules], list(ModuleRecord.__dataclass_fields__))

    lines = [
        "# Shadow313 NEXUS Repository Completeness Audit", "",
        f"**Result:** {summary['status']}",
        f"**Commit:** `{state.metadata.get('git_commit') or 'unknown'}`",
        f"**Branch:** `{state.metadata.get('git_branch') or 'unknown'}`", "",
        "## Executive summary", "",
        f"- Findings: {len(state.findings)} ({summary['severity_counts']})",
        f"- Source modules: {summary['module_count']}",
        f"- Modules without traceable tests: {summary['untested_module_count']}",
        f"- API routes: {summary['route_count']}",
        f"- API routes without traceable tests: {summary['untested_route_count']}",
        f"- CLI surfaces: {summary['cli_surface_count']}",
        f"- CLI surfaces without traceable tests: {summary['untested_cli_count']}",
        f"- Detector files: {summary['detector_file_count']}",
        f"- Sigma rules: {summary['sigma_rule_count']}",
        f"- TODO/FIXME/STUB markers: {summary['marker_count']}", "",
        "## Findings by category", "",
    ]
    for category, count in sorted(summary["category_counts"].items()):
        lines.append(f"- **{category}**: {count}")
    lines += ["", "## Detailed findings", ""]
    for f in sorted(state.findings, key=lambda x: ({"FAIL": 0, "WARN": 1, "INFO": 2}.get(x.severity, 9), x.category, x.path, x.line or 0)):
        location = f" `{f.path}:{f.line}`" if f.path and f.line else f" `{f.path}`" if f.path else ""
        lines.append(f"### [{f.severity}] {f.id} - {f.category}{location}")
        lines.append(f.message)
        if f.evidence:
            lines.append(f"\nEvidence: `{f.evidence.replace('`', chr(39))}`")
        if f.remediation:
            lines.append(f"\nRemediation: {f.remediation}")
        lines.append("")
    lines += ["## Output files", "", "- `repository-audit.json`", "- `findings.csv`", "- `api-endpoints.csv`", "- `cli-surfaces.csv`", "- `module-inventory.csv`", ""]
    (state.out / "remediation-report.md").write_text("\n".join(lines), encoding="utf-8")
    return summary


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Audit Shadow313 repository completeness without modifying the repository.")
    p.add_argument("--root", default=".", help="Repository root (default: current directory)")
    p.add_argument("--output", default="audit-results", help="Output directory, relative to root unless absolute")
    p.add_argument("--source-root", action="append", dest="source_roots", help="Source root; repeat to override defaults")
    p.add_argument("--exclude", action="append", default=[], help="Additional glob exclusion; repeat as needed")
    p.add_argument("--strict", action="store_true", help="Return exit 2 for WARN as well as FAIL")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print(f"ERROR: repository root does not exist: {root}", file=sys.stderr)
        return 3
    out = Path(args.output).expanduser()
    if not out.is_absolute():
        out = root / out
    source_roots = tuple(args.source_roots or DEFAULT_SOURCE_ROOTS)
    excludes = tuple(DEFAULT_EXCLUDES) + tuple(args.exclude) + (rel(out, root) + "/*",)
    state = AuditState(root=root, out=out)
    try:
        discover(state, excludes, source_roots)
        git_metadata(state)
        scan_structure(state, source_roots)
        scan_ast(state, source_roots)
        scan_text(state)
        scan_detectors_and_rules(state)
        scan_packaging(state)
        scan_containers(state)
        summary = write_outputs(state)
    except Exception as exc:
        print(f"ERROR: audit aborted: {exc}", file=sys.stderr)
        return 3
    if not args.quiet:
        print("Shadow313 NEXUS Repository Completeness Audit")
        print(f"Result: {summary['status']}")
        print(f"Findings: {summary['severity_counts']}")
        print(f"Modules: {summary['module_count']} | API routes: {summary['route_count']} | CLI: {summary['cli_surface_count']}")
        print(f"Reports: {out}")
    if summary["status"] == "FAIL":
        return 2
    if summary["status"] == "WARNING":
        return 2 if args.strict else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
