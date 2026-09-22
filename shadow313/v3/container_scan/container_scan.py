"""
shadow313.v3.container_scan.container_scan  — v4
OCI image layer CVE analysis, Dockerfile linting, base image risk scoring.

BUG FIXES:
  - Dockerfile parser split on newlines but didn't handle line continuations
    (backslash at end of line) — now joins continuation lines.
  - _score_base_image() returned None for unknown images instead of a dict —
    fixed to always return a dict.
  - Docker SDK calls had no timeout — added timeout parameter.
"""
from __future__ import annotations
import re
import subprocess
from pathlib import Path
from typing import Any


# ── Dockerfile linter ─────────────────────────────────────────────────────────

DOCKERFILE_RULES = [
    ("DF-ROOT-USER",    r"^USER\s+root",                "HIGH",   "Container runs as root — use non-root USER"),
    ("DF-LATEST-TAG",   r"FROM\s+\S+:latest",           "MEDIUM", "Using :latest tag — pin to specific version"),
    ("DF-NO-HEALTHCHECK",None,                           "LOW",    "No HEALTHCHECK instruction"),
    ("DF-ADD-INSTEAD-COPY",r"^ADD\s+",                  "LOW",    "Use COPY instead of ADD (unless extracting archives)"),
    ("DF-CURL-PIPE-BASH",r"curl\s+.*\|\s*(bash|sh)",    "CRITICAL","curl | bash pattern — arbitrary code execution risk"),
    ("DF-WGET-PIPE-BASH",r"wget\s+.*\|\s*(bash|sh)",    "CRITICAL","wget | bash pattern — arbitrary code execution risk"),
    ("DF-HARDCODED-SECRET",r"(password|secret|key|token)\s*=\s*\S+","CRITICAL","Hardcoded secret in Dockerfile"),
    ("DF-PRIVILEGED",   r"--privileged",                "CRITICAL","--privileged flag — full host access"),
    ("DF-NO-USER",      None,                           "MEDIUM", "No USER instruction — defaults to root"),
    ("DF-APT-NO-CLEAN", r"apt-get install(?!.*rm -rf /var/lib/apt)", "LOW", "apt-get install without cleanup increases image size"),
    ("DF-EXPOSE-ALL",   r"EXPOSE\s+0\.0\.0\.0",         "MEDIUM", "Exposing on all interfaces"),
    ("DF-SECRETS-IN-ENV",r"ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN)\s*=","CRITICAL","Secret in ENV instruction"),
]


def _join_continuations(text: str) -> list[str]:
    """FIX: join backslash-continued lines before parsing."""
    lines = []
    current = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
        else:
            current += stripped
            lines.append(current)
            current = ""
    if current:
        lines.append(current)
    return lines


class DockerfileLinter:
    def lint(self, dockerfile_path: str) -> list[dict]:
        path = Path(dockerfile_path)
        if not path.exists():
            return [{"rule": "ERROR", "detail": f"File not found: {dockerfile_path}", "severity": "INFO"}]

        text  = path.read_text(errors="replace")
        lines = _join_continuations(text)

        findings = []
        has_user       = any(re.match(r"^USER\s+(?!root)", l, re.IGNORECASE) for l in lines)
        has_healthcheck= any(re.match(r"^HEALTHCHECK", l, re.IGNORECASE) for l in lines)

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for rule_id, pattern, severity, detail in DOCKERFILE_RULES:
                if pattern is None:
                    continue
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append({
                        "rule":     rule_id,
                        "line":     lineno,
                        "severity": severity,
                        "detail":   detail,
                        "code":     stripped[:100],
                    })

        # Structural checks
        if not has_user:
            findings.append({"rule": "DF-NO-USER", "line": 0, "severity": "MEDIUM",
                             "detail": "No non-root USER instruction found"})
        if not has_healthcheck:
            findings.append({"rule": "DF-NO-HEALTHCHECK", "line": 0, "severity": "LOW",
                             "detail": "No HEALTHCHECK instruction"})

        return findings


# ── Base image risk scorer ────────────────────────────────────────────────────

BASE_IMAGE_RISK: dict[str, dict] = {
    "scratch":          {"risk": "LOW",    "note": "Minimal attack surface"},
    "alpine":           {"risk": "LOW",    "note": "Minimal Alpine Linux"},
    "distroless":       {"risk": "LOW",    "note": "Google distroless — no shell"},
    "debian:slim":      {"risk": "LOW",    "note": "Slim Debian variant"},
    "ubuntu":           {"risk": "MEDIUM", "note": "Full Ubuntu — larger attack surface"},
    "debian":           {"risk": "MEDIUM", "note": "Full Debian"},
    "centos":           {"risk": "HIGH",   "note": "CentOS EOL — no longer maintained"},
    "python":           {"risk": "MEDIUM", "note": "Official Python image"},
    "node":             {"risk": "MEDIUM", "note": "Official Node.js image"},
    "openjdk":          {"risk": "MEDIUM", "note": "Official OpenJDK image"},
    "nginx":            {"risk": "MEDIUM", "note": "Official Nginx image"},
    "redis":            {"risk": "LOW",    "note": "Official Redis image"},
    "postgres":         {"risk": "LOW",    "note": "Official PostgreSQL image"},
    "mysql":            {"risk": "MEDIUM", "note": "Official MySQL image"},
    "latest":           {"risk": "HIGH",   "note": "Unpinned :latest tag"},
}


def _score_base_image(image: str) -> dict:
    """FIX: always return a dict, never None."""
    image_lower = image.lower()
    for key, info in BASE_IMAGE_RISK.items():
        if key in image_lower:
            return {"image": image, **info}
    return {"image": image, "risk": "UNKNOWN", "note": "Unknown base image — manual review required"}


# ── Image CVE scanner ─────────────────────────────────────────────────────────

class ImageCVEScanner:
    """Scans Docker images for CVEs using Trivy (if available) or Grype."""

    def scan(self, image: str) -> list[dict]:
        # Try Trivy first
        result = self._try_trivy(image)
        if result is not None:
            return result
        # Try Grype
        result = self._try_grype(image)
        if result is not None:
            return result
        return [{"note": "No scanner available. Install trivy or grype for CVE scanning.",
                 "image": image}]

    def _try_trivy(self, image: str) -> list[dict] | None:
        try:
            proc = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", image],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                return None
            import json
            data = json.loads(proc.stdout)
            findings = []
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    findings.append({
                        "cve":         vuln.get("VulnerabilityID", ""),
                        "package":     vuln.get("PkgName", ""),
                        "version":     vuln.get("InstalledVersion", ""),
                        "fixed_in":    vuln.get("FixedVersion", ""),
                        "severity":    vuln.get("Severity", "").upper(),
                        "description": vuln.get("Description", "")[:200],
                        "scanner":     "trivy",
                    })
            return findings
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            return None

    def _try_grype(self, image: str) -> list[dict] | None:
        try:
            proc = subprocess.run(
                ["grype", image, "-o", "json"],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                return None
            import json
            data = json.loads(proc.stdout)
            findings = []
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                findings.append({
                    "cve":      vuln.get("id", ""),
                    "package":  match.get("artifact", {}).get("name", ""),
                    "version":  match.get("artifact", {}).get("version", ""),
                    "severity": vuln.get("severity", "").upper(),
                    "scanner":  "grype",
                })
            return findings
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            return None


# ── ContainerScanModule ───────────────────────────────────────────────────────

class ContainerScanModule:
    """shadow313.v3.container_scan — Container/image scanning. Registered: container_scan"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        self._linter = DockerfileLinter()
        self._scanner= ImageCVEScanner()

    def register(self, kernel) -> None:
        kernel.register("container_scan", self.run)

    def run(
        self,
        image: str = "",
        dockerfile: str = "",
        scan_dir: str = "",
    ) -> dict:
        self.out.section("CONTAINER SECURITY SCAN")
        result: dict[str, Any] = {}

        # Dockerfile linting
        if dockerfile or scan_dir:
            dockerfiles = []
            if dockerfile:
                dockerfiles = [dockerfile]
            elif scan_dir:
                dockerfiles = [str(p) for p in Path(scan_dir).rglob("Dockerfile*")]

            all_lint = []
            for df in dockerfiles:
                self.out.info(f"Linting Dockerfile: {df} …")
                findings = self._linter.lint(df)
                all_lint.extend(findings)

                # Extract base image for risk scoring
                try:
                    text = Path(df).read_text(errors="replace")
                    from_match = re.search(r"^FROM\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
                    if from_match:
                        base_image = from_match.group(1)
                        risk = _score_base_image(base_image)
                        result["base_image_risk"] = risk
                        self.out.info(f"Base image: {base_image} — Risk: {risk['risk']}")
                except Exception as _exc:  # S01-fixed
                    import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
                    pass

            result["dockerfile_findings"] = all_lint
            if all_lint:
                rows = [[f["rule"], f.get("line",0), f["severity"], f["detail"][:60]]
                        for f in all_lint[:20]]
                self.out.table(["Rule","Line","Severity","Detail"], rows,
                               f"Dockerfile Issues ({len(all_lint)})")
            else:
                self.out.success("No Dockerfile issues found.")

        # Image CVE scan
        if image:
            self.out.info(f"Scanning image for CVEs: {image} …")
            cve_findings = self._scanner.scan(image)
            result["cve_findings"] = cve_findings

            critical = [f for f in cve_findings if f.get("severity") == "CRITICAL"]
            high     = [f for f in cve_findings if f.get("severity") == "HIGH"]
            self.out.info(f"CVEs: {len(cve_findings)} total, {len(critical)} CRITICAL, {len(high)} HIGH")

            if cve_findings and "note" not in cve_findings[0]:
                rows = [[f.get("cve",""), f.get("package",""), f.get("version",""),
                         f.get("severity",""), f.get("fixed_in","")]
                        for f in sorted(cve_findings, key=lambda x: x.get("severity",""), reverse=True)[:20]]
                self.out.table(["CVE","Package","Version","Severity","Fixed In"], rows,
                               "Container CVEs")

        # AI analysis
        result["ai_analysis"] = self.kernel.ai.chat(
            "Analyse these container security findings. Prioritize critical issues, "
            "explain the risk of each Dockerfile pattern, and recommend remediation steps.",
            context=result,
        )
        self.out.ai_response(result["ai_analysis"], "Container Security Analysis")

        self.session.write("container_scan.json", result)
        return result