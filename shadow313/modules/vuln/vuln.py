"""
shadow313.modules.vuln
Vulnerability analysis — CVE correlation, CVSS scoring, exploit availability,
dependency auditing, and AI-driven triage.
"""
from __future__ import annotations
import json
import re
import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urlreq


# ── Constants ─────────────────────────────────────────────────────────────────

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_DB_PATH = Path("~/.shadow313/cve.db").expanduser()

SEVERITY_MAP = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   4.0,
    "LOW":      0.1,
    "NONE":     0.0,
}

EXPLOIT_DB_SEARCH = "https://www.exploit-db.com/search?cve={cve}"
POC_GITHUB_API    = "https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── CVE Database ──────────────────────────────────────────────────────────────

class CVEDatabase:
    """
    Local SQLite CVE mirror.
    Schema mirrors NVD JSON 2.0 feed key fields.
    Populated via `shadow313 update --db cve`.
    """

    def __init__(self, db_path: Path = CVE_DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id          TEXT PRIMARY KEY,
                description TEXT,
                cvss_v3     REAL,
                severity    TEXT,
                published   TEXT,
                modified    TEXT,
                cpe         TEXT,
                cve_references  TEXT
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cpe_cve (
                cpe TEXT,
                cve TEXT,
                PRIMARY KEY (cpe, cve)
            )
        """)
        self._conn.commit()

    def search_by_keyword(self, keyword: str, limit: int = 20) -> list[dict]:
        cur = self._conn.execute(
            "SELECT id, description, cvss_v3, severity, published FROM cves "
            "WHERE description LIKE ? OR id LIKE ? ORDER BY cvss_v3 DESC LIMIT ?",
            (f"%{keyword}%", f"%{keyword}%", limit),
        )
        return [{"cve": r[0], "description": r[1][:200],
                 "cvss_v3": r[2], "severity": r[3], "published": r[4]}
                for r in cur.fetchall()]

    def search_by_cpe(self, cpe: str, limit: int = 20) -> list[dict]:
        cur = self._conn.execute(
            "SELECT c.id, c.description, c.cvss_v3, c.severity FROM cves c "
            "JOIN cpe_cve m ON c.id = m.cve WHERE m.cpe LIKE ? "
            "ORDER BY c.cvss_v3 DESC LIMIT ?",
            (f"%{cpe}%", limit),
        )
        return [{"cve": r[0], "description": r[1][:200],
                 "cvss_v3": r[2], "severity": r[3]}
                for r in cur.fetchall()]

    def get_cve(self, cve_id: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT id, description, cvss_v3, severity, published, modified, "
            "cpe, cve_references FROM cves WHERE id = ?", (cve_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "cve":         row[0], "description": row[1],
            "cvss_v3":     row[2], "severity":    row[3],
            "published":   row[4], "modified":    row[5],
            "cpe":         row[6], "cve_references":  row[7],
        }

    def insert_cve(self, cve: dict) -> None:
        self._conn.execute("""
            INSERT OR REPLACE INTO cves
            (id, description, cvss_v3, severity, published, modified, cpe, cve_references)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve.get("id"), cve.get("description", ""),
            cve.get("cvss_v3", 0.0), cve.get("severity", ""),
            cve.get("published", ""), cve.get("modified", ""),
            json.dumps(cve.get("cpe", [])),
            json.dumps(cve.get("cve_references", [])),
        ))
        self._conn.commit()

    def record_count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM cves")
        return cur.fetchone()[0]

    def update_from_nvd(self, keyword: str, api_key: str = "") -> list[dict]:
        """Fetch from NVD API and insert into local DB."""
        headers = {}
        if api_key:
            headers["apiKey"] = api_key
        url = f"{NVD_API}?keywordSearch={keyword}&resultsPerPage=50"
        try:
            req = urlreq.Request(url, headers={
                "User-Agent": "shadow313/1.0",
                **headers,
            })
            with urlreq.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as exc:
            return [{"error": str(exc)}]

        fetched = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            descs    = cve_data.get("descriptions", [])
            desc     = next((d["value"] for d in descs if d["lang"] == "en"), "")
            metrics  = cve_data.get("metrics", {})
            cvss_v3  = 0.0
            severity = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key in metrics and metrics[key]:
                    cvss_v3  = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                    severity = metrics[key][0]["cvssData"].get("baseSeverity", "")
                    break
            record = {
                "id":          cve_id,
                "description": desc,
                "cvss_v3":     cvss_v3,
                "severity":    severity,
                "published":   cve_data.get("published", ""),
                "modified":    cve_data.get("lastModified", ""),
                "cpe":         [],
                "cve_references":  [r["url"] for r in cve_data.get("cve_references", [])[:5]],
            }
            self.insert_cve(record)
            fetched.append(record)
        return fetched


# ── Service version → CVE mapper ──────────────────────────────────────────────

class ServiceVulnMapper:
    """Maps banner/version strings to CVE candidates via local DB + keyword."""

    SERVICE_KEYWORDS = {
        "openssh":  "OpenSSH",
        "apache":   "Apache httpd",
        "nginx":    "nginx",
        "vsftpd":   "vsftpd",
        "proftpd":  "ProFTPD",
        "mysql":    "MySQL",
        "mariadb":  "MariaDB",
        "postgres": "PostgreSQL",
        "iis":      "Microsoft IIS",
        "tomcat":   "Apache Tomcat",
        "php":      "PHP",
        "openssl":  "OpenSSL",
        "samba":    "Samba",
        "wordpress":"WordPress",
    }

    def __init__(self, db: CVEDatabase) -> None:
        self.db = db

    def map_banner(self, banner: str) -> list[dict]:
        """Find CVEs matching a service banner string."""
        banner_lc = banner.lower()
        results   = []
        for keyword, nvd_term in self.SERVICE_KEYWORDS.items():
            if keyword in banner_lc:
                hits = self.db.search_by_keyword(nvd_term, limit=10)
                for h in hits:
                    h["matched_service"] = nvd_term
                results.extend(hits)
        return results

    def map_service_list(self, services: list[dict]) -> list[dict]:
        """Process a list of port-scan service dicts."""
        all_findings = []
        seen         = set()
        for svc in services:
            banner   = svc.get("banner", "")
            port     = svc.get("port", 0)
            for finding in self.map_banner(banner):
                key = finding["cve"]
                if key not in seen:
                    finding["port"] = port
                    finding["banner"] = banner[:100]
                    seen.add(key)
                    all_findings.append(finding)
        return sorted(all_findings, key=lambda x: x.get("cvss_v3", 0), reverse=True)


# ── Dependency auditor ────────────────────────────────────────────────────────

class DependencyAuditor:
    """Audit package dependency files for known vulnerabilities."""

    PARSERS = {
        "requirements.txt": "_parse_requirements",
        "package.json":     "_parse_package_json",
        "go.mod":           "_parse_go_mod",
        "Gemfile.lock":     "_parse_gemfile",
        "Cargo.toml":       "_parse_cargo",
    }

    def __init__(self, db: CVEDatabase) -> None:
        self.db = db

    def audit_file(self, path: str) -> list[dict]:
        try:
            p = Path(path).expanduser().resolve()
        except Exception as exc:
            return [{"error": f"Invalid path: {exc}"}]
        if not p.exists():
            return [{"error": f"File not found: {path}"}]
        # Reject paths that look like system files outside project scope
        _BLOCKED = ('/etc/passwd', '/etc/shadow', '/proc/', '/sys/', '/dev/')
        if any(str(p).startswith(b) for b in _BLOCKED):
            return [{"error": f"Access denied: {path}"}]
        parser_method = self.PARSERS.get(p.name)
        if not parser_method:
            return [{"error": f"Unsupported file: {p.name}"}]
        packages = getattr(self, parser_method)(p.read_text(errors="replace"))
        findings = []
        for pkg, ver in packages.items():
            hits = self.db.search_by_keyword(pkg, limit=5)
            for h in hits:
                h["package"]    = pkg
                h["version"]    = ver
                h["dep_source"] = p.name
                findings.append(h)
        return sorted(findings, key=lambda x: x.get("cvss_v3", 0), reverse=True)

    def _parse_requirements(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:\[[^\]]*\])?([>=<!~^]+)(.+)?", line)
            if match:
                pkgs[match.group(1).lower()] = match.group(3) or ""
        return pkgs

    def _parse_package_json(self, text: str) -> dict[str, str]:
        try:
            data = json.loads(text)
            pkgs = {}
            for section in ("dependencies", "devDependencies"):
                pkgs.update({k.lower(): v for k, v in
                             data.get(section, {}).items()})
            return pkgs
        except Exception:
            return {}

    def _parse_go_mod(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            m = re.match(r"\s+(\S+)\s+v(\S+)", line)
            if m:
                pkgs[m.group(1).split("/")[-1].lower()] = m.group(2)
        return pkgs

    def _parse_gemfile(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            m = re.match(r"\s+(\w[\w\-]+)\s+\((.+)\)", line)
            if m:
                pkgs[m.group(1).lower()] = m.group(2)
        return pkgs

    def _parse_cargo(self, text: str) -> dict[str, str]:
        pkgs = {}
        for line in text.splitlines():
            m = re.match(r'(\w[\w\-]+)\s*=\s*"(.+)"', line)
            if m:
                pkgs[m.group(1).lower()] = m.group(2)
        return pkgs


# ── Exploit availability checker ──────────────────────────────────────────────

def check_exploit_availability(cve_id: str) -> dict:
    """Check GitHub PoC index for exploit availability."""
    try:
        url = POC_GITHUB_API.format(cve=cve_id)
        req = urlreq.Request(url, headers={"User-Agent": "shadow313/1.0"})
        with urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        pocs = data.get("pocs", [])
        return {
            "cve":           cve_id,
            "poc_count":     len(pocs),
            "exploit_db_url": EXPLOIT_DB_SEARCH.format(cve=cve_id),
            "pocs": [{"url": p.get("html_url"), "stars": p.get("stargazers_count", 0)}
                     for p in pocs[:5]],
        }
    except Exception:
        return {"cve": cve_id, "poc_count": 0, "pocs": []}


# ── Risk scorer ───────────────────────────────────────────────────────────────

def compute_risk_score(cvss: float, has_exploit: bool,
                       is_internet_facing: bool) -> float:
    """Adjust CVSS with contextual factors."""
    score = cvss
    if has_exploit:
        score = min(10.0, score * 1.3)
    if is_internet_facing:
        score = min(10.0, score * 1.1)
    return round(score, 1)


# ── VulnModule ────────────────────────────────────────────────────────────────

class VulnModule:
    """
    shadow313.vuln — CVE correlation, risk scoring, AI triage.
    Registered commands: vuln
    """

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session
        self.db      = CVEDatabase()

    def register(self, kernel) -> None:
        kernel.register("vuln", self.run)

    # ── Entry point ───────────────────────────────────────────────────────────
    def run(self, from_session: str = "", target: str = "",
            audit_deps: str = "", quick: bool = False,
            internet_facing: bool = False) -> dict:
        self.out.section("VULNERABILITY ANALYSIS")
        self.session.audit("vuln", "start")

        result: dict[str, Any] = {
            "timestamp": _now(),
            "findings":  [],
            "dep_audit": [],
            "risk_matrix": [],
        }

        # Load recon data
        recon_data = self._load_recon(from_session)

        # Service → CVE mapping
        if recon_data:
            ports = recon_data.get("ports", [])
            if ports:
                self.out.info(f"Mapping {len(ports)} services to CVEs …")
                mapper   = ServiceVulnMapper(self.db)
                findings = mapper.map_service_list(ports)
                result["findings"] = findings
                self._print_findings(findings)

        # Single target quick scan
        if target and not recon_data:
            self.out.info(f"Quick CVE search for '{target}' …")
            result["findings"] = self.db.search_by_keyword(target, limit=20)
            self._print_findings(result["findings"])

        # Dependency audit
        if audit_deps:
            self.out.info(f"Auditing dependencies: {audit_deps} …")
            auditor = DependencyAuditor(self.db)
            result["dep_audit"] = auditor.audit_file(audit_deps)
            self._print_dep_audit(result["dep_audit"])

        # Exploit availability (top 10 findings, skip in quick mode)
        if not quick and result["findings"]:
            self.out.info("Checking exploit availability …")
            top = result["findings"][:10]
            for f in top:
                cve = f.get("cve", "")
                if cve and cve.startswith("CVE-"):
                    exploit_info = check_exploit_availability(cve)
                    f["exploit"]  = exploit_info
                    f["has_poc"]  = exploit_info.get("poc_count", 0) > 0
                    f["risk_score"] = compute_risk_score(
                        f.get("cvss_v3", 0),
                        f.get("has_poc", False),
                        internet_facing,
                    )

        # Build risk matrix
        result["risk_matrix"] = self._build_risk_matrix(result["findings"])

        # AI triage
        self.out.info("Running AI triage …")
        result["ai_triage"] = self._ai_triage(result)
        self.out.ai_response(result["ai_triage"], "AI Vulnerability Triage")

        path = self.session.write("findings.json", result)
        self.out.success(f"Findings saved → {path}")
        self.session.audit("vuln", "complete", str(path))
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _load_recon(self, from_session: str) -> dict | None:
        if from_session:
            from shadow313.core.session import Session
            s = Session.resume(from_session)
            return s.read("recon.json")
        return self.session.read("recon.json")

    def _build_risk_matrix(self, findings: list[dict]) -> list[dict]:
        matrix = []
        for f in findings:
            cvss  = f.get("cvss_v3", 0.0)
            sev   = f.get("severity", "UNKNOWN")
            matrix.append({
                "cve":        f.get("cve", ""),
                "severity":   sev,
                "cvss_v3":    cvss,
                "risk_score": f.get("risk_score", cvss),
                "has_poc":    f.get("has_poc", False),
                "service":    f.get("matched_service", f.get("package", "")),
            })
        return sorted(matrix, key=lambda x: x["risk_score"], reverse=True)

    def _print_findings(self, findings: list[dict]) -> None:
        if not findings:
            self.out.warn("No CVE findings matched.")
            return
        rows = [
            [f.get("cve", ""), f.get("severity", ""), f.get("cvss_v3", ""),
             f.get("description", "")[:60]]
            for f in findings[:20]
        ]
        self.out.table(["CVE", "Severity", "CVSS", "Description"], rows,
                       title=f"Vulnerabilities ({len(findings)} found)")

    def _print_dep_audit(self, findings: list[dict]) -> None:
        if not findings:
            self.out.success("No known vulnerabilities in dependencies.")
            return
        rows = [[f.get("package", ""), f.get("version", ""),
                 f.get("cve", ""), f.get("cvss_v3", "")]
                for f in findings[:20]]
        self.out.table(["Package", "Version", "CVE", "CVSS"], rows,
                       title="Dependency Vulnerabilities")

    def _ai_triage(self, data: dict) -> str:
        top = sorted(data.get("findings", []),
                     key=lambda x: x.get("cvss_v3", 0), reverse=True)[:15]
        ctx = {
            "top_findings":   top,
            "dep_findings":   data.get("dep_audit", [])[:10],
            "total_findings": len(data.get("findings", [])),
        }
        return self.ai.chat(
            "As a security triage analyst, rank these vulnerabilities by actual risk. "
            "Consider: CVSS score, exploit availability, service exposure. "
            "Output a prioritized remediation plan with: (1) immediate actions, "
            "(2) short-term patches, (3) long-term hardening. Be concise.",
            context=ctx,
        )

    def update_cve_db(self, keyword: str = "critical", api_key: str = "") -> None:
        self.out.info(f"Updating CVE DB for keyword '{keyword}' …")
        records = self.db.update_from_nvd(keyword, api_key)
        self.out.success(f"Fetched {len(records)} records. "
                         f"DB total: {self.db.record_count():,}")