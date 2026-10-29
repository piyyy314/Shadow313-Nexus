"""shadow313.modules.vuln.vuln_module — VulnModule orchestrator."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

from .cve_db       import CVEDatabase
from .dep_audit    import DependencyAuditor
from .exploit_check import ExploitChecker
from .cvss         import CVSSScorer


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


SERVICE_KEYWORDS = {
    "openssh": "OpenSSH", "apache": "Apache httpd", "nginx": "nginx",
    "vsftpd": "vsftpd", "mysql": "MySQL", "mariadb": "MariaDB",
    "postgres": "PostgreSQL", "iis": "Microsoft IIS", "tomcat": "Apache Tomcat",
    "php": "PHP", "openssl": "OpenSSL", "samba": "Samba",
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
}


class VulnModule:
    """shadow313.vuln — CVE correlation, risk scoring, AI triage."""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session
        self.db      = CVEDatabase()
        self.scorer  = CVSSScorer()
        self.checker = ExploitChecker()

    def register(self, kernel) -> None:
        kernel.register("vuln", self.run)

    def run(self, from_session: str = "", target: str = "",
            audit_deps: str = "", quick: bool = False,
            internet_facing: bool = False, epss: bool = False,
            kev: bool = False, attack_map: bool = False) -> dict:
        self.out.section("VULNERABILITY ANALYSIS")
        self.session.audit("vuln", "start")

        result: dict[str, Any] = {
            "timestamp":   _now(),
            "findings":    [],
            "dep_audit":   [],
            "risk_matrix": [],
            "epss_stub":   {},
        }

        recon_data = self._load_recon(from_session)

        if recon_data:
            ports = recon_data.get("ports", [])
            if ports:
                self.out.info(f"Mapping {len(ports)} services to CVEs …")
                findings = self._map_services(ports)
                result["findings"] = findings
                self._print_findings(findings)

        if target and not recon_data:
            self.out.info(f"Quick CVE search for '{target}' …")
            result["findings"] = self.db.search_by_keyword(target, limit=20)
            self._print_findings(result["findings"])

        if audit_deps:
            self.out.info(f"Auditing dependencies: {audit_deps} …")
            auditor = DependencyAuditor(self.db)
            result["dep_audit"] = auditor.audit_file(audit_deps)
            self._print_dep_audit(result["dep_audit"])

        if not quick and result["findings"]:
            self.out.info("Checking exploit availability …")
            for f in result["findings"][:10]:
                cve = f.get("cve", "")
                if cve and cve.startswith("CVE-"):
                    exploit_info = self.checker.check(cve)
                    f["exploit"]    = exploit_info
                    f["has_poc"]    = exploit_info.get("poc_count", 0) > 0
                    f["risk_score"] = self.scorer.contextual_score(
                        f.get("cvss_v3", 0), f.get("has_poc", False), internet_facing
                    )

        result["risk_matrix"] = self._build_risk_matrix(result["findings"])

        self.out.info("Running AI triage …")
        result["ai_triage"] = self._ai_triage(result)
        self.out.ai_response(result["ai_triage"], "AI Vulnerability Triage")

        path = self.session.write("findings.json", result)
        self.session.write("risk_matrix.json", result["risk_matrix"])
        self.out.success(f"Findings saved → {path}")
        self.session.audit("vuln", "complete", str(path))
        return result

    def update_cve_db(self, keyword: str = "critical", api_key: str = "") -> None:
        self.out.info(f"Updating CVE DB for keyword '{keyword}' …")
        records = self.db.update_from_nvd(keyword, api_key)
        self.out.success(f"Fetched {len(records)} records. DB total: {self.db.record_count():,}")

    def ai_context(self) -> dict:
        data = self.session.read("findings.json") or {}
        findings = data.get("findings", [])
        return {
            "module":          "vuln",
            "total_findings":  len(findings),
            "critical_count":  sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high_count":      sum(1 for f in findings if f.get("severity") == "HIGH"),
            "top_cves":        [f.get("cve") for f in findings[:5]],
        }

    def _load_recon(self, from_session: str) -> dict | None:
        if from_session:
            from shadow313.core.session import Session
            s = Session.resume(from_session)
            return s.read("recon.json")
        return self.session.read("recon.json")

    def _map_services(self, ports: list[dict]) -> list[dict]:
        all_findings: list[dict] = []
        seen: set[str] = set()
        for svc in ports:
            banner = svc.get("banner", "").lower()
            port   = svc.get("port", 0)
            for keyword, nvd_term in SERVICE_KEYWORDS.items():
                if keyword in banner:
                    hits = self.db.search_by_keyword(nvd_term, limit=10)
                    for h in hits:
                        key = h["cve"]
                        if key not in seen:
                            h["port"]   = port
                            h["banner"] = banner[:100]
                            h["matched_service"] = nvd_term
                            seen.add(key)
                            all_findings.append(h)
        return sorted(all_findings, key=lambda x: x.get("cvss_v3", 0), reverse=True)

    def _build_risk_matrix(self, findings: list[dict]) -> list[dict]:
        matrix = []
        for f in findings:
            cvss = f.get("cvss_v3", 0.0)
            matrix.append({
                "cve":        f.get("cve", ""),
                "severity":   f.get("severity", "UNKNOWN"),
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
        rows = [[f.get("cve", ""), f.get("severity", ""), f.get("cvss_v3", ""),
                 f.get("description", "")[:60]] for f in findings[:20]]
        self.out.table(["CVE", "Severity", "CVSS", "Description"], rows,
                       title=f"Vulnerabilities ({len(findings)} found)")

    def _print_dep_audit(self, findings: list[dict]) -> None:
        if not findings:
            self.out.success("No known vulnerabilities in dependencies.")
            return
        rows = [[f.get("package", ""), f.get("version", ""),
                 f.get("cve", ""), f.get("cvss_v3", "")] for f in findings[:20]]
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