"""shadow313.modules.quantum.quantum_module — QuantumModule orchestrator."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .quantum_data  import NIST_PQC_STANDARDS, classify_algorithm
from .tls_scanner   import TLSScanner
from .cert_auditor  import CertificateAuditor
from .code_scanner  import SourceCodeScanner
from .timeline      import estimate_threat_timeline


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class QuantumModule:
    """shadow313.quantum — Post-quantum cryptography audit."""

    def __init__(self, kernel) -> None:
        """Bind cryptography audits to kernel output, AI, and session services."""
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        """Register the quantum command with the supplied kernel."""
        kernel.register("quantum", self.run)

    def run(self, scan_host: str = "", audit_certs: str = "",
            scan_code: str = "", lang: str = "",
            report: bool = False, output: str = "rich",
            scan_cert: str = "") -> dict:
        """Run requested crypto audits, request an AI roadmap, and save quantum_report.json.

        scan_host accepts host[:port], using 443 for absent or nonnumeric ports.
        audit_certs overrides scan_cert; certificate and code inputs may be files
        or directories. report includes the bundled PQC reference data. output
        is unused. Session writes and uncaught scan errors propagate.
        """
        self.out.section("QUANTUM CRYPTOGRAPHY AUDIT")
        self.session.audit("quantum", "start")

        result: dict[str, Any] = {
            "timestamp": _now(), "findings": [], "algorithms_found": [],
        }

        # TLS endpoint scan
        if scan_host:
            host_str = scan_host.split(":")[0]
            port_str = scan_host.split(":")[-1] if ":" in scan_host else "443"
            try:
                port = int(port_str)
            except ValueError:
                port = 443
            self.out.info(f"Scanning TLS endpoint {host_str}:{port} …")
            tls_result = TLSScanner(host_str, port).scan()
            result["tls"] = tls_result
            if tls_result.get("error"):
                self.out.warn(f"TLS scan: {tls_result['error']}")
            else:
                self.out.info(f"TLS: {tls_result.get('tls_version', 'unknown')}  "
                              f"Cipher: {tls_result.get('cipher_suite', 'unknown')}")
                cert = tls_result.get("cert_info", {})
                if cert.get("days_left", 999) < 30:
                    self.out.warn(f"Certificate expires in {cert.get('days_left')} days!")
                tls_findings = tls_result.get("findings", [])
                result["findings"].extend(tls_findings)
                for finding in tls_findings:
                    result["algorithms_found"].append(
                        finding.get("cipher", scan_host).split("-")[0]
                    )

        # Certificate audit
        cert_path = audit_certs or scan_cert
        if cert_path:
            self.out.info(f"Auditing certificates in {cert_path} …")
            auditor      = CertificateAuditor()
            cert_results = (
                auditor.audit_directory(cert_path)
                if Path(cert_path).is_dir()
                else [auditor.audit_file(cert_path)]
            )
            result["certificates"] = cert_results
            for cr in cert_results:
                for f in cr.get("findings", []):
                    result["findings"].append(f)
                    result["algorithms_found"].append(f.get("algorithm", ""))
                    if f.get("quantum") == "VULNERABLE":
                        self.out.finding(
                            f"Certificate: {cr.get('subject', cr.get('path', ''))}",
                            "HIGH", f"{f['algorithm']} — {f['reason']}",
                        )

        # Source code scan
        if scan_code:
            self.out.info(f"Scanning source code: {scan_code} …")
            scanner      = SourceCodeScanner(lang=lang or None)
            code_findings = (
                scanner.scan_directory(scan_code)
                if Path(scan_code).is_dir()
                else scanner.scan_file(scan_code)
            )
            result["code_findings"] = code_findings
            result["findings"].extend(code_findings)
            result["algorithms_found"].extend(
                [f.get("algorithm", "") for f in code_findings]
            )
            if code_findings:
                rows = [[Path(f["file"]).name, f["line"], f["algorithm"],
                         f["quantum"], f["code"][:50]] for f in code_findings[:30]]
                self.out.table(
                    ["File", "Line", "Algorithm", "Quantum", "Code"],
                    rows, f"Source Code Crypto Scan ({len(code_findings)} findings)"
                )
            else:
                self.out.success("No quantum-vulnerable crypto usage found in source code.")

        # Risk timeline
        algos_unique = list(set(result["algorithms_found"]))
        if algos_unique:
            result["threat_timeline"] = estimate_threat_timeline(algos_unique)
            tl = result["threat_timeline"]
            self.out.warn(f"Threat Timeline: {tl['risk_level']} risk — {tl['harvest_now_threat']}")

        # PQC migration map
        result["pqc_mapping"] = self._build_pqc_mapping(result["findings"])
        if result["pqc_mapping"]:
            rows = [[m["from"], m["to"], m["fips"], m["priority"]]
                    for m in result["pqc_mapping"]]
            self.out.table(["Current Algorithm", "PQC Replacement", "FIPS Standard", "Priority"],
                           rows, "NIST PQC Migration Map")

        # AI migration roadmap
        self.out.info("Generating AI PQC migration roadmap …")
        result["ai_roadmap"] = self._ai_roadmap(result)
        self.out.ai_response(result["ai_roadmap"], "AI Post-Quantum Migration Roadmap")

        if report:
            result["nist_pqc_standards"] = NIST_PQC_STANDARDS

        path = self.session.write("quantum_report.json", result)
        self.out.success(f"Quantum audit saved → {path}")
        self.session.audit("quantum", "complete", str(path))
        return result

    def ai_context(self) -> dict:
        """Summarize saved quantum findings and threat risk for AI requests."""
        data = self.session.read("quantum_report.json") or {}
        findings = data.get("findings", [])
        return {
            "module":          "quantum",
            "vulnerable_count": sum(1 for f in findings if f.get("quantum") == "VULNERABLE"),
            "weakened_count":   sum(1 for f in findings if f.get("quantum") == "WEAKENED"),
            "risk_level":       data.get("threat_timeline", {}).get("risk_level", "UNKNOWN"),
        }

    def _build_pqc_mapping(self, findings: list[dict]) -> list[dict]:
        """Return one replacement mapping per algorithm with a nonempty recommendation."""
        mapping = []
        seen    = set()
        priority_map = {"VULNERABLE": "IMMEDIATE", "WEAKENED": "SHORT-TERM", "UNKNOWN": "ASSESS"}
        for f in findings:
            algo = f.get("algorithm", "")
            repl = f.get("replace", "")
            vuln = f.get("quantum", "UNKNOWN")
            if algo and repl and algo not in seen:
                seen.add(algo)
                pqc_info = {}
                for name, info in NIST_PQC_STANDARDS.items():
                    if name.upper().replace("-", "") in repl.upper().replace("-", "").replace("_", ""):
                        pqc_info = info
                        break
                mapping.append({
                    "from":     algo,
                    "to":       repl,
                    "fips":     pqc_info.get("fips", "See NIST PQC"),
                    "priority": priority_map.get(vuln, "ASSESS"),
                })
        return mapping

    def _ai_roadmap(self, data: dict) -> str:
        """Request an AI migration roadmap using findings, replacement mappings, and risk data."""
        vuln_count = sum(1 for f in data.get("findings", []) if f.get("quantum") == "VULNERABLE")
        ctx = {
            "vulnerable_algorithms": list({f.get("algorithm", "") for f in data.get("findings", [])
                                           if f.get("quantum") == "VULNERABLE"}),
            "total_findings":        len(data.get("findings", [])),
            "vulnerable_count":      vuln_count,
            "pqc_mapping":           data.get("pqc_mapping", []),
            "threat_timeline":       data.get("threat_timeline", {}),
            "nist_standards":        list(NIST_PQC_STANDARDS.keys()),
        }
        return self.ai.chat(
            "You are a post-quantum cryptography migration expert. "
            "Based on this quantum audit, generate a 3-phase PQC migration roadmap: "
            "Phase 1 (0-6 months): Immediate actions for CRITICAL findings. "
            "Phase 2 (6-18 months): Systematic algorithm replacement with NIST FIPS 203/204/205. "
            "Phase 3 (18-36 months): Full PQC posture validation and crypto-agility implementation. "
            "Reference NIST SP 800-208 and FIPS 203/204/205 where applicable.",
            context=ctx,
        )