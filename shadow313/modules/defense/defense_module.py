"""shadow313.modules.defense.defense_module — DefenseModule orchestrator."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

from .system_info  import SystemInfo
from .cis_checker  import CISBenchmarkChecker
from .firewall     import FirewallAnalyzer
from .remediation  import RemediationGenerator


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class DefenseModule:
    """shadow313.defense — System hardening audit and AI remediation."""

    def __init__(self, kernel) -> None:
        """Bind hardening audits to the kernel configuration and session services."""
        self.kernel  = kernel
        self.config  = kernel.config.get("defense", default={})
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        """Register the defense command with the supplied kernel."""
        kernel.register("defense", self.run)

    def run(self, audit: bool = False, profile: str = "cis-level1",
            firewall_check: bool = False, fw_tool: str = "auto",
            generate_remediation: str = "", apply_fixes: bool = False,
            # v1 compat aliases
            firewall: bool = False, remediate: bool = False,
            output_fmt: str = "bash") -> dict:
        """Collect system information, run requested audits, and save compliance.json.

        Profiles containing "level2" select the extended CIS checks. Failed or
        warning checks may write a remediation script; "ansible" selects YAML
        and other formats select Bash. The script is generated without execution;
        apply_fixes is unused. An AI plan is requested on every completed run.
        File I/O errors propagate.
        """
        self.out.section("DEFENSIVE HARDENING AUDIT")
        self.session.audit("defense", "start", profile)

        result: dict[str, Any] = {
            "timestamp": _now(),
            "profile":   profile,
            "findings":  [],
        }

        self.out.info("Collecting system information …")
        sysinfo = SystemInfo().collect()
        result["system_info"] = sysinfo
        self.out.success(f"OS: {sysinfo.get('os', 'Unknown')}  "
                         f"Kernel: {sysinfo.get('kernel', '')}")

        if audit:
            level = 2 if "level2" in profile else 1
            self.out.info(f"Running CIS Level {level} checks …")
            findings = CISBenchmarkChecker(level=level).run_all()
            result["findings"] = findings

            pass_count = sum(1 for f in findings if f.get("status") == "PASS")
            fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
            warn_count = sum(1 for f in findings if f.get("status") == "WARN")
            self.out.info(f"Results: {pass_count} PASS / {fail_count} FAIL / {warn_count} WARN")

            rows = [[f.get("check", ""), f.get("status", ""), f.get("severity", ""),
                     f.get("detail", "")[:70], f.get("cis_id", "")]
                    for f in findings]
            self.out.table(["Check", "Status", "Severity", "Detail", "CIS ID"],
                           rows, "CIS Benchmark Results")

            total = len(findings)
            score = round((pass_count / total) * 100, 1) if total > 0 else 0
            result["compliance_score"] = score
            self.out.info(f"Compliance Score: {score}%")

        if firewall_check or firewall:
            self.out.info(f"Analysing firewall ({fw_tool}) …")
            fw_result = FirewallAnalyzer().analyse(fw_tool)
            result["firewall"] = fw_result
            for issue in fw_result.get("issues", []):
                self.out.warn(f"Firewall: {issue}")

        # Remediation generation
        fmt = generate_remediation or (output_fmt if remediate else "")
        if fmt or result.get("findings"):
            failed = [f for f in result.get("findings", [])
                      if f.get("status") in ("FAIL", "WARN")]
            if failed:
                gen = RemediationGenerator()
                if fmt == "ansible":
                    script = gen.ansible_playbook(failed)
                    ext    = "yml"
                else:
                    script = gen.bash_script(failed)
                    ext    = "sh"
                script_path = self.session.path(f"remediation.{ext}")
                script_path.write_text(script)
                result["remediation_script"] = str(script_path)
                self.out.success(f"Remediation script → {script_path}")

        self.out.info("Generating AI remediation plan …")
        result["ai_plan"] = self._ai_plan(result)
        self.out.ai_response(result["ai_plan"], "AI Hardening Remediation Plan")

        path = self.session.write("compliance.json", result)
        self.out.success(f"Audit results saved → {path}")
        self.session.audit("defense", "complete", str(path))
        return result

    def ai_context(self) -> dict:
        """Summarize saved compliance findings for AI requests."""
        data = self.session.read("compliance.json") or {}
        findings = data.get("findings", [])
        return {
            "module":           "defense",
            "compliance_score": data.get("compliance_score", "N/A"),
            "fail_count":       sum(1 for f in findings if f.get("status") == "FAIL"),
            "warn_count":       sum(1 for f in findings if f.get("status") == "WARN"),
            "os":               data.get("system_info", {}).get("os", ""),
        }

    def _ai_plan(self, data: dict) -> str:
        """Request an AI remediation plan using up to 20 failed or warning checks."""
        failed = [f for f in data.get("findings", [])
                  if f.get("status") in ("FAIL", "WARN")]
        ctx = {
            "os":               data.get("system_info", {}).get("os", ""),
            "kernel":           data.get("system_info", {}).get("kernel", ""),
            "failed_checks":    failed[:20],
            "compliance_score": data.get("compliance_score", "N/A"),
        }
        return self.ai.chat(
            "You are a Linux hardening expert. Analyse these CIS benchmark failures and generate a "
            "prioritised remediation plan. For each critical/high finding: (1) explain the risk, "
            "(2) provide the exact fix command, (3) estimated effort. Then provide a phased "
            "hardening roadmap (immediate/short-term/long-term). Be specific and actionable.",
            context=ctx,
        )