"""shadow313.modules.defense.firewall — Firewall rule analyser (UFW/iptables)."""
from __future__ import annotations
from .system_info import _run


class FirewallAnalyzer:
    def analyse_iptables(self) -> dict:
        """Return iptables rule excerpts and detected issues, or an error on probe failure."""
        out, _, rc = _run(["iptables", "-L", "-n", "-v", "--line-numbers"])
        if rc != 0:
            return {"error": "iptables not available or requires root"}
        issues = []
        if "ACCEPT" in out and "0.0.0.0/0" in out:
            issues.append("Permissive ACCEPT rules for 0.0.0.0/0 detected")
        if "policy ACCEPT" in out.lower():
            issues.append("Default chain policy is ACCEPT (recommend DROP/REJECT)")
        return {"tool": "iptables", "rules": out[:3000], "issues": issues}

    def analyse_ufw(self) -> dict:
        """Return UFW rule excerpts and inactivity findings, or an error on probe failure."""
        out, _, rc = _run(["ufw", "status", "verbose"])
        if rc != 0:
            return {"error": "ufw not available"}
        issues = []
        if "Status: inactive" in out:
            issues.append("UFW is INACTIVE")
        return {"tool": "ufw", "rules": out[:2000], "issues": issues}

    def analyse_nftables(self) -> dict:
        """Return an nftables rule excerpt with no issue analysis, or an error on probe failure."""
        out, _, rc = _run(["nft", "list", "ruleset"])
        if rc != 0:
            return {"error": "nftables not available"}
        return {"tool": "nftables", "rules": out[:3000], "issues": []}

    def analyse(self, tool: str = "auto") -> dict:
        """Return the selected firewall analysis or an error result.

        "auto" tries UFW, iptables, then nftables until a probe succeeds.
        """
        if tool in ("auto", "ufw"):
            res = self.analyse_ufw()
            if "error" not in res:
                return res
        if tool in ("auto", "iptables"):
            res = self.analyse_iptables()
            if "error" not in res:
                return res
        if tool in ("auto", "nftables"):
            return self.analyse_nftables()
        return {"error": f"Unknown firewall tool: {tool}"}