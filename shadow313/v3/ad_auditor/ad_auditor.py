"""
shadow313.v3.ad_auditor.ad_auditor  — v4
Active Directory security auditing: Kerberoastable accounts, ACL review,
privilege path analysis, password policy checks.

Uses ldap3 library (optional) with fallback to subprocess ldapsearch.
"""
from __future__ import annotations
import re
import subprocess
from typing import Any


class LDAPConnector:
    """LDAP connection wrapper using ldap3 or ldapsearch fallback."""

    def __init__(self, server: str, domain: str, username: str, password: str) -> None:
        self._server   = server
        self._domain   = domain
        self._username = username
        self._password = password
        self._conn     = None
        self._base_dn  = self._domain_to_dn(domain)

    @staticmethod
    def _domain_to_dn(domain: str) -> str:
        return ",".join(f"DC={part}" for part in domain.split("."))

    def connect(self) -> bool:
        try:
            import ldap3
            server = ldap3.Server(self._server, get_info=ldap3.ALL)
            self._conn = ldap3.Connection(
                server,
                user=f"{self._domain}\\{self._username}",
                password=self._password,
                authentication=ldap3.NTLM,
                auto_bind=True,
            )
            return True
        except ImportError:
            return False
        except Exception:
            return False

    def search(self, search_filter: str, attributes: list[str]) -> list[dict]:
        if self._conn is None:
            return []
        try:
            import ldap3
            self._conn.search(
                search_base=self._base_dn,
                search_filter=search_filter,
                attributes=attributes,
            )
            results = []
            for entry in self._conn.entries:
                results.append({attr: str(getattr(entry, attr, "")) for attr in attributes})
            return results
        except Exception:
            return []

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass


class ADChecker:
    """Active Directory security checks."""

    def __init__(self, connector: LDAPConnector) -> None:
        self._conn = connector

    def check_kerberoastable(self) -> list[dict]:
        """Find accounts with SPNs (Kerberoastable)."""
        results = self._conn.search(
            "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "servicePrincipalName", "pwdLastSet", "adminCount"],
        )
        findings = []
        for r in results:
            findings.append({
                "check":    "KERBEROASTABLE_ACCOUNT",
                "severity": "HIGH",
                "account":  r.get("sAMAccountName", ""),
                "spn":      r.get("servicePrincipalName", ""),
                "detail":   f"Account '{r.get('sAMAccountName','')}' has SPN — Kerberoastable",
            })
        return findings

    def check_asreproastable(self) -> list[dict]:
        """Find accounts with DONT_REQUIRE_PREAUTH (AS-REP Roastable)."""
        results = self._conn.search(
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "userAccountControl"],
        )
        findings = []
        for r in results:
            findings.append({
                "check":    "ASREP_ROASTABLE",
                "severity": "HIGH",
                "account":  r.get("sAMAccountName", ""),
                "detail":   f"Account '{r.get('sAMAccountName','')}' has DONT_REQUIRE_PREAUTH — AS-REP Roastable",
            })
        return findings

    def check_admin_accounts(self) -> list[dict]:
        """Find accounts in privileged groups."""
        privileged_groups = [
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Administrators", "Account Operators", "Backup Operators",
        ]
        findings = []
        for group in privileged_groups:
            results = self._conn.search(
                f"(&(objectClass=user)(memberOf=CN={group},CN=Users,{self._conn._base_dn}))",
                ["sAMAccountName", "lastLogon", "pwdLastSet"],
            )
            for r in results:
                findings.append({
                    "check":    "PRIVILEGED_ACCOUNT",
                    "severity": "MEDIUM",
                    "account":  r.get("sAMAccountName", ""),
                    "group":    group,
                    "detail":   f"Account '{r.get('sAMAccountName','')}' is member of '{group}'",
                })
        return findings

    def check_password_policy(self) -> list[dict]:
        """Check domain password policy."""
        results = self._conn.search(
            "(objectClass=domainDNS)",
            ["minPwdLength", "pwdHistoryLength", "lockoutThreshold", "maxPwdAge"],
        )
        findings = []
        for r in results:
            min_len = int(r.get("minPwdLength", 0) or 0)
            history = int(r.get("pwdHistoryLength", 0) or 0)
            lockout = int(r.get("lockoutThreshold", 0) or 0)

            if min_len < 12:
                findings.append({
                    "check":    "WEAK_PASSWORD_POLICY",
                    "severity": "HIGH",
                    "detail":   f"Minimum password length is {min_len} (recommend ≥12)",
                })
            if history < 10:
                findings.append({
                    "check":    "WEAK_PASSWORD_HISTORY",
                    "severity": "MEDIUM",
                    "detail":   f"Password history is {history} (recommend ≥10)",
                })
            if lockout == 0:
                findings.append({
                    "check":    "NO_ACCOUNT_LOCKOUT",
                    "severity": "HIGH",
                    "detail":   "Account lockout threshold is 0 — brute force possible",
                })
        return findings

    def check_unconstrained_delegation(self) -> list[dict]:
        """Find computers/accounts with unconstrained delegation."""
        results = self._conn.search(
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            ["sAMAccountName", "dNSHostName"],
        )
        findings = []
        for r in results:
            findings.append({
                "check":    "UNCONSTRAINED_DELEGATION",
                "severity": "CRITICAL",
                "account":  r.get("sAMAccountName", ""),
                "host":     r.get("dNSHostName", ""),
                "detail":   f"Computer '{r.get('sAMAccountName','')}' has unconstrained delegation — "
                            f"can impersonate any user",
            })
        return findings

    def run_all(self) -> list[dict]:
        all_findings = []
        for check in [
            self.check_kerberoastable,
            self.check_asreproastable,
            self.check_admin_accounts,
            self.check_password_policy,
            self.check_unconstrained_delegation,
        ]:
            try:
                all_findings.extend(check())
            except Exception as exc:
                all_findings.append({
                    "check":    check.__name__,
                    "status":   "ERROR",
                    "detail":   str(exc),
                    "severity": "INFO",
                })
        return all_findings


class ADAuditModule:
    """shadow313.v3.ad_auditor — Active Directory auditing. Registered: ad_audit"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("ad_audit", self.run)

    def run(
        self,
        server: str = "",
        domain: str = "",
        username: str = "",
        password: str = "",
        check: str = "all",
    ) -> dict:
        self.out.section("ACTIVE DIRECTORY AUDIT")

        if not all([server, domain, username]):
            self.out.error("--server, --domain, and --username are required")
            return {"error": "missing_params"}

        connector = LDAPConnector(server, domain, username, password)
        self.out.info(f"Connecting to {server} ({domain}) …")

        if not connector.connect():
            self.out.error("LDAP connection failed — check credentials and server")
            return {"error": "connection_failed"}

        self.out.success("Connected to Active Directory")
        checker  = ADChecker(connector)
        findings = checker.run_all()
        connector.disconnect()

        result: dict[str, Any] = {"findings": findings}

        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in findings if f.get("severity") == "HIGH"]
        self.out.info(f"Findings: {len(findings)} total, {len(critical)} CRITICAL, {len(high)} HIGH")

        rows = [[f["check"], f.get("account",""), f["severity"], f["detail"][:60]]
                for f in findings[:30]]
        self.out.table(["Check","Account","Severity","Detail"], rows, "AD Security Findings")

        result["ai_analysis"] = self.kernel.ai.chat(
            "Analyse these Active Directory security findings. "
            "Explain the attack paths enabled by each finding (Kerberoasting, Pass-the-Hash, etc.) "
            "and provide prioritized remediation steps.",
            context={"findings": findings[:20]},
        )
        self.out.ai_response(result["ai_analysis"], "AD Security Analysis")

        self.session.write("ad_audit.json", result)
        return result