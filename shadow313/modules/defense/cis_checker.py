"""shadow313.modules.defense.cis_checker — CIS Benchmark Level 1 and 2 checks."""
from __future__ import annotations
import os
import re
import stat
from pathlib import Path
from .system_info import _run


def _sev(critical=False, high=False, medium=False, low=False) -> str:
    """Return the highest enabled severity, defaulting to INFO."""
    if critical: return "CRITICAL"
    if high:     return "HIGH"
    if medium:   return "MEDIUM"
    if low:      return "LOW"
    return "INFO"


class CISBenchmarkChecker:
    def __init__(self, level: int = 1) -> None:
        """Select base checks, adding the extended checks when level is at least two."""
        self.level = level

    def run_all(self) -> list[dict]:
        """Return results for the selected checks, converting exceptions to ERROR results."""
        checks = [
            self.check_ssh_config, self.check_password_policy,
            self.check_firewall, self.check_suid_sgid,
            self.check_world_writable, self.check_no_empty_passwords,
            self.check_root_path, self.check_sticky_bit,
            self.check_cron_permissions, self.check_core_dumps,
            self.check_yama_ptrace, self.check_randomize_va,
            self.check_no_rsh_services, self.check_unused_filesystems,
        ]
        if self.level >= 2:
            checks += [self.check_auditd, self.check_apparmor_selinux,
                       self.check_umask, self.check_login_banners]
        results = []
        for check in checks:
            try:
                result = check()
                if result:
                    results.append(result)
            except Exception as exc:
                results.append({"check": check.__name__, "status": "ERROR",
                                "detail": str(exc), "severity": "INFO"})
        return results

    def check_ssh_config(self) -> dict:
        """Return SSH setting findings, or SKIP when sshd_config is absent.

        Missing required settings count as issues. File read errors propagate.
        """
        sshd_path = Path("/etc/ssh/sshd_config")
        if not sshd_path.exists():
            return {"check": "SSH Config", "status": "SKIP",
                    "detail": "sshd_config not found", "severity": "INFO", "cis_id": "5.2"}
        text = sshd_path.read_text(errors="replace")
        issues = []
        def _get_val(key):
            """Return the first matching SSH option value in lowercase, or "" if absent."""
            m = re.search(rf"^\s*{key}\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            return m.group(1).lower() if m else ""
        if _get_val("PermitRootLogin") not in ("no", "prohibit-password", "forced-commands-only"):
            issues.append("PermitRootLogin should be 'no'")
        if _get_val("PasswordAuthentication") not in ("no",):
            issues.append("PasswordAuthentication should be 'no'")
        if _get_val("X11Forwarding") == "yes":
            issues.append("X11Forwarding should be disabled")
        if not _get_val("MaxAuthTries"):
            issues.append("MaxAuthTries not set")
        return {"check": "SSH Configuration", "status": "PASS" if not issues else "FAIL",
                "severity": _sev(high=len(issues) > 2, medium=0 < len(issues) <= 2),
                "detail": "; ".join(issues) if issues else "SSH configuration looks hardened",
                "issues": issues, "cis_id": "5.2"}

    def check_password_policy(self) -> dict:
        """Return password policy findings from pwquality.conf and login.defs.

        Require a minlen entry and flag missing or excessive PASS_MAX_DAYS and
        PASS_MIN_DAYS values against limits of 90 and 7. Read errors propagate.
        """
        issues = []
        pwqual  = Path("/etc/security/pwquality.conf")
        logindf = Path("/etc/login.defs")
        if pwqual.exists():
            text = pwqual.read_text(errors="replace")
            if not re.search(r"minlen\s*=\s*\d+", text):
                issues.append("minlen not configured")
        else:
            issues.append("pam_pwquality not configured")
        if logindf.exists():
            text = logindf.read_text(errors="replace")
            for key, minval in [("PASS_MAX_DAYS", 90), ("PASS_MIN_DAYS", 7)]:
                m = re.search(rf"^{key}\s+(\d+)", text, re.MULTILINE)
                if not m or int(m.group(1)) > minval:
                    issues.append(f"{key} not set or exceeds {minval}")
        return {"check": "Password Policy", "status": "PASS" if not issues else "FAIL",
                "severity": _sev(medium=bool(issues)),
                "detail": "; ".join(issues) if issues else "Password policy configured",
                "cis_id": "5.4"}

    def check_firewall(self) -> dict:
        """Return the first successful firewall probe's status, or FAIL if none succeeds."""
        for cmd, name in [
            (["ufw", "status"], "UFW"),
            (["firewall-cmd", "--state"], "firewalld"),
            (["iptables", "-L", "-n"], "iptables"),
        ]:
            out, _, rc = _run(cmd, timeout=5)
            if rc == 0:
                active = "active" in out.lower() or "running" in out.lower() or bool(out.strip())
                return {"check": "Firewall Status",
                        "status": "PASS" if active else "FAIL",
                        "severity": _sev(high=not active),
                        "detail": f"{name}: {'active' if active else 'INACTIVE'}",
                        "cis_id": "3.6"}
        return {"check": "Firewall Status", "status": "FAIL", "severity": "HIGH",
                "detail": "No firewall tool found", "cis_id": "3.6"}

    def check_suid_sgid(self) -> dict:
        """Return unexpected privileged binary findings, including at most 20 paths."""
        out, _, _ = _run(["find", "/", "-perm", "-4000", "-o", "-perm", "-2000",
                           "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"], timeout=30)
        binaries = [l.strip() for l in out.splitlines() if l.strip()]
        expected = {"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/bin/mount",
                    "/bin/umount", "/bin/ping"}
        unexpected = [b for b in binaries if b not in expected]
        return {"check": "SUID/SGID Binaries",
                "status": "PASS" if not unexpected else "WARN",
                "severity": _sev(medium=len(unexpected) > 5, low=0 < len(unexpected) <= 5),
                "detail": f"{len(binaries)} total; {len(unexpected)} unexpected",
                "unexpected": unexpected[:20], "cis_id": "6.1.13"}

    def check_world_writable(self) -> dict:
        """Return world-writable file findings on the root filesystem, listing up to 20 paths."""
        out, _, _ = _run(["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
                           "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"], timeout=30)
        files = [l.strip() for l in out.splitlines() if l.strip()]
        return {"check": "World-Writable Files",
                "status": "PASS" if not files else "FAIL",
                "severity": _sev(high=len(files) > 20, medium=0 < len(files) <= 20),
                "detail": f"{len(files)} world-writable files found",
                "files": files[:20], "cis_id": "6.1.11"}

    def check_no_empty_passwords(self) -> dict:
        """Return a critical failure for empty password fields reported from /etc/shadow."""
        out, _, _ = _run(["awk", "-F:", '($2 == "" ) {print}', "/etc/shadow"])
        empty = [l.strip() for l in out.splitlines() if l.strip()]
        return {"check": "Empty Passwords",
                "status": "PASS" if not empty else "FAIL",
                "severity": _sev(critical=bool(empty)),
                "detail": f"Accounts with empty passwords: {empty}" if empty else "No empty passwords",
                "cis_id": "6.2.1"}

    def check_root_path(self) -> dict:
        """Return findings for empty, dot, or dot-dot entries in the current PATH."""
        path_val  = os.environ.get("PATH", "")
        dangerous = [p for p in path_val.split(":") if p in (".", "", "..")]
        return {"check": "Root PATH Integrity",
                "status": "PASS" if not dangerous else "FAIL",
                "severity": _sev(high=bool(dangerous)),
                "detail": f"Dangerous PATH entries: {dangerous}" if dangerous else "PATH is clean",
                "cis_id": "6.2.6"}

    def check_sticky_bit(self) -> dict:
        """Return findings for directories lacking the sticky bit under temporary directories."""
        out, _, _ = _run(["find", "/tmp", "/var/tmp", "/dev/shm", "-type", "d",
                           "-not", "-perm", "-1000"], timeout=10)
        dirs = [l.strip() for l in out.splitlines() if l.strip()]
        return {"check": "Sticky Bit on World-Writable Dirs",
                "status": "PASS" if not dirs else "FAIL",
                "severity": _sev(medium=bool(dirs)),
                "detail": f"Missing sticky bit: {dirs}" if dirs else "Sticky bit set on temp dirs",
                "cis_id": "1.1.18"}

    def check_cron_permissions(self) -> dict:
        """Return findings for group/world-writable cron paths; stat errors propagate."""
        issues = []
        for path in ["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly",
                     "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]:
            p = Path(path)
            if p.exists():
                mode = p.stat().st_mode
                if mode & stat.S_IWGRP or mode & stat.S_IWOTH:
                    issues.append(f"{path} is group/world writable")
        return {"check": "Cron Permissions",
                "status": "PASS" if not issues else "FAIL",
                "severity": _sev(medium=bool(issues)),
                "detail": "; ".join(issues) if issues else "Cron permissions secure",
                "cis_id": "5.1"}

    def check_core_dumps(self) -> dict:
        """Return core-dump status from ulimit or limits.conf; file read errors propagate."""
        out, _, _ = _run(["ulimit", "-c"])
        disabled  = out.strip() == "0"
        limits_file = Path("/etc/security/limits.conf")
        if limits_file.exists():
            text = limits_file.read_text(errors="replace")
            if "* hard core 0" in text or "* soft core 0" in text:
                disabled = True
        return {"check": "Core Dumps Disabled",
                "status": "PASS" if disabled else "WARN",
                "severity": _sev(low=not disabled),
                "detail": "Core dumps disabled" if disabled else "Core dumps enabled",
                "cis_id": "1.6.1"}

    def check_yama_ptrace(self) -> dict:
        """Return ptrace restriction status, or SKIP if unavailable; read errors propagate."""
        scope_file = Path("/proc/sys/kernel/yama/ptrace_scope")
        if not scope_file.exists():
            return {"check": "Yama ptrace_scope", "status": "SKIP",
                    "detail": "Yama LSM not available", "severity": "INFO"}
        val = scope_file.read_text().strip()
        ok  = val in ("1", "2", "3")
        return {"check": "Yama ptrace_scope",
                "status": "PASS" if ok else "FAIL",
                "severity": _sev(medium=not ok),
                "detail": f"ptrace_scope={val}" + ("" if ok else " — set to >=1"),
                "cis_id": "1.6.3"}

    def check_randomize_va(self) -> dict:
        """Return PASS only for ASLR value 2; an absent setting is treated as zero.

        File read errors propagate.
        """
        aslr_file = Path("/proc/sys/kernel/randomize_va_space")
        val = aslr_file.read_text().strip() if aslr_file.exists() else "0"
        ok  = val == "2"
        return {"check": "ASLR (randomize_va_space)",
                "status": "PASS" if ok else "FAIL",
                "severity": _sev(high=val == "0", medium=val == "1"),
                "detail": f"randomize_va_space={val}" + ("" if ok else " — should be 2"),
                "cis_id": "1.6.2"}

    def check_no_rsh_services(self) -> dict:
        """Return findings for enabled rsh, rlogin, rexec, telnet, and ftp services."""
        issues = []
        for svc in ["rsh", "rlogin", "rexec", "telnet", "ftp"]:
            out, _, rc = _run(["systemctl", "is-enabled", svc], timeout=5)
            if rc == 0 and "enabled" in out:
                issues.append(svc)
        return {"check": "Legacy/Insecure Services",
                "status": "PASS" if not issues else "FAIL",
                "severity": _sev(high=bool(issues)),
                "detail": f"Insecure services enabled: {issues}" if issues else "No legacy services found",
                "cis_id": "2.1"}

    def check_unused_filesystems(self) -> dict:
        """Return warnings for filesystem modules not reported as disabled or missing."""
        issues = []
        for fs in ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"]:
            out, _, _ = _run(["modprobe", "-n", "-v", fs], timeout=5)
            if "install /bin/true" not in out and "not found" not in out.lower():
                issues.append(fs)
        return {"check": "Unused Filesystem Modules",
                "status": "PASS" if not issues else "WARN",
                "severity": _sev(low=bool(issues)),
                "detail": f"Loadable unused filesystems: {issues}" if issues else "Unused filesystems disabled",
                "cis_id": "1.1"}

    def check_auditd(self) -> dict:
        """Return auditd status from the systemctl probe."""
        out, _, rc = _run(["systemctl", "is-active", "auditd"])
        active = rc == 0 and "active" in out
        return {"check": "Auditd Service",
                "status": "PASS" if active else "FAIL",
                "severity": _sev(medium=not active),
                "detail": "auditd running" if active else "auditd not active",
                "cis_id": "4.1"}

    def check_apparmor_selinux(self) -> dict:
        """Return status from the first available MAC tool, or FAIL if neither responds."""
        for mac, cmd in [("AppArmor", ["aa-status"]), ("SELinux", ["sestatus"])]:
            out, _, rc = _run(cmd, timeout=5)
            if rc == 0 and out:
                enforcing = "enforcing" in out.lower() or "enabled" in out.lower()
                return {"check": f"MAC ({mac})",
                        "status": "PASS" if enforcing else "WARN",
                        "severity": _sev(medium=not enforcing),
                        "detail": f"{mac} {'enforcing' if enforcing else 'not enforcing'}",
                        "cis_id": "1.7"}
        return {"check": "MAC (AppArmor/SELinux)", "status": "FAIL", "severity": "MEDIUM",
                "detail": "Neither AppArmor nor SELinux found active", "cis_id": "1.7"}

    def check_umask(self) -> dict:
        """Return PASS for a reported mask of 027 or 077, otherwise WARN."""
        out, _, _ = _run(["umask"])
        mask = out.strip()
        ok   = mask in ("0027", "0077", "027", "077")
        return {"check": "Default umask",
                "status": "PASS" if ok else "WARN",
                "severity": _sev(low=not ok),
                "detail": f"umask={mask}" + ("" if ok else " — recommend 0027 or 0077"),
                "cis_id": "5.4.4"}

    def check_login_banners(self) -> dict:
        """Return warnings for missing/empty login banners; file read errors propagate."""
        issues = []
        for f in ["/etc/issue", "/etc/issue.net", "/etc/motd"]:
            if not Path(f).exists() or not Path(f).read_text().strip():
                issues.append(f"{f} is missing or empty")
        return {"check": "Login Banners",
                "status": "PASS" if not issues else "WARN",
                "severity": _sev(low=bool(issues)),
                "detail": "; ".join(issues) if issues else "Login banners configured",
                "cis_id": "1.9"}