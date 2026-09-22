"""
shadow313.modules.defense
Defensive hardening — CIS benchmark audits, firewall analysis,
SSH hardening, file permission checks, AI remediation plan generation.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """Run a shell command safely. Returns (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as exc:
        return "", str(exc), 1


# ── Finding severity ──────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def _sev(critical=False, high=False, medium=False, low=False) -> str:
    if critical: return "CRITICAL"
    if high:     return "HIGH"
    if medium:   return "MEDIUM"
    if low:      return "LOW"
    return "INFO"


# ── System info collector ─────────────────────────────────────────────────────

class SystemInfo:
    """Collect OS / kernel / package / service information."""

    def collect(self) -> dict:
        info: dict[str, Any] = {}
        info["os"]            = self._os_info()
        info["kernel"]        = self._kernel()
        info["hostname"]      = self._hostname()
        info["users"]         = self._users()
        info["listening"]     = self._listening_services()
        info["installed_pkgs"]= self._installed_packages()[:50]
        return info

    def _os_info(self) -> str:
        out, _, _ = _run(["cat", "/etc/os-release"])
        for line in out.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return "Unknown"

    def _kernel(self) -> str:
        out, _, _ = _run(["uname", "-r"])
        return out.strip()

    def _hostname(self) -> str:
        out, _, _ = _run(["hostname"])
        return out.strip()

    def _users(self) -> list[dict]:
        out, _, _ = _run(["cat", "/etc/passwd"])
        users = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                uid = int(parts[2]) if parts[2].isdigit() else -1
                users.append({
                    "username": parts[0],
                    "uid":      uid,
                    "shell":    parts[6],
                    "home":     parts[5],
                    "has_login": parts[6] not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"),
                })
        return users

    def _listening_services(self) -> list[dict]:
        out, _, _ = _run(["ss", "-tlnp"])
        services = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                addr  = parts[3]
                proc  = parts[6] if len(parts) > 6 else ""
                port  = addr.split(":")[-1]
                services.append({"address": addr, "port": port, "process": proc})
        return services

    def _installed_packages(self) -> list[str]:
        for cmd in (["dpkg", "--list"], ["rpm", "-qa"], ["brew", "list"]):
            out, _, rc = _run(cmd, timeout=10)
            if rc == 0 and out:
                pkgs = [line.split()[1] for line in out.splitlines()
                        if line.startswith("ii")] or out.splitlines()
                return pkgs[:100]
        return []


# ── CIS Benchmark checks ──────────────────────────────────────────────────────

class CISBenchmark:
    """
    CIS Linux Level 1 / Level 2 benchmark checks.
    Each check returns a Finding dict.
    """

    def __init__(self, level: int = 1) -> None:
        self.level = level

    def run_all(self) -> list[dict]:
        checks = [
            self.check_password_policy,
            self.check_ssh_config,
            self.check_firewall,
            self.check_suid_sgid,
            self.check_world_writable,
            self.check_no_empty_passwords,
            self.check_root_path,
            self.check_sticky_bit,
            self.check_cron_permissions,
            self.check_core_dumps,
            self.check_yama_ptrace,
            self.check_randomize_va,
            self.check_no_rsh_services,
            self.check_unused_filesystems,
        ]
        if self.level >= 2:
            checks += [
                self.check_auditd,
                self.check_apparmor_selinux,
                self.check_umask,
                self.check_login_banners,
            ]
        results = []
        for check in checks:
            try:
                result = check()
                if result:
                    results.append(result)
            except Exception as exc:
                results.append({"check": check.__name__,
                                "status": "ERROR", "detail": str(exc),
                                "severity": "INFO"})
        return results

    # ── Individual checks ──────────────────────────────────────────────────────
    def check_ssh_config(self) -> dict:
        sshd_path = Path("/etc/ssh/sshd_config")
        if not sshd_path.exists():
            return {"check": "SSH Config", "status": "SKIP",
                    "detail": "sshd_config not found", "severity": "INFO"}
        text = sshd_path.read_text(errors="replace")

        findings = []
        issues   = []

        def _get_val(key: str) -> str:
            m = re.search(rf"^\s*{key}\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            return m.group(1).lower() if m else ""

        if _get_val("PermitRootLogin") not in ("no", "prohibit-password", "forced-commands-only"):
            issues.append("PermitRootLogin should be 'no' or 'prohibit-password'")
        if _get_val("PasswordAuthentication") not in ("no",):
            issues.append("PasswordAuthentication should be 'no' (use keys)")
        if _get_val("Protocol") == "1":
            issues.append("SSH Protocol 1 is obsolete — use Protocol 2")
        if _get_val("X11Forwarding") == "yes":
            issues.append("X11Forwarding should be disabled")
        if not _get_val("MaxAuthTries"):
            issues.append("MaxAuthTries not set — recommend MaxAuthTries 3")
        if not _get_val("LoginGraceTime"):
            issues.append("LoginGraceTime not set — recommend LoginGraceTime 60")

        status   = "PASS" if not issues else "FAIL"
        severity = _sev(high=len(issues) > 2, medium=0 < len(issues) <= 2)
        return {
            "check":    "SSH Configuration",
            "status":   status,
            "severity": severity,
            "detail":   "; ".join(issues) if issues else "SSH configuration looks hardened",
            "issues":   issues,
            "cis_id":   "5.2",
        }

    def check_password_policy(self) -> dict:
        issues = []
        pwqual  = Path("/etc/security/pwquality.conf")
        logindf = Path("/etc/login.defs")

        if pwqual.exists():
            text = pwqual.read_text(errors="replace")
            if not re.search(r"minlen\s*=\s*\d+", text):
                issues.append("minlen not configured in pwquality.conf")
            if not re.search(r"minclass\s*=\s*[3-4]", text):
                issues.append("minclass (character classes) not set to ≥3")
        else:
            issues.append("pam_pwquality not configured (/etc/security/pwquality.conf missing)")

        if logindf.exists():
            text = logindf.read_text(errors="replace")
            for key, minval in [("PASS_MAX_DAYS", 90), ("PASS_MIN_DAYS", 7),
                                 ("PASS_WARN_AGE", 14)]:
                m = re.search(rf"^{key}\s+(\d+)", text, re.MULTILINE)
                if not m or int(m.group(1)) > minval:
                    issues.append(f"{key} not set or exceeds recommended value ({minval})")

        status   = "PASS" if not issues else "FAIL"
        severity = _sev(medium=bool(issues))
        return {
            "check":    "Password Policy",
            "status":   status,
            "severity": severity,
            "detail":   "; ".join(issues) if issues else "Password policy configured",
            "cis_id":   "5.4",
        }

    def check_firewall(self) -> dict:
        for cmd, name in [
            (["ufw", "status"], "UFW"),
            (["firewall-cmd", "--state"], "firewalld"),
            (["iptables", "-L", "-n"], "iptables"),
        ]:
            out, _, rc = _run(cmd, timeout=5)
            if rc == 0:
                active = "active" in out.lower() or "running" in out.lower() or bool(out.strip())
                return {
                    "check":    "Firewall Status",
                    "status":   "PASS" if active else "FAIL",
                    "severity": _sev(high=not active),
                    "detail":   f"{name}: {'active' if active else 'INACTIVE — no firewall protection'}",
                    "cis_id":   "3.6",
                }
        return {"check": "Firewall Status", "status": "FAIL",
                "severity": "HIGH",
                "detail": "No firewall tool found (ufw/firewalld/iptables)", "cis_id": "3.6"}

    def check_suid_sgid(self) -> dict:
        out, _, _ = _run(["find", "/", "-perm", "-4000", "-o", "-perm", "-2000",
                           "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
                         timeout=30)
        binaries = [l.strip() for l in out.splitlines() if l.strip()]
        expected = {"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
                    "/usr/bin/chfn", "/bin/mount", "/bin/umount", "/bin/ping"}
        unexpected = [b for b in binaries if b not in expected]
        status   = "PASS" if not unexpected else "WARN"
        severity = _sev(medium=len(unexpected) > 5, low=0 < len(unexpected) <= 5)
        return {
            "check":      "SUID/SGID Binaries",
            "status":     status,
            "severity":   severity,
            "detail":     f"{len(binaries)} total SUID/SGID files; {len(unexpected)} unexpected",
            "unexpected": unexpected[:20],
            "cis_id":     "6.1.13",
        }

    def check_world_writable(self) -> dict:
        out, _, _ = _run(
            ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            timeout=30,
        )
        files    = [l.strip() for l in out.splitlines() if l.strip()]
        status   = "PASS" if not files else "FAIL"
        severity = _sev(high=len(files) > 20, medium=0 < len(files) <= 20)
        return {
            "check":    "World-Writable Files",
            "status":   status,
            "severity": severity,
            "detail":   f"{len(files)} world-writable files found",
            "files":    files[:20],
            "cis_id":   "6.1.11",
        }

    def check_no_empty_passwords(self) -> dict:
        out, _, _ = _run(["awk", "-F:", "($2 == \"\" ) {print}", "/etc/shadow"])
        empty = [l.strip() for l in out.splitlines() if l.strip()]
        return {
            "check":    "Empty Passwords",
            "status":   "PASS" if not empty else "FAIL",
            "severity": _sev(critical=bool(empty)),
            "detail":   f"Accounts with empty passwords: {empty}" if empty else "No empty passwords",
            "cis_id":   "6.2.1",
        }

    def check_root_path(self) -> dict:
        path_val = os.environ.get("PATH", "")
        dangerous = [p for p in path_val.split(":") if p in (".", "", "..")]
        return {
            "check":    "Root PATH Integrity",
            "status":   "PASS" if not dangerous else "FAIL",
            "severity": _sev(high=bool(dangerous)),
            "detail":   f"Dangerous PATH entries: {dangerous}" if dangerous else "PATH is clean",
            "cis_id":   "6.2.6",
        }

    def check_sticky_bit(self) -> dict:
        out, _, _ = _run(
            ["find", "/tmp", "/var/tmp", "/dev/shm", "-type", "d",
             "-not", "-perm", "-1000"],
            timeout=10,
        )
        dirs = [l.strip() for l in out.splitlines() if l.strip()]
        return {
            "check":    "Sticky Bit on World-Writable Dirs",
            "status":   "PASS" if not dirs else "FAIL",
            "severity": _sev(medium=bool(dirs)),
            "detail":   f"Missing sticky bit: {dirs}" if dirs else "Sticky bit set on temp dirs",
            "cis_id":   "1.1.18",
        }

    def check_cron_permissions(self) -> dict:
        issues = []
        for path in ["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly",
                     "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]:
            p = Path(path)
            if p.exists():
                mode = p.stat().st_mode
                if mode & stat.S_IWGRP or mode & stat.S_IWOTH:
                    issues.append(f"{path} is group/world writable")
        return {
            "check":    "Cron Permissions",
            "status":   "PASS" if not issues else "FAIL",
            "severity": _sev(medium=bool(issues)),
            "detail":   "; ".join(issues) if issues else "Cron permissions secure",
            "cis_id":   "5.1",
        }

    def check_core_dumps(self) -> dict:
        out, _, _ = _run(["ulimit", "-c"])
        disabled  = out.strip() == "0"
        limits_file = Path("/etc/security/limits.conf")
        if limits_file.exists():
            text = limits_file.read_text(errors="replace")
            if "* hard core 0" in text or "* soft core 0" in text:
                disabled = True
        return {
            "check":    "Core Dumps Disabled",
            "status":   "PASS" if disabled else "WARN",
            "severity": _sev(low=not disabled),
            "detail":   "Core dumps disabled" if disabled else
                        "Core dumps enabled — may expose sensitive memory",
            "cis_id":   "1.6.1",
        }

    def check_yama_ptrace(self) -> dict:
        scope_file = Path("/proc/sys/kernel/yama/ptrace_scope")
        if not scope_file.exists():
            return {"check": "Yama ptrace_scope", "status": "SKIP",
                    "detail": "Yama LSM not available", "severity": "INFO"}
        val = scope_file.read_text().strip()
        ok  = val in ("1", "2", "3")
        return {
            "check":    "Yama ptrace_scope",
            "status":   "PASS" if ok else "FAIL",
            "severity": _sev(medium=not ok),
            "detail":   f"ptrace_scope={val}" + ("" if ok else " — set to ≥1 to restrict ptrace"),
            "cis_id":   "1.6.3",
        }

    def check_randomize_va(self) -> dict:
        aslr_file = Path("/proc/sys/kernel/randomize_va_space")
        val = aslr_file.read_text().strip() if aslr_file.exists() else "0"
        ok  = val == "2"
        return {
            "check":    "ASLR (randomize_va_space)",
            "status":   "PASS" if ok else "FAIL",
            "severity": _sev(high=val == "0", medium=val == "1"),
            "detail":   f"randomize_va_space={val}" + ("" if ok else " — should be 2 (full ASLR)"),
            "cis_id":   "1.6.2",
        }

    def check_no_rsh_services(self) -> dict:
        issues = []
        for svc in ["rsh", "rlogin", "rexec", "telnet", "ftp"]:
            out, _, rc = _run(["systemctl", "is-enabled", svc], timeout=5)
            if rc == 0 and "enabled" in out:
                issues.append(svc)
        return {
            "check":    "Legacy/Insecure Services",
            "status":   "PASS" if not issues else "FAIL",
            "severity": _sev(high=bool(issues)),
            "detail":   f"Insecure services enabled: {issues}" if issues
                        else "No legacy insecure services found",
            "cis_id":   "2.1",
        }

    def check_unused_filesystems(self) -> dict:
        issues = []
        for fs in ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"]:
            out, _, _ = _run(["modprobe", "-n", "-v", fs], timeout=5)
            if "install /bin/true" not in out and "not found" not in out.lower():
                issues.append(fs)
        return {
            "check":    "Unused Filesystem Modules",
            "status":   "PASS" if not issues else "WARN",
            "severity": _sev(low=bool(issues)),
            "detail":   f"Loadable unused filesystems: {issues}" if issues
                        else "Unused filesystem modules disabled",
            "cis_id":   "1.1",
        }

    def check_auditd(self) -> dict:
        out, _, rc = _run(["systemctl", "is-active", "auditd"])
        active = rc == 0 and "active" in out
        return {
            "check":    "Auditd Service",
            "status":   "PASS" if active else "FAIL",
            "severity": _sev(medium=not active),
            "detail":   "auditd running" if active else "auditd not active — enable for audit logging",
            "cis_id":   "4.1",
        }

    def check_apparmor_selinux(self) -> dict:
        for mac, cmd in [("AppArmor", ["aa-status"]),
                         ("SELinux",  ["sestatus"])]:
            out, _, rc = _run(cmd, timeout=5)
            if rc == 0 and out:
                enforcing = "enforcing" in out.lower() or "enabled" in out.lower()
                return {
                    "check":    f"MAC ({mac})",
                    "status":   "PASS" if enforcing else "WARN",
                    "severity": _sev(medium=not enforcing),
                    "detail":   f"{mac} {'enforcing' if enforcing else 'not enforcing'}",
                    "cis_id":   "1.7",
                }
        return {"check": "MAC (AppArmor/SELinux)", "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Neither AppArmor nor SELinux found active", "cis_id": "1.7"}

    def check_umask(self) -> dict:
        out, _, _ = _run(["umask"])
        mask = out.strip()
        ok   = mask in ("0027", "0077", "027", "077")
        return {
            "check":    "Default umask",
            "status":   "PASS" if ok else "WARN",
            "severity": _sev(low=not ok),
            "detail":   f"umask={mask}" + ("" if ok else " — recommend 0027 or 0077"),
            "cis_id":   "5.4.4",
        }

    def check_login_banners(self) -> dict:
        issues = []
        for f in ["/etc/issue", "/etc/issue.net", "/etc/motd"]:
            if not Path(f).exists() or not Path(f).read_text().strip():
                issues.append(f"{f} is missing or empty")
        return {
            "check":    "Login Banners",
            "status":   "PASS" if not issues else "WARN",
            "severity": _sev(low=bool(issues)),
            "detail":   "; ".join(issues) if issues else "Login banners configured",
            "cis_id":   "1.9",
        }


# ── Firewall analyser ─────────────────────────────────────────────────────────

class FirewallAnalyser:
    def analyse_iptables(self) -> dict:
        out, _, rc = _run(["iptables", "-L", "-n", "-v", "--line-numbers"])
        if rc != 0:
            return {"error": "iptables not available or requires root"}
        issues = []
        if "ACCEPT" in out and "0.0.0.0/0" in out:
            issues.append("Permissive ACCEPT rules for 0.0.0.0/0 detected")
        if "policy ACCEPT" in out.lower():
            issues.append("Default chain policy is ACCEPT (recommend DROP/REJECT)")
        return {
            "tool":   "iptables",
            "rules":  out[:3000],
            "issues": issues,
        }

    def analyse_ufw(self) -> dict:
        out, _, rc = _run(["ufw", "status", "verbose"])
        if rc != 0:
            return {"error": "ufw not available"}
        issues = []
        if "Status: inactive" in out:
            issues.append("UFW is INACTIVE")
        return {"tool": "ufw", "rules": out[:2000], "issues": issues}

    def analyse(self, tool: str = "auto") -> dict:
        if tool in ("auto", "ufw"):
            res = self.analyse_ufw()
            if "error" not in res:
                return res
        if tool in ("auto", "iptables"):
            return self.analyse_iptables()
        return {"error": f"Unknown firewall tool: {tool}"}


# ── Remediation generator ─────────────────────────────────────────────────────

class RemediationGenerator:
    def bash_script(self, findings: list[dict]) -> str:
        lines = [
            "#!/usr/bin/env bash",
            "# Shadow313 Auto-Remediation Script",
            f"# Generated: {_now()}",
            "# Run as root. Review each command before applying.",
            "set -euo pipefail",
            "",
        ]
        fix_map = {
            "SSH Configuration": [
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
                "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config",
                "grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config",
                "systemctl restart sshd",
            ],
            "ASLR (randomize_va_space)": [
                "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-shadow313.conf",
                "sysctl -p /etc/sysctl.d/99-shadow313.conf",
            ],
            "Yama ptrace_scope": [
                "echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-shadow313.conf",
                "sysctl -p /etc/sysctl.d/99-shadow313.conf",
            ],
            "Core Dumps Disabled": [
                "echo '* hard core 0' >> /etc/security/limits.conf",
                "echo '* soft core 0' >> /etc/security/limits.conf",
            ],
            "Auditd Service": [
                "apt-get install -y auditd audispd-plugins || yum install -y audit",
                "systemctl enable auditd && systemctl start auditd",
            ],
            "Firewall Status": [
                "apt-get install -y ufw || yum install -y firewalld",
                "ufw default deny incoming && ufw default allow outgoing && ufw enable",
            ],
        }
        for finding in findings:
            check = finding.get("check", "")
            status = finding.get("status", "")
            if status in ("FAIL", "WARN") and check in fix_map:
                lines.append(f"\n# ── Fix: {check} ──")
                lines.extend(fix_map[check])

        lines += ["", "echo 'Remediation complete. Review changes and re-run shadow313 defense --audit'"]
        return "\n".join(lines)

    def ansible_playbook(self, findings: list[dict]) -> str:
        tasks = []
        for f in findings:
            if f.get("status") not in ("FAIL", "WARN"):
                continue
            check = f.get("check", "")
            if "SSH" in check:
                tasks.append({
                    "name": f"Harden SSH — {check}",
                    "lineinfile": {
                        "path": "/etc/ssh/sshd_config",
                        "regexp": "^#?PermitRootLogin",
                        "line": "PermitRootLogin no",
                    },
                })
            if "ASLR" in check:
                tasks.append({
                    "name": "Enable full ASLR",
                    "sysctl": {"name": "kernel.randomize_va_space", "value": "2"},
                })
            if "Firewall" in check:
                tasks.append({
                    "name": "Enable UFW firewall",
                    "community.general.ufw": {"state": "enabled", "policy": "deny"},
                })

        play = [{
            "name":  "Shadow313 Hardening Playbook",
            "hosts": "all",
            "become": True,
            "tasks": tasks,
        }]
        try:
            import yaml
            return yaml.dump(play, default_flow_style=False)
        except ImportError:
            return json.dumps(play, indent=2)


# ── DefenseModule ─────────────────────────────────────────────────────────────

class DefenseModule:
    """
    shadow313.defense — System hardening audit and AI remediation.
    Registered commands: defense
    """

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.config  = kernel.config.get("defense", default={})
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("defense", self.run)

    def run(self, audit: bool = False, profile: str = "cis-level1",
            firewall: bool = False, fw_tool: str = "auto",
            remediate: bool = False, output_fmt: str = "bash",
            apply_fixes: bool = False) -> dict:
        self.out.section("DEFENSIVE HARDENING AUDIT")
        self.session.audit("defense", "start", profile)

        result: dict[str, Any] = {
            "timestamp": _now(),
            "profile":   profile,
            "findings":  [],
        }

        # System info
        self.out.info("Collecting system information …")
        sysinfo = SystemInfo().collect()
        result["system_info"] = sysinfo
        self.out.success(f"OS: {sysinfo.get('os', 'Unknown')}  "
                         f"Kernel: {sysinfo.get('kernel', '')}")

        # CIS Benchmark
        if audit:
            level = 2 if "level2" in profile else 1
            self.out.info(f"Running CIS Level {level} checks …")
            cis = CISBenchmark(level=level)
            findings = cis.run_all()
            result["findings"] = findings

            pass_count = sum(1 for f in findings if f.get("status") == "PASS")
            fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
            warn_count = sum(1 for f in findings if f.get("status") == "WARN")

            self.out.info(
                f"Results: {pass_count} PASS / {fail_count} FAIL / {warn_count} WARN"
            )

            # Print findings table
            rows = [
                [f.get("check", ""), f.get("status", ""), f.get("severity", ""),
                 f.get("detail", "")[:70], f.get("cis_id", "")]
                for f in findings
            ]
            self.out.table(
                ["Check", "Status", "Severity", "Detail", "CIS ID"],
                rows, "CIS Benchmark Results"
            )

            # Compliance score
            total = len(findings)
            score = round((pass_count / total) * 100, 1) if total > 0 else 0
            result["compliance_score"] = score
            self.out.info(f"Compliance Score: {score}%")

        # Firewall analysis
        if firewall:
            self.out.info(f"Analysing firewall ({fw_tool}) …")
            fw_result = FirewallAnalyser().analyse(fw_tool)
            result["firewall"] = fw_result
            if fw_result.get("issues"):
                for issue in fw_result["issues"]:
                    self.out.warn(f"Firewall: {issue}")

        # Remediation
        if remediate or result.get("findings"):
            failed = [f for f in result.get("findings", [])
                      if f.get("status") in ("FAIL", "WARN")]
            if failed:
                gen = RemediationGenerator()
                if output_fmt == "ansible":
                    script = gen.ansible_playbook(failed)
                    ext    = "yml"
                else:
                    script = gen.bash_script(failed)
                    ext    = "sh"

                script_path = self.session.path(f"remediation.{ext}")
                script_path.write_text(script)
                result["remediation_script"] = str(script_path)
                self.out.success(f"Remediation script → {script_path}")

                if apply_fixes:
                    self.out.warn("--apply flag detected: executing remediation script …")
                    _run(["bash", str(script_path)], timeout=120)

        # AI remediation plan
        self.out.info("Generating AI remediation plan …")
        result["ai_plan"] = self._ai_plan(result)
        self.out.ai_response(result["ai_plan"], "AI Hardening Remediation Plan")

        path = self.session.write("compliance.json", result)
        self.out.success(f"Audit results saved → {path}")
        self.session.audit("defense", "complete", str(path))
        return result

    def _ai_plan(self, data: dict) -> str:
        failed = [f for f in data.get("findings", [])
                  if f.get("status") in ("FAIL", "WARN")]
        ctx = {
            "os":              data.get("system_info", {}).get("os", ""),
            "kernel":          data.get("system_info", {}).get("kernel", ""),
            "failed_checks":   failed[:20],
            "compliance_score":data.get("compliance_score", "N/A"),
            "firewall_issues": data.get("firewall", {}).get("issues", []),
        }
        return self.ai.chat(
            "You are a Linux hardening expert. Analyse these CIS benchmark failures and generate a "
            "prioritised remediation plan. For each critical/high finding: (1) explain the risk, "
            "(2) provide the exact fix command, (3) estimated effort. Then provide a phased "
            "hardening roadmap (immediate/short-term/long-term). Be specific and actionable.",
            context=ctx,
        )