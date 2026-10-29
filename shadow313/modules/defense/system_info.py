"""shadow313.modules.defense.system_info — System information collector."""
from __future__ import annotations
import subprocess
from typing import Any


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """Run a command with a timeout in seconds; return stdout, stderr, and exit code.

    Missing commands return code 127; timeouts and other execution failures
    return code 1 with an error string instead of raising.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors="replace", check=False)
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as exc:
        return "", str(exc), 1


class SystemInfo:
    def collect(self) -> dict[str, Any]:
        """Return OS, kernel, host, user, listener, and up to 50 package records."""
        return {
            "os":             self._os_info(),
            "kernel":         self._kernel(),
            "hostname":       self._hostname(),
            "users":          self._users(),
            "listening":      self._listening_services(),
            "installed_pkgs": self._installed_packages()[:50],
        }

    def _os_info(self) -> str:
        """Return PRETTY_NAME from os-release, or "Unknown" if unavailable."""
        out, _, _ = _run(["cat", "/etc/os-release"])
        for line in out.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return "Unknown"

    def _kernel(self) -> str:
        """Return the kernel release, or an empty string if the command produces no output."""
        out, _, _ = _run(["uname", "-r"])
        return out.strip()

    def _hostname(self) -> str:
        """Return the hostname, or an empty string if the command produces no output."""
        out, _, _ = _run(["hostname"])
        return out.strip()

    def _users(self) -> list[dict]:
        """Return passwd user records with a login-shell flag; unavailable output yields []."""
        out, _, _ = _run(["cat", "/etc/passwd"])
        users = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                uid = int(parts[2]) if parts[2].isdigit() else -1
                users.append({
                    "username":  parts[0],
                    "uid":       uid,
                    "shell":     parts[6],
                    "home":      parts[5],
                    "has_login": parts[6] not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"),
                })
        return users

    def _listening_services(self) -> list[dict]:
        """Return TCP listener records parsed from ss output, or [] when unavailable."""
        out, _, _ = _run(["ss", "-tlnp"])
        services = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[3]
                proc = parts[6] if len(parts) > 6 else ""
                port = addr.split(":")[-1]
                services.append({"address": addr, "port": port, "process": proc})
        return services

    def _installed_packages(self) -> list[str]:
        """Return up to 100 package entries from the first successful package manager probe."""
        for cmd in (["dpkg", "--list"], ["rpm", "-qa"], ["brew", "list"]):
            out, _, rc = _run(cmd, timeout=10)
            if rc == 0 and out:
                pkgs = [line.split()[1] for line in out.splitlines()
                        if line.startswith("ii")] or out.splitlines()
                return pkgs[:100]
        return []