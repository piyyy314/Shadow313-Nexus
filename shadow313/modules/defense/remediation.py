"""shadow313.modules.defense.remediation — Bash and Ansible remediation generator."""
from __future__ import annotations
import json
from datetime import datetime, timezone


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


FIX_MAP = {
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


class RemediationGenerator:
    def bash_script(self, findings: list[dict]) -> str:
        """Return Bash commands for supported FAIL/WARN findings without executing them."""
        lines = [
            "#!/usr/bin/env bash",
            "# Shadow313 v2 Auto-Remediation Script",
            f"# Generated: {_now()}",
            "# Run as root. Review each command before applying.",
            "set -euo pipefail",
            "",
        ]
        for finding in findings:
            check  = finding.get("check", "")
            status = finding.get("status", "")
            if status in ("FAIL", "WARN") and check in FIX_MAP:
                lines.append(f"\n# ── Fix: {check} ──")
                lines.extend(FIX_MAP[check])
        lines += ["", "echo 'Remediation complete. Re-run: shadow313 defense --audit'"]
        return "\n".join(lines)

    def ansible_playbook(self, findings: list[dict]) -> str:
        """Return an Ansible playbook for supported FAIL/WARN findings without applying it.

        Use JSON text when PyYAML is unavailable.
        """
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
        play = [{"name": "Shadow313 v2 Hardening Playbook",
                 "hosts": "all", "become": True, "tasks": tasks}]
        try:
            import yaml
            return yaml.dump(play, default_flow_style=False)
        except ImportError:
            return json.dumps(play, indent=2)

# ── File Encryption Rate Monitor (RW-01) ─────────────────────────────────────
import threading
import time as _time
from pathlib import Path as _Path


class FileEncryptionRateMonitor:
    """Monitor file-system rename/modification rate to detect ransomware.

    Watches a set of directories using polling (inotify not always available).
    Fires alert_callback when rename rate exceeds threshold.

    Args:
        watch_dirs:       Directories to monitor (default: home + /tmp).
        threshold_per_s:  Renames/sec that triggers alert (default: 50).
        window_s:         Sliding window in seconds (default: 10).
        poll_interval_s:  How often to scan (default: 2).
        alert_callback:   Callable(rate, path) invoked on threshold breach.
    """

    def __init__(
        self,
        watch_dirs: list[str] | None = None,
        threshold_per_s: float = 50.0,
        window_s: float = 10.0,
        poll_interval_s: float = 2.0,
        alert_callback=None,
    ) -> None:
        """Configure polling of recently modified paths without starting the monitor.

        Rates count observations per second, including repeated observations of
        the same path. Window and polling intervals are in seconds. A falsy
        watch_dirs uses home and /tmp. The callback receives (rate, sample_path).
        """
        self.watch_dirs = [_Path(d) for d in (watch_dirs or [str(_Path.home()), "/tmp"])]
        self.threshold_per_s = threshold_per_s
        self.window_s = window_s
        self.poll_interval_s = poll_interval_s
        self.alert_callback = alert_callback or self._default_alert
        self._running = False
        self._thread: threading.Thread | None = None
        self._events: list[tuple[float, str]] = []  # (timestamp, path)
        self._lock = threading.Lock()

    def _default_alert(self, rate: float, sample_path: str) -> None:
        """Print the observed event rate and a sample path to stdout."""
        print(
            f"[SHADOW313-RW-01] RANSOMWARE ALERT: {rate:.1f} file events/sec "
            f"(threshold={self.threshold_per_s}). Sample: {sample_path}"
        )

    def _scan(self) -> list[tuple[float, str]]:
        """Return (observation time, path) pairs for recently modified entries.

        Include entries modified within twice the polling interval, including
        directories. Timestamps are epoch seconds at observation, not mtimes.
        Skip stat errors and permission failures while walking directories.
        """
        events = []
        cutoff = _time.time() - self.poll_interval_s * 2
        for d in self.watch_dirs:
            if not d.exists():
                continue
            try:
                for p in d.rglob("*"):
                    try:
                        st = p.stat()
                        if st.st_mtime >= cutoff:
                            events.append((_time.time(), str(p)))
                    except OSError:
                        pass
            except PermissionError:
                pass
        return events

    def _monitor_loop(self) -> None:
        """Poll paths and invoke the callback when the window rate reaches the threshold.

        Callback errors are not caught and end the monitoring thread.
        """
        while self._running:
            new_events = self._scan()
            now = _time.time()
            with self._lock:
                self._events.extend(new_events)
                # Prune events outside sliding window
                self._events = [
                    (ts, p) for ts, p in self._events
                    if now - ts <= self.window_s
                ]
                count = len(self._events)
                rate = count / self.window_s
                if rate >= self.threshold_per_s and self._events:
                    sample = self._events[-1][1]
                    self.alert_callback(rate, sample)
            _time.sleep(self.poll_interval_s)

    def start(self) -> None:
        """Start background monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Request monitoring to stop and wait up to five seconds for the thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def current_rate(self) -> float:
        """Return current file event rate (events/sec) over the sliding window."""
        now = _time.time()
        with self._lock:
            recent = [ts for ts, _ in self._events if now - ts <= self.window_s]
            return len(recent) / self.window_s
