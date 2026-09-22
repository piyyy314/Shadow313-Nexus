"""
shadow313.v4.detection.enforcement — NEXUS Complete
D3-PT (Process Termination) + D3-OTF (Outbound Traffic Filtering)

Closes the critical enforcement gap identified in the Aegis telemetry:
  nc PID 14209 was detected 3× over 35 minutes and never killed.
  The eBPF socket intercept logged events but did not enforce termination.

This module adds the Evict tactic to Shadow313's detection pipeline:
  D3-PT: Process Termination — kill processes violating network policy
  D3-OTF: Outbound Traffic Filtering — block known C2 ports via iptables

D3FEND references:
  D3-PT:  d3fend.mitre.org/technique/d3f:ProcessTermination/
  D3-OTF: d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/

ATT&CK techniques countered:
  T1095  Non-Application Layer Protocol (nc reverse shell)
  T1071.001  Web Protocols (Cobalt Strike beacon)
  T1071.004  DNS Tunneling
  T1105  Ingress Tool Transfer (curl download)
"""
from __future__ import annotations

import hmac
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Policy definitions ────────────────────────────────────────────────────────

# Ports that are NEVER permitted for outbound connections from monitored hosts
# These are canonical attacker/C2 ports with no legitimate use in production
BLOCKED_OUTBOUND_PORTS: frozenset[int] = frozenset({
    4444,   # Metasploit/nc default reverse shell — confirmed in telemetry
    4445,   # Metasploit alternative
    4446,   # Metasploit alternative
    1234,   # Common reverse shell
    1337,   # "Elite" port — common backdoor
    31337,  # "Elite" port — common backdoor
    9001,   # Tor relay default — confirmed in telemetry (svchost_local.exe)
    9050,   # Tor SOCKS proxy
    9150,   # Tor Browser SOCKS
    6666,   # IRC/botnet
    6667,   # IRC/botnet
    6668,   # IRC/botnet
    6669,   # IRC/botnet
})

# Process names that should NEVER make outbound connections
# Any outbound connection from these processes is an IOC
RESTRICTED_PROCESSES: frozenset[str] = frozenset({
    "nc",
    "ncat",
    "netcat",
    "nmap",              # Should not make outbound connections in production
    "backdoor_payload",  # Explicit IOC from Aegis telemetry
    "payload",
    "shell",
    "reverse_shell",
})

# External IP ranges that monitored server processes should not connect to
# (RFC1918 private ranges are always allowed)
APPROVED_EXTERNAL_DESTINATIONS: frozenset[str] = frozenset({
    # NVD API
    "services.nvd.nist.gov",
    # KEV feed
    "www.cisa.gov",
    # EPSS API
    "api.first.org",
    # MITRE ATT&CK STIX
    "raw.githubusercontent.com",
    # PyPI (for pip-audit)
    "pypi.org",
    "files.pythonhosted.org",
})


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class EnforcementAction:
    """Record of a D3-PT enforcement decision."""
    pid:          int
    process_name: str
    dst_ip:       str
    dst_port:     int
    action:       str       # KILLED | BLOCKED | LOGGED | ALLOWED | WOULD_KILL
    timestamp:    str
    reason:       str
    d3fend:       str = "D3-PT"
    attack:       str = "T1095"
    signal_sent:  Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OTFRule:
    """An outbound traffic filtering rule (D3-OTF)."""
    rule_id:    str
    dst_port:   Optional[int]
    dst_ip:     Optional[str]
    protocol:   str = "tcp"
    action:     str = "DROP"
    comment:    str = ""
    applied:    bool = False
    error:      str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# D3-PT: PROCESS TERMINATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ProcessTerminator:
    """
    D3-PT: Process Termination (Evict tactic)

    Kills processes that violate network policy when triggered by the
    eBPF sys_enter_connect tracepoint.

    The critical gap this closes:
      nc PID 14209 was detected 3× over 35 minutes and never killed.
      This class adds os.kill(pid, SIGKILL) to the enforcement path.

    Enforcement modes:
      enforcement_mode=True:  SIGKILL delivered immediately on policy violation
      enforcement_mode=False: Log only (monitoring mode — the current gap)

    Kernel alternative:
      bpf_send_signal(SIGKILL) from eBPF program (Linux 5.3+) delivers
      the signal without a userspace round-trip, reducing enforcement
      latency from ~1ms to ~10μs.

    D3FEND: d3fend.mitre.org/technique/d3f:ProcessTermination/
    ATT&CK countered: T1095, T1071.001, T1071.004, T1105
    """

    def __init__(
        self,
        blocked_ports:     frozenset[int] = BLOCKED_OUTBOUND_PORTS,
        restricted_procs:  frozenset[str] = RESTRICTED_PROCESSES,
        enforcement_mode:  bool = True,
        log_all:           bool = True,
    ) -> None:
        self._blocked_ports    = blocked_ports
        self._restricted_procs = restricted_procs
        self._enforcement_mode = enforcement_mode
        self._log_all          = log_all
        self._actions: list[EnforcementAction] = []
        self._kill_count   = 0
        self._block_count  = 0
        self._allow_count  = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate_connection(
        self,
        pid:          int,
        process_name: str,
        dst_ip:       str,
        dst_port:     int,
    ) -> EnforcementAction:
        """
        Evaluate an outbound connection attempt and enforce policy.

        Called by the eBPF sys_enter_connect handler when a process
        attempts an outbound TCP/UDP connection.

        Returns an EnforcementAction describing what was done.
        """
        now = _now_iso()

        # Policy 1: blocked port — highest priority
        if dst_port in self._blocked_ports:
            return self._enforce(
                pid, process_name, dst_ip, dst_port, now,
                reason=f"Port {dst_port} is in blocked outbound port list "
                       f"(canonical C2/reverse-shell port)",
                attack="T1095",
            )

        # Policy 2: restricted process name
        if process_name.lower() in self._restricted_procs:
            return self._enforce(
                pid, process_name, dst_ip, dst_port, now,
                reason=f"Process '{process_name}' is in restricted process list — "
                       f"should never make outbound connections",
                attack="T1095",
            )

        # Policy 3: external destination from a process that should be local-only
        if self._is_external(dst_ip) and self._is_server_process(process_name):
            # Log but do not kill — server processes legitimately make external calls
            return self._log_only(
                pid, process_name, dst_ip, dst_port, now,
                reason=f"Server process '{process_name}' connecting to external "
                       f"IP {dst_ip} — monitoring",
            )

        # Allowed
        self._allow_count += 1
        action = EnforcementAction(
            pid=pid, process_name=process_name, dst_ip=dst_ip, dst_port=dst_port,
            action="ALLOWED", timestamp=now,
            reason="Policy: permitted outbound connection",
        )
        if self._log_all:
            self._actions.append(action)
        return action

    def kill_pid(self, pid: int, reason: str = "manual") -> dict:
        """
        Directly kill a PID. Used for manual enforcement (e.g., kill nc PID 14209).
        """
        now = _now_iso()
        try:
            os.kill(pid, signal.SIGKILL)
            self._kill_count += 1
            log.critical("D3-PT MANUAL KILL: PID %d — %s", pid, reason)
            return {"pid": pid, "action": "KILLED", "reason": reason, "timestamp": now}
        except ProcessLookupError:
            log.warning("D3-PT: PID %d not found (already terminated)", pid)
            return {"pid": pid, "action": "NOT_FOUND", "reason": reason, "timestamp": now}
        except PermissionError:
            log.error("D3-PT: Cannot kill PID %d — insufficient privileges", pid)
            return {"pid": pid, "action": "PERMISSION_DENIED", "reason": reason, "timestamp": now}

    def find_and_kill_process(self, process_name: str) -> list[dict]:
        """
        Find all PIDs matching a process name and kill them.
        Used for: kill_process("nc") to terminate all nc instances.
        """
        results = []
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                comm = (pid_dir / "comm").read_text().strip()
                if comm.lower() == process_name.lower():
                    result = self.kill_pid(int(pid_dir.name), f"process name match: {process_name}")
                    results.append(result)
            except Exception as _exc:
                import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
                continue
        return results

    # ── Internal ──────────────────────────────────────────────────────────────

    def _enforce(
        self, pid: int, process_name: str, dst_ip: str,
        dst_port: int, now: str, reason: str, attack: str = "T1095",
    ) -> EnforcementAction:
        """Kill the process (enforcement mode) or log (monitoring mode)."""
        if self._enforcement_mode:
            try:
                os.kill(pid, signal.SIGKILL)
                action_str  = "KILLED"
                signal_sent = signal.SIGKILL
                self._kill_count += 1
                log.critical(
                    "D3-PT ENFORCEMENT [%s]: Killed PID %d (%s) → %s:%d — %s",
                    attack, pid, process_name, dst_ip, dst_port, reason,
                )
            except ProcessLookupError:
                action_str  = "ALREADY_DEAD"
                signal_sent = None
                log.warning("D3-PT: PID %d already terminated", pid)
            except PermissionError:
                action_str  = "PERMISSION_DENIED"
                signal_sent = None
                log.error(
                    "D3-PT: Cannot kill PID %d — insufficient privileges. "
                    "Shadow313 must run as root or with CAP_KILL for enforcement.",
                    pid,
                )
        else:
            action_str  = "WOULD_KILL"
            signal_sent = None
            self._block_count += 1
            log.warning(
                "D3-PT MONITORING [%s]: Would kill PID %d (%s) → %s:%d — %s "
                "(enforcement_mode=False)",
                attack, pid, process_name, dst_ip, dst_port, reason,
            )

        action = EnforcementAction(
            pid=pid, process_name=process_name, dst_ip=dst_ip, dst_port=dst_port,
            action=action_str, timestamp=now, reason=reason,
            d3fend="D3-PT", attack=attack, signal_sent=signal_sent,
        )
        self._actions.append(action)
        return action

    def _log_only(
        self, pid: int, process_name: str, dst_ip: str,
        dst_port: int, now: str, reason: str,
    ) -> EnforcementAction:
        action = EnforcementAction(
            pid=pid, process_name=process_name, dst_ip=dst_ip, dst_port=dst_port,
            action="LOGGED", timestamp=now, reason=reason,
            d3fend="D3-PT", attack="T1095",
        )
        self._actions.append(action)
        log.warning("D3-PT MONITOR: %s", reason)
        return action

    @staticmethod
    def _is_external(ip: str) -> bool:
        """Returns True if IP is not RFC1918 private or loopback."""
        try:
            parts = [int(x) for x in ip.split(".")]
            if parts[0] == 10:                              return False
            if parts[0] == 172 and 16 <= parts[1] <= 31:   return False
            if parts[0] == 192 and parts[1] == 168:         return False
            if parts[0] == 127:                             return False
            if parts[0] == 169 and parts[1] == 254:         return False
        except Exception as _exc:
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
        return True

    @staticmethod
    def _is_server_process(name: str) -> bool:
        """Returns True if the process is a known server that makes external calls."""
        server_procs = {"python3", "python", "uvicorn", "gunicorn", "nginx", "node"}
        return name.lower() in server_procs

    # ── Reporting ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "enforcement_mode": self._enforcement_mode,
            "total_actions":    len(self._actions),
            "killed":           self._kill_count,
            "blocked":          self._block_count,
            "allowed":          self._allow_count,
            "blocked_ports":    sorted(self._blocked_ports),
            "restricted_procs": sorted(self._restricted_procs),
        }

    def get_enforcement_log(self) -> list[dict]:
        return [a.to_dict() for a in self._actions]

    def get_kill_log(self) -> list[dict]:
        return [a.to_dict() for a in self._actions if a.action == "KILLED"]


# ═══════════════════════════════════════════════════════════════════════════════
# D3-OTF: OUTBOUND TRAFFIC FILTER
# ═══════════════════════════════════════════════════════════════════════════════

class OutboundTrafficFilter:
    """
    D3-OTF: Outbound Traffic Filtering (Isolate tactic)

    Applies iptables rules to block outbound connections on known C2 ports.
    Complements D3-PT: D3-PT kills the process, D3-OTF blocks the packets.
    Defense in depth: even if D3-PT fails (permission error), D3-OTF blocks.

    Implementations (per D3FEND):
      - iptables (Linux) — used here
      - nftables (Linux, modern alternative)
      - pf (BSD)
      - Windows Firewall

    D3FEND: d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/
    ATT&CK countered: T1095, T1071.001, T1071.004
    """

    def __init__(
        self,
        blocked_ports: frozenset[int] = BLOCKED_OUTBOUND_PORTS,
        dry_run:       bool = False,
    ) -> None:
        self._blocked_ports = blocked_ports
        self._dry_run       = dry_run
        self._rules: list[OTFRule] = []
        self._applied_rules: list[OTFRule] = []

    def generate_rules(self) -> list[OTFRule]:
        """Generate iptables rules for all blocked ports."""
        rules = []
        for port in sorted(self._blocked_ports):
            rules.append(OTFRule(
                rule_id  = f"OTF-PORT-{port}",
                dst_port = port,
                dst_ip   = None,
                protocol = "tcp",
                action   = "DROP",
                comment  = f"D3-OTF: block C2 port {port} (T1095/T1071)",
            ))
            # Also block UDP (some C2 tools use UDP)
            rules.append(OTFRule(
                rule_id  = f"OTF-PORT-{port}-UDP",
                dst_port = port,
                dst_ip   = None,
                protocol = "udp",
                action   = "DROP",
                comment  = f"D3-OTF: block C2 port {port} UDP",
            ))
        self._rules = rules
        return rules

    def apply_rules(self) -> dict:
        """Apply iptables rules. Returns summary of applied/failed rules."""
        if not self._rules:
            self.generate_rules()

        applied = 0
        failed  = 0
        errors  = []

        for rule in self._rules:
            cmd = self._build_iptables_cmd(rule)
            if self._dry_run:
                log.info("D3-OTF DRY-RUN: %s", " ".join(cmd))
                rule.applied = True
                applied += 1
                continue

            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    rule.applied = True
                    applied += 1
                    log.info("D3-OTF APPLIED: %s", rule.comment)
                else:
                    rule.error = result.stderr.strip()
                    failed += 1
                    errors.append(f"{rule.rule_id}: {rule.error}")
                    log.error("D3-OTF FAILED: %s — %s", rule.rule_id, rule.error)
            except FileNotFoundError:
                rule.error = "iptables not found"
                failed += 1
                errors.append(f"{rule.rule_id}: iptables not available")
            except subprocess.TimeoutExpired:
                rule.error = "timeout"
                failed += 1

        self._applied_rules = [r for r in self._rules if r.applied]

        return {
            "total_rules": len(self._rules),
            "applied":     applied,
            "failed":      failed,
            "errors":      errors,
            "dry_run":     self._dry_run,
            "d3fend":      "D3-OTF",
            "timestamp":   _now_iso(),
        }

    def flush_rules(self) -> dict:
        """Remove all D3-OTF rules (for cleanup/testing)."""
        removed = 0
        for rule in self._applied_rules:
            cmd = self._build_iptables_cmd(rule, delete=True)
            if self._dry_run:
                log.info("D3-OTF DRY-RUN FLUSH: %s", " ".join(cmd))
                removed += 1
                continue
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    removed += 1
            except Exception as _exc:
                import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
        return {"removed": removed, "timestamp": _now_iso()}

    def get_rules_as_bash(self) -> str:
        """Return rules as a bash script for manual application."""
        if not self._rules:
            self.generate_rules()
        lines = [
            "#!/bin/bash",
            "# Shadow313 D3-OTF: Outbound Traffic Filtering",
            "# Generated: " + _now_iso(),
            "# ATT&CK countered: T1095, T1071.001, T1071.004",
            "",
        ]
        for rule in self._rules:
            cmd = self._build_iptables_cmd(rule)
            lines.append(" ".join(cmd))
        return "\n".join(lines)

    @staticmethod
    def _build_iptables_cmd(rule: OTFRule, delete: bool = False) -> list[str]:
        flag = "-D" if delete else "-A"
        cmd  = ["iptables", flag, "OUTPUT", "-p", rule.protocol]
        if rule.dst_port:
            cmd += ["--dport", str(rule.dst_port)]
        if rule.dst_ip:
            cmd += ["-d", rule.dst_ip]
        cmd += ["-j", rule.action]
        if rule.comment:
            cmd += ["-m", "comment", "--comment", rule.comment]
        return cmd


# ═══════════════════════════════════════════════════════════════════════════════
# D3-SCA EXTENSION: memfd_create + execveat monitoring
# ═══════════════════════════════════════════════════════════════════════════════

# These tokens extend the zero_evasion_countermeasure.py ZERO_EVASION_TOKENS
# to cover T1620 (Reflective Code Loading / fileless execution)
T1620_TOKENS = {
    "memfd_create":  33,  # Anonymous executable memory — fileless malware
    "execveat":      34,  # Execute from file descriptor — memfd execution
    "mprotect_exec": 35,  # Memory permission change to executable
}

# Additional SENSITIVE_SYSCALLS entries for EBPFSyscallTracer
T1620_SENSITIVE_SYSCALLS = {
    "memfd_create": {
        "target_process": "any",
        "severity":       "CRITICAL",
        "note":           "Anonymous executable memory — T1620 fileless malware pattern. "
                          "Legitimate uses: memfd for IPC (rare). "
                          "Malicious use: download payload → write to memfd → execveat.",
        "d3fend":         "D3-SCA",
        "attack":         "T1620",
    },
    "execveat": {
        "target_process": "any",
        "severity":       "CRITICAL",
        "note":           "Execute from file descriptor — T1620 memfd execution. "
                          "execveat(fd, '', argv, envp, AT_EMPTY_PATH) executes "
                          "the file referred to by fd without a filesystem path.",
        "d3fend":         "D3-SCA",
        "attack":         "T1620",
    },
    "mprotect": {
        "target_process": "any",
        "severity":       "HIGH",
        "note":           "Memory permission change — shellcode staging. "
                          "mprotect(addr, len, PROT_EXEC) makes a memory region executable. "
                          "Legitimate uses: JIT compilers. "
                          "Malicious use: mark shellcode region as executable before execution.",
        "d3fend":         "D3-SCA + D3-PSMD",
        "attack":         "T1620 / T1055",
    },
    "process_vm_writev": {
        "target_process": "any",
        "severity":       "CRITICAL",
        "note":           "Write to another process's memory — T1055 process injection. "
                          "process_vm_writev() writes directly to another process's address space "
                          "without ptrace, bypassing some monitoring tools.",
        "d3fend":         "D3-SCA + D3-PSMD",
        "attack":         "T1055.009",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# COMBINED ENFORCEMENT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class EnforcementEngine:
    """
    Combined D3-PT + D3-OTF enforcement engine.

    Integrates process termination and outbound traffic filtering
    into a single interface for the Shadow313 kernel.

    Usage:
        engine = EnforcementEngine(enforcement_mode=True)
        engine.apply_network_filters()  # D3-OTF: iptables rules

        # Called by eBPF event handler:
        action = engine.on_connect(pid=14209, process="nc",
                                   dst_ip="192.168.1.1", dst_port=4444)
        # → action.action == "KILLED"
    """

    def __init__(
        self,
        enforcement_mode: bool = True,
        dry_run:          bool = False,
    ) -> None:
        self.terminator = ProcessTerminator(enforcement_mode=enforcement_mode)
        self.otf        = OutboundTrafficFilter(dry_run=dry_run)
        self._start_time = _now_iso()

    def apply_network_filters(self) -> dict:
        """Apply D3-OTF iptables rules at startup."""
        return self.otf.apply_rules()

    def on_connect(
        self,
        pid:          int,
        process_name: str,
        dst_ip:       str,
        dst_port:     int,
    ) -> EnforcementAction:
        """
        Handle an eBPF sys_enter_connect event.
        Applies D3-PT policy and returns the enforcement action.
        """
        return self.terminator.evaluate_connection(
            pid=pid, process_name=process_name,
            dst_ip=dst_ip, dst_port=dst_port,
        )

    def emergency_kill(self, pid: int, reason: str = "emergency") -> dict:
        """Kill a specific PID immediately (e.g., kill nc PID 14209)."""
        return self.terminator.kill_pid(pid, reason)

    def kill_all(self, process_name: str) -> list[dict]:
        """Kill all instances of a process by name."""
        return self.terminator.find_and_kill_process(process_name)

    def get_status(self) -> dict:
        return {
            "start_time":   self._start_time,
            "terminator":   self.terminator.get_stats(),
            "otf_rules":    len(self.otf._applied_rules),
            "d3fend":       ["D3-PT", "D3-OTF"],
            "attack_countered": ["T1095", "T1071.001", "T1071.004", "T1105"],
        }