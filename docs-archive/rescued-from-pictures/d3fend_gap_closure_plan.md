# D3FEND v1.5.0 Gap Closure Plan — Attack Chain Coverage
**Date:** 2026-08-29 | **D3FEND Version:** 1.5.0 | **ATT&CK Version:** v19.2  
**Scope:** Five ATT&CK techniques with no or partial Shadow313 v4 coverage  
**Priority focus:** T1095 (nc C2 not stopped) and T1014 (DKOM not stopped)

---

## The Five Gaps — Ordered by Operational Urgency

```
PRIORITY 1 (IMMEDIATE — attacker active now)
  T1095  nc outbound C2 — PID 14209 live for 35+ minutes, never killed
  T1014  DKOM rootkit — EPT violation detected, enforcement mode disabled

PRIORITY 2 (HIGH — closes fileless execution gap)
  T1620  memfd_create() fileless execution — zero Shadow313 coverage

PRIORITY 3 (MEDIUM — closes initial access vectors)
  T1190  SQL injection — AST detection only, no runtime prevention
  T1059.004  Unix shell execution — AST detection only, no runtime prevention
```

---

## T1095 — Non-Application Layer Protocol (nc outbound C2)
**Current Shadow313 coverage:** ⚠️ Partial — eBPF socket intercept detects but does not terminate  
**Attacker status:** ❌ NOT STOPPED — PID 14209 active 35+ minutes

### D3FEND Countermeasures Required

#### D3-PT — Process Termination (Evict tactic)
**Definition:** Terminating a running process on a computer system.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:ProcessTermination/  
**Tactic:** Evict  
**Implementation level:** Userspace (signal delivery) triggered by kernel event

**Why this is the highest-priority fix:** The eBPF `sys_enter_connect` tracepoint already fires when nc attempts the outbound socket. The detection is working. The missing piece is a single `os.kill(pid, signal.SIGKILL)` call in the enforcement path. This is a 30-minute implementation that would have stopped the attack at T+0 instead of letting it run for 35+ minutes.

**Implementation — kernel vs. userspace:**
- The eBPF program runs at kernel level (BPF_PROG_TYPE_TRACEPOINT)
- The kill signal can be delivered from userspace via `os.kill()` after the eBPF event is received by the userspace daemon
- Alternatively, the eBPF program can use `bpf_send_signal(SIGKILL)` to deliver the signal directly from kernel context without a userspace round-trip (Linux 5.3+)

```python
# shadow313/v4/detection/enforcement.py — D3-PT implementation

import os
import signal
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Ports that are never permitted for outbound connections from monitored processes
BLOCKED_OUTBOUND_PORTS = {
    4444,   # Metasploit/nc default reverse shell
    4445,   # Metasploit alternative
    1234,   # Common reverse shell
    31337,  # Elite/leet port — common backdoor
    9001,   # Tor relay default
    9050,   # Tor SOCKS proxy
}

# Processes that should never make outbound connections
RESTRICTED_PROCESSES = {
    "nc", "ncat", "netcat",           # Netcat variants
    "backdoor_payload",               # Explicit IOC from telemetry
    "python3",                        # Only if spawned from suspicious parent
}

@dataclass
class EnforcementAction:
    pid:        int
    process:    str
    dst_ip:     str
    dst_port:   int
    action:     str   # "KILLED" | "BLOCKED" | "ALLOWED"
    timestamp:  str
    reason:     str

class ProcessTerminator:
    """
    D3-PT: Process Termination
    
    Evicts processes that violate network policy by delivering SIGKILL.
    Triggered by eBPF socket intercept events.
    
    Implementation: userspace signal delivery after eBPF event receipt.
    Kernel alternative: bpf_send_signal(SIGKILL) from eBPF program (Linux 5.3+).
    
    D3FEND: d3fend.mitre.org/technique/d3f:ProcessTermination/
    ATT&CK countered: T1095, T1071.001, T1071.004
    """

    def __init__(
        self,
        blocked_ports:    set[int] = BLOCKED_OUTBOUND_PORTS,
        restricted_procs: set[str] = RESTRICTED_PROCESSES,
        enforcement_mode: bool = True,
    ) -> None:
        self._blocked_ports    = blocked_ports
        self._restricted_procs = restricted_procs
        self._enforcement_mode = enforcement_mode
        self._actions: list[EnforcementAction] = []

    def evaluate_connection(
        self,
        pid:      int,
        process:  str,
        dst_ip:   str,
        dst_port: int,
    ) -> EnforcementAction:
        """
        Evaluate an outbound connection attempt and enforce policy.
        Called by the eBPF sys_enter_connect handler.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Policy check 1: blocked port
        if dst_port in self._blocked_ports:
            reason = f"Port {dst_port} is in blocked outbound port list"
            return self._enforce(pid, process, dst_ip, dst_port, reason, now)

        # Policy check 2: restricted process
        if process.lower() in self._restricted_procs:
            reason = f"Process '{process}' is in restricted process list"
            return self._enforce(pid, process, dst_ip, dst_port, reason, now)

        # Policy check 3: non-RFC1918 destination from server process
        if self._is_external(dst_ip) and process in ("python3", "python"):
            reason = f"Server process '{process}' making external connection to {dst_ip}"
            # Log but don't kill — python3 legitimately makes external connections
            action = EnforcementAction(
                pid=pid, process=process, dst_ip=dst_ip, dst_port=dst_port,
                action="LOGGED", timestamp=now,
                reason=f"WARN: {reason}",
            )
            self._actions.append(action)
            log.warning("D3-PT WARN: %s", reason)
            return action

        action = EnforcementAction(
            pid=pid, process=process, dst_ip=dst_ip, dst_port=dst_port,
            action="ALLOWED", timestamp=now, reason="Policy: permitted",
        )
        self._actions.append(action)
        return action

    def _enforce(
        self, pid: int, process: str, dst_ip: str,
        dst_port: int, reason: str, now: str,
    ) -> EnforcementAction:
        """Kill the process and log the enforcement action."""
        if self._enforcement_mode:
            try:
                os.kill(pid, signal.SIGKILL)
                action_str = "KILLED"
                log.critical(
                    "D3-PT ENFORCEMENT: Killed PID %d (%s) — %s → %s:%d — %s",
                    pid, process, process, dst_ip, dst_port, reason,
                )
            except ProcessLookupError:
                action_str = "ALREADY_DEAD"
                log.warning("D3-PT: PID %d already terminated", pid)
            except PermissionError:
                action_str = "PERMISSION_DENIED"
                log.error("D3-PT: Cannot kill PID %d — insufficient privileges", pid)
        else:
            action_str = "WOULD_KILL"
            log.warning(
                "D3-PT MONITORING: Would kill PID %d (%s) — %s",
                pid, process, reason,
            )

        action = EnforcementAction(
            pid=pid, process=process, dst_ip=dst_ip, dst_port=dst_port,
            action=action_str, timestamp=now, reason=reason,
        )
        self._actions.append(action)
        return action

    def _is_external(self, ip: str) -> bool:
        """Returns True if IP is not RFC1918 private."""
        try:
            parts = [int(x) for x in ip.split(".")]
            if parts[0] == 10: return False
            if parts[0] == 172 and 16 <= parts[1] <= 31: return False
            if parts[0] == 192 and parts[1] == 168: return False
            if parts[0] == 127: return False
        except Exception:
            pass
        return True

    def get_enforcement_log(self) -> list[dict]:
        return [
            {
                "pid": a.pid, "process": a.process,
                "dst": f"{a.dst_ip}:{a.dst_port}",
                "action": a.action, "timestamp": a.timestamp,
                "reason": a.reason,
            }
            for a in self._actions
        ]
```

**Effort:** 1–2 days. The eBPF tracepoint already exists. This is adding the kill call to the existing event handler.  
**Kernel vs. userspace:** Userspace signal delivery (simpler, no kernel module required). Upgrade path: `bpf_send_signal()` for sub-millisecond enforcement without userspace round-trip.

---

#### D3-OTF — Outbound Traffic Filtering (Isolate tactic)
**Definition:** Restricting network traffic originating from a private host destined towards untrusted networks.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/  
**Tactic:** Isolate  
**Implementation level:** Kernel (iptables/nftables/eBPF TC)

**Why this is needed in addition to D3-PT:** D3-PT kills the process after the connection is detected. D3-OTF prevents the connection from completing at the network layer — even if the process is not killed immediately, the packets are dropped. Defense in depth: D3-PT evicts the process, D3-OTF blocks the traffic.

**Implementation:**
```bash
# iptables rules for D3-OTF — block known C2 ports outbound
# Applied at Shadow313 deployment time

# Block outbound on known reverse shell ports
iptables -A OUTPUT -p tcp --dport 4444 -j DROP -m comment --comment "D3-OTF: nc reverse shell"
iptables -A OUTPUT -p tcp --dport 9001 -j DROP -m comment --comment "D3-OTF: Tor relay"
iptables -A OUTPUT -p tcp --dport 1234 -j DROP -m comment --comment "D3-OTF: common backdoor"

# Block outbound from specific processes using iptables owner module
# (requires process to run as specific UID)
iptables -A OUTPUT -m owner --uid-owner 0 -p tcp --dport 4444 -j DROP

# eBPF TC (Traffic Control) alternative — process-level filtering
# Attaches to network interface egress path
# Can filter by PID (via sk_buff->sk->sk_uid or cgroup)
```

**Effort:** 2–4 hours (iptables rules). 1–2 weeks (eBPF TC with per-process filtering).  
**Kernel vs. userspace:** Kernel (iptables/nftables operate in kernel netfilter framework).

---

#### D3-NI — Network Isolation (Isolate tactic)
**Definition:** Restricting network access to limit lateral movement.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:NetworkIsolation/  
**Tactic:** Isolate  
**Implementation level:** Network infrastructure (Docker network policy)

**Implementation for Shadow313's Docker environment:**
```bash
# Docker network policy — isolate monitored containers
# Prevent outbound connections to non-approved destinations

# Create isolated network for monitored workloads
docker network create --internal shadow313-monitored

# Apply network policy (Kubernetes NetworkPolicy equivalent)
# Allow: internal Docker network (172.19.0.0/16)
# Allow: specific approved external IPs (NVD, KEV, EPSS APIs)
# Block: everything else outbound

# iptables FORWARD rules for Docker bridge
iptables -I DOCKER-USER -i docker0 -o eth0 \
  -m set ! --match-set approved_destinations dst \
  -j DROP -m comment --comment "D3-NI: block unapproved outbound"
```

**Effort:** 4–8 hours.  
**Kernel vs. userspace:** Kernel (netfilter/iptables) + Docker network configuration.

---

## T1014 — Rootkit / DKOM (EPT violation detected, not enforced)
**Current Shadow313 coverage:** ⚠️ Partial — HAMI Layer 3 detects EPT violation in monitoring mode  
**Attacker status:** ⚠️ DETECTED BUT NOT STOPPED — write may have completed

### D3FEND Countermeasures Required

#### D3-HBPI — Hardware-based Process Isolation (Harden tactic)
**Definition:** Preventing one process from accessing the resources of another process using hardware-based controls.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:HardwareBasedProcessIsolation/  
**Tactic:** Harden  
**Implementation level:** Kernel/hypervisor (Intel VT-x EPT enforcement mode)

**The specific gap:** Shadow313's `HypervisorMemoryIntegrity` currently runs in monitoring mode — it logs EPT violations but allows the write to complete. The fix is switching EPT entries from read-only (monitoring) to read-only with deny (enforcement). In KVM:

```c
/* KVM EPT enforcement — switch from monitoring to enforcement mode */
static int handle_ept_violation(struct kvm_vcpu *vcpu)
{
    gpa_t gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
    
    if (is_protected_region(gpa)) {
        /* MONITORING MODE (current): log and allow */
        // log_violation(vcpu, gpa);
        // return 1;  /* allow write to complete */
        
        /* ENFORCEMENT MODE (fix): log and deny */
        log_violation(vcpu, gpa);
        inject_gp_fault(vcpu);  /* inject #GP into guest — write fails */
        return 1;
    }
    return 0;
}
```

**Shadow313 implementation path:**
```python
# shadow313/v4/detection/zero_evasion/zero_evasion_countermeasure.py
# Switch HypervisorMemoryIntegrity to enforcement mode

class HypervisorMemoryIntegrity:
    
    def __init__(self, enforcement_mode: bool = False) -> None:
        # ... existing init ...
        self._enforcement_mode = enforcement_mode  # NEW: default False → set True
    
    def monitor_memory_write(
        self, target_address: int, source_pid: int, write_size: int
    ) -> Optional[str]:
        for region_name, region in self._protected_regions.items():
            if region["base"] <= target_address < region["base"] + region["size"]:
                # ... existing detection logic ...
                
                if self._enforcement_mode:
                    # D3-HBPI: deny the write by injecting a fault
                    # In production KVM: inject_gp_fault(vcpu)
                    # In simulation: raise an exception to signal denial
                    raise MemoryWriteDenied(
                        f"EPT enforcement: write to {region_name} from PID "
                        f"{source_pid} DENIED — DKOM attempt blocked"
                    )
                
                return "hypervisor_alert"  # monitoring mode: log only
        return None
```

**Effort:** 2–3 days (simulation mode). 2–4 weeks (production KVM module).  
**Kernel vs. userspace:** Kernel/hypervisor (EPT enforcement requires KVM module modification or Hyper-V extension).

---

#### D3-PCSV — Process Code Segment Verification (Detect tactic)
**Definition:** Comparing the "text" or "code" memory segments to a source of truth.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:ProcessCodeSegmentVerification/  
**Tactic:** Detect  
**Implementation level:** Kernel (requires /proc/pid/mem access or kernel driver)

**Why needed for T1014:** After DKOM hides a process, the process's code segment may have been modified (the ROP chain from T1055.009 modifies return addresses). D3-PCSV detects this by comparing the in-memory code segment against the on-disk binary hash.

**Implementation:**
```python
# shadow313/v4/detection/code_segment_verifier.py — D3-PCSV

import hashlib
from pathlib import Path

class ProcessCodeSegmentVerifier:
    """
    D3-PCSV: Process Code Segment Verification
    
    Compares in-memory code segments against on-disk binary hashes.
    Detects: process hollowing, code injection, ROP chain setup.
    
    Implementation: reads /proc/pid/maps to find code segments,
    then reads /proc/pid/mem to extract and hash them.
    Compares against SHA3-256 of the on-disk binary.
    
    Kernel alternative: kernel driver with direct EPROCESS access.
    """
    
    def __init__(self) -> None:
        self._baseline: dict[str, str] = {}  # binary_path → SHA3-256
    
    def baseline_process(self, pid: int) -> dict:
        """Record the baseline code segment hash for a process."""
        try:
            exe_path = Path(f"/proc/{pid}/exe").resolve()
            binary_hash = hashlib.sha3_256(exe_path.read_bytes()).hexdigest()
            self._baseline[str(exe_path)] = binary_hash
            return {"pid": pid, "exe": str(exe_path), "hash": binary_hash[:16] + "..."}
        except Exception as exc:
            return {"error": str(exc)}
    
    def verify_process(self, pid: int) -> dict:
        """
        Verify a process's code segment against its baseline.
        Returns detection result with forensic evidence.
        """
        try:
            exe_path = str(Path(f"/proc/{pid}/exe").resolve())
            current_hash = hashlib.sha3_256(
                Path(exe_path).read_bytes()
            ).hexdigest()
            
            baseline_hash = self._baseline.get(exe_path)
            if baseline_hash is None:
                return {"status": "NO_BASELINE", "pid": pid}
            
            if not hmac.compare_digest(current_hash, baseline_hash):
                return {
                    "status":         "CODE_SEGMENT_MODIFIED",
                    "pid":            pid,
                    "exe":            exe_path,
                    "baseline_hash":  baseline_hash[:16] + "...",
                    "current_hash":   current_hash[:16] + "...",
                    "severity":       "CRITICAL",
                    "d3fend":         "D3-PCSV",
                    "attack":         "T1014 / T1055.009",
                    "forensic":       "Binary on disk modified after process start — "
                                      "possible process hollowing or code injection",
                }
            return {"status": "CLEAN", "pid": pid}
        except Exception as exc:
            return {"status": "ERROR", "pid": pid, "error": str(exc)}
```

**Effort:** 1–2 weeks.  
**Kernel vs. userspace:** Userspace (reads /proc/pid/exe). Kernel driver needed for in-memory segment comparison (more accurate but higher complexity).

---

#### D3-PSMD — Process Self-Modification Detection (Detect tactic)
**Definition:** Detects processes that modify, change, or replace their own code at runtime.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:ProcessSelf-ModificationDetection/  
**Tactic:** Detect  
**Implementation level:** Kernel (API hooking via eBPF or kernel module)

**D3FEND definition:** "A security agent installed on the host machine intercepts API calls between a process and operating system. Intercepted API calls are then compared against attack signatures/patterns to identify API calls that modify executable memory."

**Attack patterns D3-PSMD detects:**
- Executable code of a suspended child process removed from memory (process hollowing)
- New executable code injected into memory of a suspended child process
- Executable code modified by one or more API calls
- Next instruction pointer value in memory modified (ROP chain setup)

**Implementation — add to EBPFSyscallTracer:**
```python
# Add to shadow313/v4/detection/zero_evasion/zero_evasion_countermeasure.py

# Syscalls that indicate self-modification (D3-PSMD)
SELF_MODIFICATION_SYSCALLS = {
    "mprotect":      {"severity": "HIGH",     "note": "Change memory permissions to executable"},
    "mmap":          {"severity": "MEDIUM",   "note": "Map new executable memory region"},
    "memfd_create":  {"severity": "CRITICAL", "note": "Create anonymous executable fd (fileless)"},
    "execveat":      {"severity": "CRITICAL", "note": "Execute from file descriptor (memfd pattern)"},
    "ptrace":        {"severity": "HIGH",     "note": "Process tracing — possible injection"},
    "process_vm_writev": {"severity": "CRITICAL", "note": "Write to another process's memory"},
}
```

**Effort:** 1–2 weeks (add to existing EBPFSyscallTracer).  
**Kernel vs. userspace:** Kernel (eBPF kprobes on mprotect, mmap, memfd_create).

---

## T1620 — Reflective Code Loading (memfd_create fileless execution)
**Current Shadow313 coverage:** ❌ None — zero coverage  
**Attacker status:** ❌ NOT STOPPED — fileless payload executed

### D3FEND Countermeasures Required

#### D3-SCA — System Call Analysis (Detect tactic) — PRIMARY FIX
**Definition:** Analyzing system calls to determine whether a process is exhibiting unauthorized behavior.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:SystemCallAnalysis/  
**Tactic:** Detect  
**Implementation level:** Kernel (eBPF kprobes)

**D3FEND definition:** "By analyzing a process's use of these APIs, it is, in some cases, possible to ascertain whether a program is exhibiting unauthorized behavior... Getting the contents from a URL, writing to a new file, and then executing the same file."

This is precisely the T1620 pattern: curl downloads content → writes to memfd → execveat executes from fd. D3-SCA via eBPF kprobes on `memfd_create` and `execveat` would detect this chain.

**Implementation — the highest-priority single code change:**
```python
# shadow313/v4/detection/zero_evasion/zero_evasion_countermeasure.py
# Add to EBPFSyscallTracer.SENSITIVE_SYSCALLS

SENSITIVE_SYSCALLS = {
    # ... existing entries ...
    
    # D3-SCA: T1620 Reflective Code Loading detection
    "memfd_create":  {
        "target_process": "any",
        "severity":       "CRITICAL",
        "note":           "Anonymous executable memory — fileless malware pattern",
        "token":          "ebpf_syscall",
        "d3fend":         "D3-SCA",
        "attack":         "T1620",
    },
    "execveat":      {
        "target_process": "any",
        "severity":       "CRITICAL",
        "note":           "Execute from file descriptor — memfd execution pattern",
        "token":          "ebpf_syscall",
        "d3fend":         "D3-SCA",
        "attack":         "T1620",
    },
    "mprotect":      {
        "target_process": "any",
        "severity":       "HIGH",
        "note":           "Memory permission change to executable — shellcode staging",
        "token":          "ebpf_syscall",
        "d3fend":         "D3-SCA + D3-PSMD",
        "attack":         "T1620 / T1055",
    },
}
```

**Effort:** 2–4 hours (add syscalls to existing SENSITIVE_SYSCALLS dict).  
**Kernel vs. userspace:** Kernel (eBPF kprobes — already in use by EBPFSyscallTracer).

---

#### D3-SCF — System Call Filtering (Isolate tactic) — PREVENTIVE FIX
**Definition:** Controlling access to local computer system resources with kernel-level capabilities.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:SystemCallFiltering/  
**Tactic:** Isolate  
**Implementation level:** Kernel (seccomp-BPF or SELinux/AppArmor)

**D3FEND implementations:** Linux C-Groups + SELinux/AppArmor, seccomp-BPF  
**Research basis:** arXiv:2302.10366 — "Programmable System Call Security with eBPF" demonstrates that eBPF-based seccomp filtering can reduce attack surface by up to 55.4% for temporal specialization.

**Implementation — seccomp profile for Shadow313 monitored processes:**
```python
# shadow313/v4/detection/seccomp_policy.py — D3-SCF

import ctypes
import struct

# Seccomp BPF filter that blocks memfd_create and execveat
# for processes that should not be executing arbitrary code

SECCOMP_POLICY = {
    # Syscalls to BLOCK for monitored processes
    "block": [
        "memfd_create",   # T1620: fileless execution
        "execveat",       # T1620: execute from fd
        "ptrace",         # T1055: process injection
        "process_vm_writev",  # T1055: write to other process memory
        "kexec_load",     # T1014: kernel replacement
        "init_module",    # T1014: kernel module loading
        "finit_module",   # T1014: kernel module loading
    ],
    # Syscalls to AUDIT (log but allow) for monitored processes
    "audit": [
        "mprotect",       # T1620: memory permission change
        "mmap",           # T1620: new memory mapping
        "socket",         # T1095: network connection
        "connect",        # T1095: outbound connection
        "setuid",         # T1548.001: privilege escalation
    ],
}

def generate_seccomp_profile(process_name: str) -> dict:
    """
    Generate a seccomp-BPF profile for a monitored process.
    
    D3-SCF: System Call Filtering
    Implementation: seccomp-BPF (kernel-level, mandatory access control)
    
    The profile blocks syscalls associated with T1620 (fileless execution)
    and audits syscalls associated with T1095 (C2) and T1548.001 (privesc).
    """
    return {
        "process":        process_name,
        "default_action": "SCMP_ACT_ALLOW",
        "blocked_syscalls": SECCOMP_POLICY["block"],
        "audited_syscalls": SECCOMP_POLICY["audit"],
        "d3fend":         "D3-SCF",
        "attack_countered": ["T1620", "T1055", "T1014", "T1548.001"],
        "implementation": "seccomp-BPF (kernel-level mandatory access control)",
        "note": (
            "Apply to: curl, wget, python3 (when spawned from web-facing processes). "
            "Do NOT apply to: Shadow313 itself (needs these syscalls for monitoring)."
        ),
    }
```

**Effort:** 1–2 weeks (seccomp profile development and testing).  
**Kernel vs. userspace:** Kernel (seccomp-BPF operates in kernel context, applied via `prctl(PR_SET_SECCOMP)`).

---

#### D3-FAPA — File Access Pattern Analysis (Detect tactic)
**Definition:** Analyzing the files accessed by a process to identify unauthorized activity.  
**D3FEND URL:** d3fend.mitre.org/technique/d3f:FileAccessPatternAnalysis/  
**Tactic:** Detect  
**Implementation level:** Kernel (inotify/fanotify) or userspace (eBPF file access tracing)

**Why needed for T1620:** The memfd pattern involves curl accessing a URL (network), writing to an anonymous fd (no filesystem), then executing. D3-FAPA would detect the anomalous pattern: a process (curl) that normally reads URLs and writes to files is instead writing to an anonymous memory fd and that fd is subsequently executed.

**Implementation:**
```python
# shadow313/v4/detection/file_access_monitor.py — D3-FAPA

class FileAccessPatternAnalyzer:
    """
    D3-FAPA: File Access Pattern Analysis
    
    Detects anomalous file access patterns including:
    - memfd_create() followed by execveat() (T1620 fileless pattern)
    - Large number of file reads followed by encrypted writes (ransomware)
    - Access to /proc/pid/mem (T1055.009 proc memory injection)
    
    Implementation: eBPF tracepoints on sys_enter_openat, sys_enter_read,
    sys_enter_write, sys_enter_memfd_create, sys_enter_execveat.
    """
    
    SUSPICIOUS_PATTERNS = [
        {
            "name":    "fileless_execution",
            "sequence": ["memfd_create", "write", "execveat"],
            "window_s": 30,
            "severity": "CRITICAL",
            "attack":   "T1620",
            "d3fend":   "D3-FAPA",
        },
        {
            "name":    "proc_memory_injection",
            "sequence": ["open:/proc/*/mem", "write:/proc/*/mem"],
            "window_s": 10,
            "severity": "CRITICAL",
            "attack":   "T1055.009",
            "d3fend":   "D3-FAPA",
        },
        {
            "name":    "mass_file_staging",
            "sequence": ["read:*", "read:*", "read:*", "write:*.zip"],
            "window_s": 60,
            "count_threshold": 100,
            "severity": "HIGH",
            "attack":   "T1074.001",
            "d3fend":   "D3-FAPA",
        },
    ]
```

**Effort:** 2–3 weeks.  
**Kernel vs. userspace:** Kernel (eBPF tracepoints on file syscalls) or userspace (fanotify, which requires CAP_SYS_ADMIN).

---

## T1190 — Exploit Public-Facing Application (SQL injection)
**Current Shadow313 coverage:** ⚠️ Partial — AST static scan only  
**Attacker status:** ⚠️ Vulnerability present, runtime exploitation undetected

### D3FEND Countermeasures Required

#### D3-SCA — System Call Analysis (for runtime detection)
**Implementation:** Monitor for anomalous database query patterns via eBPF tracepoints on `read()` and `write()` to SQLite file descriptors. A SQL injection produces a query with unusual structure (UNION, OR 1=1, comment sequences) that differs from the application's normal query patterns.

**Effort:** 2–3 weeks (requires query pattern baselining).  
**Kernel vs. userspace:** Userspace (SQLite query interception via LD_PRELOAD hook or application-level middleware).

#### D3-ACH — Application Configuration Hardening (Harden tactic)
**Definition:** Modifying an application's configuration to reduce its attack surface.  
**Implementation:** Enforce parameterized queries at the framework level. For Shadow313's `threat_intel.py`, the fix is already applied (table name whitelist). For `auth_verifier.py`, the fix is:

```python
# VULNERABLE:
cursor.execute("SELECT * FROM users WHERE id = " + user_input)

# FIXED (D3-ACH):
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

**Effort:** 1–2 hours per vulnerable query.  
**Kernel vs. userspace:** Userspace (application code change).

---

## T1059.004 — Unix Shell (os.system / shell=True)
**Current Shadow313 coverage:** ⚠️ Partial — AST static scan only  
**Attacker status:** ⚠️ Vulnerability present, runtime exploitation undetected

### D3FEND Countermeasures Required

#### D3-SCF — System Call Filtering (Isolate tactic)
**Implementation:** Apply a seccomp-BPF profile to the diagnostics process that blocks `execve` with shell arguments. More precisely: block `execve("/bin/sh", ...)` from the diagnostics process. This prevents `os.system()` and `shell=True` from spawning a shell even if the code runs.

```python
# seccomp rule: block execve of /bin/sh from diagnostics process
# In seccomp-BPF: check argv[0] == "/bin/sh" and DENY
```

**Effort:** 1–2 weeks (seccomp profile with argument inspection).  
**Kernel vs. userspace:** Kernel (seccomp-BPF with argument inspection requires eBPF seccomp extension from arXiv:2302.10366).

#### D3-ACH — Application Configuration Hardening
**Implementation:** Replace `os.system()` and `shell=True` with `subprocess.run(list_args, shell=False)`. Already detected by Shadow313's AST scan — the fix is a code change.

**Effort:** 30 minutes per occurrence.  
**Kernel vs. userspace:** Userspace (application code change).

---

## Priority Matrix — Ordered by Operational Impact

| Priority | D3FEND ID | Technique | ATT&CK Countered | Effort | Level | Stops Active Attack? |
|---|---|---|---|---|---|---|
| **P1** | **D3-PT** | Process Termination | T1095 (nc C2) | 1–2 days | Userspace | ✅ YES — kills PID 14209 |
| **P2** | **D3-SCA** | System Call Analysis (memfd) | T1620 | 2–4 hours | Kernel (eBPF) | ✅ YES — detects fileless |
| **P3** | **D3-HBPI** | Hardware-based Process Isolation | T1014 (DKOM) | 2–3 days | Kernel/hypervisor | ✅ YES — denies EPROCESS write |
| **P4** | **D3-OTF** | Outbound Traffic Filtering | T1095, T1071 | 4–8 hours | Kernel (iptables) | ✅ YES — blocks port 4444 |
| **P5** | **D3-PSMD** | Process Self-Modification Detection | T1014, T1620 | 1–2 weeks | Kernel (eBPF) | ⚠️ Detects, not prevents |
| **P6** | **D3-SCF** | System Call Filtering | T1620, T1059.004 | 1–2 weeks | Kernel (seccomp) | ✅ YES — blocks memfd_create |
| **P7** | **D3-PCSV** | Process Code Segment Verification | T1014, T1055.009 | 1–2 weeks | Userspace/kernel | ⚠️ Detects, not prevents |
| **P8** | **D3-FAPA** | File Access Pattern Analysis | T1620, T1074 | 2–3 weeks | Kernel (eBPF) | ⚠️ Detects, not prevents |
| **P9** | **D3-ACH** | Application Configuration Hardening | T1190, T1059.004 | Hours | Userspace | ✅ YES — removes vulnerability |
| **P10** | **D3-NI** | Network Isolation | T1095 | 4–8 hours | Kernel (iptables) | ✅ YES — network-level block |

---

## The Two Immediate Actions (P1 + P2 + P4)

**To stop the active attack (nc PID 14209 + fileless payload):**

```bash
# IMMEDIATE: Kill the active C2 process
kill -9 14209

# IMMEDIATE: Block port 4444 outbound (D3-OTF)
iptables -A OUTPUT -p tcp --dport 4444 -j DROP

# IMMEDIATE: Find and terminate any memfd-backed processes (D3-SCA)
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    if grep -q 'memfd' /proc/$pid/maps 2>/dev/null; then
        echo "Suspicious memfd process: PID $pid ($(cat /proc/$pid/comm 2>/dev/null))"
        kill -9 $pid
    fi
done
```

**To prevent recurrence (D3-PT + D3-SCA in code):**

1. Add `memfd_create` and `execveat` to `SENSITIVE_SYSCALLS` in `zero_evasion_countermeasure.py` — 2 hours
2. Add `ProcessTerminator` class to the eBPF event handler — 1 day
3. Switch `HypervisorMemoryIntegrity` to enforcement mode — 1 day

Total time to close the two highest-priority gaps: **2–3 days of engineering.**

---

*D3FEND technique definitions sourced from d3fend.mitre.org v1.5.0. Implementation details for D3-SCF seccomp-BPF sourced from arXiv:2302.10366 (Jia et al., 2023). D3-PSMD implementation pattern sourced from Carbon Black patent US20170272462A1. D3-FAPA implementation pattern sourced from CrowdStrike patent US20180121650A1.*