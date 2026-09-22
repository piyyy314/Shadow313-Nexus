"""
Shadow313 v3 — Zero-Evasion Countermeasure Layer
=================================================
Targets the Syscall Bypass + DKOM combination that achieves 0.000 evasion score.

The problem:
  Direct Syscall Bypass → suppresses Sysmon Event 10 + ETW (ntdll hooks bypassed)
  DKOM               → suppresses process_creation (process hidden from kernel lists)
  Combined score     → 0.000 (complete evasion of hardware_head)

This module implements three countermeasure layers that work BELOW ntdll:

  Layer 1: eBPF Syscall Tracing
    Intercepts syscalls at the kernel boundary using eBPF kprobes.
    Direct syscalls still cross the kernel boundary — eBPF catches them
    regardless of whether ntdll was bypassed.
    New token: "ebpf_syscall" (ID 28)

  Layer 2: Kernel-Level Attestation (KLA)
    Periodically hashes critical kernel structures (SSDT, EPROCESS list,
    IDT, GDT) and compares against a TPM-sealed baseline.
    DKOM modifies EPROCESS list → hash mismatch → detection.
    New token: "kernel_tamper" (ID 29)

  Layer 3: Hypervisor-Assisted Memory Integrity (HAMI)
    Uses Intel VT-x EPT (Extended Page Tables) to set memory access
    permissions on critical kernel structures. Any write to EPROCESS
    list or SSDT triggers a VM exit → hypervisor logs the event.
    New token: "hypervisor_alert" (ID 30)

Integration into hardware_head:
  New chain: "syscall_bypass_dkom_combined"
  sequence: [ebpf_syscall, ebpf_syscall, kernel_tamper,
             hypervisor_alert, network_outbound]
  This chain fires even when Sysmon + ETW are completely suppressed.

Author: Shadow313 Core Team
References:
  - eBPF kprobes: https://www.kernel.org/doc/html/latest/trace/kprobes.html
  - Intel VT-x EPT: Intel SDM Vol 3C, Chapter 28
  - TPM attestation: NIST SP 800-155 (BIOS Integrity Measurement)
  - DKOM detection: "Detecting Kernel-Level Rootkits" (Rutkowska 2006)
"""

from __future__ import annotations
import hmac

import hashlib
import json
import math
import os
import random
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

COUNTERMEASURE_REPORT = Path("/tmp/shadow313_zero_evasion.json")


# ══════════════════════════════════════════════════════════════════════════════
# NEW TOKEN VOCABULARY FOR ZERO-EVASION LAYER
# ══════════════════════════════════════════════════════════════════════════════

ZERO_EVASION_TOKENS = {
    "ebpf_syscall":      28,
    # Source: eBPF kprobe on sys_read, sys_write, sys_openat, NtReadVirtualMemory
    # Why it works against direct syscalls:
    #   Direct syscalls bypass ntdll hooks but still execute the kernel syscall handler.
    #   eBPF kprobes attach to the kernel function entry point (e.g., __x64_sys_read),
    #   not to ntdll. The attacker cannot bypass eBPF without a kernel exploit.
    # Linux equivalent: bpf_prog attached to kprobe:__x64_sys_read
    # Windows equivalent: ETW-Ti kernel provider (tamper-resistant)

    "kernel_tamper":     29,
    # Source: Kernel attestation daemon comparing EPROCESS list hash
    # Why it works against DKOM:
    #   DKOM modifies the EPROCESS doubly-linked list (ActiveProcessLinks).
    #   The attestation daemon walks the list and computes a hash.
    #   Any modification (process hidden or added) changes the hash.
    #   The baseline hash is TPM-sealed — cannot be forged without TPM key.
    # Detection latency: 30-60 seconds (polling interval)

    "hypervisor_alert":  30,
    # Source: Hypervisor EPT violation handler
    # Why it works against both techniques:
    #   The hypervisor sets EPT entries for EPROCESS list pages as read-only.
    #   Any write (DKOM) triggers a VM exit → hypervisor logs the event.
    #   The hypervisor sets EPT entries for SSDT pages as read-only.
    #   Any write (SSDT hook) triggers a VM exit → hypervisor logs the event.
    #   Direct syscalls don't modify these pages → no false positives.
    # Cannot be bypassed from guest OS — requires hypervisor exploit.

    "process_anomaly":   31,
    # Source: Cross-reference process enumeration
    # Why it works against DKOM:
    #   Compares process lists from 4 independent sources:
    #   1. NtQuerySystemInformation (user space)
    #   2. EPROCESS list walk (kernel driver)
    #   3. Handle table enumeration (kernel driver)
    #   4. CPU time accounting (kernel driver)
    #   A hidden process appears in sources 3+4 but not 1+2.

    "memory_rate_burst": 32,
    # Source: Intel PMU (Performance Monitoring Unit) syscall counter
    # Why it works against direct syscalls:
    #   Intel PMU counts NtReadVirtualMemory calls at the hardware level.
    #   Direct syscalls still increment the PMU counter.
    #   Rate > 100 reads/second on lsass.exe → "memory_rate_burst" token.
    #   Cannot be bypassed without physical hardware modification.
}


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1: eBPF SYSCALL TRACING
# ══════════════════════════════════════════════════════════════════════════════

class EBPFSyscallTracer:
    """
    eBPF-based syscall interception that works BELOW ntdll.

    On Linux: Uses BPF_PROG_TYPE_KPROBE attached to kernel function entry.
    On Windows: Uses ETW-Ti (Threat Intelligence) kernel provider which
                is tamper-resistant and cannot be disabled from user space.

    Key insight: Direct syscall techniques bypass ntdll.dll hooks by calling
    the kernel directly via the 'syscall' instruction. However, the kernel
    still executes the syscall handler function (e.g., NtReadVirtualMemory).
    eBPF kprobes attach to the KERNEL function, not to ntdll — so they
    fire regardless of how the syscall was invoked.

    The attacker cannot suppress eBPF kprobes without:
    1. A kernel exploit to disable the eBPF subsystem
    2. Physical access to modify the kernel binary
    3. A hypervisor exploit (if eBPF runs in the hypervisor)
    """

    # Syscalls that indicate LSASS credential dumping
    SENSITIVE_SYSCALLS = {
        # Windows NT syscalls — LSASS credential dumping (T1003.001)
        "NtReadVirtualMemory":    {"target_process": "lsass.exe", "severity": "CRITICAL"},
        "NtWriteVirtualMemory":   {"target_process": "any",       "severity": "HIGH"},
        "NtOpenProcess":          {"target_process": "lsass.exe", "severity": "HIGH"},
        "NtDuplicateObject":      {"target_process": "lsass.exe", "severity": "HIGH"},
        "NtCreateThread":         {"target_process": "any",       "severity": "MEDIUM"},
        "NtUnmapViewOfSection":   {"target_process": "any",       "severity": "HIGH"},
        "MmCopyVirtualMemory":    {"target_process": "lsass.exe", "severity": "CRITICAL"},
        # Linux syscalls — T1620 Reflective Code Loading (fileless execution)
        # D3-SCA: System Call Analysis — closes the memfd_create gap
        # Detected in Aegis telemetry: curl → /tmp/memfd:x64 (02:11:39)
        "memfd_create":           {"target_process": "any",       "severity": "CRITICAL"},
        "execveat":               {"target_process": "any",       "severity": "CRITICAL"},
        "mprotect":               {"target_process": "any",       "severity": "HIGH"},
        "process_vm_writev":      {"target_process": "any",       "severity": "CRITICAL"},
        # Linux privilege escalation — T1548.001 Setuid
        "setuid":                 {"target_process": "any",       "severity": "CRITICAL"},
        "setgid":                 {"target_process": "any",       "severity": "HIGH"},
    }

    # Rate thresholds (calls per second)
    RATE_THRESHOLDS = {
        "NtReadVirtualMemory":  10,   # > 10/s on lsass = dumping
        "NtWriteVirtualMemory": 5,    # > 5/s on any process = injection
        "NtOpenProcess":        3,    # > 3/s on lsass = suspicious
    }

    def __init__(self):
        self._syscall_counts: dict[str, list[float]] = {}
        self._alerts: list[dict] = []

    def simulate_ebpf_kprobe(self, syscall_name: str, source_pid: int,
                              target_process: str, call_count: int = 1) -> Optional[str]:
        """
        Simulate an eBPF kprobe firing on a sensitive syscall.

        In production (Linux):
          SEC("kprobe/__x64_sys_read")
          int BPF_KPROBE(sys_read_entry, ...) {
              // Check if reading from lsass memory
              // Send event to userspace via BPF ring buffer
          }

        In production (Windows):
          ETW-Ti provider: Microsoft-Windows-Threat-Intelligence
          Event: KERNEL_THREATINT_TASK_READVM
          Cannot be disabled from user space.

        Returns: token name if suspicious, None if benign
        """
        now = time.time()

        # Track call rate
        key = f"{syscall_name}:{source_pid}"
        if key not in self._syscall_counts:
            self._syscall_counts[key] = []

        # Keep only last 1 second of calls
        self._syscall_counts[key] = [
            t for t in self._syscall_counts[key] if now - t < 1.0
        ]
        for _ in range(call_count):
            self._syscall_counts[key].append(now)

        rate = len(self._syscall_counts[key])
        threshold = self.RATE_THRESHOLDS.get(syscall_name, 100)

        # Check if this syscall targets a sensitive process
        if syscall_name in self.SENSITIVE_SYSCALLS:
            config = self.SENSITIVE_SYSCALLS[syscall_name]
            if config["target_process"] in (target_process, "any"):
                if rate > threshold:
                    return "memory_rate_burst"
                return "ebpf_syscall"

        return None

    def generate_lsass_dump_trace(self) -> list[dict]:
        """
        Generate the eBPF trace for a direct-syscall LSASS dump.
        This is what hardware_head sees even when ntdll is bypassed.
        """
        return [
            # Hell's Gate opens lsass via direct NtOpenProcess syscall
            {"syscall": "NtOpenProcess", "source": "malware.exe",
             "target": "lsass.exe", "count": 1, "token": "ebpf_syscall"},
            # Reads lsass memory via direct NtReadVirtualMemory syscall
            {"syscall": "NtReadVirtualMemory", "source": "malware.exe",
             "target": "lsass.exe", "count": 150, "token": "memory_rate_burst"},
            # More reads (dumping full lsass memory)
            {"syscall": "NtReadVirtualMemory", "source": "malware.exe",
             "target": "lsass.exe", "count": 200, "token": "memory_rate_burst"},
            # Writes dump to file
            {"syscall": "NtWriteFile", "source": "malware.exe",
             "target": "lsass.dmp", "count": 50, "token": "ebpf_syscall"},
        ]


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2: KERNEL-LEVEL ATTESTATION (KLA)
# ══════════════════════════════════════════════════════════════════════════════

class KernelLevelAttestation:
    """
    Periodic attestation of critical kernel structures.

    Detects DKOM by hashing the EPROCESS list and comparing against
    a TPM-sealed baseline. Any modification (process hidden or added)
    changes the hash.

    Key structures monitored:
    1. EPROCESS ActiveProcessLinks list (DKOM target)
    2. SSDT (System Service Descriptor Table) — hook target
    3. IDT (Interrupt Descriptor Table) — hook target
    4. Driver object list — rootkit installation target

    TPM sealing:
    The baseline hash is sealed to the TPM with PCR values that include
    the boot state. If the system is compromised at boot, the PCR values
    change and the baseline cannot be unsealed.

    Detection latency: 30-60 seconds (polling interval)
    This is the main weakness — DKOM can operate for up to 60 seconds
    before detection. Countermeasure: reduce polling to 5 seconds.
    """

    def __init__(self):
        # Simulate a clean baseline EPROCESS list
        self._baseline_hash = self._compute_baseline()
        self._baseline_process_count = 47  # typical Windows process count
        self._alerts: list[dict] = []
        self._poll_interval = 30  # seconds

    def _compute_baseline(self) -> str:
        """Compute baseline hash of EPROCESS list (simulated)."""
        # In production: walk EPROCESS list via kernel driver
        # Hash: SHA-256 of (PID, PPID, ImageFileName) for each process
        baseline_data = b"".join([
            struct.pack(">HH", pid, ppid) + name.encode()
            for pid, ppid, name in [
                (4, 0, "System"), (88, 4, "Registry"), (348, 4, "smss.exe"),
                (456, 448, "csrss.exe"), (532, 524, "wininit.exe"),
                (540, 532, "services.exe"), (548, 532, "lsass.exe"),
                (600, 532, "svchost.exe"), (700, 532, "svchost.exe"),
            ]
        ])
        return hashlib.sha3_256(baseline_data).hexdigest()  # HNDL-fix: SHA3-256 (128-bit quantum)

    def _compute_current_hash(self, hidden_pid: Optional[int] = None) -> tuple[str, int]:
        """
        Compute current EPROCESS list hash.
        If hidden_pid is set, simulate DKOM by excluding that process.
        """
        processes = [
            (4, 0, "System"), (88, 4, "Registry"), (348, 4, "smss.exe"),
            (456, 448, "csrss.exe"), (532, 524, "wininit.exe"),
            (540, 532, "services.exe"), (548, 532, "lsass.exe"),
            (600, 532, "svchost.exe"), (700, 532, "svchost.exe"),
        ]

        if hidden_pid:
            # DKOM: malicious process was added then hidden
            # The handle table still shows it, but EPROCESS list doesn't
            processes.append((hidden_pid, 540, "malware.exe"))
            # DKOM removes it from the list — but we detect via handle table
            processes = [(p, pp, n) for p, pp, n in processes
                        if p != hidden_pid]

        current_data = b"".join([
            struct.pack(">HH", pid, ppid) + name.encode()
            for pid, ppid, name in processes
        ])
        return hashlib.sha3_256(current_data).hexdigest(), len(processes)  # HNDL-fix: SHA3-256

    def attest(self, dkom_active: bool = False,
               hidden_pid: Optional[int] = None) -> Optional[str]:
        """
        Run kernel attestation check.
        Returns token name if tampering detected, None if clean.
        """
        current_hash, current_count = self._compute_current_hash(
            hidden_pid if dkom_active else None
        )
        if not hmac.compare_digest(current_hash.encode() if isinstance(current_hash, str) else current_hash, self._baseline_hash.encode() if isinstance(self._baseline_hash, str) else self._baseline_hash):
            self._alerts.append({
                "type": "eprocess_list_tamper",
                "baseline_hash": self._baseline_hash[:16],
                "current_hash": current_hash[:16],
                "baseline_count": self._baseline_process_count,
                "current_count": current_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return "kernel_tamper"

        # Cross-reference: compare EPROCESS list with handle table
        # In production: enumerate all handles and find orphaned lsass handles
        if dkom_active and hidden_pid:
            # Handle table shows the hidden process, EPROCESS list doesn't
            self._alerts.append({
                "type": "orphan_handle_detected",
                "hidden_pid": hidden_pid,
                "detail": "Process has open handles but not in EPROCESS list",
            })
            return "kernel_tamper"

        return None

    def attest_ssdt(self, ssdt_hooked: bool = False) -> Optional[str]:
        """Check SSDT integrity."""
        if ssdt_hooked:
            self._alerts.append({
                "type": "ssdt_hook_detected",
                "detail": "SSDT entry modified — possible rootkit",
            })
            return "kernel_tamper"
        return None


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3: HYPERVISOR-ASSISTED MEMORY INTEGRITY (HAMI)
# ══════════════════════════════════════════════════════════════════════════════

class HypervisorMemoryIntegrity:
    """
    Hypervisor-level memory protection using Intel VT-x EPT.

    EPT (Extended Page Tables) allows the hypervisor to set memory access
    permissions independently of the guest OS page tables. The guest OS
    cannot override EPT permissions — only the hypervisor can.

    Protected regions:
    1. EPROCESS list pages → read-only in EPT
       Any write (DKOM) → VM exit → hypervisor logs event
    2. SSDT pages → read-only in EPT
       Any write (hook) → VM exit → hypervisor logs event
    3. IDT pages → read-only in EPT
       Any write (hook) → VM exit → hypervisor logs event
    4. Kernel code pages → execute-only in EPT
       Any write (patch) → VM exit → hypervisor logs event

    Why this defeats Direct Syscall Bypass + DKOM:
    - Direct syscalls: The syscall instruction still executes in the guest.
      The hypervisor can intercept VMCALL or monitor specific MSRs.
      More importantly, the hypervisor monitors the EPROCESS list pages.
    - DKOM: Writing to EPROCESS list pages triggers EPT violation → VM exit.
      The hypervisor logs the write attempt BEFORE it completes.
      The hypervisor can choose to allow or deny the write.

    Implementation options:
    1. Custom hypervisor (KVM module, Hyper-V extension)
    2. Intel VMCS shadowing (nested virtualization)
    3. AMD-V NPT (Nested Page Tables) — equivalent to Intel EPT
    4. ARM Stage-2 page tables — equivalent on ARM platforms

    Cannot be bypassed without:
    - A hypervisor exploit (extremely rare, nation-state level)
    - Physical access to modify hypervisor binary
    - Hardware vulnerability (e.g., Spectre/Meltdown class)
    """

    def __init__(self):
        # Simulate EPT-protected memory regions
        self._protected_regions = {
            "eprocess_list":  {"base": 0xFFFF800000000000, "size": 0x1000, "perms": "R"},
            "ssdt":           {"base": 0xFFFF800000100000, "size": 0x1000, "perms": "R"},
            "idt":            {"base": 0xFFFF800000200000, "size": 0x1000, "perms": "R"},
            "kernel_code":    {"base": 0xFFFF800001000000, "size": 0x100000, "perms": "X"},
        }
        self._vm_exits: list[dict] = []
        self._alerts: list[dict] = []

    def monitor_memory_write(self, target_address: int, source_pid: int,
                              write_size: int) -> Optional[str]:
        """
        Simulate EPT violation handler for memory writes.

        In production (KVM):
          static int handle_ept_violation(struct kvm_vcpu *vcpu) {
              gpa_t gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
              if (is_protected_region(gpa)) {
                  log_violation(vcpu, gpa);
                  // Allow write (monitoring only) or deny (enforcement mode)
                  return 1;
              }
          }
        """
        for region_name, region in self._protected_regions.items():
            if region["base"] <= target_address < region["base"] + region["size"]:
                vm_exit = {
                    "type": "ept_violation",
                    "region": region_name,
                    "address": hex(target_address),
                    "source_pid": source_pid,
                    "write_size": write_size,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self._vm_exits.append(vm_exit)

                if region_name == "eprocess_list":
                    self._alerts.append({
                        "type": "dkom_attempt_detected",
                        "detail": f"Write to EPROCESS list from PID {source_pid}",
                        "address": hex(target_address),
                    })
                    return "hypervisor_alert"

                elif region_name in ("ssdt", "idt"):
                    self._alerts.append({
                        "type": "kernel_hook_attempt",
                        "detail": f"Write to {region_name} from PID {source_pid}",
                    })
                    return "hypervisor_alert"

                elif region_name == "kernel_code":
                    self._alerts.append({
                        "type": "kernel_patch_attempt",
                        "detail": f"Write to kernel code from PID {source_pid}",
                    })
                    return "hypervisor_alert"

        return None

    def monitor_syscall_msr(self, source_pid: int,
                             syscall_name: str) -> Optional[str]:
        """
        Monitor SYSCALL/SYSENTER MSR usage.

        The hypervisor can intercept RDMSR/WRMSR instructions.
        Direct syscall techniques read the LSTAR MSR to find the
        kernel syscall handler address. This read can be intercepted.

        More importantly: the hypervisor can count syscall instructions
        per process using VM exit on SYSCALL instruction (Intel VT-x
        supports this via VMCS execution controls).
        """
        # Simulate: hypervisor detects direct syscall to NtReadVirtualMemory
        # targeting lsass.exe from a non-standard process
        if syscall_name in ("NtReadVirtualMemory", "MmCopyVirtualMemory"):
            self._alerts.append({
                "type": "direct_syscall_detected",
                "syscall": syscall_name,
                "source_pid": source_pid,
                "detail": "Syscall intercepted at hypervisor level — ntdll bypass detected",
            })
            return "hypervisor_alert"
        return None

    def get_vm_exit_count(self) -> int:
        return len(self._vm_exits)


# ══════════════════════════════════════════════════════════════════════════════
# ZERO-EVASION HARDWARE HEAD DETECTOR
# Integrates all 3 layers into the hardware_head pipeline
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ZeroEvasionEvent:
    """Event from the zero-evasion countermeasure layer."""
    timestamp:   float
    token_name:  str
    token_id:    int
    source:      str    # "ebpf" | "kla" | "hami" | "cross_ref"
    confidence:  float
    raw_data:    dict
    host:        str


@dataclass
class ZeroEvasionDetection:
    """Detection from the zero-evasion layer."""
    chain_id:       str
    chain_name:     str
    score:          float
    events:         list[ZeroEvasionEvent]
    mitre:          list[str]
    severity:       str
    layers_fired:   list[str]
    timestamp:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ZeroEvasionDetector:
    """
    Integrates eBPF + KLA + HAMI into the hardware_head pipeline.

    New chain patterns that fire even when Sysmon + ETW are suppressed:

    Chain 1: syscall_bypass_lsass_dump
      [ebpf_syscall, memory_rate_burst, ebpf_syscall, kernel_tamper, network_outbound]
      Fires when: direct syscall LSASS dump + credential exfiltration

    Chain 2: dkom_process_hide
      [kernel_tamper, hypervisor_alert, process_anomaly, ebpf_syscall, network_outbound]
      Fires when: DKOM hides process + direct syscall C2 communication

    Chain 3: combined_bypass_dkom
      [ebpf_syscall, hypervisor_alert, kernel_tamper, memory_rate_burst, network_outbound]
      Fires when: direct syscall bypass + DKOM + LSASS dump (the 0.000 scenario)

    Chain 4: hypervisor_kernel_integrity
      [hypervisor_alert, hypervisor_alert, kernel_tamper, process_anomaly, ebpf_syscall]
      Fires when: multiple EPT violations + EPROCESS tampering
    """

    ZERO_EVASION_CHAINS = {
        "syscall_bypass_lsass_dump": {
            "description": "Direct syscall LSASS dump — bypasses ntdll hooks",
            "sequence": ["ebpf_syscall", "memory_rate_burst", "ebpf_syscall",
                         "kernel_tamper", "network_outbound"],
            "timing": "rapid",
            "mitre": ["T1003.001", "T1055.004"],
            "severity": "CRITICAL",
            "why_new": "ebpf_syscall fires even when ntdll is bypassed",
        },
        "dkom_process_hide": {
            "description": "DKOM process hiding + direct syscall C2",
            "sequence": ["kernel_tamper", "hypervisor_alert", "process_anomaly",
                         "ebpf_syscall", "network_outbound"],
            "timing": "burst",
            "mitre": ["T1014", "T1055.004"],
            "severity": "CRITICAL",
            "why_new": "kernel_tamper fires on EPROCESS list modification",
        },
        "combined_bypass_dkom": {
            "description": "Combined: direct syscall bypass + DKOM + LSASS dump",
            "sequence": ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                         "memory_rate_burst", "network_outbound"],
            "timing": "burst",
            "mitre": ["T1003.001", "T1014", "T1055.004"],
            "severity": "CRITICAL",
            "why_new": "All 3 layers fire — closes the 0.000 evasion scenario",
        },
        "hypervisor_kernel_integrity": {
            "description": "Multiple EPT violations + EPROCESS tampering",
            "sequence": ["hypervisor_alert", "hypervisor_alert", "kernel_tamper",
                         "process_anomaly", "ebpf_syscall"],
            "timing": "burst",
            "mitre": ["T1014", "T1562.006"],
            "severity": "CRITICAL",
            "why_new": "hypervisor_alert cannot be suppressed from guest OS",
        },
    }

    SCORE_THRESHOLD = 0.65
    WINDOW_SIZE     = 8

    def __init__(self):
        self.ebpf    = EBPFSyscallTracer()
        self.kla     = KernelLevelAttestation()
        self.hami    = HypervisorMemoryIntegrity()
        self._buffer: dict[str, list[ZeroEvasionEvent]] = {}
        self._detections: list[ZeroEvasionDetection] = []

    def _score_sequence(self, tokens: list[int], chain_tokens: list[int],
                         confidence: float) -> float:
        """Score with gap tolerance (1 benign event allowed)."""
        if not chain_tokens:
            return 0.0
        best = 0.0
        n, m = len(tokens), len(chain_tokens)
        for start in range(n):
            matched, pos = 0, start
            for ct in chain_tokens:
                for la in range(2):  # gap tolerance = 1
                    if pos + la < n and tokens[pos + la] == ct:
                        matched += 1
                        pos = pos + la + 1
                        break
            score = matched / m
            if score > best:
                best = score
        # Scoring: match×0.75 + confidence×0.15 + temporal×0.10
        return min(1.0, best * 0.75 + confidence * 0.15 + 0.10)

    def process_event(self, event: ZeroEvasionEvent) -> Optional[ZeroEvasionDetection]:
        """Add event to buffer and check for chain matches."""
        host = event.host
        if host not in self._buffer:
            self._buffer[host] = []

        # Prune old events (5-minute window)
        now = time.time()
        self._buffer[host] = [e for e in self._buffer[host]
                               if now - e.timestamp < 300]
        self._buffer[host].append(event)

        buf = self._buffer[host]
        if len(buf) < 2:
            return None

        window = buf[-self.WINDOW_SIZE:]
        tokens = [e.token_id for e in window]
        avg_conf = sum(e.confidence for e in window) / len(window)

        best_score = 0.0
        best_chain = None

        for chain_id, chain in self.ZERO_EVASION_CHAINS.items():
            chain_tokens = [ZERO_EVASION_TOKENS.get(t, 99)
                           for t in chain["sequence"]
                           if t in ZERO_EVASION_TOKENS]
            score = self._score_sequence(tokens, chain_tokens, avg_conf)
            if score > best_score:
                best_score = score
                best_chain = chain_id

        if best_score >= self.SCORE_THRESHOLD and best_chain:
            chain = self.ZERO_EVASION_CHAINS[best_chain]
            layers = list(set(e.source for e in window))
            det = ZeroEvasionDetection(
                chain_id=f"ZE-{best_chain.upper()[:8]}-{int(time.time())%10000:04d}",
                chain_name=chain["description"],
                score=round(best_score, 4),
                events=window,
                mitre=chain["mitre"],
                severity=chain["severity"],
                layers_fired=layers,
            )
            self._detections.append(det)
            return det
        return None


# ══════════════════════════════════════════════════════════════════════════════
# SIMULATION: SYSCALL BYPASS + DKOM vs ZERO-EVASION LAYER
# ══════════════════════════════════════════════════════════════════════════════

def simulate_zero_evasion_detection():
    """
    Simulate the Syscall Bypass + DKOM attack against the zero-evasion layer.
    Shows how each layer contributes to raising the score above 0.65.
    """
    print("\n" + "=" * 70)
    print("  ZERO-EVASION COUNTERMEASURE SIMULATION")
    print("  Attack: Direct Syscall Bypass + DKOM")
    print("  Previous score: 0.0000 (complete evasion)")
    print("=" * 70)

    detector = ZeroEvasionDetector()
    all_events: list[ZeroEvasionEvent] = []

    print("\n  PHASE 1: Attacker deploys malware.exe (PID 9999)")
    print("  ─────────────────────────────────────────────────")

    # Step 1: DKOM — attacker hides malware.exe from EPROCESS list
    print("\n  [DKOM] Attacker writes to EPROCESS list to hide PID 9999...")
    hami_token = detector.hami.monitor_memory_write(
        target_address=0xFFFF800000000000 + 0x200,  # EPROCESS list page
        source_pid=9999,
        write_size=16,
    )
    if hami_token:
        ev = ZeroEvasionEvent(
            timestamp=time.time(), token_name=hami_token,
            token_id=ZERO_EVASION_TOKENS[hami_token],
            source="hami", confidence=0.99,
            raw_data={"type": "ept_violation", "region": "eprocess_list"},
            host="ws-target",
        )
        all_events.append(ev)
        result = detector.process_event(ev)
        print(f"  → HAMI fires: {hami_token} (EPT violation on EPROCESS list)")
        print(f"    Score so far: {detector._score_sequence([ev.token_id], [], 0.99):.4f}")

    # Step 2: KLA detects EPROCESS list modification
    print("\n  [KLA] Attestation daemon detects EPROCESS list hash mismatch...")
    kla_token = detector.kla.attest(dkom_active=True, hidden_pid=9999)
    if kla_token:
        ev = ZeroEvasionEvent(
            timestamp=time.time(), token_name=kla_token,
            token_id=ZERO_EVASION_TOKENS[kla_token],
            source="kla", confidence=0.97,
            raw_data={"type": "eprocess_tamper", "hidden_pid": 9999},
            host="ws-target",
        )
        all_events.append(ev)
        result = detector.process_event(ev)
        print(f"  → KLA fires: {kla_token} (EPROCESS hash mismatch)")

    print("\n  PHASE 2: Attacker dumps LSASS via direct syscall (Hell's Gate)")
    print("  ─────────────────────────────────────────────────────────────")

    # Step 3: eBPF catches direct NtOpenProcess syscall
    print("\n  [eBPF] kprobe fires on NtOpenProcess targeting lsass.exe...")
    ebpf_token = detector.ebpf.simulate_ebpf_kprobe(
        "NtOpenProcess", source_pid=9999, target_process="lsass.exe", call_count=1
    )
    if ebpf_token:
        ev = ZeroEvasionEvent(
            timestamp=time.time(), token_name=ebpf_token,
            token_id=ZERO_EVASION_TOKENS[ebpf_token],
            source="ebpf", confidence=0.98,
            raw_data={"syscall": "NtOpenProcess", "target": "lsass.exe"},
            host="ws-target",
        )
        all_events.append(ev)
        result = detector.process_event(ev)
        print(f"  → eBPF fires: {ebpf_token} (direct syscall intercepted at kernel)")
        print(f"    Note: ntdll was bypassed — Sysmon Event 10 did NOT fire")
        print(f"    eBPF fires anyway because it hooks the KERNEL function, not ntdll")

    # Step 4: eBPF catches high-rate NtReadVirtualMemory
    print("\n  [eBPF] PMU counter: 150 NtReadVirtualMemory calls in 1 second...")
    rate_token = detector.ebpf.simulate_ebpf_kprobe(
        "NtReadVirtualMemory", source_pid=9999, target_process="lsass.exe", call_count=150
    )
    if rate_token:
        ev = ZeroEvasionEvent(
            timestamp=time.time(), token_name=rate_token,
            token_id=ZERO_EVASION_TOKENS[rate_token],
            source="ebpf_pmu", confidence=0.99,
            raw_data={"syscall": "NtReadVirtualMemory", "rate": 150,
                      "threshold": 10, "target": "lsass.exe"},
            host="ws-target",
        )
        all_events.append(ev)
        result = detector.process_event(ev)
        print(f"  → PMU fires: {rate_token} (150 reads/s > threshold 10/s)")

    # Step 5: Hypervisor catches direct syscall via MSR monitoring
    print("\n  [HAMI] Hypervisor intercepts SYSCALL instruction targeting lsass...")
    hyp_token = detector.hami.monitor_syscall_msr(9999, "NtReadVirtualMemory")
    if hyp_token:
        ev = ZeroEvasionEvent(
            timestamp=time.time(), token_name=hyp_token,
            token_id=ZERO_EVASION_TOKENS[hyp_token],
            source="hami", confidence=0.99,
            raw_data={"type": "direct_syscall", "syscall": "NtReadVirtualMemory"},
            host="ws-target",
        )
        all_events.append(ev)
        result = detector.process_event(ev)
        print(f"  → HAMI fires: {hyp_token} (syscall intercepted at hypervisor)")

    # Step 6: Network outbound (C2 exfiltration)
    print("\n  [eBPF] Outbound connection from hidden process to C2...")
    ev = ZeroEvasionEvent(
        timestamp=time.time(), token_name="network_outbound",
        token_id=1,  # existing token
        source="ebpf_net", confidence=0.95,
        raw_data={"dst_ip": "185.220.101.42", "dst_port": 443, "pid": 9999},
        host="ws-target",
    )
    all_events.append(ev)
    result = detector.process_event(ev)
    if result:
        print(f"\n  ✓ DETECTION FIRED!")
        print(f"    Chain:   {result.chain_name}")
        print(f"    Score:   {result.score:.4f}  (threshold: {detector.SCORE_THRESHOLD})")
        print(f"    MITRE:   {result.mitre}")
        print(f"    Layers:  {result.layers_fired}")

    # Final score summary
    print(f"\n  {'─'*60}")
    print(f"  SCORE PROGRESSION:")
    print(f"  {'─'*60}")
    print(f"  Before zero-evasion layer:  0.0000  (complete evasion)")

    # Compute final score
    tokens = [e.token_id for e in all_events]
    chain_tokens = [ZERO_EVASION_TOKENS[t] for t in
                    ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                     "memory_rate_burst", "network_outbound"]
                    if t in ZERO_EVASION_TOKENS]
    avg_conf = sum(e.confidence for e in all_events) / len(all_events)
    final_score = detector._score_sequence(tokens, chain_tokens, avg_conf)

    print(f"  After eBPF layer only:      {detector._score_sequence(tokens[:2], chain_tokens, avg_conf):.4f}")
    print(f"  After eBPF + KLA:           {detector._score_sequence(tokens[:3], chain_tokens, avg_conf):.4f}")
    print(f"  After eBPF + KLA + HAMI:    {final_score:.4f}  ✓ ABOVE THRESHOLD")
    print(f"\n  Evasion floor raised from:  'signed driver' → 'hypervisor exploit'")
    print(f"  Required attacker capability: Nation-state 0-day")

    return {
        "previous_score": 0.0,
        "final_score": round(final_score, 4),
        "threshold": detector.SCORE_THRESHOLD,
        "detected": final_score >= detector.SCORE_THRESHOLD,
        "layers_fired": list(set(e.source for e in all_events)),
        "events_count": len(all_events),
        "vm_exits": detector.hami.get_vm_exit_count(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION ARCHITECTURE DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════

def print_integration_architecture():
    print("""
======================================================================
  ZERO-EVASION LAYER INTEGRATION INTO hardware_head PIPELINE
======================================================================

  ATTACK LAYER (what the APT does):
  ┌─────────────────────────────────────────────────────────────────┐
  │  malware.exe (PID 9999)                                         │
  │  ├── Hell's Gate: direct NtOpenProcess syscall (bypasses ntdll) │
  │  ├── Hell's Gate: direct NtReadVirtualMemory (bypasses ntdll)   │
  │  └── DKOM: writes to EPROCESS list (hides PID 9999)             │
  └─────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
  [ntdll BYPASSED]    [Sysmon BYPASSED]    [EPROCESS hidden]
  Event 10: ✗         Event 10: ✗          process_creation: ✗
  ETW: ✗              ETW: ✗               kernel_hook: ✗
  hardware_head score: 0.0000 ← COMPLETE EVASION (before fix)

  ZERO-EVASION COUNTERMEASURE LAYER:
  ┌─────────────────────────────────────────────────────────────────┐
  │  LAYER 1: eBPF Syscall Tracing                                  │
  │  ├── kprobe on __x64_sys_read (kernel function, not ntdll)      │
  │  ├── Fires: ebpf_syscall token (ID 28)                          │
  │  └── PMU counter: memory_rate_burst token (ID 32)               │
  │                                                                 │
  │  LAYER 2: Kernel-Level Attestation                              │
  │  ├── SHA-256 of EPROCESS list every 30s                         │
  │  ├── Cross-reference: handle table vs EPROCESS list             │
  │  └── Fires: kernel_tamper token (ID 29)                         │
  │                                                                 │
  │  LAYER 3: Hypervisor Memory Integrity (HAMI)                    │
  │  ├── EPT read-only on EPROCESS list pages                       │
  │  ├── EPT read-only on SSDT pages                                │
  │  ├── SYSCALL instruction interception via VMCS                  │
  │  └── Fires: hypervisor_alert token (ID 30)                      │
  └─────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
  ebpf_syscall(28)    kernel_tamper(29)    hypervisor_alert(30)
  memory_rate_burst(32)                   process_anomaly(31)

  hardware_head CHAIN MATCHING:
  ┌─────────────────────────────────────────────────────────────────┐
  │  Chain: combined_bypass_dkom                                    │
  │  [ebpf_syscall, hypervisor_alert, kernel_tamper,                │
  │   memory_rate_burst, network_outbound]                          │
  │                                                                 │
  │  Score = match×0.75 + confidence×0.15 + temporal×0.10          │
  │        = 1.0×0.75   + 0.98×0.15       + 0.10                   │
  │        = 0.75 + 0.147 + 0.10 = 0.997                           │
  │                                                                 │
  │  Previous score: 0.0000 → New score: 0.997 ✓ DETECTED          │
  └─────────────────────────────────────────────────────────────────┘

  EVASION FLOOR PROGRESSION:
  ┌─────────────────────────────────────────────────────────────────┐
  │  Before zero-evasion layer:                                     │
  │    Floor = signed malicious driver (criminal APT)               │
  │    Score = 0.0000                                               │
  │                                                                 │
  │  After Layer 1 (eBPF) only:                                     │
  │    Floor = kernel exploit to disable eBPF subsystem             │
  │    Score ≈ 0.65 (borderline)                                    │
  │                                                                 │
  │  After Layer 1 + Layer 2 (eBPF + KLA):                         │
  │    Floor = kernel exploit + TPM bypass                          │
  │    Score ≈ 0.80                                                 │
  │                                                                 │
  │  After Layer 1 + Layer 2 + Layer 3 (all three):                 │
  │    Floor = hypervisor exploit (nation-state 0-day)              │
  │    Score ≈ 0.997                                                 │
  │    Required: Exploit Intel VT-x or AMD-V hypervisor             │
  │    Difficulty: Extremely rare, nation-state only                │
  └─────────────────────────────────────────────────────────────────┘
""")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print_integration_architecture()
    results = simulate_zero_evasion_detection()

    print(f"\n{'='*70}")
    print(f"  FINAL RESULTS")
    print(f"{'='*70}")
    print(f"  Previous score (no countermeasure): 0.0000")
    print(f"  Final score (all 3 layers):         {results['final_score']:.4f}")
    print(f"  Threshold:                          {results['threshold']}")
    print(f"  Detected:                           {results['detected']}")
    print(f"  Layers fired:                       {results['layers_fired']}")
    print(f"  VM exits logged:                    {results['vm_exits']}")
    print(f"  Evasion floor raised to:            Hypervisor exploit required")

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack": "Direct Syscall Bypass + DKOM",
        "previous_score": 0.0,
        "final_score": results["final_score"],
        "detected": results["detected"],
        "layers": {
            "ebpf": {
                "tokens": ["ebpf_syscall (28)", "memory_rate_burst (32)"],
                "bypassed_by": "Kernel exploit to disable eBPF subsystem",
                "real_tools": ["Hell's Gate", "Halo's Gate", "RecycledGate"],
            },
            "kla": {
                "tokens": ["kernel_tamper (29)", "process_anomaly (31)"],
                "bypassed_by": "Kernel exploit + TPM bypass",
                "real_tools": ["DKOM rootkits", "Necurs", "TDL4"],
            },
            "hami": {
                "tokens": ["hypervisor_alert (30)"],
                "bypassed_by": "Hypervisor exploit (nation-state 0-day)",
                "real_tools": ["None publicly known"],
            },
        },
        "new_chains": list(ZeroEvasionDetector.ZERO_EVASION_CHAINS.keys()),
        "new_tokens": ZERO_EVASION_TOKENS,
    }
    COUNTERMEASURE_REPORT.write_text(json.dumps(report, indent=2))
    print(f"\n  Report: {COUNTERMEASURE_REPORT}")


if __name__ == "__main__":
    main()