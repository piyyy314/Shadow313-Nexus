"""
shadow313.v4.detection.kernel_gap_hardening
────────────────────────────────────────────
Closes the 9 kernel-callback blind spots identified in the NEXUS vs
CrowdStrike fidelity analysis.  Operates entirely from userspace /
eBPF-equivalent simulation — no kernel driver required.

Gaps addressed (all 12 attack steps → 12/12 visible):
  GAP-KH-01  Direct syscall stub (Hell's Gate / Halo's Gate / SysWhispers3)
  GAP-KH-02  Tartarus' Gate (suspended-process SSN harvest)
  GAP-KH-03  RecycledGate (ntdll ROP gadget reuse)
  GAP-KH-04  Heaven's Gate (WoW64 32→64 mode switch)
  GAP-KH-05  Reflective DLL / PE injection (no disk backing)
  GAP-KH-06  VirtualAlloc RWX / RW→RX stub allocation
  GAP-KH-07  lsass fork-dump (Nanodump --fork)
  GAP-KH-08  Network-exfil dump (Nanodump --write-to-network)
  GAP-KH-09  BYOVD driver staging (*.sys from temp path)
  GAP-KH-10  lsass handle probe (PROCESS_QUERY_INFORMATION only)
  GAP-KH-11  ETW session enumeration (QueryAllTraces recon)
  GAP-KH-12  Timing side-channel (ObRegisterCallbacks latency probe)

Each detector returns a KernelGapAlert with:
  - technique_id  (MITRE ATT&CK)
  - confidence    (0.0–1.0)
  - sysmon_event  (which Sysmon event would fire, if any)
  - cs_event      (what CrowdStrike ETW-TI / callback would catch)
  - artifact      (what NEXUS can observe post-hoc)
  - blocked       (False — NEXUS detects, cannot block without kernel driver)
"""
from __future__ import annotations

import hashlib
import math
import re
import statistics
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class KernelGapAlert:
    gap_id:        str
    technique_id:  str
    technique_name: str
    confidence:    float          # 0.0–1.0
    sysmon_event:  Optional[str]  # Sysmon event that fires (or None)
    cs_event:      str            # What CS would catch
    artifact:      str            # Observable artifact in NEXUS
    blocked:       bool = False   # NEXUS cannot block without kernel driver
    details:       dict = field(default_factory=dict)

    @property
    def severity(self) -> str:
        if self.confidence >= 0.85:
            return "CRITICAL"
        if self.confidence >= 0.65:
            return "HIGH"
        if self.confidence >= 0.40:
            return "MEDIUM"
        return "LOW"


# ── GAP-KH-01: Direct Syscall Stub Detector ───────────────────────────────────

class DirectSyscallStubDetector:
    """
    Detects Hell's Gate / Halo's Gate / SysWhispers3 patterns.

    Observable artifacts (userspace):
    1. ntdll.dll opened as a DATA file (not image) — CreateFile + MapViewOfFile
       on ntdll.dll path → Hell's Gate SSN harvest
    2. Anonymous RX memory region containing syscall stub bytes
       (4C 8B D1 B8 ?? 00 00 00 0F 05 C3) — detectable via /proc/PID/maps
    3. VirtualProtect RW→RX on small (<64 byte) anonymous region
    4. Halo's Gate: GetProcAddress called on neighboring Nt* functions
       in rapid succession (>3 Nt* exports in <100ms)

    Sysmon coverage: NONE for the syscall itself.
    Sysmon Event 7 (ImageLoad) fires for ntdll.dll load — but not for
    data-file mapping of ntdll.dll.
    CS coverage: ETW-TI OPENPROC/READVM fires regardless of call path.
    """

    # Syscall stub byte pattern: mov r10,rcx / mov eax,SSN / syscall / ret
    STUB_PATTERN = bytes([0x4C, 0x8B, 0xD1, 0xB8])  # first 4 bytes
    STUB_SUFFIX  = bytes([0x0F, 0x05, 0xC3])          # syscall; ret

    def __init__(self):
        self._ntdll_data_opens: dict[int, list[float]] = defaultdict(list)  # pid → timestamps
        self._nt_export_calls:  dict[int, list[float]] = defaultdict(list)  # pid → timestamps
        self._lock = threading.Lock()

    def record_ntdll_data_open(self, pid: int, path: str, timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Fire when ntdll.dll is opened as a data file (not image load)."""
        ts = timestamp or time.time()
        if "ntdll" not in path.lower():
            return None
        with self._lock:
            self._ntdll_data_opens[pid].append(ts)
        return KernelGapAlert(
            gap_id="GAP-KH-01",
            technique_id="T1055.001",
            technique_name="Direct Syscall / Hell's Gate SSN Harvest",
            confidence=0.72,
            sysmon_event=None,  # No Sysmon event for data-file open of ntdll
            cs_event="ETW-TI READVM fires when ntdll memory is read cross-process",
            artifact=f"PID {pid} opened ntdll.dll as data file (not image load) — Hell's Gate indicator",
            details={"pid": pid, "path": path, "method": "hell_gate_disk_read"},
        )

    def record_nt_export_probe(self, pid: int, export_name: str, timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Fire when multiple Nt* exports are probed rapidly (Halo's Gate)."""
        ts = timestamp or time.time()
        if not export_name.startswith(("Nt", "Zw")):
            return None
        with self._lock:
            calls = self._nt_export_calls[pid]
            calls.append(ts)
            # Keep only last 2 seconds
            cutoff = ts - 2.0
            self._nt_export_calls[pid] = [t for t in calls if t > cutoff]
            count = len(self._nt_export_calls[pid])

        if count >= 4:
            return KernelGapAlert(
                gap_id="GAP-KH-01",
                technique_id="T1055.001",
                technique_name="Direct Syscall / Halo's Gate SSN Walk",
                confidence=0.68,
                sysmon_event=None,
                cs_event="ETW-TI call stack analysis detects non-ntdll return address",
                artifact=f"PID {pid} probed {count} Nt* exports in <2s — Halo's Gate SSN walk",
                details={"pid": pid, "export": export_name, "rapid_count": count},
            )
        return None

    def detect_stub_in_memory(self, pid: int, region_base: int, region_bytes: bytes,
                               is_anonymous: bool, is_rx: bool) -> Optional[KernelGapAlert]:
        """Detect syscall stub pattern in anonymous RX memory."""
        if not (is_anonymous and is_rx):
            return None
        if len(region_bytes) > 256:  # Stubs are tiny (<64 bytes)
            return None
        if self.STUB_PATTERN in region_bytes and self.STUB_SUFFIX in region_bytes:
            return KernelGapAlert(
                gap_id="GAP-KH-01",
                technique_id="T1055.001",
                technique_name="Direct Syscall Stub in Anonymous RX Memory",
                confidence=0.91,
                sysmon_event=None,
                cs_event="ETW-TI ALLOCVM + PROTECTVM fires on stub allocation",
                artifact=f"PID {pid}: syscall stub bytes (4C 8B D1 B8 ... 0F 05 C3) in anonymous RX region @ 0x{region_base:X}",
                details={"pid": pid, "region_base": hex(region_base), "size": len(region_bytes)},
            )
        return None


# ── GAP-KH-02: Tartarus' Gate Detector ────────────────────────────────────────

class TartarusGateDetector:
    """
    Detects Tartarus' Gate: suspended process created, memory read, terminated.

    Observable in NEXUS:
    - Sysmon Event 1: process created with CREATE_SUSPENDED flag
    - Sysmon Event 10: ReadProcessMemory on the suspended process
    - Sysmon Event 5: process terminated within SHORT_LIFE_S seconds

    CS coverage: ETW-TI READVM fires on the ReadProcessMemory call.
    The 3-event correlation is the NEXUS compensating control.
    """

    SHORT_LIFE_S = 10.0  # Suspended process lives < 10s in Tartarus' Gate

    def __init__(self):
        # pid → {created_ts, read_ts, terminated_ts, parent_pid}
        self._suspended: dict[int, dict] = {}
        self._lock = threading.Lock()

    def record_suspended_create(self, pid: int, parent_pid: int, image: str,
                                 timestamp: float | None = None) -> None:
        ts = timestamp or time.time()
        with self._lock:
            self._suspended[pid] = {
                "created_ts": ts, "parent_pid": parent_pid,
                "image": image, "read_ts": None, "terminated_ts": None,
            }

    def record_memory_read(self, reader_pid: int, target_pid: int,
                            timestamp: float | None = None) -> None:
        ts = timestamp or time.time()
        with self._lock:
            if target_pid in self._suspended:
                self._suspended[target_pid]["read_ts"] = ts
                self._suspended[target_pid]["reader_pid"] = reader_pid

    def record_termination(self, pid: int, timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        with self._lock:
            entry = self._suspended.pop(pid, None)
        if not entry:
            return None
        entry["terminated_ts"] = ts
        life = ts - entry["created_ts"]
        if entry.get("read_ts") and life < self.SHORT_LIFE_S:
            return KernelGapAlert(
                gap_id="GAP-KH-02",
                technique_id="T1055.001",
                technique_name="Tartarus' Gate — Suspended Process SSN Harvest",
                confidence=0.78,
                sysmon_event="Event 1 (CREATE_SUSPENDED) + Event 10 (ReadProcessMemory) + Event 5 (terminate)",
                cs_event="ETW-TI READVM fires on ReadProcessMemory; PsSetCreateProcessNotifyRoutineEx fires on create",
                artifact=f"PID {pid} ({entry['image']}) created suspended, memory-read by PID {entry.get('reader_pid','?')}, terminated in {life:.1f}s",
                details=entry,
            )
        return None


# ── GAP-KH-03: RecycledGate Detector ──────────────────────────────────────────

class RecycledGateDetector:
    """
    Detects RecycledGate: ntdll ROP gadget (0F 05 C3) used as syscall trampoline.

    Observable: ntdll.dll memory scanned for 0F 05 C3 pattern by attacker process.
    Proxy signal: process reads ntdll.dll image memory in small chunks
    (scanning for gadget) rather than loading it normally.

    Sysmon: No event for ntdll memory scanning.
    CS: ETW-TI READVM fires on cross-process ntdll read; call stack shows
        Frame 0 at ntdll+offset NOT matching known stub offsets.
    """

    def __init__(self):
        self._ntdll_scan_events: dict[int, list[dict]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_ntdll_scan(self, pid: int, scan_offset: int, scan_size: int,
                           timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        with self._lock:
            events = self._ntdll_scan_events[pid]
            events.append({"offset": scan_offset, "size": scan_size, "ts": ts})
            # Keep last 5 seconds
            self._ntdll_scan_events[pid] = [e for e in events if e["ts"] > ts - 5.0]
            count = len(self._ntdll_scan_events[pid])

        # RecycledGate scans ntdll in many small reads looking for 0F 05 C3
        if count >= 10 and scan_size <= 16:
            return KernelGapAlert(
                gap_id="GAP-KH-03",
                technique_id="T1055.001",
                technique_name="RecycledGate — ntdll ROP Gadget Scan",
                confidence=0.65,
                sysmon_event=None,
                cs_event="ETW-TI call stack: Frame 0 at ntdll+offset not matching known stub — direct syscall via gadget",
                artifact=f"PID {pid}: {count} small ntdll reads in <5s — scanning for 0F 05 C3 syscall gadget",
                details={"pid": pid, "scan_count": count, "last_offset": hex(scan_offset)},
            )
        return None


# ── GAP-KH-04: Heaven's Gate Detector ─────────────────────────────────────────

class HeavensGateDetector:
    """
    Detects Heaven's Gate: 32-bit process executing 64-bit code via CS:0x33.

    Observable artifacts:
    1. 32-bit process (WoW64) with unusual memory layout:
       - 64-bit code region in 32-bit process address space
       - Anonymous RX region above 0x7FFFFFFF (64-bit range)
    2. Far call / retf instruction pattern in process memory
    3. 32-bit process making syscalls with 64-bit calling convention
       (r10 register used — not normal in 32-bit code)

    Sysmon: Event 1 fires for process creation (32-bit flag visible).
    No Sysmon event for CPU mode switch.
    CS: ETW-TI fires on all syscalls regardless of CPU mode.
    """

    def __init__(self):
        self._wow64_processes: dict[int, dict] = {}
        self._lock = threading.Lock()

    def record_wow64_process(self, pid: int, image: str, timestamp: float | None = None) -> None:
        ts = timestamp or time.time()
        with self._lock:
            self._wow64_processes[pid] = {"image": image, "ts": ts, "anomalies": []}

    def record_high_address_rx_region(self, pid: int, region_base: int,
                                       region_size: int) -> Optional[KernelGapAlert]:
        """64-bit RX region in a 32-bit (WoW64) process — Heaven's Gate indicator."""
        with self._lock:
            if pid not in self._wow64_processes:
                return None
            entry = self._wow64_processes[pid]

        # 32-bit processes normally can't have RX regions above 0x7FFFFFFF
        if region_base > 0x7FFFFFFF:
            return KernelGapAlert(
                gap_id="GAP-KH-04",
                technique_id="T1055.001",
                technique_name="Heaven's Gate — WoW64 64-bit Code Region",
                confidence=0.83,
                sysmon_event="Event 1 (32-bit process creation visible)",
                cs_event="ETW-TI fires on all syscalls regardless of CPU mode; ALLOCVM fires on 64-bit region",
                artifact=f"WoW64 PID {pid} ({entry['image']}): RX region at 0x{region_base:X} (64-bit range) — Heaven's Gate stub",
                details={"pid": pid, "region_base": hex(region_base), "size": region_size},
            )
        return None

    def record_retf_pattern(self, pid: int, code_bytes: bytes) -> Optional[KernelGapAlert]:
        """Detect far return (CB/CA) instruction in WoW64 process — mode switch."""
        with self._lock:
            if pid not in self._wow64_processes:
                return None
            entry = self._wow64_processes[pid]

        # 0xCB = retf (far return without pop), 0xCA = retf imm16
        if b'\xcb' in code_bytes or b'\xca' in code_bytes:
            return KernelGapAlert(
                gap_id="GAP-KH-04",
                technique_id="T1055.001",
                technique_name="Heaven's Gate — Far Return (RETF) Mode Switch",
                confidence=0.87,
                sysmon_event=None,
                cs_event="ETW-TI OPENPROC/READVM fires on subsequent 64-bit syscalls",
                artifact=f"WoW64 PID {pid} ({entry['image']}): RETF instruction (0xCB) detected — CS:0x33 mode switch to 64-bit",
                details={"pid": pid, "image": entry["image"]},
            )
        return None


# ── GAP-KH-05: Reflective DLL / PE Injection Detector ─────────────────────────

class ReflectiveDLLDetector:
    """
    Detects reflective DLL / PE injection (no disk backing).

    Observable artifacts:
    1. Anonymous RX memory region containing MZ/PE header
    2. Large anonymous RX region (>100KB) — typical for injected DLL
    3. Thread created with start address in anonymous memory
    4. Process with no new disk-backed DLL loads but new RX regions

    Sysmon Event 7 (ImageLoad): DOES NOT FIRE for reflective loads.
    Sysmon Event 8 (CreateRemoteThread): fires if NtCreateThreadEx used
       via Win32 API — but direct syscall bypasses this.
    CS: PsSetLoadImageNotifyRoutine fires on NtMapViewOfSection;
        ETW-TI ALLOCVM/PROTECTVM fires on memory operations.
    """

    PE_MAGIC = b'MZ'
    MIN_REFLECTIVE_SIZE = 4096  # 4KB minimum for a PE

    def __init__(self):
        self._anonymous_rx: dict[int, list[dict]] = defaultdict(list)  # pid → regions
        self._lock = threading.Lock()

    def record_anonymous_rx_region(self, pid: int, base: int, size: int,
                                    content_sample: bytes | None = None,
                                    timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        has_pe_header = content_sample and content_sample[:2] == self.PE_MAGIC

        with self._lock:
            self._anonymous_rx[pid].append({
                "base": base, "size": size, "ts": ts, "has_pe": has_pe_header
            })

        if has_pe_header and size >= self.MIN_REFLECTIVE_SIZE:
            return KernelGapAlert(
                gap_id="GAP-KH-05",
                technique_id="T1055.002",
                technique_name="Reflective PE Injection — MZ Header in Anonymous RX Memory",
                confidence=0.93,
                sysmon_event=None,  # Event 7 does NOT fire for reflective loads
                cs_event="PsSetLoadImageNotifyRoutine fires on NtMapViewOfSection; ETW-TI ALLOCVM fires",
                artifact=f"PID {pid}: MZ/PE header in anonymous RX region @ 0x{base:X} ({size//1024}KB) — reflective DLL injection",
                details={"pid": pid, "base": hex(base), "size": size, "has_pe_header": True},
            )

        if size >= 100 * 1024:  # Large anonymous RX without PE header
            return KernelGapAlert(
                gap_id="GAP-KH-05",
                technique_id="T1055.002",
                technique_name="Reflective Injection — Large Anonymous RX Region",
                confidence=0.71,
                sysmon_event=None,
                cs_event="ETW-TI ALLOCVM + PROTECTVM fires on allocation sequence",
                artifact=f"PID {pid}: {size//1024}KB anonymous RX region @ 0x{base:X} — possible shellcode/reflective load",
                details={"pid": pid, "base": hex(base), "size": size},
            )
        return None

    def record_thread_in_anonymous_memory(self, pid: int, thread_start: int) -> Optional[KernelGapAlert]:
        """Thread start address in anonymous (non-module) memory."""
        with self._lock:
            regions = self._anonymous_rx.get(pid, [])
            for r in regions:
                if r["base"] <= thread_start < r["base"] + r["size"]:
                    return KernelGapAlert(
                        gap_id="GAP-KH-05",
                        technique_id="T1055.002",
                        technique_name="Reflective Injection — Thread Start in Anonymous Memory",
                        confidence=0.88,
                        sysmon_event="Event 8 (CreateRemoteThread) — ONLY if Win32 API used, not direct syscall",
                        cs_event="ETW-TI QUEUEAPC or PsSetCreateThreadNotifyRoutine fires",
                        artifact=f"PID {pid}: thread start @ 0x{thread_start:X} is inside anonymous RX region — shellcode execution",
                        details={"pid": pid, "thread_start": hex(thread_start)},
                    )
        return None


# ── GAP-KH-06: VirtualAlloc RWX / RW→RX Stub Allocation Detector ──────────────

class StubAllocationDetector:
    """
    Detects VirtualAlloc patterns used for syscall stub construction.

    Observable:
    1. Small (<256 byte) RWX allocation — classic stub pattern
    2. Small RW allocation followed by VirtualProtect to RX within 1 second
    3. Multiple small RX allocations in rapid succession (stub array)

    Sysmon: No event for VirtualAlloc or VirtualProtect.
    CS: ETW-TI ALLOCVM fires on allocation; ETW-TI PROTECTVM fires on RW→RX.
    """

    STUB_MAX_SIZE = 256
    PROTECT_WINDOW_S = 2.0

    def __init__(self):
        self._small_rw_allocs: dict[int, list[dict]] = defaultdict(list)  # pid → allocs
        self._lock = threading.Lock()

    def record_allocation(self, pid: int, base: int, size: int, protection: str,
                           timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        with self._lock:
            if protection == "RWX" and size <= self.STUB_MAX_SIZE:
                return KernelGapAlert(
                    gap_id="GAP-KH-06",
                    technique_id="T1055.001",
                    technique_name="Syscall Stub — Small RWX Allocation",
                    confidence=0.79,
                    sysmon_event=None,
                    cs_event="ETW-TI ALLOCVM fires; PROTECTVM fires if protection changes",
                    artifact=f"PID {pid}: {size}B RWX allocation @ 0x{base:X} — syscall stub construction",
                    details={"pid": pid, "base": hex(base), "size": size, "prot": "RWX"},
                )
            if protection == "RW" and size <= self.STUB_MAX_SIZE:
                self._small_rw_allocs[pid].append({"base": base, "size": size, "ts": ts})
        return None

    def record_protect_change(self, pid: int, base: int, size: int,
                               old_prot: str, new_prot: str,
                               timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        if new_prot != "RX" or size > self.STUB_MAX_SIZE:
            return None
        with self._lock:
            allocs = self._small_rw_allocs.get(pid, [])
            matching = [a for a in allocs
                        if a["base"] == base and ts - a["ts"] < self.PROTECT_WINDOW_S]
        if matching:
            return KernelGapAlert(
                gap_id="GAP-KH-06",
                technique_id="T1055.001",
                technique_name="Syscall Stub — RW→RX Protection Change on Small Region",
                confidence=0.85,
                sysmon_event=None,
                cs_event="ETW-TI PROTECTVM fires on VirtualProtect; ALLOCVM fired on initial allocation",
                artifact=f"PID {pid}: {size}B region @ 0x{base:X} changed RW→RX within {self.PROTECT_WINDOW_S}s — syscall stub finalized",
                details={"pid": pid, "base": hex(base), "size": size, "old": old_prot, "new": new_prot},
            )
        return None


# ── GAP-KH-07: lsass Fork-Dump Detector ───────────────────────────────────────

class LsassForkDumpDetector:
    """
    Detects Nanodump --fork: lsass.exe spawns a child process which is then dumped.

    lsass.exe should NEVER spawn child processes in normal operation.
    Any child of lsass.exe is a high-confidence indicator.

    Sysmon Event 1: fires for child process creation (parent = lsass.exe).
    CS: PsSetCreateProcessNotifyRoutineEx fires synchronously; can block.
    """

    LSASS_NAMES = {"lsass.exe", "lsass"}

    def __init__(self):
        self._lsass_children: list[dict] = []
        self._lock = threading.Lock()

    def record_process_create(self, pid: int, parent_pid: int,
                               parent_name: str, child_image: str,
                               timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        if parent_name.lower() not in self.LSASS_NAMES:
            return None
        with self._lock:
            self._lsass_children.append({
                "child_pid": pid, "parent_pid": parent_pid,
                "child_image": child_image, "ts": ts
            })
        return KernelGapAlert(
            gap_id="GAP-KH-07",
            technique_id="T1003.001",
            technique_name="lsass Fork-Dump (Nanodump --fork)",
            confidence=0.96,
            sysmon_event="Event 1 (process creation with ParentImage=lsass.exe)",
            cs_event="PsSetCreateProcessNotifyRoutineEx fires synchronously; blocks before first instruction",
            artifact=f"lsass.exe (PID {parent_pid}) spawned child {child_image} (PID {pid}) — lsass fork-dump indicator",
            details={"child_pid": pid, "parent_pid": parent_pid, "child_image": child_image},
        )


# ── GAP-KH-08: Network-Exfil Dump Detector ────────────────────────────────────

class NetworkExfilDumpDetector:
    """
    Detects Nanodump --write-to-network: dump sent over network, no .dmp file.

    Observable:
    1. Process opens lsass handle (any access right) — Sysmon Event 10
    2. Same process makes outbound network connection within SHORT_WINDOW_S
    3. No .dmp file created (distinguishes from disk dump)
    4. Large outbound data transfer (>10MB) shortly after lsass access

    Sysmon Event 10: fires on lsass open (if Win32 API used — not direct syscall).
    Sysmon Event 3: fires on network connection.
    CS: ETW-TI OPENPROC + READVM fires; ObRegisterCallbacks strips VM_READ.
    """

    SHORT_WINDOW_S = 30.0
    MIN_EXFIL_BYTES = 10 * 1024 * 1024  # 10MB

    def __init__(self):
        self._lsass_accessors: dict[int, float] = {}  # pid → timestamp
        self._network_events: dict[int, list[dict]] = defaultdict(list)
        self._dump_files: set[int] = set()  # pids that wrote .dmp files
        self._lock = threading.Lock()

    def record_lsass_access(self, pid: int, access_mask: int,
                             timestamp: float | None = None) -> None:
        ts = timestamp or time.time()
        with self._lock:
            self._lsass_accessors[pid] = ts

    def record_network_connection(self, pid: int, dst_ip: str, dst_port: int,
                                   bytes_sent: int = 0,
                                   timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        with self._lock:
            lsass_ts = self._lsass_accessors.get(pid)
            if lsass_ts is None:
                return None
            delta = ts - lsass_ts
            if delta > self.SHORT_WINDOW_S:
                return None
            has_dump_file = pid in self._dump_files
            self._network_events[pid].append({
                "dst": f"{dst_ip}:{dst_port}", "bytes": bytes_sent, "ts": ts
            })

        if not has_dump_file:
            confidence = 0.82 if bytes_sent >= self.MIN_EXFIL_BYTES else 0.61
            return KernelGapAlert(
                gap_id="GAP-KH-08",
                technique_id="T1003.001",
                technique_name="lsass Network-Exfil Dump (Nanodump --write-to-network)",
                confidence=confidence,
                sysmon_event="Event 10 (lsass access) + Event 3 (network connection) — ONLY if Win32 API used",
                cs_event="ETW-TI OPENPROC + READVM fires; ObRegisterCallbacks strips PROCESS_VM_READ",
                artifact=f"PID {pid}: lsass access → network connection to {dst_ip}:{dst_port} within {delta:.1f}s, no .dmp file — network exfil dump",
                details={"pid": pid, "dst": f"{dst_ip}:{dst_port}", "bytes_sent": bytes_sent, "delta_s": delta},
            )
        return None

    def record_dump_file(self, pid: int) -> None:
        with self._lock:
            self._dump_files.add(pid)


# ── GAP-KH-09: BYOVD Driver Staging Detector ──────────────────────────────────

class BYOVDStagingDetector:
    """
    Detects BYOVD driver staging: *.sys file written to temp/unusual path.

    Observable:
    1. Sysmon Event 11 (FileCreate): *.sys file created in Temp/Downloads/AppData
    2. Service creation pointing to the staged driver (Sysmon Event 13)
    3. Known-vulnerable driver filename patterns

    Sysmon Event 11: fires on file creation.
    Sysmon Event 13: fires on registry service key creation.
    CS: PsSetLoadImageNotifyRoutine fires when driver loads; BYOVD hash blocklist.
    """

    SUSPICIOUS_PATHS = [
        "/temp/", "/tmp/", "/downloads/",
        "/appdata/local/temp/", "/users/public/",
        "\\temp\\", "\\tmp\\", "\\downloads\\",
    ]
    KNOWN_BYOVD = {
        "rtcore64.sys", "gdrv.sys", "asrdrv101.sys", "mhyprot2.sys",
        "iqvw64e.sys", "truesight.sys", "dbutil_2_3.sys", "procexp.sys",
        "kprocesshacker.sys", "winring0x64.sys",
    }

    def __init__(self):
        self._staged_drivers: dict[str, dict] = {}  # path → info
        self._lock = threading.Lock()

    def record_file_create(self, pid: int, path: str,
                            timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        if not path.lower().endswith(".sys"):
            return None

        path_lower = path.lower().replace("\\", "/")
        filename = path.split("\\")[-1].lower()

        is_suspicious_path = any(p in path_lower for p in self.SUSPICIOUS_PATHS)
        is_known_byovd = filename in self.KNOWN_BYOVD

        if not (is_suspicious_path or is_known_byovd):
            return None

        with self._lock:
            self._staged_drivers[path] = {"pid": pid, "ts": ts, "filename": filename}

        confidence = 0.95 if is_known_byovd else 0.72
        return KernelGapAlert(
            gap_id="GAP-KH-09",
            technique_id="T1543.003",
            technique_name="BYOVD Driver Staging" + (" (Known Vulnerable)" if is_known_byovd else ""),
            confidence=confidence,
            sysmon_event="Event 11 (FileCreate: *.sys in suspicious path)",
            cs_event="PsSetLoadImageNotifyRoutine fires on driver load; BYOVD hash blocklist match",
            artifact=f"PID {pid}: driver staged at {path}" + (" — KNOWN BYOVD DRIVER" if is_known_byovd else ""),
            details={"pid": pid, "path": path, "filename": filename,
                     "known_byovd": is_known_byovd, "suspicious_path": is_suspicious_path},
        )



# ── GAP-KH-10b: WoW64 Process Creation Detector ───────────────────────────────

class WoW64ProcessCreationDetector:
    """
    Detects 32-bit (WoW64) process creation as a Heaven's Gate precursor.

    A 32-bit process on a 64-bit system is not inherently suspicious, but
    combined with:
    - Suspicious image name (not in known-legitimate list)
    - Suspicious parent (cmd.exe, powershell.exe, wscript.exe)
    - Suspicious path (Temp, Downloads, AppData)

    it becomes a meaningful signal.

    Sysmon Event 1: fires for process creation (32-bit flag visible).
    CS: PsSetCreateProcessNotifyRoutineEx fires synchronously with WoW64 flag.
    """

    SUSPICIOUS_PARENTS = {
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "wmic.exe",
        "excel.exe", "word.exe", "outlook.exe",
    }
    SUSPICIOUS_PATHS = ["/temp/", "/tmp/", "/downloads/", "/appdata/local/temp/",
                         "/users/public/", "/programdata/"]
    # Hardened: removed setup.exe/install.exe (too broad — easily abused)
    # Only truly OS-level 32-bit processes are always trusted
    KNOWN_LEGIT_32BIT = {
        "wow64.exe", "ntvdm.exe", "msiexec.exe",
    }

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize path: strip UNC prefix, lowercase, forward slashes."""
        p = path.lower()
        # Strip extended-length path prefix \\?\ or \\?\UNC\
        if p.startswith("\\\\?\\"):
            p = p[4:]
        if p.startswith("//?/"):
            p = p[4:]
        return p.replace("\\", "/").replace("\\", "/")

    def __init__(self):
        self._wow64_procs: list[dict] = []
        self._lock = threading.Lock()

    def record_wow64_process(self, pid: int, image: str, parent_name: str = "",
                              image_path: str = "",
                              timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        image_lower = image.lower()
        parent_lower = parent_name.lower()
        path_lower = self._normalize_path(image_path)

        if image_lower in self.KNOWN_LEGIT_32BIT:
            return None

        suspicious_parent = parent_lower in self.SUSPICIOUS_PARENTS
        suspicious_path   = any(p in path_lower for p in self.SUSPICIOUS_PATHS)

        if not (suspicious_parent or suspicious_path):
            # Still record for subsequent Heaven's Gate detection
            with self._lock:
                self._wow64_procs.append({"pid": pid, "image": image, "ts": ts})
            return None

        confidence = 0.72 if suspicious_parent else 0.65
        if suspicious_parent and suspicious_path:
            confidence = 0.84

        with self._lock:
            self._wow64_procs.append({"pid": pid, "image": image, "ts": ts})

        return KernelGapAlert(
            gap_id="GAP-KH-04",
            technique_id="T1055.001",
            technique_name="Heaven's Gate Precursor — Suspicious WoW64 Process Creation",
            confidence=confidence,
            sysmon_event="Event 1 (process creation — 32-bit/WoW64 flag visible)",
            cs_event="PsSetCreateProcessNotifyRoutineEx fires synchronously; WoW64 flag + parent anomaly noted",
            artifact=f"32-bit process {image} (PID {pid}) created by {parent_name or 'unknown'}"
                     + (f" from suspicious path {image_path}" if suspicious_path else "")
                     + " — Heaven's Gate precursor",
            details={"pid": pid, "image": image, "parent": parent_name,
                     "path": image_path, "suspicious_parent": suspicious_parent,
                     "suspicious_path": suspicious_path},
        )

# ── GAP-KH-10: lsass Handle Probe Detector ────────────────────────────────────

class LsassHandleProbeDetector:
    """
    Detects the ObRegisterCallbacks enumeration probe:
    attacker opens lsass with PROCESS_QUERY_INFORMATION (0x0400) only,
    then checks GrantedAccess to determine if ObRegisterCallbacks is stripping rights.

    Observable: Sysmon Event 10 fires on lsass open — but access mask 0x0400
    is low-suspicion (many legitimate tools use it). NEXUS must track frequency.

    CS: ObRegisterCallbacks fires synchronously on every lsass handle open.
    """

    PROBE_MASK      = 0x0400  # PROCESS_QUERY_INFORMATION
    PROBE_WINDOW_S  = 300.0   # Extended from 60s — catches slow probers
    PROBE_THRESHOLD = 2       # Lowered from 3 — catches 2-sample timing probes

    def __init__(self):
        # Hardened: track per-destination (lsass) not per-source PID
        # Key: (source_pid, lsass_pid) → timestamps
        # Simplified: track all probes globally per lsass target
        self._probes_by_dest: dict[str, list[dict]] = defaultdict(list)  # "lsass" → events
        self._probes: dict[int, list[float]] = defaultdict(list)  # pid → timestamps (legacy)
        self._lock = threading.Lock()

    def record_lsass_open(self, pid: int, access_mask: int,
                           timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        if access_mask != self.PROBE_MASK:
            return None  # Only track pure QUERY_INFORMATION probes

        with self._lock:
            # Track per-source PID (legacy — for backward compat)
            probes = self._probes[pid]
            probes.append(ts)
            self._probes[pid] = [t for t in probes if t > ts - self.PROBE_WINDOW_S]
            per_pid_count = len(self._probes[pid])

            # Hardened: also track cross-PID probes to same destination
            dest_probes = self._probes_by_dest["lsass"]
            dest_probes.append({"pid": pid, "ts": ts})
            self._probes_by_dest["lsass"] = [
                e for e in dest_probes if e["ts"] > ts - self.PROBE_WINDOW_S
            ]
            unique_pids = len({e["pid"] for e in self._probes_by_dest["lsass"]})
            total_dest_count = len(self._probes_by_dest["lsass"])

        # Fire on per-PID threshold OR cross-PID threshold (PID rotation detection)
        if per_pid_count >= self.PROBE_THRESHOLD:
            return KernelGapAlert(
                gap_id="GAP-KH-10",
                technique_id="T1003.001",
                technique_name="lsass Handle Probe — ObRegisterCallbacks Enumeration (per-PID)",
                confidence=0.72,
                sysmon_event="Event 10 (ProcessAccess: lsass, mask=0x0400) — low suspicion individually",
                cs_event="ObRegisterCallbacks fires synchronously on every lsass open regardless of access mask",
                artifact=f"PID {pid}: {per_pid_count} lsass opens with PROCESS_QUERY_INFORMATION in {self.PROBE_WINDOW_S}s — EDR enumeration probe",
                details={"pid": pid, "probe_count": per_pid_count, "access_mask": hex(access_mask)},
            )
        if unique_pids >= 3 and total_dest_count >= self.PROBE_THRESHOLD:
            return KernelGapAlert(
                gap_id="GAP-KH-10",
                technique_id="T1003.001",
                technique_name="lsass Handle Probe — PID Rotation Enumeration",
                confidence=0.68,
                sysmon_event="Event 10 (ProcessAccess: lsass, mask=0x0400) from multiple PIDs",
                cs_event="ObRegisterCallbacks fires on each; CS correlates cross-process pattern",
                artifact=f"{unique_pids} distinct PIDs probing lsass with PROCESS_QUERY_INFORMATION in {self.PROBE_WINDOW_S}s — PID rotation EDR probe",
                details={"unique_pids": unique_pids, "total_probes": total_dest_count},
            )
        return None


# ── GAP-KH-11: ETW Session Enumeration Detector ────────────────────────────────

class ETWEnumerationDetector:
    """
    Detects QueryAllTraces() / EnumerateTraceGuids() calls used to enumerate
    ETW sessions and check for ETW-TI subscription (EDR presence check).

    Observable: These are standard Win32 API calls — Sysmon does not log them.
    Proxy signal: process calls advapi32!QueryAllTraces or
    ntdll!NtQuerySystemInformation with SystemTraceInformation class.

    CS: Behavioral anomaly — security tool recon pattern.
    """

    ENUM_WINDOW_S = 30.0

    def __init__(self):
        self._enum_events: dict[int, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_etw_enumeration(self, pid: int, api_name: str,
                                timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        etw_apis = {"QueryAllTraces", "EnumerateTraceGuids",
                    "NtQuerySystemInformation_TraceInfo", "ControlTrace"}
        if api_name not in etw_apis:
            return None

        with self._lock:
            events = self._enum_events[pid]
            events.append(ts)
            self._enum_events[pid] = [t for t in events if t > ts - self.ENUM_WINDOW_S]
            count = len(self._enum_events[pid])

        if count >= 2:
            return KernelGapAlert(
                gap_id="GAP-KH-11",
                technique_id="T1518.001",
                technique_name="ETW Session Enumeration — EDR Presence Check",
                confidence=0.73,
                sysmon_event=None,
                cs_event="Behavioral anomaly: security tool recon pattern flagged by CS cloud graph",
                artifact=f"PID {pid}: {count} ETW enumeration calls ({api_name}) in {self.ENUM_WINDOW_S}s — checking for ETW-TI subscription",
                details={"pid": pid, "api": api_name, "count": count},
            )
        return None


# ── GAP-KH-12: Timing Side-Channel Detector ────────────────────────────────────

class TimingSideChannelDetector:
    """
    Detects the ObRegisterCallbacks timing side-channel:
    attacker measures NtOpenProcess latency on lsass vs non-sensitive process.
    Delta < 5μs → no ObRegisterCallbacks → no kernel EDR.

    Observable: Repeated lsass opens in rapid succession (timing measurement
    requires multiple samples for statistical significance).

    CS: ObRegisterCallbacks fires on every lsass open; behavioral anomaly
    for repeated rapid opens.
    """

    RAPID_WINDOW_S = 5.0
    RAPID_THRESHOLD = 5  # >5 lsass opens in 5s = timing probe

    def __init__(self):
        self._rapid_opens: dict[int, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_lsass_open(self, pid: int, timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()
        with self._lock:
            opens = self._rapid_opens[pid]
            opens.append(ts)
            self._rapid_opens[pid] = [t for t in opens if t > ts - self.RAPID_WINDOW_S]
            count = len(self._rapid_opens[pid])

        if count >= self.RAPID_THRESHOLD:
            return KernelGapAlert(
                gap_id="GAP-KH-12",
                technique_id="T1518.001",
                technique_name="Timing Side-Channel — ObRegisterCallbacks Latency Probe",
                confidence=0.71,
                sysmon_event="Event 10 (ProcessAccess: lsass) — multiple rapid opens",
                cs_event="ObRegisterCallbacks fires on each open; behavioral anomaly for rapid repeated opens",
                artifact=f"PID {pid}: {count} lsass opens in {self.RAPID_WINDOW_S}s — timing side-channel to detect ObRegisterCallbacks",
                details={"pid": pid, "open_count": count, "window_s": self.RAPID_WINDOW_S},
            )
        return None



# ── GAP-KH-15: Full-Access lsass Open Detector ────────────────────────────────

class FullAccessLsassDetector:
    """
    Detects any lsass open with PROCESS_VM_READ or PROCESS_ALL_ACCESS.

    This is the most critical single-event detector:
    ANY process opening lsass with VM_READ (0x0010) or ALL_ACCESS (0x1FFFFF)
    is HIGH confidence credential access — regardless of call frequency.

    Sysmon Event 10: fires ONLY if Win32 API used (not direct syscall).
    CS: ETW-TI OPENPROC fires regardless of call path; ObRegisterCallbacks
        strips PROCESS_VM_READ before handle is granted.

    NEXUS compensating control: detect the access attempt from any observable
    signal (Sysmon Event 10 if Win32 API, or correlated with stub allocation).
    """

    VM_READ_MASK         = 0x0010   # PROCESS_VM_READ
    VM_OPERATION_MASK    = 0x0008   # PROCESS_VM_OPERATION (can map memory into lsass)
    ALL_ACCESS_MASK      = 0x1FFFFF # PROCESS_ALL_ACCESS
    QUERY_LIMITED_MASK   = 0x1000   # PROCESS_QUERY_LIMITED_INFORMATION (also risky)
    QUERY_INFO_MASK      = 0x0400   # PROCESS_QUERY_INFORMATION (probe only)
    DEDUP_WINDOW_S       = 10.0     # Reduced from 60s — closes dedup exploitation

    # Hardened: name-based list replaced with hash verification stub.
    # In production: compare PE hash against signed-binary allowlist.
    # Here: only allow processes with verified system paths.
    TRUSTED_PROCESS_PATHS = {
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\",
    }
    # Names that MUST also have a trusted path to be whitelisted
    TRUSTED_NAMES_REQUIRE_PATH = {
        "taskmgr.exe", "procexp.exe", "procexp64.exe",
        "procdump.exe", "procdump64.exe", "mssense.exe",
    }
    # Names always trusted regardless of path (OS components)
    ALWAYS_TRUSTED = {"csrss.exe", "winlogon.exe", "services.exe"}

    def __init__(self):
        self._seen: dict[int, float] = {}  # pid → first alert ts (dedup)
        self._lock = threading.Lock()

    def _is_trusted(self, process_name: str, process_path: str = "") -> bool:
        """Hardened trust check: name + path verification."""
        name  = process_name.lower()
        ppath = process_path.lower()
        if name in self.ALWAYS_TRUSTED:
            return True
        if name in self.TRUSTED_NAMES_REQUIRE_PATH:
            # Must be in a trusted system path
            return any(ppath.startswith(p) for p in self.TRUSTED_PROCESS_PATHS)
        return False

    def record_lsass_open(self, pid: int, access_mask: int,
                           process_name: str = "",
                           process_path: str = "",
                           timestamp: float | None = None) -> Optional[KernelGapAlert]:
        ts = timestamp or time.time()

        # Flag VM_READ, VM_OPERATION, ALL_ACCESS, and QUERY_LIMITED
        has_vm_read       = bool(access_mask & self.VM_READ_MASK)
        has_vm_operation  = bool(access_mask & self.VM_OPERATION_MASK)
        has_all_access    = access_mask == self.ALL_ACCESS_MASK
        has_query_limited = bool(access_mask & self.QUERY_LIMITED_MASK)

        if not (has_vm_read or has_vm_operation or has_all_access or has_query_limited):
            return None

        # Hardened trust check: name + path
        if self._is_trusted(process_name, process_path):
            return None

        # Deduplicate: reduced to 10s window (was 60s)
        with self._lock:
            last = self._seen.get(pid, 0)
            if ts - last < self.DEDUP_WINDOW_S:
                return None
            self._seen[pid] = ts

        if has_all_access:
            confidence, mask_name = 0.88, "PROCESS_ALL_ACCESS"
        elif has_vm_read:
            confidence, mask_name = 0.82, "PROCESS_VM_READ"
        elif has_vm_operation:
            confidence, mask_name = 0.78, "PROCESS_VM_OPERATION"
        else:
            confidence, mask_name = 0.72, "PROCESS_QUERY_LIMITED"

        return KernelGapAlert(
            gap_id="GAP-KH-15",
            technique_id="T1003.001",
            technique_name=f"lsass Full-Access Open ({mask_name})",
            confidence=confidence,
            sysmon_event="Event 10 (ProcessAccess: lsass) — ONLY if Win32 API used; direct syscall bypasses this",
            cs_event="ETW-TI OPENPROC fires regardless of call path; ObRegisterCallbacks strips VM_READ from handle",
            artifact=f"PID {pid}{' (' + process_name + ')' if process_name else ''}: "
                     f"lsass opened with {mask_name} (0x{access_mask:X}) — credential access attempt",
            blocked=False,
            details={"pid": pid, "access_mask": hex(access_mask),
                     "mask_name": mask_name, "process_name": process_name},
        )

# ── Unified KernelGapHardeningEngine ──────────────────────────────────────────

class KernelGapHardeningEngine:
    """
    Unified engine that wires all 12 kernel-gap detectors together.
    Provides a single interface for the attack simulation and test suite.
    """

    def __init__(self):
        self.direct_syscall    = DirectSyscallStubDetector()
        self.tartarus_gate     = TartarusGateDetector()
        self.recycled_gate     = RecycledGateDetector()
        self.heavens_gate      = HeavensGateDetector()
        self.reflective_dll    = ReflectiveDLLDetector()
        self.stub_allocation   = StubAllocationDetector()
        self.lsass_fork        = LsassForkDumpDetector()
        self.network_exfil     = NetworkExfilDumpDetector()
        self.byovd_staging     = BYOVDStagingDetector()
        self.handle_probe      = LsassHandleProbeDetector()
        self.etw_enum          = ETWEnumerationDetector()
        self.timing_probe      = TimingSideChannelDetector()
        self.full_access_lsass = FullAccessLsassDetector()
        self.wow64_creation    = WoW64ProcessCreationDetector()
        self.etw_patching      = ETWPatchingDetector()
        self.token_theft       = TokenTheftDetector()
        self.proc_hollowing    = ProcessHollowingDetector()
        self.apc_injection     = APCInjectionDetector()
        self._alerts: list[KernelGapAlert] = []
        self._lock = threading.Lock()

    def _record(self, alert: Optional[KernelGapAlert]) -> Optional[KernelGapAlert]:
        if alert:
            with self._lock:
                self._alerts.append(alert)
        return alert

    def get_alerts(self) -> list[KernelGapAlert]:
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts.clear()

    # ── Convenience wrappers ──────────────────────────────────────────────────

    def on_ntdll_data_open(self, pid: int, path: str) -> Optional[KernelGapAlert]:
        return self._record(self.direct_syscall.record_ntdll_data_open(pid, path))

    def on_nt_export_probe(self, pid: int, export: str) -> Optional[KernelGapAlert]:
        return self._record(self.direct_syscall.record_nt_export_probe(pid, export))

    def on_stub_in_memory(self, pid: int, base: int, data: bytes,
                           anonymous: bool, rx: bool) -> Optional[KernelGapAlert]:
        return self._record(self.direct_syscall.detect_stub_in_memory(pid, base, data, anonymous, rx))

    def on_suspended_create(self, pid: int, parent: int, image: str) -> None:
        self.tartarus_gate.record_suspended_create(pid, parent, image)

    def on_memory_read(self, reader: int, target: int) -> None:
        self.tartarus_gate.record_memory_read(reader, target)

    def on_process_terminate(self, pid: int) -> Optional[KernelGapAlert]:
        return self._record(self.tartarus_gate.record_termination(pid))

    def on_ntdll_scan(self, pid: int, offset: int, size: int) -> Optional[KernelGapAlert]:
        return self._record(self.recycled_gate.record_ntdll_scan(pid, offset, size))

    def on_wow64_process(self, pid: int, image: str, parent_name: str = "",
                         image_path: str = "") -> Optional[KernelGapAlert]:
        self.heavens_gate.record_wow64_process(pid, image)
        alert = self.wow64_creation.record_wow64_process(
            pid, image, parent_name, image_path)
        return self._record(alert)

    def on_high_address_rx(self, pid: int, base: int, size: int) -> Optional[KernelGapAlert]:
        return self._record(self.heavens_gate.record_high_address_rx_region(pid, base, size))

    def on_retf_pattern(self, pid: int, code: bytes = b"",
                        code_bytes: bytes = b"") -> Optional[KernelGapAlert]:
        return self._record(self.heavens_gate.record_retf_pattern(pid, code_bytes or code))

    def on_anonymous_rx(self, pid: int, base: int, size: int,
                         sample: bytes | None = None) -> Optional[KernelGapAlert]:
        return self._record(self.reflective_dll.record_anonymous_rx_region(pid, base, size, sample))

    def on_thread_in_anon(self, pid: int, start: int) -> Optional[KernelGapAlert]:
        return self._record(self.reflective_dll.record_thread_in_anonymous_memory(pid, start))

    def on_allocation(self, pid: int, base: int, size: int, prot: str,
                      timestamp: float | None = None) -> Optional[KernelGapAlert]:
        return self._record(self.stub_allocation.record_allocation(pid, base, size, prot, timestamp))

    def on_protect_change(self, pid: int, base: int, size: int,
                           old: str, new: str,
                           timestamp: float | None = None) -> Optional[KernelGapAlert]:
        return self._record(self.stub_allocation.record_protect_change(pid, base, size, old, new, timestamp))

    def on_process_create(self, pid: int, parent_pid: int,
                           parent_name: str, image: str = "",
                           child_image: str = "") -> Optional[KernelGapAlert]:
        effective_image = child_image or image
        return self._record(self.lsass_fork.record_process_create(pid, parent_pid, parent_name, effective_image))

    def on_lsass_access(self, pid: int, mask: int,
                        timestamp: float | None = None) -> Optional[KernelGapAlert]:
        self.network_exfil.record_lsass_access(pid, mask, timestamp)
        # Full-access lsass open (VM_READ or ALL_ACCESS) — single-event HIGH alert
        full_access_alert = self.full_access_lsass.record_lsass_open(pid, mask, timestamp=timestamp)
        probe_alert   = self.handle_probe.record_lsass_open(pid, mask, timestamp)
        timing_alert  = self.timing_probe.record_lsass_open(pid, timestamp)
        # Return first non-None alert (priority: full_access > probe > timing)
        for a in (full_access_alert, probe_alert, timing_alert):
            if a is not None:
                return self._record(a)
        return None

    def on_network_connect(self, pid: int, dst_ip: str, dst_port: int,
                            bytes_sent: int = 0) -> Optional[KernelGapAlert]:
        return self._record(self.network_exfil.record_network_connection(pid, dst_ip, dst_port, bytes_sent))

    def on_file_create(self, pid: int, path: str) -> Optional[KernelGapAlert]:
        if path.lower().endswith(".dmp"):
            self.network_exfil.record_dump_file(pid)
        return self._record(self.byovd_staging.record_file_create(pid, path))

    def on_etw_enum(self, pid: int, api: str) -> Optional[KernelGapAlert]:
        return self._record(self.etw_enum.record_etw_enumeration(pid, api))


# ── GAP-KH-16: ETW Patching Detector (T1562.001) ──────────────────────────────

class ETWPatchingDetector:
    """
    Detects EtwEventWrite NOP patching — T1562.001 Impair Defenses.

    Attackers patch ntdll!EtwEventWrite with NOP (0x90) or RET (0xC3) bytes
    to disable ETW telemetry collection. This silences ScriptBlock logging,
    WMI activity logging, and other ETW-based detection.

    Observable artifacts:
    1. VirtualProtect on ntdll.dll text section (RX → RW → RX)
    2. WriteProcessMemory targeting ntdll.dll address range
    3. Memory scan: EtwEventWrite first bytes changed from expected pattern
    4. Process with ETW provider disabled mid-session (provider count drops)

    Sysmon: No event for memory writes to ntdll.dll.
    CS: ETW-TI PROTECTVM fires on VirtualProtect; WRITEVM fires on patch write.
    """

    # Expected first bytes of EtwEventWrite (Windows 10/11)
    ETW_WRITE_EXPECTED = bytes([0x48, 0x8B, 0xC4])  # mov rax, rsp
    ETW_WRITE_NOPED    = bytes([0x90, 0x90, 0x90])  # NOP NOP NOP
    ETW_WRITE_RETTED   = bytes([0xC3, 0x90, 0x90])  # RET NOP NOP
    ETW_WRITE_XORED    = bytes([0x33, 0xC0, 0xC3])  # xor eax,eax; ret

    def __init__(self):
        self._ntdll_protect_events: dict[int, list[dict]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_ntdll_protect_change(self, pid: int, base: int, size: int,
                                     old_prot: str, new_prot: str,
                                     is_ntdll_range: bool,
                                     timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Detect VirtualProtect on ntdll.dll text section."""
        ts = timestamp or time.time()
        if not is_ntdll_range:
            return None
        if new_prot not in ("RW", "RWX"):
            return None

        with self._lock:
            events = self._ntdll_protect_events[pid]
            events.append({"base": base, "size": size, "ts": ts,
                           "old": old_prot, "new": new_prot})
            self._ntdll_protect_events[pid] = [
                e for e in events if e["ts"] > ts - 10.0
            ]

        return KernelGapAlert(
            gap_id="GAP-KH-16",
            technique_id="T1562.001",
            technique_name="ETW Patching — ntdll.dll Text Section Made Writable",
            confidence=0.81,
            sysmon_event=None,
            cs_event="ETW-TI PROTECTVM fires on VirtualProtect; CS detects ntdll text section modification",
            artifact=f"PID {pid}: ntdll.dll region @ 0x{base:X} changed {old_prot}→{new_prot} — ETW patch preparation",
            details={"pid": pid, "base": hex(base), "size": size,
                     "old_prot": old_prot, "new_prot": new_prot},
        )

    def record_etw_write_patch(self, pid: int, patch_bytes: bytes,
                                target_addr: int) -> Optional[KernelGapAlert]:
        """Detect actual EtwEventWrite patch bytes written."""
        is_nop   = patch_bytes[:3] == self.ETW_WRITE_NOPED
        is_ret   = patch_bytes[:3] == self.ETW_WRITE_RETTED
        is_xored = patch_bytes[:3] == self.ETW_WRITE_XORED
        is_patch = is_nop or is_ret or is_xored

        if not is_patch:
            return None

        patch_type = "NOP sled" if is_nop else ("RET stub" if is_ret else "XOR-RET stub")
        return KernelGapAlert(
            gap_id="GAP-KH-16",
            technique_id="T1562.001",
            technique_name=f"ETW Patching — EtwEventWrite {patch_type} Detected",
            confidence=0.95,
            sysmon_event=None,
            cs_event="ETW-TI WRITEVM fires on WriteProcessMemory; CS detects EtwEventWrite modification",
            artifact=f"PID {pid}: EtwEventWrite patched with {patch_type} at 0x{target_addr:X} — ETW telemetry disabled",
            details={"pid": pid, "patch_bytes": patch_bytes[:8].hex(),
                     "target": hex(target_addr), "patch_type": patch_type},
        )

    def record_etw_provider_drop(self, pid: int, provider_count_before: int,
                                  provider_count_after: int) -> Optional[KernelGapAlert]:
        """Detect ETW provider count drop mid-session."""
        if provider_count_after >= provider_count_before:
            return None
        dropped = provider_count_before - provider_count_after
        if dropped < 1:
            return None
        return KernelGapAlert(
            gap_id="GAP-KH-16",
            technique_id="T1562.001",
            technique_name="ETW Patching — Provider Count Drop Mid-Session",
            confidence=0.74,
            sysmon_event=None,
            cs_event="CS monitors ETW provider registration state; drop triggers behavioral alert",
            artifact=f"PID {pid}: ETW provider count dropped {provider_count_before}→{provider_count_after} ({dropped} providers disabled)",
            details={"pid": pid, "before": provider_count_before,
                     "after": provider_count_after, "dropped": dropped},
        )


# ── GAP-KH-17: Token Theft Detector (T1134.001) ───────────────────────────────

class TokenTheftDetector:
    """
    Detects token impersonation/theft — T1134.001.

    Attack chain:
    1. NtOpenProcessToken(target_process, TOKEN_DUPLICATE) → get token handle
    2. NtDuplicateToken(token, SecurityImpersonation) → duplicate token
    3. NtSetInformationThread(thread, ThreadImpersonationToken, dup_token) → impersonate
    OR
    3. CreateProcessWithTokenW(dup_token, ...) → spawn process as target user

    Observable:
    - Process opens token of high-privilege process (SYSTEM, admin)
    - Token duplication within short window
    - Thread impersonation token set

    Sysmon: No event for NtOpenProcessToken or NtDuplicateToken.
    CS: ETW-TI fires on token handle operations; ObRegisterCallbacks (Token object).
    """

    # Hardened: expanded to include domain admin and high-value user processes
    HIGH_PRIV_PROCESSES = {
        # OS system processes
        "lsass.exe", "winlogon.exe", "services.exe", "csrss.exe",
        "wininit.exe", "smss.exe", "system",
        # High-value user processes (domain admin sessions)
        "explorer.exe",   # Domain admin desktop session
        "mmc.exe",        # Management console (admin tools)
        "taskmgr.exe",    # Task manager (admin context)
        "powershell.exe", # Admin PowerShell sessions
        "cmd.exe",        # Admin command prompt
    }
    TOKEN_DUPLICATE_MASK  = 0x0002  # TOKEN_DUPLICATE
    TOKEN_IMPERSONATE     = 0x0004  # TOKEN_IMPERSONATE
    TOKEN_QUERY_MASK      = 0x0008  # TOKEN_QUERY (can precede duplication)
    TOKEN_ALL_ACCESS      = 0x000F  # TOKEN_ALL_ACCESS (subset)

    # Impersonation levels that indicate real privilege escalation
    HIGH_IMPERSONATION_LEVELS = {"SecurityImpersonation", "SecurityDelegation"}
    # SecurityIdentification is now also tracked when combined with high-priv open
    MEDIUM_IMPERSONATION_LEVELS = {"SecurityIdentification"}

    def __init__(self):
        self._token_opens: dict[int, list[dict]] = defaultdict(list)  # pid → token events
        self._query_opens: dict[int, list[dict]] = defaultdict(list)  # pid → query-only opens
        self._lock = threading.Lock()

    def record_token_open(self, pid: int, target_process: str,
                           access_mask: int,
                           timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Detect NtOpenProcessToken — hardened to catch query-only + subsequent dup."""
        ts = timestamp or time.time()
        target_lower = target_process.lower()

        has_dup   = bool(access_mask & self.TOKEN_DUPLICATE_MASK)
        has_imp   = bool(access_mask & self.TOKEN_IMPERSONATE)
        has_query = bool(access_mask & self.TOKEN_QUERY_MASK)
        is_high_priv = target_lower in self.HIGH_PRIV_PROCESSES

        # Track query-only opens for correlation with subsequent duplication
        if has_query and not (has_dup or has_imp) and is_high_priv:
            with self._lock:
                self._query_opens[pid].append({
                    "target": target_process, "mask": access_mask, "ts": ts
                })
            # Don't alert yet — wait for duplication
            return None

        if not (has_dup or has_imp):
            return None
        if not is_high_priv:
            return None

        with self._lock:
            self._token_opens[pid].append({
                "target": target_process, "mask": access_mask, "ts": ts
            })

        confidence = 0.87 if (has_dup and has_imp) else 0.76
        return KernelGapAlert(
            gap_id="GAP-KH-17",
            technique_id="T1134.001",
            technique_name="Token Theft — High-Privilege Process Token Open",
            confidence=confidence,
            sysmon_event=None,
            cs_event="ETW-TI fires on NtOpenProcessToken; ObRegisterCallbacks (Token object) strips TOKEN_DUPLICATE",
            artifact=f"PID {pid}: opened token of {target_process} with mask 0x{access_mask:X} (TOKEN_DUPLICATE/IMPERSONATE) — token theft",
            details={"pid": pid, "target": target_process,
                     "access_mask": hex(access_mask), "has_dup": has_dup},
        )

    def record_token_duplicate(self, pid: int, impersonation_level: str,
                                timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Detect NtDuplicateToken — hardened to catch SecurityIdentification + query chain."""
        ts = timestamp or time.time()

        with self._lock:
            recent_opens  = [e for e in self._token_opens.get(pid, [])
                             if ts - e["ts"] < 10.0]
            recent_queries = [e for e in self._query_opens.get(pid, [])
                              if ts - e["ts"] < 10.0]

        is_high_level   = impersonation_level in self.HIGH_IMPERSONATION_LEVELS
        is_medium_level = impersonation_level in self.MEDIUM_IMPERSONATION_LEVELS

        if not (is_high_level or is_medium_level):
            return None

        if recent_opens:
            target = recent_opens[-1]["target"]
            confidence = 0.92 if is_high_level else 0.74
            return KernelGapAlert(
                gap_id="GAP-KH-17",
                technique_id="T1134.001",
                technique_name=f"Token Theft — NtDuplicateToken ({impersonation_level}) after High-Priv Open",
                confidence=confidence,
                sysmon_event=None,
                cs_event="ETW-TI fires on NtDuplicateToken; CS correlates with prior token open",
                artifact=f"PID {pid}: duplicated {target} token with {impersonation_level} — token theft chain complete",
                details={"pid": pid, "level": impersonation_level, "source": target,
                         "chain": "open+dup"},
            )

        if recent_queries and is_high_level:
            # Query-only open followed by high-level duplication — token theft via query path
            target = recent_queries[-1]["target"]
            return KernelGapAlert(
                gap_id="GAP-KH-17",
                technique_id="T1134.001",
                technique_name=f"Token Theft — Query+Duplicate Chain ({impersonation_level})",
                confidence=0.81,
                sysmon_event=None,
                cs_event="ETW-TI fires on both NtOpenProcessToken and NtDuplicateToken",
                artifact=f"PID {pid}: TOKEN_QUERY open of {target} followed by {impersonation_level} duplication — token theft via query path",
                details={"pid": pid, "level": impersonation_level, "source": target,
                         "chain": "query+dup"},
            )

        if is_high_level:
            return KernelGapAlert(
                gap_id="GAP-KH-17",
                technique_id="T1134.001",
                technique_name=f"Token Theft — Standalone NtDuplicateToken ({impersonation_level})",
                confidence=0.68,
                sysmon_event=None,
                cs_event="ETW-TI fires on NtDuplicateToken",
                artifact=f"PID {pid}: NtDuplicateToken with {impersonation_level} — possible token theft",
                details={"pid": pid, "level": impersonation_level},
            )
        return None

    def record_create_token(self, pid: int, token_type: str = "Primary",
                             timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Detect NtCreateToken — synthetic token creation (T1134.001 advanced variant)."""
        ts = timestamp or time.time()
        # NtCreateToken requires SeCreateTokenPrivilege — extremely rare in legitimate use
        return KernelGapAlert(
            gap_id="GAP-KH-17",
            technique_id="T1134.001",
            technique_name=f"Token Theft — NtCreateToken Synthetic Token ({token_type})",
            confidence=0.91,
            sysmon_event=None,
            cs_event="ETW-TI fires on NtCreateToken; requires SeCreateTokenPrivilege — CS flags privilege use",
            artifact=f"PID {pid}: NtCreateToken called (type={token_type}) — synthetic token creation requires SeCreateTokenPrivilege",
            details={"pid": pid, "token_type": token_type},
        )


# ── GAP-KH-18: Process Hollowing Detector (T1055.012) ─────────────────────────

class ProcessHollowingDetector:
    """
    Detects process hollowing — T1055.012.

    Attack chain:
    1. CreateProcess(target, CREATE_SUSPENDED) → create hollow container
    2. NtUnmapViewOfSection(target, base_addr) → unmap original PE
    3. VirtualAllocEx(target, base_addr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    4. WriteProcessMemory(target, base_addr, malicious_pe) → write payload
    5. SetThreadContext(thread, new_entry_point) → redirect execution
    6. ResumeThread(thread) → execute payload

    Observable:
    - Suspended process created
    - NtUnmapViewOfSection on the suspended process (unmapping its own PE)
    - Large WriteProcessMemory to the unmapped region
    - SetThreadContext on the suspended thread

    Sysmon: Event 1 (CREATE_SUSPENDED), Event 8 (SetThreadContext if Win32 API).
    CS: ETW-TI WRITEVM + PROTECTVM + SETTHREAD fires; PsSetLoadImageNotify detects remap.
    """

    def __init__(self):
        self._hollow_candidates: dict[int, dict] = {}  # target_pid → state
        self._lock = threading.Lock()

    def record_suspended_create(self, target_pid: int, creator_pid: int,
                                 image: str,
                                 timestamp: float | None = None) -> None:
        ts = timestamp or time.time()
        with self._lock:
            self._hollow_candidates[target_pid] = {
                "creator": creator_pid, "image": image, "ts": ts,
                "unmapped": False, "written": False, "context_set": False,
            }

    def record_unmap_section(self, target_pid: int,
                              timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """NtUnmapViewOfSection on suspended process — hollowing step 2."""
        ts = timestamp or time.time()
        with self._lock:
            entry = self._hollow_candidates.get(target_pid)
            if not entry:
                return None
            entry["unmapped"] = True

        return KernelGapAlert(
            gap_id="GAP-KH-18",
            technique_id="T1055.012",
            technique_name="Process Hollowing — NtUnmapViewOfSection on Suspended Process",
            confidence=0.82,
            sysmon_event="Event 1 (CREATE_SUSPENDED) precedes this — partial chain visible",
            cs_event="ETW-TI MAPVIEW fires on unmap; PsSetLoadImageNotify detects PE removal",
            artifact=f"PID {target_pid} ({entry['image']}): NtUnmapViewOfSection called — process hollowing step 2",
            details={"target_pid": target_pid, "image": entry["image"],
                     "creator": entry["creator"]},
        )

    def record_cross_process_write(self, writer_pid: int, target_pid: int,
                                    write_size: int,
                                    timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Large WriteProcessMemory to hollowed process — step 4."""
        ts = timestamp or time.time()
        with self._lock:
            entry = self._hollow_candidates.get(target_pid)
            if not entry or not entry.get("unmapped"):
                return None
            if write_size < 4096:
                return None
            entry["written"] = True

        return KernelGapAlert(
            gap_id="GAP-KH-18",
            technique_id="T1055.012",
            technique_name="Process Hollowing — Large WriteProcessMemory to Hollowed Process",
            confidence=0.91,
            sysmon_event=None,
            cs_event="ETW-TI WRITEVM fires; CS correlates with prior NtUnmapViewOfSection",
            artifact=f"PID {writer_pid}: wrote {write_size//1024}KB to hollowed PID {target_pid} ({entry['image']}) — process hollowing step 4",
            details={"writer": writer_pid, "target": target_pid,
                     "size": write_size, "image": entry["image"]},
        )

    def record_set_thread_context(self, target_pid: int,
                                   timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """NtSetContextThread on hollowed process — step 5."""
        ts = timestamp or time.time()
        with self._lock:
            entry = self._hollow_candidates.get(target_pid)
            if not entry:
                return None
            entry["context_set"] = True
            all_steps = entry["unmapped"] and entry["written"]

        confidence = 0.97 if all_steps else 0.71
        return KernelGapAlert(
            gap_id="GAP-KH-18",
            technique_id="T1055.012",
            technique_name="Process Hollowing — NtSetContextThread (Entry Point Redirect)",
            confidence=confidence,
            sysmon_event="Event 8 (SetThreadContext) — ONLY if Win32 API used, not direct syscall",
            cs_event="ETW-TI SETTHREAD fires; CS correlates full hollowing chain",
            artifact=f"PID {target_pid} ({entry['image']}): thread context set — process hollowing complete (confidence: {confidence:.0%})",
            details={"target_pid": target_pid, "image": entry["image"],
                     "full_chain": all_steps},
        )


# ── GAP-KH-19: APC Injection Detector (T1055.004) ─────────────────────────────

class APCInjectionDetector:
    """
    Detects APC (Asynchronous Procedure Call) injection — T1055.004.

    Attack variants:
    1. Classic APC: NtQueueApcThread(target_thread, shellcode_addr)
    2. Early Bird APC: Queue APC before process initialization completes
    3. Special User APC (Windows 10+): NtQueueApcThreadEx with SpecialUserApc

    Observable:
    1. Memory allocation in target process (shellcode staging)
    2. WriteProcessMemory to target process
    3. NtQueueApcThread call (if Win32 API — Sysmon has no event for this)
    4. Target thread resumes after APC queue

    Sysmon: No event for NtQueueApcThread.
    CS: ETW-TI QUEUEAPC fires; ObRegisterCallbacks (Thread) strips THREAD_SET_CONTEXT.
    """

    def __init__(self):
        self._apc_staging: dict[int, list[dict]] = defaultdict(list)  # target_pid → events
        self._lock = threading.Lock()

    def record_cross_process_alloc(self, writer_pid: int, target_pid: int,
                                    alloc_size: int, protection: str,
                                    timestamp: float | None = None) -> None:
        """Record memory allocation in target process (APC shellcode staging)."""
        ts = timestamp or time.time()
        if protection not in ("RWX", "RX", "RW"):
            return
        with self._lock:
            self._apc_staging[target_pid].append({
                "writer": writer_pid, "size": alloc_size,
                "prot": protection, "ts": ts, "written": False,
            })

    def record_cross_process_write(self, writer_pid: int, target_pid: int,
                                    write_size: int,
                                    timestamp: float | None = None) -> None:
        ts = timestamp or time.time()
        with self._lock:
            for e in self._apc_staging.get(target_pid, []):
                if e["writer"] == writer_pid and ts - e["ts"] < 10.0:
                    e["written"] = True

    def record_apc_queue(self, writer_pid: int, target_pid: int,
                          target_thread_id: int, apc_routine_addr: int,
                          is_special_user_apc: bool = False,
                          timestamp: float | None = None) -> Optional[KernelGapAlert]:
        """Detect NtQueueApcThread call."""
        ts = timestamp or time.time()
        with self._lock:
            staged = [e for e in self._apc_staging.get(target_pid, [])
                      if e.get("written") and ts - e["ts"] < 30.0]

        has_staged_shellcode = len(staged) > 0
        confidence = 0.92 if has_staged_shellcode else 0.68
        variant = "Special User APC" if is_special_user_apc else "Classic APC"

        return KernelGapAlert(
            gap_id="GAP-KH-19",
            technique_id="T1055.004",
            technique_name=f"APC Injection — {variant} (NtQueueApcThread)",
            confidence=confidence,
            sysmon_event=None,
            cs_event="ETW-TI QUEUEAPC fires; ObRegisterCallbacks (Thread) strips THREAD_SET_CONTEXT",
            artifact=f"PID {writer_pid}: queued APC to thread {target_thread_id} in PID {target_pid} @ 0x{apc_routine_addr:X}"
                     + (" with staged shellcode" if has_staged_shellcode else ""),
            details={"writer": writer_pid, "target": target_pid,
                     "thread": target_thread_id, "routine": hex(apc_routine_addr),
                     "variant": variant, "has_staged": has_staged_shellcode},
        )

    def record_early_bird_apc(self, writer_pid: int, target_pid: int,
                               target_image: str) -> Optional[KernelGapAlert]:
        """Detect Early Bird APC: APC queued before process init completes."""
        return KernelGapAlert(
            gap_id="GAP-KH-19",
            technique_id="T1055.004",
            technique_name="APC Injection — Early Bird (Pre-Init APC Queue)",
            confidence=0.88,
            sysmon_event="Event 1 (CREATE_SUSPENDED) + no Event 8 (direct syscall bypasses)",
            cs_event="ETW-TI QUEUEAPC fires before process init; PsSetCreateProcessNotifyRoutineEx notes suspended state",
            artifact=f"PID {writer_pid}: Early Bird APC queued to {target_image} (PID {target_pid}) before initialization",
            details={"writer": writer_pid, "target": target_pid, "image": target_image},
        )

# ── Unified KernelGapHardeningEngine — new convenience methods ────────────────
# These are added as a mixin-style extension to avoid class structure issues

_ENGINE_NEW_METHODS = {
    'on_ntdll_protect_change': lambda self, pid, base, size, old_prot, new_prot, is_ntdll_range=False: self._record(self.etw_patching.record_ntdll_protect_change(pid, base, size, old_prot, new_prot, is_ntdll_range)),
    'on_etw_write_patch': lambda self, pid, patch_bytes, target_addr: self._record(self.etw_patching.record_etw_write_patch(pid, patch_bytes, target_addr)),
    'on_etw_provider_drop': lambda self, pid, before, after: self._record(self.etw_patching.record_etw_provider_drop(pid, before, after)),
    'on_token_open': lambda self, pid, target_process, access_mask: self._record(self.token_theft.record_token_open(pid, target_process, access_mask)),
    'on_token_duplicate': lambda self, pid, impersonation_level: self._record(self.token_theft.record_token_duplicate(pid, impersonation_level)),
    'on_create_token': lambda self, pid, token_type="Primary": self._record(self.token_theft.record_create_token(pid, token_type)),
    'on_hollow_create': lambda self, target_pid, creator_pid, image: (self.proc_hollowing.record_suspended_create(target_pid, creator_pid, image), self.tartarus_gate.record_suspended_create(target_pid, creator_pid, image)),
    'on_unmap_section': lambda self, target_pid: self._record(self.proc_hollowing.record_unmap_section(target_pid)),
    'on_cross_process_write': lambda self, writer_pid, target_pid, write_size: (self.apc_injection.record_cross_process_write(writer_pid, target_pid, write_size), self._record(self.proc_hollowing.record_cross_process_write(writer_pid, target_pid, write_size)))[1],
    'on_set_thread_context': lambda self, target_pid: self._record(self.proc_hollowing.record_set_thread_context(target_pid)),
    'on_cross_process_alloc': lambda self, writer_pid, target_pid, size, prot: self.apc_injection.record_cross_process_alloc(writer_pid, target_pid, size, prot),
    'on_apc_queue': lambda self, writer_pid, target_pid, thread_id, routine_addr, is_special=False: self._record(self.apc_injection.record_apc_queue(writer_pid, target_pid, thread_id, routine_addr, is_special)),
    'on_early_bird_apc': lambda self, writer_pid, target_pid, image: self._record(self.apc_injection.record_early_bird_apc(writer_pid, target_pid, image)),
}

import types as _types
for _name, _fn in _ENGINE_NEW_METHODS.items():
    setattr(KernelGapHardeningEngine, _name, _types.MethodType.__func__ if False else _fn)
