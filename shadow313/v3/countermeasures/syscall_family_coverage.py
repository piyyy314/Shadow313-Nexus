"""
Shadow313 v3 — Syscall Family Coverage Monitor
Full stub implementation with velocity and PMU tracking.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import time

SYSCALL_FAMILIES = {
    "file_io":    ["open","read","write","close","unlink","rename"],
    "network":    ["socket","connect","bind","listen","accept","send","recv"],
    "process":    ["fork","exec","clone","kill","wait","ptrace"],
    "memory":     ["mmap","mprotect","munmap","brk","mremap",
                   "NtReadVirtualMemory","NtWriteVirtualMemory",
                   "NtMapViewOfSection","NtOpenProcess","MmCopyVirtualMemory",
                   "NtQueryVirtualMemory","NtProtectVirtualMemory",
                   "NtAllocateVirtualMemory","NtFreeVirtualMemory",
                   "NtCreateSection","NtDuplicateObject"],
    "credential": ["setuid","setgid","capset","prctl"],
}

SYSCALL_ANOMALY_THRESHOLD = 50


@dataclass
class SyscallEvent:
    syscall:     str
    family:      str
    pid:         int
    timestamp:   str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    args:        dict  = field(default_factory=dict)
    anomalous:   bool  = False
    final_score: float = 0.85
    token:       str   = ""


class SyscallFamilyMonitor:
    """Monitors syscall families for anomalous patterns."""

    def __init__(self, callback=None):
        self.events:     list[SyscallEvent] = []
        self.coverage:   dict[str, int]     = {f: 0 for f in SYSCALL_FAMILIES}
        self._callback   = callback
        self._velocity:  list[dict]         = []   # Velocity anomaly records
        self._pmu_events: list[dict]        = []   # PMU anomaly records
        self._burst_window: list[float]     = []   # Timestamps for burst detection
        self._burst_threshold = 10           # Events per 100ms = burst

    def record(self, event: SyscallEvent) -> None:
        self.events.append(event)
        if event.family in self.coverage:
            self.coverage[event.family] += 1
        if self._callback:
            try: self._callback(event)
            except Exception: pass
        # Velocity tracking
        now = time.monotonic()
        self._burst_window = [t for t in self._burst_window if now - t < 0.1]
        self._burst_window.append(now)
        if len(self._burst_window) >= self._burst_threshold:
            self._velocity.append({"ts": now, "count": len(self._burst_window),
                                   "syscall": event.syscall})
            self._pmu_events.append({"ts": now, "type": "burst",
                                     "syscall": event.syscall})

    def get_coverage_pct(self) -> float:
        covered = sum(1 for v in self.coverage.values() if v > 0)
        return covered / max(len(self.coverage), 1) * 100

    def anomalous_events(self) -> list[SyscallEvent]:
        return [e for e in self.events if e.anomalous]

    def get_composite_score(self) -> float:
        """Compute composite syscall anomaly detection score."""
        anomalous = self.anomalous_events()
        velocity_score = min(1.0, len(self._velocity) * 0.30)
        if not anomalous and not self._velocity:
            return 0.0
        # Use max final_score from anomalous events (not just count)
        if anomalous:
            max_score = max(e.final_score for e in anomalous)
        else:
            max_score = 0.0
        coverage_bonus = self.get_coverage_pct() / 100 * 0.10
        return min(1.0, max(max_score, velocity_score) + coverage_bonus)

    def inject_anomaly(self, syscall: str, family: str, pid: int = 1234) -> None:
        evt = SyscallEvent(syscall=syscall, family=family, pid=pid, anomalous=True)
        self.record(evt)

    def simulate_syscall(self, syscall: str, family: str = None,
                         pid: int = 1234, anomalous: bool = True,
                         **kwargs) -> SyscallEvent:
        if family is None:
            family = next((f for f, calls in SYSCALL_FAMILIES.items()
                           if syscall in calls), "memory")
        evt = SyscallEvent(syscall=syscall, family=family, pid=pid,
                           anomalous=anomalous, args=kwargs)
        self.record(evt)
        return evt

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass
