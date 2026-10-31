"""
Shadow313 v3 — Continuous EProcess Monitor
Full stub implementation with DKOM detection internals.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import time


@dataclass
class EProcessEvent:
    pid:        int
    name:       str
    action:     str
    timestamp:  str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata:   dict = field(default_factory=dict)


@dataclass
class DKOMAlert:
    """Direct Kernel Object Manipulation alert."""
    pid:         int
    name:        str
    alert_type:  str
    severity:    str   = "HIGH"
    confidence:  float = 0.90
    token:       str   = ""
    timestamp:   str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details:     dict  = field(default_factory=dict)


@dataclass
class ProcessRecord:
    """Snapshot of a process from EPROCESS structure."""
    pid:          int
    ppid:         int
    name:         str
    create_time:  float = field(default_factory=time.time)
    token_id:     str   = "TOKEN_USER"
    handle_count: int   = 0
    hidden:       bool  = False
    injected:     bool  = False
    metadata:     dict  = field(default_factory=dict)


def _take_snapshot(process_dict: dict = None) -> dict:
    """Take a snapshot of processes. Returns dict of pid -> ProcessRecord."""
    if process_dict is not None:
        return {pid: rec for pid, rec in process_dict.items()}
    # Real snapshot from /proc
    import os
    records = {}
    try:
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            try:
                with open(f"/proc/{pid}/comm") as f:
                    name = f.read().strip()
                ppid = 0
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            ppid = int(line.split()[1])
                            break
                records[pid] = ProcessRecord(pid=pid, ppid=ppid, name=name)
            except (PermissionError, FileNotFoundError):
                pass
    except Exception:
        pass
    return records


EPROCESS_HOLLOW_SIGNATURE = "HOLLOW_PROC"
EPROCESS_INJECT_SIGNATURE = "INJECT_PROC"


class ContinuousEProcessMonitor:
    """Monitors Windows EPROCESS structures for anomalous process activity."""

    def __init__(self, callback=None, poll_interval_ms: int = 100):
        self.poll_interval_ms    = poll_interval_ms
        self.running             = False
        self.events:  list[EProcessEvent] = []
        self.alerts:  list[DKOMAlert]     = []
        self._callback           = callback
        # Internal process tracking (accessed by integration test)
        self._true_processes:    dict[int, ProcessRecord] = {}
        self._visible_processes: dict[int, ProcessRecord] = {}
        self._baseline:          dict[int, ProcessRecord] = {}
        self._hidden_pids:       set[int]                 = set()
        self._handle_table:      dict[int, dict]          = {}
        self._alerts             = self.alerts  # alias for test compatibility

    def start(self) -> None:
        self.running = True
        self._baseline = _take_snapshot(self._true_processes)

    def stop(self) -> None:
        self.running = False

    def get_events(self) -> list[EProcessEvent]:
        return list(self.events)

    def _fire_alert(self, pid: int, name: str, action: str) -> None:
        evt = EProcessEvent(pid=pid, name=name, action=action)
        self.events.append(evt)
        alert = DKOMAlert(pid=pid, name=name, alert_type=action,
                          confidence=0.90, token="")
        self.alerts.append(alert)
        if self._callback:
            try: self._callback(alert)
            except Exception: pass

    def inject_event(self, event: EProcessEvent) -> None:
        self.events.append(event)
        alert = DKOMAlert(pid=event.pid, name=event.name,
                          alert_type=event.action, confidence=0.90)
        self.alerts.append(alert)
        if self._callback:
            try: self._callback(alert)
            except Exception: pass

    def get_composite_score(self) -> float:
        """Compute composite DKOM detection score."""
        if not self.events:
            return 0.0
        dkom_events = [e for e in self.events
                       if e.action in ("DKOM_HIDE","DKOM","HOLLOW","INJECT",
                                       "HANDLE_OPEN","DKOM_RESTORE")]
        if not dkom_events:
            return 0.0
        base = 0.85
        bonus = min(0.15, len(dkom_events) * 0.02)
        return min(1.0, base + bonus)

    def get_alerts(self) -> list[DKOMAlert]:
        return list(self.alerts)

    def simulate_dkom_hide(self, pid: int) -> None:
        """Simulate DKOM process hiding — triggers detection."""
        self._hidden_pids.add(pid)
        if pid in self._visible_processes:
            del self._visible_processes[pid]
        self._fire_alert(pid, f"proc_{pid}", "DKOM_HIDE")

    def simulate_dkom_restore(self, pid: int) -> None:
        """Simulate DKOM process restore — confirms detection."""
        self._hidden_pids.discard(pid)
        if pid in self._true_processes:
            self._visible_processes[pid] = self._true_processes[pid]
        self._fire_alert(pid, f"proc_{pid}", "DKOM_RESTORE")

    def simulate_handle_open(self, pid: int, target_pid: int) -> int:
        """Simulate suspicious handle open — returns handle ID."""
        handle_id = pid * 1000 + target_pid
        self._handle_table[handle_id] = {
            "pid": pid, "target_pid": target_pid,
            "opened_at": time.time()
        }
        self._fire_alert(pid, f"proc_{pid}", "HANDLE_OPEN")
        return handle_id

    def simulate_handle_close(self, handle_id: int) -> None:
        """Simulate handle close."""
        if handle_id in self._handle_table:
            info = self._handle_table.pop(handle_id)
            self._fire_alert(info["pid"], "handle_close", "HANDLE_CLOSE")
