"""
Shadow313 v3 Bridge — EventRateTracker
=======================================
Sliding window event rate tracker that populates dim[18] (event_frequency)
in the 20-dimensional feature vector.

Closes the following detection blind spots:
  - C2 beaconing:          regular low-frequency outbound connections
  - Credential stuffing:   high-frequency auth failures from single host
  - Port scanning:         high-frequency network events from single host
  - Ransomware staging:    high-frequency file creation events

Architecture:
  - Per-(host, event_type) sliding window deque
  - Configurable window size (default: 60 seconds)
  - Normalized output: 0.0=rare, 0.5=moderate, 1.0=burst
  - Beacon detector: identifies regular timing patterns (C2 indicator)
  - Thread-safe: uses threading.Lock for concurrent access
  - Memory-bounded: max 10,000 buckets, LRU eviction

Normalization scale:
  0.0  = < 1 event/min   (rare — baseline)
  0.25 = ~ 5 events/min  (low activity)
  0.50 = ~10 events/min  (moderate)
  0.75 = ~50 events/min  (elevated)
  1.0  = 100+ events/min (burst — scanning/stuffing/ransomware)

Beacon detection (C2 indicator):
  Regular timing = coefficient of variation (CV) < 0.15
  CV = std_dev(intervals) / mean(intervals)
  Low CV = highly regular = likely automated/beaconing
"""

from __future__ import annotations

import math
import statistics
import threading
import time
from collections import deque, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# ── Constants ──────────────────────────────────────────────────────────────────

DEFAULT_WINDOW_S    = 60.0
BEACON_WINDOW_S     = 300.0
MAX_BUCKETS         = 10_000
BEACON_CV_THRESHOLD = 0.15
BEACON_MIN_EVENTS   = 5
BURST_THRESHOLD     = 100
_LOG_SCALE          = math.log10(BURST_THRESHOLD + 1)


# ── Data Structures ────────────────────────────────────────────────────────────

@dataclass
class RateWindow:
    host:        str
    event_type:  str
    timestamps:  deque = field(default_factory=lambda: deque(maxlen=1000))
    last_access: float = field(default_factory=time.time)

    def record(self, ts: float) -> None:
        self.timestamps.append(ts)
        self.last_access = ts

    def rate_per_min(self, window_s: float, now: float) -> float:
        cutoff = now - window_s
        count  = sum(1 for t in self.timestamps if t >= cutoff)
        return count / (window_s / 60.0)

    def beacon_score(self, window_s: float, now: float) -> float:
        cutoff  = now - window_s
        recent  = [t for t in self.timestamps if t >= cutoff]
        if len(recent) < BEACON_MIN_EVENTS:
            return 0.0
        intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
        if not intervals:
            return 0.0
        mean_interval = statistics.mean(intervals)
        if mean_interval < 0.001:
            return 0.0
        try:
            std_dev = statistics.stdev(intervals)
            cv      = std_dev / mean_interval
            return min(1.0, max(0.0, 1.0 - (cv / BEACON_CV_THRESHOLD)))
        except statistics.StatisticsError:
            return 0.0

    def frequency_score(self, window_s: float, now: float) -> float:
        rate = self.rate_per_min(window_s, now)
        if rate <= 0:
            return 0.0
        return min(1.0, math.log10(rate + 1) / _LOG_SCALE)


@dataclass
class RateAlert:
    timestamp:    str
    host:         str
    event_type:   str
    rate_per_min: float
    score:        float
    alert_type:   str
    beacon_score: float
    token:        str = "ebpf_syscall"


# ── EventRateTracker ───────────────────────────────────────────────────────────

class EventRateTracker:
    """
    Thread-safe sliding window event rate tracker.
    Populates dim[18] (event_frequency) in the 20-dim feature vector.
    """

    THRESHOLDS = {
        "network_outbound": {"burst": 50,  "sustained": 10},
        "logon_failure":    {"burst": 20,  "sustained": 5},
        "auth_failure":     {"burst": 20,  "sustained": 5},
        "network_event":    {"burst": 100, "sustained": 30},
        "file_create":      {"burst": 200, "sustained": 50},
        "file_write":       {"burst": 200, "sustained": 50},
        "dns_query":        {"burst": 100, "sustained": 20},
        "process_creation": {"burst": 30,  "sustained": 10},
        "registry_write":   {"burst": 50,  "sustained": 15},
        "default":          {"burst": 100, "sustained": 30},
    }

    def __init__(
        self,
        window_s:       float = DEFAULT_WINDOW_S,
        beacon_window_s:float = BEACON_WINDOW_S,
        max_buckets:    int   = MAX_BUCKETS,
    ):
        self._window_s        = window_s
        self._beacon_window_s = beacon_window_s
        self._max_buckets     = max_buckets
        self._buckets:  OrderedDict[tuple, RateWindow] = OrderedDict()
        self._alerts:   list[RateAlert] = []
        self._lock      = threading.Lock()
        self._total_events = 0

    def record_and_score(self, host: str, event_type: str) -> float:
        """Record an event and return normalized frequency score (0.0-1.0) for dim[18]."""
        now = time.time()
        key = (host, event_type.lower())
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= self._max_buckets:
                self._buckets.popitem(last=False)
            if key not in self._buckets:
                self._buckets[key] = RateWindow(host=host, event_type=event_type)
            window = self._buckets[key]
            self._buckets.move_to_end(key)
            window.record(now)
            self._total_events += 1
            score        = window.frequency_score(self._window_s, now)
            rate_per_min = window.rate_per_min(self._window_s, now)
            self._check_thresholds(window, rate_per_min, score, now)
        return score

    def get_beacon_score(self, host: str, event_type: str) -> float:
        """Get beacon regularity score (0=random, 1=perfectly regular timing)."""
        key = (host, event_type.lower())
        with self._lock:
            window = self._buckets.get(key)
            if not window:
                return 0.0
            return window.beacon_score(self._beacon_window_s, time.time())

    def get_combined_score(self, host: str, event_type: str) -> float:
        """Combined score: max(frequency_score, beacon_score * 0.8)."""
        freq   = self.record_and_score(host, event_type)
        beacon = self.get_beacon_score(host, event_type)
        return max(freq, beacon * 0.8)

    def get_rate(self, host: str, event_type: str) -> float:
        key = (host, event_type.lower())
        with self._lock:
            window = self._buckets.get(key)
            if not window:
                return 0.0
            return window.rate_per_min(self._window_s, time.time())

    def get_alerts(self, since_s: float = 60.0) -> list[RateAlert]:
        cutoff = time.time() - since_s
        with self._lock:
            return [
                a for a in self._alerts
                if datetime.fromisoformat(a.timestamp).timestamp() >= cutoff
            ]

    def get_top_hosts(self, n: int = 10) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            host_rates: dict[str, float] = {}
            for (host, etype), window in self._buckets.items():
                rate = window.rate_per_min(self._window_s, now)
                host_rates[host] = host_rates.get(host, 0) + rate
            sorted_hosts = sorted(host_rates.items(), key=lambda x: -x[1])
            return [{"host": h, "total_rate_per_min": r} for h, r in sorted_hosts[:n]]

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_events":    self._total_events,
                "active_buckets":  len(self._buckets),
                "max_buckets":     self._max_buckets,
                "window_s":        self._window_s,
                "beacon_window_s": self._beacon_window_s,
                "total_alerts":    len(self._alerts),
            }

    def _check_thresholds(
        self,
        window:       RateWindow,
        rate_per_min: float,
        score:        float,
        now:          float,
    ) -> None:
        thresholds = self.THRESHOLDS.get(
            window.event_type.lower(),
            self.THRESHOLDS["default"]
        )
        alert_type = None
        if rate_per_min >= thresholds["burst"]:
            alert_type = "BURST"
        elif rate_per_min >= thresholds["sustained"]:
            alert_type = "SUSTAINED"

        beacon_score = window.beacon_score(self._beacon_window_s, now)
        if beacon_score >= 0.8 and alert_type is None:
            alert_type = "BEACON"

        if alert_type:
            recent = [
                a for a in self._alerts[-20:]
                if a.host == window.host and
                   a.event_type == window.event_type and
                   a.alert_type == alert_type and
                   datetime.fromisoformat(a.timestamp).timestamp() > now - 30
            ]
            if not recent:
                self._alerts.append(RateAlert(
                    timestamp    = datetime.now(timezone.utc).isoformat(),
                    host         = window.host,
                    event_type   = window.event_type,
                    rate_per_min = rate_per_min,
                    score        = score,
                    alert_type   = alert_type,
                    beacon_score = beacon_score,
                ))
                if len(self._alerts) > 10_000:
                    self._alerts = self._alerts[-5_000:]


# ── Global Singleton ───────────────────────────────────────────────────────────

_global_tracker: Optional[EventRateTracker] = None
_tracker_lock   = threading.Lock()


def get_global_tracker() -> EventRateTracker:
    global _global_tracker
    if _global_tracker is None:
        with _tracker_lock:
            if _global_tracker is None:
                _global_tracker = EventRateTracker()
    return _global_tracker


def reset_global_tracker() -> None:
    global _global_tracker
    with _tracker_lock:
        _global_tracker = None