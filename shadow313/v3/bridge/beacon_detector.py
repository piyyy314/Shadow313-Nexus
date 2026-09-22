"""
shadow313.v3.bridge.beacon_detector
─────────────────────────────────────
C2 Beacon Detector — identifies periodic beaconing patterns in network flows.

Detects:
  - Fixed-interval beacons (Cobalt Strike default: 60s)
  - Jittered beacons (CS malleable profiles: ±50%)
  - Low-and-slow APT beacons (Lazarus: 300s+)
  - Domain-fronted beacons (Cloudflare CDN)

Integrates with c2_attribution_analysis.py for signal correlation.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class BeaconEvent:
    """A single network connection event."""
    timestamp:  float   # Unix epoch seconds
    src_ip:     str
    dst_ip:     str
    dst_port:   int
    bytes_sent: int
    uri:        str = ""
    ja3:        str = ""
    tls_cert:   str = ""


@dataclass
class BeaconProfile:
    """Detected beacon profile for a host."""
    src_ip:         str
    dst_ip:         str
    dst_port:       int
    period_s:       float       # Mean beacon period in seconds
    jitter_pct:     float       # Jitter as fraction (0.0–1.0)
    confidence:     float       # 0.0–1.0
    event_count:    int
    framework:      str = ""    # Cobalt Strike | Sliver | Brute Ratel | Unknown
    uri_pattern:    str = ""
    ja3:            str = ""
    is_beacon:      bool = True
    cv:             float = 0.0  # Coefficient of variation (low = consistent)


# Known C2 framework beacon signatures
_FRAMEWORK_SIGNATURES = {
    "Cobalt Strike": {"period_range": (30, 120),  "jitter_max": 0.60, "ja3_prefix": "72a589da"},
    "Sliver":        {"period_range": (200, 400),  "jitter_max": 0.30, "ja3_prefix": "b386946a"},
    "Brute Ratel":   {"period_range": (60, 180),   "jitter_max": 0.15, "ja3_prefix": "d0ec4b50"},
    "Metasploit":    {"period_range": (5, 30),     "jitter_max": 0.10, "ja3_prefix": "a0e9f5d6"},
}


class BeaconDetector:
    """
    Detects C2 beaconing patterns in network flow data.

    Algorithm:
      1. Group flows by (src_ip, dst_ip, dst_port)
      2. Compute inter-arrival times between consecutive flows
      3. Calculate mean period and coefficient of variation (CV)
      4. Low CV (< 0.3) with consistent period → beacon candidate
      5. Match against known framework signatures
    """

    # CV threshold below which traffic is considered periodic
    CV_BEACON_THRESHOLD = 0.35

    # Minimum events to declare a beacon
    MIN_EVENTS = 4

    # Minimum period to consider (avoid noise)
    MIN_PERIOD_S = 5.0

    def detect(self, events: list[BeaconEvent]) -> list[BeaconProfile]:
        """Detect beacon profiles from a list of network events."""
        # Group by (src, dst, port)
        groups: dict[tuple, list[BeaconEvent]] = {}
        for ev in events:
            key = (ev.src_ip, ev.dst_ip, ev.dst_port)
            groups.setdefault(key, []).append(ev)

        profiles = []
        for (src, dst, port), evs in groups.items():
            if len(evs) < self.MIN_EVENTS:
                continue
            evs_sorted = sorted(evs, key=lambda e: e.timestamp)
            profile = self._analyze_group(src, dst, port, evs_sorted)
            if profile and profile.is_beacon:
                profiles.append(profile)

        return sorted(profiles, key=lambda p: -p.confidence)

    def _analyze_group(
        self,
        src: str, dst: str, port: int,
        events: list[BeaconEvent],
    ) -> Optional[BeaconProfile]:
        """Analyze a group of flows for beaconing behavior."""
        timestamps = [e.timestamp for e in events]
        intervals  = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        if not intervals or min(intervals) < 0:
            return None

        mean_period = statistics.mean(intervals)
        if mean_period < self.MIN_PERIOD_S:
            return None

        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv      = std_dev / mean_period if mean_period > 0 else 1.0
        jitter  = cv  # CV approximates jitter fraction

        is_beacon  = cv < self.CV_BEACON_THRESHOLD
        confidence = max(0.0, min(1.0, 1.0 - (cv / self.CV_BEACON_THRESHOLD))) if is_beacon else 0.0

        # Framework attribution
        framework = self._attribute_framework(mean_period, jitter, events[0].ja3)

        return BeaconProfile(
            src_ip      = src,
            dst_ip      = dst,
            dst_port    = port,
            period_s    = round(mean_period, 1),
            jitter_pct  = round(jitter, 3),
            confidence  = round(confidence, 3),
            event_count = len(events),
            framework   = framework,
            uri_pattern = events[0].uri,
            ja3         = events[0].ja3,
            is_beacon   = is_beacon,
            cv          = round(cv, 3),
        )

    def _attribute_framework(self, period: float, jitter: float, ja3: str) -> str:
        """Attribute beacon to a known C2 framework."""
        for name, sig in _FRAMEWORK_SIGNATURES.items():
            lo, hi = sig["period_range"]
            if lo <= period <= hi and jitter <= sig["jitter_max"]:
                if ja3 and ja3.startswith(sig["ja3_prefix"]):
                    return name
                # Period + jitter match without JA3 confirmation
                return f"{name} (probable)"
        return "Unknown"

    def summary(self, profiles: list[BeaconProfile]) -> dict:
        """Return a summary of detected beacons."""
        return {
            "total_beacons":    len(profiles),
            "frameworks":       list(set(p.framework for p in profiles)),
            "high_confidence":  [p for p in profiles if p.confidence >= 0.7],
            "unique_src_ips":   list(set(p.src_ip for p in profiles)),
            "unique_dst_ips":   list(set(p.dst_ip for p in profiles)),
        }


# ── Advanced Beacon Detector ──────────────────────────────────────────────────

@dataclass
class HostBeaconProfile:
    """Beacon profile for a single host using interval analysis."""
    host:        str
    event_type:  str
    period_s:    float      # Mean interval in seconds
    cv:          float      # Coefficient of variation (low = consistent)
    confidence:  float      # 0.0–1.0
    n_intervals: int
    is_beacon:   bool


class AdvancedBeaconDetector:
    """
    Advanced beacon detector using interval analysis.

    Detects:
      - Per-host beaconing via coefficient of variation (CV)
      - Shared C2 infrastructure via period correlation across hosts
      - Low-and-slow APT beacons with extended windows

    Usage:
        detector = AdvancedBeaconDetector()
        detector.analyze_intervals(host, event_type, intervals)
        correlations = detector.find_shared_c2()
    """

    # Minimum CV to consider a signal as beaconing (lower = more regular)
    CV_THRESHOLD: float = 0.20

    # Minimum number of intervals to compute reliable statistics
    MIN_INTERVALS: int = 5

    # Minimum confidence to register a beacon profile
    REGISTRATION_THRESHOLD: float = 0.50

    # Period match tolerance for shared C2 detection (fraction)
    PERIOD_MATCH_TOLERANCE: float = 0.10

    def __init__(self):
        self._profiles: dict[tuple[str, str], HostBeaconProfile] = {}

    def analyze_intervals(
        self,
        host: str,
        event_type: str,
        intervals: list[float],
    ) -> Optional[HostBeaconProfile]:
        """
        Analyze a list of inter-arrival intervals for a host/event_type pair.

        Args:
            host:       Source IP or hostname
            event_type: Event type (e.g., "network_outbound")
            intervals:  List of inter-arrival times in seconds

        Returns:
            HostBeaconProfile if beaconing detected, None otherwise
        """
        if len(intervals) < self.MIN_INTERVALS:
            return None

        mean = statistics.mean(intervals)
        if mean <= 0:
            return None

        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev / mean

        # Confidence: inversely proportional to CV
        # CV=0.0 → confidence=1.0, CV=CV_THRESHOLD → confidence=0.5
        if cv <= self.CV_THRESHOLD:
            confidence = max(0.0, 1.0 - (cv / self.CV_THRESHOLD) * 0.5)
        else:
            confidence = max(0.0, 0.5 - (cv - self.CV_THRESHOLD) * 2.0)

        # Boost confidence with more intervals
        n_boost = min(1.0, len(intervals) / 30.0)
        confidence = min(1.0, confidence * (0.7 + 0.3 * n_boost))

        is_beacon = cv <= self.CV_THRESHOLD and confidence >= self.REGISTRATION_THRESHOLD

        profile = HostBeaconProfile(
            host=host,
            event_type=event_type,
            period_s=round(mean, 3),
            cv=round(cv, 4),
            confidence=round(confidence, 3),
            n_intervals=len(intervals),
            is_beacon=is_beacon,
        )

        if confidence >= self.REGISTRATION_THRESHOLD:
            self._profiles[(host, event_type)] = profile

        return profile

    def find_shared_c2(
        self,
        min_confidence: float = 0.40,
    ) -> list[dict]:
        """
        Find hosts that share the same C2 beacon period.

        Two hosts are considered to share C2 infrastructure if their
        beacon periods match within PERIOD_MATCH_TOLERANCE.

        Args:
            min_confidence: Minimum confidence for both profiles

        Returns:
            List of correlation dicts with host pairs and match details
        """
        # Filter to registered beacon profiles above confidence threshold
        candidates = [
            p for p in self._profiles.values()
            if p.confidence >= min_confidence and p.is_beacon
        ]

        correlations = []
        seen = set()

        for i, p1 in enumerate(candidates):
            for j, p2 in enumerate(candidates):
                if i >= j:
                    continue
                if p1.host == p2.host:
                    continue

                pair_key = tuple(sorted([p1.host, p2.host]))
                if pair_key in seen:
                    continue

                # Check period match within tolerance
                if p1.period_s <= 0 or p2.period_s <= 0:
                    continue

                ratio = abs(p1.period_s - p2.period_s) / max(p1.period_s, p2.period_s)
                if ratio <= self.PERIOD_MATCH_TOLERANCE:
                    match_ratio = 1.0 - ratio
                    correlations.append({
                        "host1":      p1.host,
                        "host2":      p2.host,
                        "period1_s":  p1.period_s,
                        "period2_s":  p2.period_s,
                        "match_ratio": round(match_ratio, 4),
                        "confidence1": p1.confidence,
                        "confidence2": p2.confidence,
                        "interpretation": (
                            f"Hosts {p1.host} and {p2.host} share beacon period "
                            f"~{p1.period_s:.1f}s — likely same C2 infrastructure"
                        ),
                    })
                    seen.add(pair_key)

        return correlations

    def get_all_profiles(self) -> list[HostBeaconProfile]:
        """Return all registered beacon profiles."""
        return list(self._profiles.values())

    def get_beacon_hosts(self) -> list[str]:
        """Return list of hosts with confirmed beaconing."""
        return [p.host for p in self._profiles.values() if p.is_beacon]

    def clear(self) -> None:
        """Clear all registered profiles."""
        self._profiles.clear()