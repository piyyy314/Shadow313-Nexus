"""shadow313.modules.network.flow_tracker — 5-tuple flow tracker with statistics."""
from __future__ import annotations
from collections import defaultdict


class FlowTracker:
    """Maintains 5-tuple flow table with per-flow statistics."""

    def __init__(self) -> None:
        self._flows: dict[tuple, dict] = {}

    def update(self, pkt: dict) -> None:
        if not pkt.get("src_ip"):
            return
        key = (pkt.get("src_ip", ""), pkt.get("dst_ip", ""),
               pkt.get("sport", 0), pkt.get("dport", 0),
               pkt.get("protocol", ""))
        ts = pkt.get("ts", 0.0)
        if key not in self._flows:
            self._flows[key] = {"packets": 0, "bytes": 0, "first": ts, "last": ts}
        self._flows[key]["packets"] += 1
        self._flows[key]["bytes"]   += pkt.get("length", 0)
        self._flows[key]["last"]     = ts

    def get_flows(self) -> list[dict]:
        results = []
        for (src_ip, dst_ip, sport, dport, proto), stats in self._flows.items():
            duration = max(stats["last"] - stats["first"], 0.001)
            results.append({
                "src_ip":      src_ip, "dst_ip":  dst_ip,
                "sport":       sport,  "dport":   dport,
                "proto":       proto,
                "packets":     stats["packets"],
                "bytes":       stats["bytes"],
                "duration":    round(duration, 3),
                "packet_rate": round(stats["packets"] / duration, 2),
                "byte_rate":   round(stats["bytes"] / duration, 2),
            })
        return sorted(results, key=lambda x: x["bytes"], reverse=True)

    def from_packets(self, packets: list[dict]) -> list[dict]:
        for pkt in packets:
            self.update(pkt)
        return self.get_flows()

# ── UEBA: Per-Endpoint Outbound Volume Monitor (Gap 9 / DLP) ─────────────────
from collections import defaultdict as _defaultdict
from datetime import datetime as _datetime, timezone as _timezone


class OutboundVolumeMonitor:
    """Track per-endpoint outbound data volume to detect exfiltration (T1041/T1048).

    Detects Gap 9 (DLP) identified in Operation GHOSTPRINT simulation:
    alerts when any endpoint uploads > threshold bytes to non-approved domains
    within a sliding time window.

    Args:
        threshold_bytes:    Alert threshold per endpoint per window (default 1GB).
        window_s:           Sliding window in seconds (default 86400 = 24h).
        approved_domains:   Set of approved cloud storage domains (allowlist).
        alert_callback:     Callable(src_ip, dest_domain, bytes_sent) on breach.
    """

    DEFAULT_THRESHOLD = 1_073_741_824  # 1 GB
    DEFAULT_WINDOW_S  = 86_400         # 24 hours

    APPROVED_DOMAINS: frozenset[str] = frozenset({
        "sharepoint.com", "onedrive.live.com", "drive.google.com",
        "s3.amazonaws.com", "blob.core.windows.net", "dropbox.com",
    })

    def __init__(
        self,
        threshold_bytes: int = DEFAULT_THRESHOLD,
        window_s: float = DEFAULT_WINDOW_S,
        approved_domains: set[str] | None = None,
        alert_callback=None,
    ) -> None:
        self.threshold_bytes = threshold_bytes
        self.window_s = window_s
        self.approved_domains = approved_domains or self.APPROVED_DOMAINS
        self.alert_callback = alert_callback or self._default_alert
        # {(src_ip, dest_domain): [(timestamp, bytes)]}
        self._events: dict[tuple[str, str], list[tuple[float, int]]] = _defaultdict(list)

    def _default_alert(self, src_ip: str, dest_domain: str, total_bytes: int) -> None:
        mb = total_bytes / 1_048_576
        print(
            f"[SHADOW313-GAP9] EXFIL ALERT: {src_ip} → {dest_domain} "
            f"sent {mb:.1f} MB in window (threshold={self.threshold_bytes // 1_048_576} MB)"
        )

    def _is_approved(self, domain: str) -> bool:
        domain = domain.lower()
        return any(domain == d or domain.endswith("." + d) for d in self.approved_domains)

    def record(self, src_ip: str, dest_domain: str, bytes_sent: int) -> bool:
        """Record an outbound transfer event.

        Returns:
            True if alert was triggered, False otherwise.
        """
        if self._is_approved(dest_domain):
            return False

        now = _datetime.now(_timezone.utc).timestamp()
        key = (src_ip, dest_domain)
        self._events[key].append((now, bytes_sent))

        # Prune old events outside window
        cutoff = now - self.window_s
        self._events[key] = [(ts, b) for ts, b in self._events[key] if ts >= cutoff]

        total = sum(b for _, b in self._events[key])
        if total >= self.threshold_bytes:
            self.alert_callback(src_ip, dest_domain, total)
            return True
        return False

    def stats(self) -> list[dict]:
        """Return current per-endpoint outbound volume stats."""
        now = _datetime.now(_timezone.utc).timestamp()
        cutoff = now - self.window_s
        results = []
        for (src_ip, dest_domain), events in self._events.items():
            recent = [(ts, b) for ts, b in events if ts >= cutoff]
            if not recent:
                continue
            total = sum(b for _, b in recent)
            results.append({
                "src_ip": src_ip,
                "dest_domain": dest_domain,
                "total_bytes": total,
                "total_mb": round(total / 1_048_576, 2),
                "event_count": len(recent),
                "approved": self._is_approved(dest_domain),
                "alert": total >= self.threshold_bytes,
            })
        return sorted(results, key=lambda x: x["total_bytes"], reverse=True)


# ── UEBA: User File Access Anomaly Detector (Gap 8) ──────────────────────────
class UserFileAccessMonitor:
    """Detect anomalous file access volume per user (T1083 / insider threat).

    Detects Gap 8 (UEBA) identified in Operation GHOSTPRINT simulation:
    alerts when a user accesses > multiplier × their 30-day average file count
    within a single observation window.

    Args:
        alert_multiplier:   Alert when access > multiplier × baseline (default 3×).
        min_baseline:       Minimum baseline count to avoid false positives (default 100).
        alert_callback:     Callable(username, count, baseline) on breach.
    """

    def __init__(
        self,
        alert_multiplier: float = 3.0,
        min_baseline: int = 100,
        alert_callback=None,
    ) -> None:
        self.alert_multiplier = alert_multiplier
        self.min_baseline = min_baseline
        self.alert_callback = alert_callback or self._default_alert
        # {username: [daily_count, ...]} — rolling 30-day history
        self._history: dict[str, list[int]] = _defaultdict(list)
        self._today: dict[str, int] = _defaultdict(int)

    def _default_alert(self, username: str, count: int, baseline: float) -> None:
        print(
            f"[SHADOW313-GAP8] UEBA ALERT: {username} accessed {count} files "
            f"(baseline={baseline:.0f}, threshold={baseline * self.alert_multiplier:.0f})"
        )

    def record_access(self, username: str, file_path: str = "") -> bool:
        """Record a file access event for a user.

        Returns:
            True if alert was triggered, False otherwise.
        """
        self._today[username] += 1
        count = self._today[username]
        history = self._history[username]

        if len(history) < 7:
            # Not enough history for reliable baseline
            return False

        baseline = sum(history[-30:]) / min(len(history), 30)
        if baseline < self.min_baseline:
            return False

        if count >= baseline * self.alert_multiplier:
            self.alert_callback(username, count, baseline)
            return True
        return False

    def end_of_day(self) -> None:
        """Call at end of each day to rotate daily counts into history."""
        for username, count in self._today.items():
            self._history[username].append(count)
            # Keep only 30 days
            if len(self._history[username]) > 30:
                self._history[username] = self._history[username][-30:]
        self._today.clear()

    def set_baseline(self, username: str, daily_counts: list[int]) -> None:
        """Seed baseline history for a user (e.g., from SIEM historical data)."""
        self._history[username] = list(daily_counts[-30:])
