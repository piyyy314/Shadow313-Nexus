"""
shadow313.v4.detection.temporal_correlation
Temporal Correlation Engine — correlates events across time windows to detect slow-burn APT campaigns.
"""
from __future__ import annotations
import time
import statistics
from collections import defaultdict
from typing import Optional


class TemporalCorrelationEngine:
    """Correlates security events across configurable time windows."""

    def __init__(self, window_seconds: int = 3600):
        self.window_seconds = window_seconds
        self.event_store: list = []
        self.correlations: list = []
        self._entity_events: dict = defaultdict(list)

    def ingest_event(self, event: dict) -> None:
        event["_ingested_at"] = time.time()
        self.event_store.append(event)
        entity = event.get("entity", event.get("user", event.get("ip", "unknown")))
        self._entity_events[entity].append(event)
        self._prune_old_events()

    def correlate(self, entity: str) -> dict:
        now = time.time()
        window_start = now - self.window_seconds
        events = [e for e in self._entity_events.get(entity, [])
                  if e.get("_ingested_at", 0) >= window_start]
        if len(events) < 2:
            return {"entity": entity, "correlated": False, "event_count": len(events)}
        techniques = list(set(e.get("technique", "unknown") for e in events))
        severities = [e.get("severity_score", 0.5) for e in events]
        timestamps = [e.get("_ingested_at", now) for e in events]
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        correlation = {
            "entity": entity, "correlated": True, "event_count": len(events),
            "techniques": techniques,
            "mean_severity": round(statistics.mean(severities), 3),
            "mean_interval_s": round(statistics.mean(intervals), 1) if intervals else 0,
            "cv_interval": round(
                statistics.stdev(intervals) / max(statistics.mean(intervals), 1), 3
            ) if len(intervals) > 1 else 0,
            "campaign_suspected": len(techniques) >= 3 and statistics.mean(severities) > 0.6,
            "window_seconds": self.window_seconds,
            "timestamp": now,
        }
        self.correlations.append(correlation)
        return correlation

    def detect_slow_burn(self, min_events: int = 5, max_interval_s: float = 3600) -> list:
        campaigns = []
        for entity in self._entity_events:
            events = self._entity_events[entity]
            if len(events) >= min_events:
                result = self.correlate(entity)
                if result.get("cv_interval", 1) < 0.3 and result.get("mean_interval_s", 0) < max_interval_s:
                    campaigns.append({**result, "pattern": "LOW_AND_SLOW_APT"})
        return campaigns

    def _prune_old_events(self) -> None:
        cutoff = time.time() - self.window_seconds * 2
        self.event_store = [e for e in self.event_store if e.get("_ingested_at", 0) > cutoff]
        for entity in list(self._entity_events.keys()):
            self._entity_events[entity] = [
                e for e in self._entity_events[entity]
                if e.get("_ingested_at", 0) > cutoff
            ]

    def status(self) -> dict:
        return {
            "events_stored": len(self.event_store),
            "entities_tracked": len(self._entity_events),
            "correlations_run": len(self.correlations),
            "window_seconds": self.window_seconds,
        }