"""
nexus_toolkit.engine
──────────────────────
NexusDetectionEngine — unified detection engine combining ML anomaly
scoring, threat intelligence, and ATT&CK mapping.

Integrates:
  - 37-dim feature extraction (log_parser.py)
  - ML anomaly detection (ml_engine.py)
  - Shadow313 bridge for 313-BIND receipts
  - ATT&CK technique attribution
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .core.log_parser import LogEntry, FeatureExtractor
from .core.ml_engine import NexusMLEngine, AnomalyScore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DetectionResult:
    """Complete detection result for a log entry."""
    log_id:         str
    anomaly_score:  AnomalyScore
    threat_level:   str           # CRITICAL | HIGH | MEDIUM | LOW | NONE
    techniques:     list[str]     # MITRE ATT&CK technique IDs
    indicators:     list[str]     # Human-readable indicators
    timestamp:      str = field(default_factory=_now_iso)
    bind_id:        Optional[str] = None

    @property
    def is_threat(self) -> bool:
        return self.threat_level in ("CRITICAL", "HIGH", "MEDIUM")


class NexusDetectionEngine:
    """
    Unified detection engine for Shadow313 NEXUS.

    Combines ML anomaly detection with rule-based ATT&CK mapping
    to produce structured threat detections from raw log entries.
    """

    def __init__(self, threshold: float = 0.5) -> None:
        self.extractor = FeatureExtractor()
        self.ml_engine = NexusMLEngine(threshold=threshold)
        self._feature_names = self.extractor.feature_names()
        self._detection_count = 0
        self._fitted = False

    def train(self, log_entries: list[LogEntry]) -> None:
        """Train the ML engine on a set of log entries."""
        matrix = [self.extractor.extract(e) for e in log_entries]
        self.ml_engine.fit(matrix)
        self._fitted = True

    def detect(self, entry: LogEntry) -> DetectionResult:
        """Detect threats in a single log entry."""
        fv = self.extractor.extract(entry)
        log_id = entry.raw.get("log_id", f"log-{int(time.time_ns())}")

        # ML scoring
        score = self.ml_engine.predict(fv, log_id=log_id, feature_names=self._feature_names)

        # Rule-based ATT&CK mapping
        techniques = self._map_techniques(entry, fv)
        indicators = self._extract_indicators(entry, fv)

        # Threat level
        threat_level = self._compute_threat_level(score, techniques, entry)

        self._detection_count += 1

        return DetectionResult(
            log_id        = log_id,
            anomaly_score = score,
            threat_level  = threat_level,
            techniques    = techniques,
            indicators    = indicators,
        )

    def detect_batch(self, entries: list[LogEntry]) -> list[DetectionResult]:
        """Detect threats in a batch of log entries."""
        return [self.detect(e) for e in entries]

    def _map_techniques(self, entry: LogEntry, fv: list[float]) -> list[str]:
        """Map feature vector to MITRE ATT&CK techniques."""
        techniques = []
        cmd = entry.command_line

        if fv[8] > 0:   techniques.append("T1059.001")  # PowerShell encoded
        if fv[6] > 0:   techniques.append("T1218")       # LOLBAS
        if fv[25] > 0:  techniques.append("T1003.001")   # LSASS dump
        if fv[26] > 0:  techniques.append("T1003.006")   # DCSync
        if fv[23] > 0:  techniques.append("T1548.002")   # UAC bypass
        if fv[32] > 0:  techniques.append("T1055")       # Process injection
        if fv[14] > 0:  techniques.append("T1021.002")   # SMB lateral
        if fv[29] > 0:  techniques.append("T1569.002")   # PsExec
        if fv[30] > 0:  techniques.append("T1041")       # Exfil over C2
        if fv[31] > 0:  techniques.append("T1490")       # Inhibit recovery
        if fv[34] > 0:  techniques.append("T1070.004")   # File deletion
        if fv[36] > 0:  techniques.append("T1134")       # Token manipulation
        if fv[20] > 0:  techniques.append("T1547.001")   # Registry run key
        if fv[12] > 0:  techniques.append("T1095")       # Non-standard port C2

        return list(set(techniques))

    def _extract_indicators(self, entry: LogEntry, fv: list[float]) -> list[str]:
        """Extract human-readable threat indicators."""
        indicators = []
        if fv[5] > 0:  indicators.append(f"Suspicious process: {entry.process}")
        if fv[8] > 0:  indicators.append("Encoded PowerShell command")
        if fv[25] > 0: indicators.append("LSASS memory access")
        if fv[26] > 0: indicators.append("DCSync replication request")
        if fv[23] > 0: indicators.append("UAC bypass via fodhelper")
        if fv[32] > 0: indicators.append("Process injection into LSASS")
        if fv[12] > 0: indicators.append(f"C2 port {entry.dest_port}")
        if fv[31] > 0: indicators.append("Shadow copy deletion")
        return indicators

    def _compute_threat_level(
        self,
        score: AnomalyScore,
        techniques: list[str],
        entry: LogEntry,
    ) -> str:
        """Compute overall threat level."""
        # High-severity techniques override ML score
        critical_techniques = {"T1003.001", "T1003.006", "T1055", "T1490"}
        if any(t in critical_techniques for t in techniques):
            return "CRITICAL"
        if entry.severity == "critical":
            return "CRITICAL"
        if score.score >= 0.8 or len(techniques) >= 3:
            return "HIGH"
        if score.score >= 0.5 or len(techniques) >= 1:
            return "MEDIUM"
        if score.score >= 0.3:
            return "LOW"
        return "NONE"

    def stats(self) -> dict:
        return {
            "detections":  self._detection_count,
            "fitted":      self._fitted,
            "ml_stats":    self.ml_engine.stats(),
        }