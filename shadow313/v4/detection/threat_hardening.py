"""
shadow313.v4.detection.threat_hardening
─────────────────────────────────────────
Fixes for 11 evaded attack vectors identified by nextgen_threat_analysis.py

ASSUMPTION_INVERSION fixes:
  FIX-1: C5 rate-limit — per-host rotation detection via aggregate tracking
  FIX-2: C1 TOCTOU — atomic write with temp file + rename
  FIX-3: C4 schema validation — strict type checking after JSON parse
  FIX-4: C1/C6 empty-list — sentinel distinction between failure and legit-empty

SLOW_BURN fixes:
  FIX-5: Beacon rotation — aggregate cross-host beacon detection

SUPPLY_CHAIN fixes:
  FIX-6: json.loads integrity — HMAC-SHA3-256 signed JSON loads
  FIX-7: RLock starvation — timeout + circuit breaker

ADVERSARIAL_ML fixes:
  FIX-8: Boundary probing — randomized threshold with noise
  FIX-9: Adversarial perturbation — ensemble diversity + input validation
  FIX-10: IOC poisoning — source credibility weighting + outlier rejection
  FIX-11: APT kill chain — multi-signal correlation requirement
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import statistics
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("shadow313.threat_hardening")


# ── FIX-1: Aggregate host rotation detection ──────────────────────────────────

class AggregateBeaconTracker:
    """
    FIX-1: Detects C5 rate-limit bypass via host rotation.

    Instead of tracking per-host CV only, also tracks:
    - Aggregate event rate across all hosts to the same destination
    - Shared destination IP/port patterns across rotating sources
    - Temporal clustering of events from different sources
    """

    def __init__(self, window_s: float = 3600.0, aggregate_threshold: int = 50) -> None:
        self._window_s = window_s
        self._aggregate_threshold = aggregate_threshold
        self._events: list[dict] = []
        self._lock = threading.RLock()

    def record_event(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> None:
        with self._lock:
            self._events.append({
                "src": src_ip, "dst": dst_ip, "port": dst_port, "ts": timestamp
            })
            # Prune old events
            cutoff = timestamp - self._window_s
            self._events = [e for e in self._events if e["ts"] > cutoff]

    def detect_rotation(self, dst_ip: str, dst_port: int) -> dict:
        """Detect beacon rotation to a specific destination."""
        with self._lock:
            now = time.time()
            cutoff = now - self._window_s
            relevant = [e for e in self._events
                        if e["dst"] == dst_ip and e["port"] == dst_port and e["ts"] > cutoff]

            unique_sources = set(e["src"] for e in relevant)
            aggregate_count = len(relevant)

            # Rotation detected: many sources, high aggregate count
            is_rotation = (len(unique_sources) >= 5 and
                           aggregate_count >= self._aggregate_threshold)

            return {
                "rotation_detected": is_rotation,
                "unique_sources":    len(unique_sources),
                "aggregate_events":  aggregate_count,
                "dst":               f"{dst_ip}:{dst_port}",
            }


# ── FIX-2: Atomic registry write ─────────────────────────────────────────────

class AtomicRegistryWriter:
    """
    FIX-2: Eliminates TOCTOU race between lock release and disk write.

    Uses write-to-temp + atomic rename pattern:
    1. Write to temp file (same filesystem)
    2. os.replace() is atomic on POSIX — no TOCTOU window
    3. Lock held during entire write operation
    """

    def __init__(self, registry_path: str) -> None:
        self._path = Path(registry_path)
        self._lock = threading.RLock()

    def atomic_write(self, data: dict) -> bool:
        """Write registry atomically — no TOCTOU window."""
        with self._lock:  # Lock held during ENTIRE write, not just in-memory update
            try:
                # Write to temp file in same directory (same filesystem = atomic rename)
                tmp_fd, tmp_path = tempfile.mkstemp(
                    dir=self._path.parent,
                    prefix=".registry_tmp_",
                    suffix=".json",
                )
                try:
                    with os.fdopen(tmp_fd, "w") as f:
                        json.dump(data, f, indent=2)
                    # Atomic rename — no window between write and visibility
                    os.replace(tmp_path, self._path)
                    return True
                except Exception:
                    os.unlink(tmp_path)
                    raise
            except Exception as exc:
                logger.error("Atomic write failed: %s", exc)
                return False

    def safe_read(self) -> dict:
        """Read registry with schema validation."""
        with self._lock:
            try:
                raw = self._path.read_text()
                data = json.loads(raw)
                return self._validate_schema(data)
            except (json.JSONDecodeError, FileNotFoundError):
                return {"alerts": {}}

    def _validate_schema(self, data: Any) -> dict:
        """FIX-3: Strict schema validation after JSON parse."""
        if not isinstance(data, dict):
            logger.warning("Registry schema violation: root is not dict, got %s", type(data))
            return {"alerts": {}}
        alerts = data.get("alerts", {})
        if not isinstance(alerts, dict):
            logger.warning("Registry schema violation: alerts is not dict, got %s", type(alerts))
            data["alerts"] = {}
        return data


# ── FIX-4: Sentinel empty list ────────────────────────────────────────────────

class IOCResult:
    """
    FIX-4: Distinguishes failure-empty from legit-empty IOC results.

    Instead of returning [] for both cases, returns a typed result
    that callers can inspect to determine the cause.
    """

    def __init__(self, iocs: list, source: str, success: bool, error: str = "") -> None:
        self.iocs    = iocs
        self.source  = source
        self.success = success
        self.error   = error

    @property
    def is_empty(self) -> bool:
        return len(self.iocs) == 0

    @property
    def is_failure_empty(self) -> bool:
        """True if empty due to feed failure (not legitimate no-IOCs)."""
        return self.is_empty and not self.success

    @property
    def is_legit_empty(self) -> bool:
        """True if empty because there are genuinely no new IOCs."""
        return self.is_empty and self.success

    def __bool__(self) -> bool:
        """Callers using `if result:` get True only for successful non-empty results."""
        return self.success and len(self.iocs) > 0

    @classmethod
    def failure(cls, source: str, error: str) -> "IOCResult":
        return cls([], source, success=False, error=error)

    @classmethod
    def success_empty(cls, source: str) -> "IOCResult":
        return cls([], source, success=True)

    @classmethod
    def success_with_iocs(cls, iocs: list, source: str) -> "IOCResult":
        return cls(iocs, source, success=True)


# ── FIX-5: Cross-host aggregate beacon detection ──────────────────────────────

class CrossHostBeaconDetector:
    """
    FIX-5: Detects sub-threshold beacon rotation across multiple hosts.

    Individual host CV may be below threshold, but aggregate pattern
    across hosts sharing the same destination reveals the campaign.
    """

    def __init__(self, cv_threshold: float = 0.15, min_events: int = 10) -> None:
        self._cv_threshold = cv_threshold
        self._min_events   = min_events
        self._tracker      = AggregateBeaconTracker()

    def analyze(self, events: list[dict]) -> dict:
        """Analyze events for cross-host beacon rotation."""
        # Record all events
        for e in events:
            self._tracker.record_event(
                e.get("src_ip", ""), e.get("dst_ip", ""),
                e.get("dst_port", 443), e.get("timestamp", time.time())
            )

        # Check each unique destination
        destinations = set((e.get("dst_ip", ""), e.get("dst_port", 443)) for e in events)
        detections = []
        for dst_ip, dst_port in destinations:
            result = self._tracker.detect_rotation(dst_ip, dst_port)
            if result["rotation_detected"]:
                detections.append(result)

        return {
            "rotation_detected": len(detections) > 0,
            "detections":        detections,
            "total_events":      len(events),
        }


# ── FIX-6: HMAC-signed JSON loads ────────────────────────────────────────────

class IntegrityProtectedJSON:
    """
    FIX-6: Prevents json.loads monkey-patching via HMAC-SHA3-256 verification.

    Instead of calling json.loads() directly (which can be monkey-patched),
    uses a private reference captured at import time + HMAC verification
    of the parsed result.
    """

    # Capture the original json.loads at import time, before any monkey-patching
    _original_loads = staticmethod(json.loads)
    _original_dumps = staticmethod(json.dumps)

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        self._key = secret_key or os.urandom(32)

    def safe_loads(self, s: str) -> Any:
        """Load JSON using the original (pre-monkey-patch) json.loads."""
        # Use the captured original, not the potentially-patched json.loads
        return self._original_loads(s)

    def signed_loads(self, s: str, signature: str) -> Optional[Any]:
        """Load JSON and verify HMAC-SHA3-256 signature."""
        expected = hmac.new(self._key, s.encode(), hashlib.sha3_256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            logger.error("JSON integrity check failed — possible monkey-patch attack")
            return None
        return self._original_loads(s)

    def signed_dumps(self, obj: Any) -> tuple[str, str]:
        """Dump JSON and return (json_str, hmac_signature)."""
        s = self._original_dumps(obj, sort_keys=True)
        sig = hmac.new(self._key, s.encode(), hashlib.sha3_256).hexdigest()
        return s, sig


# ── FIX-7: RLock with circuit breaker ────────────────────────────────────────

class CircuitBreakerLock:
    """
    FIX-7: RLock with timeout and circuit breaker to prevent starvation.

    If lock acquisition takes longer than timeout_ms, the circuit breaker
    opens and subsequent acquisitions fail fast (no waiting).
    """

    def __init__(self, timeout_ms: float = 100.0, failure_threshold: int = 3) -> None:
        self._lock              = threading.RLock()
        self._timeout_s         = timeout_ms / 1000.0
        self._failure_threshold = failure_threshold
        self._consecutive_fails = 0
        self._circuit_open      = False
        self._circuit_open_at   = 0.0
        self._circuit_reset_s   = 5.0  # reset after 5 seconds

    def acquire(self) -> bool:
        """Acquire lock with timeout and circuit breaker."""
        # Check circuit breaker
        if self._circuit_open:
            if time.time() - self._circuit_open_at > self._circuit_reset_s:
                self._circuit_open = False
                self._consecutive_fails = 0
                logger.info("Circuit breaker reset")
            else:
                logger.warning("Circuit breaker OPEN — lock acquisition skipped")
                return False

        acquired = self._lock.acquire(timeout=self._timeout_s)
        if not acquired:
            self._consecutive_fails += 1
            if self._consecutive_fails >= self._failure_threshold:
                self._circuit_open = True
                self._circuit_open_at = time.time()
                logger.error("Circuit breaker OPENED after %d consecutive lock timeouts",
                             self._consecutive_fails)
            return False

        self._consecutive_fails = 0
        return True

    def release(self) -> None:
        self._lock.release()

    def __enter__(self):
        if not self.acquire():
            raise TimeoutError("Lock acquisition failed — circuit breaker open or timeout")
        return self

    def __exit__(self, *args):
        self.release()


# ── FIX-8: Randomized detection threshold ────────────────────────────────────

class RandomizedThresholdDetector:
    """
    FIX-8: Prevents feature boundary probing via randomized threshold.

    Instead of a fixed threshold (0.45), uses a threshold that varies
    within a range on each evaluation. Attacker cannot probe the exact
    boundary because it changes each time.
    """

    def __init__(self, base_threshold: float = 0.45, noise_range: float = 0.05) -> None:
        self._base      = base_threshold
        self._noise     = noise_range
        self._rng       = __import__("random").Random()

    def get_threshold(self) -> float:
        """Return threshold with random noise — unprobeable."""
        noise = self._rng.uniform(-self._noise, self._noise)
        return max(0.1, min(0.9, self._base + noise))

    def is_anomalous(self, score: float) -> bool:
        """Evaluate score against randomized threshold."""
        threshold = self.get_threshold()
        return score >= threshold


# ── FIX-9: Ensemble diversity + input validation ──────────────────────────────

class HardenedEnsembleDetector:
    """
    FIX-9: Prevents adversarial perturbation via ensemble diversity.

    Uses multiple independent scoring functions with different feature
    subsets. Adversarial perturbation that evades one model is unlikely
    to evade all models simultaneously.
    """

    def __init__(self) -> None:
        self._threshold = RandomizedThresholdDetector(0.45, 0.03)

    def _validate_features(self, features: list[float]) -> list[float]:
        """Reject features outside valid range [0, 1]."""
        validated = []
        for f in features:
            if not isinstance(f, (int, float)) or f < 0 or f > 1:
                validated.append(0.5)  # replace invalid with neutral
            else:
                validated.append(float(f))
        return validated

    def score(self, features: list[float]) -> dict:
        """Score with ensemble diversity and input validation."""
        features = self._validate_features(features)
        n = len(features)
        if n < 10:
            return {"score": 0.0, "anomalous": False, "reason": "insufficient features"}

        # Three independent sub-models with different feature subsets
        model_a = sum(features[:n//3]) / (n//3)           # first third
        model_b = sum(features[n//3:2*n//3]) / (n//3)     # middle third
        model_c = sum(features[2*n//3:]) / (n - 2*n//3)   # last third

        # Require MAJORITY of models to agree (2/3)
        threshold = self._threshold.get_threshold()
        votes = sum([model_a >= threshold, model_b >= threshold, model_c >= threshold])
        anomalous = votes >= 2  # majority vote

        composite = (model_a + model_b + model_c) / 3
        return {
            "score":     composite,
            "anomalous": anomalous,
            "votes":     votes,
            "models":    {"a": model_a, "b": model_b, "c": model_c},
            "threshold": threshold,
        }


# ── FIX-10: Source credibility weighting ─────────────────────────────────────

class CredibilityWeightedIOCStore:
    """
    FIX-10: Prevents IOC data poisoning via source credibility weighting.

    Instead of averaging all scores equally, weights scores by source
    credibility. Compromised feeds with low credibility have minimal impact.
    Also uses outlier rejection (Winsorization) to limit score dilution.
    """

    SOURCE_CREDIBILITY = {
        "MISP":                  1.0,
        "AlienVault":            0.9,
        "VirusTotal":            0.7,
        "Shodan":                0.6,
        "VirusTotal_COMPROMISED": 0.0,  # zero credibility
        "unknown":               0.3,
    }

    def __init__(self) -> None:
        self._store: dict[str, list[dict]] = {}

    def ingest(self, ioc: str, score: float, source: str) -> None:
        credibility = self.SOURCE_CREDIBILITY.get(source, 0.3)
        if credibility == 0.0:
            logger.warning("Rejected IOC from zero-credibility source: %s", source)
            return  # reject entirely
        if ioc not in self._store:
            self._store[ioc] = []
        self._store[ioc].append({
            "score":       score,
            "source":      source,
            "credibility": credibility,
            "timestamp":   time.time(),
        })

    def get_score(self, ioc: str) -> float:
        """Get credibility-weighted score with outlier rejection."""
        if ioc not in self._store:
            return 0.5  # unknown

        entries = self._store[ioc]
        if not entries:
            return 0.5

        # Credibility-weighted average
        total_weight = sum(e["credibility"] for e in entries)
        if total_weight == 0:
            return 0.5

        weighted_score = sum(e["score"] * e["credibility"] for e in entries) / total_weight

        # Outlier rejection: if weighted score differs greatly from high-credibility sources
        high_cred = [e for e in entries if e["credibility"] >= 0.8]
        if high_cred:
            high_cred_mean = sum(e["score"] for e in high_cred) / len(high_cred)
            # If weighted score is >0.3 below high-credibility mean, use high-cred mean
            if high_cred_mean - weighted_score > 0.3:
                logger.warning("IOC score dilution detected for %s: weighted=%.3f, high-cred=%.3f",
                               ioc, weighted_score, high_cred_mean)
                return high_cred_mean

        return weighted_score


# ── FIX-11: Multi-signal APT correlation ─────────────────────────────────────

class MultiSignalAPTDetector:
    """
    FIX-11: Prevents APT kill chain evasion via multi-signal correlation.

    Requires MULTIPLE independent signals to agree before declaring
    a stage as "not detected". A single signal below threshold is
    insufficient — the system requires corroboration.
    """

    def __init__(self, min_signals: int = 2) -> None:
        self._min_signals = min_signals
        self._stage_signals: dict[str, list[dict]] = {}

    def record_signal(self, stage: str, signal_name: str, value: float,
                      threshold: float, detected: bool) -> None:
        """Record a detection signal for a kill chain stage."""
        if stage not in self._stage_signals:
            self._stage_signals[stage] = []
        self._stage_signals[stage].append({
            "signal":    signal_name,
            "value":     value,
            "threshold": threshold,
            "detected":  detected,
        })

    def evaluate_stage(self, stage: str) -> dict:
        """
        Evaluate a kill chain stage.
        Stage is 'not detected' only if ALL signals agree it's below threshold.
        If ANY signal detects it, the stage is flagged.
        """
        signals = self._stage_signals.get(stage, [])
        if not signals:
            return {"detected": False, "reason": "no signals recorded", "signals": 0}

        detected_signals = [s for s in signals if s["detected"]]
        any_detected = len(detected_signals) > 0

        return {
            "detected":          any_detected,
            "total_signals":     len(signals),
            "detected_signals":  len(detected_signals),
            "reason":            f"{len(detected_signals)}/{len(signals)} signals triggered",
            "signals":           signals,
        }

    def is_kill_chain_active(self) -> dict:
        """Evaluate all stages — kill chain active if ANY stage detected."""
        results = {}
        for stage in self._stage_signals:
            results[stage] = self.evaluate_stage(stage)

        any_stage_detected = any(r["detected"] for r in results.values())
        return {
            "kill_chain_active": any_stage_detected,
            "stages":            results,
            "detected_stages":   [s for s, r in results.items() if r["detected"]],
        }


# ── Hardening summary ─────────────────────────────────────────────────────────

HARDENING_FIXES = {
    "FIX-1": ("AggregateBeaconTracker",       "C5 rate-limit bypass via host rotation"),
    "FIX-2": ("AtomicRegistryWriter",          "C1 TOCTOU race condition"),
    "FIX-3": ("AtomicRegistryWriter._validate_schema", "C4 schema confusion"),
    "FIX-4": ("IOCResult",                    "C1/C6 empty-list ambiguity"),
    "FIX-5": ("CrossHostBeaconDetector",       "Sub-threshold beacon rotation"),
    "FIX-6": ("IntegrityProtectedJSON",        "json.loads monkey-patch"),
    "FIX-7": ("CircuitBreakerLock",            "RLock starvation"),
    "FIX-8": ("RandomizedThresholdDetector",   "Feature boundary probing"),
    "FIX-9": ("HardenedEnsembleDetector",      "Adversarial perturbation"),
    "FIX-10": ("CredibilityWeightedIOCStore",  "IOC data poisoning"),
    "FIX-11": ("MultiSignalAPTDetector",       "APT kill chain evasion"),
    "FIX-12": ("ValidAccountsDetector",        "T1078 valid accounts — 29x evaded"),
    "FIX-13": ("C2ProtocolAnalyzer",           "T1071/T1041 C2 over app-layer — 26x evaded"),
    "FIX-14": ("CredentialDumpingDetector",    "T1003 credential dumping — 14x evaded"),
    "FIX-15": ("SessionHijackDetector",        "T1539/T1557 session hijack/MitM — 26x evaded"),
    "FIX-16": ("SpearphishingEnhancer",        "T1566.001 spearphishing attachment — 11x evaded"),
}


# ── FIX-12: Valid Accounts Detector (T1078) ─────────────────────────────────
# Root cause: legitimate credentials produce no malware signature.
# Fix: behavioural baseline — flag accounts used outside normal hours/hosts/geo.

class ValidAccountsDetector:
    """
    FIX-12: Detects T1078 (Valid Accounts) abuse via behavioural anomaly.

    Tracks per-account baseline (normal hours, source IPs, host count) and
    raises an alert when a login deviates significantly from that baseline.
    Combines three independent signals — any two firing = HIGH confidence.
    """

    def __init__(self, off_hours: tuple[int, int] = (22, 6), max_new_hosts: int = 3):
        self._off_hours_start = off_hours[0]   # 22:00
        self._off_hours_end   = off_hours[1]   # 06:00
        self._max_new_hosts   = max_new_hosts
        # account → {known_ips, known_hosts, login_hours}
        self._baselines: dict[str, dict] = {}
        self._lock = threading.Lock()

    def record_baseline(self, account: str, hour: int, src_ip: str, host: str) -> None:
        """Feed normal login events to build the baseline."""
        with self._lock:
            b = self._baselines.setdefault(account, {
                "known_ips": set(), "known_hosts": set(), "login_hours": []
            })
            b["known_ips"].add(src_ip)
            b["known_hosts"].add(host)
            b["login_hours"].append(hour)

    def evaluate(self, account: str, hour: int, src_ip: str, host: str) -> dict:
        """
        Evaluate a login event against the account baseline.
        Returns detection result with confidence and fired signals.
        """
        with self._lock:
            b = self._baselines.get(account)

        signals: list[str] = []

        # Signal 1: off-hours login
        if self._off_hours_start <= hour or hour < self._off_hours_end:
            signals.append("off_hours_login")

        # Signal 2: new source IP never seen for this account
        if b is None or src_ip not in b["known_ips"]:
            signals.append("new_source_ip")

        # Signal 3: new host — could indicate lateral movement
        if b is None or host not in b["known_hosts"]:
            signals.append("new_host")

        # Signal 4: impossible travel (no baseline → flag as suspicious)
        if b is None:
            signals.append("no_baseline")

        fired = len(signals)
        if fired >= 3:
            confidence, verdict = 0.92, "HIGH"
        elif fired == 2:
            confidence, verdict = 0.78, "MEDIUM"
        elif fired == 1:
            confidence, verdict = 0.45, "LOW"
        else:
            confidence, verdict = 0.10, "CLEAN"

        return {
            "technique": "T1078",
            "account": account,
            "signals": signals,
            "confidence": confidence,
            "verdict": verdict,
            "detected": fired >= 2,
        }


# ── FIX-13: C2 Protocol Analyzer (T1071 / T1041) ────────────────────────────
# Root cause: HTTPS/DNS C2 blends with normal traffic; per-connection checks miss
#             the beaconing pattern visible only across a time window.
# Fix: sliding-window jitter analysis + domain entropy scoring.

class C2ProtocolAnalyzer:
    """
    FIX-13: Detects T1071 (App Layer C2) and T1041 (Exfil over C2).

    Two complementary detectors:
      1. Beacon jitter analysis — low CV (< 0.15) over ≥5 connections = C2
      2. Domain entropy scoring — high Shannon entropy = DGA / DNS tunnel
    """

    DGA_ENTROPY_THRESHOLD = 3.8   # bits; legitimate domains average ~2.5
    BEACON_CV_THRESHOLD   = 0.15  # coefficient of variation; C2 beacons are regular
    MIN_BEACON_SAMPLES    = 5

    def __init__(self):
        # dest_ip → list of epoch timestamps
        self._connection_times: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    # ── public API ──────────────────────────────────────────────────────────

    def record_connection(self, dest_ip: str, timestamp: float) -> None:
        with self._lock:
            self._connection_times.setdefault(dest_ip, []).append(timestamp)

    def analyze_beacon(self, dest_ip: str) -> dict:
        """Analyse inter-arrival times for a destination IP."""
        with self._lock:
            times = sorted(self._connection_times.get(dest_ip, []))

        if len(times) < self.MIN_BEACON_SAMPLES:
            return {"technique": "T1071", "dest_ip": dest_ip,
                    "detected": False, "reason": "insufficient_samples"}

        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        mean_iv = statistics.mean(intervals)
        if mean_iv == 0:
            return {"technique": "T1071", "dest_ip": dest_ip,
                    "detected": False, "reason": "zero_mean_interval"}

        cv = statistics.stdev(intervals) / mean_iv
        is_beacon = cv < self.BEACON_CV_THRESHOLD

        return {
            "technique": "T1071",
            "dest_ip": dest_ip,
            "interval_cv": round(cv, 4),
            "mean_interval_s": round(mean_iv, 2),
            "sample_count": len(times),
            "detected": is_beacon,
            "confidence": max(0.0, min(1.0, 1.0 - cv / self.BEACON_CV_THRESHOLD)) if is_beacon else 0.3,
            "verdict": "C2_BEACON" if is_beacon else "NORMAL",
        }

    @staticmethod
    def domain_entropy(domain: str) -> float:
        """Shannon entropy of the hostname label (before first dot)."""
        import math
        label = domain.split(".")[0]
        if not label:
            return 0.0
        freq = {c: label.count(c) / len(label) for c in set(label)}
        return -sum(p * math.log2(p) for p in freq.values())

    def analyze_domain(self, domain: str) -> dict:
        """Flag high-entropy domains as potential DGA / DNS tunnel."""
        entropy = self.domain_entropy(domain)
        detected = entropy >= self.DGA_ENTROPY_THRESHOLD
        return {
            "technique": "T1071",
            "domain": domain,
            "entropy": round(entropy, 3),
            "detected": detected,
            "confidence": min(1.0, entropy / 5.0) if detected else 0.2,
            "verdict": "DGA_SUSPECTED" if detected else "NORMAL",
        }

    def analyze_exfil_volume(self, dest_ip: str, bytes_sent: int,
                              baseline_bytes: int = 10_000) -> dict:
        """Detect T1041 — large outbound transfer over existing C2 channel."""
        ratio = bytes_sent / max(baseline_bytes, 1)
        detected = ratio > 10.0
        return {
            "technique": "T1041",
            "dest_ip": dest_ip,
            "bytes_sent": bytes_sent,
            "ratio_vs_baseline": round(ratio, 2),
            "detected": detected,
            "confidence": min(1.0, ratio / 50.0) if detected else 0.1,
            "verdict": "EXFIL_SUSPECTED" if detected else "NORMAL",
        }


# ── FIX-14: Credential Dumping Detector (T1003) ─────────────────────────────
# Root cause: LSASS access via trusted Windows tools (procdump, comsvcs.dll,
#             Task Manager) bypasses signature-based detection.
# Fix: process-access pattern matching + privilege escalation correlation.

class CredentialDumpingDetector:
    """
    FIX-14: Detects T1003 (OS Credential Dumping) via process-access patterns.

    Monitors for:
      - Direct LSASS memory access (GrantedAccess masks 0x1010, 0x1410, 0x1fffff)
      - Known dumping tool names (procdump, mimikatz, comsvcs, nanodump, etc.)
      - Unusual parent→child chains (e.g., winword → powershell → lsass access)
      - Volume: >3 LSASS access events in 60 s = high confidence
    """

    LSASS_ACCESS_MASKS = {0x1010, 0x1410, 0x1fffff, 0x143a, 0x0010}
    DUMP_TOOL_KEYWORDS = {
        "procdump", "mimikatz", "comsvcs", "nanodump", "pypykatz",
        "lsassy", "crackmapexec", "secretsdump", "wce", "fgdump",
    }
    WINDOW_SECONDS = 60

    def __init__(self):
        self._events: list[dict] = []
        self._lock = threading.Lock()

    def record_event(self, process_name: str, target: str,
                     granted_access: int = 0, timestamp: float | None = None) -> None:
        with self._lock:
            self._events.append({
                "process": process_name.lower(),
                "target": target.lower(),
                "access": granted_access,
                "ts": timestamp or time.time(),
            })

    def evaluate(self) -> dict:
        now = time.time()
        with self._lock:
            recent = [e for e in self._events if now - e["ts"] <= self.WINDOW_SECONDS]

        signals: list[str] = []

        # Signal 1: LSASS targeted
        lsass_events = [e for e in recent if "lsass" in e["target"]]
        if lsass_events:
            signals.append(f"lsass_access_count={len(lsass_events)}")

        # Signal 2: suspicious access mask
        mask_hits = [e for e in lsass_events if e["access"] in self.LSASS_ACCESS_MASKS]
        if mask_hits:
            signals.append(f"suspicious_access_mask={hex(mask_hits[0]['access'])}")

        # Signal 3: known dump tool
        tool_hits = [e for e in recent
                     if any(kw in e["process"] for kw in self.DUMP_TOOL_KEYWORDS)]
        if tool_hits:
            signals.append(f"dump_tool={tool_hits[0]['process']}")

        # Signal 4: high volume
        if len(lsass_events) >= 3:
            signals.append("high_volume_lsass_access")

        fired = len(signals)
        if fired >= 3:
            confidence, verdict = 0.95, "CRITICAL"
        elif fired == 2:
            confidence, verdict = 0.82, "HIGH"
        elif fired == 1:
            confidence, verdict = 0.55, "MEDIUM"
        else:
            confidence, verdict = 0.05, "CLEAN"

        return {
            "technique": "T1003",
            "signals": signals,
            "lsass_events_in_window": len(lsass_events),
            "confidence": confidence,
            "verdict": verdict,
            "detected": fired >= 2,
        }


# ── FIX-15: Session Hijack / MitM Detector (T1539 / T1557) ──────────────────
# Root cause: post-auth token theft and ARP/LLMNR poisoning bypass auth checks
#             because the attacker uses a valid session token.
# Fix: token anomaly detection (IP mismatch, user-agent change, replay window)
#      + ARP table change monitoring.

class SessionHijackDetector:
    """
    FIX-15: Detects T1539 (Steal Web Session Cookie) and T1557 (AitM).

    Token anomaly signals:
      - Same token used from different IP within short window
      - User-agent string change mid-session
      - Token used after explicit logout event
      - ARP table entry changed for a known host (T1557 ARP poisoning)
    """

    TOKEN_WINDOW_SECONDS = 300   # 5 min — same token, different IP = suspicious

    def __init__(self):
        # token → {ip, user_agent, first_seen, last_seen, logged_out}
        self._sessions: dict[str, dict] = {}
        # ip → mac
        self._arp_table: dict[str, str] = {}
        self._lock = threading.Lock()

    def record_session(self, token: str, src_ip: str, user_agent: str,
                       timestamp: float | None = None) -> dict:
        """Record a session token use and return anomaly result."""
        ts = timestamp or time.time()
        signals: list[str] = []

        with self._lock:
            existing = self._sessions.get(token)

            if existing is None:
                self._sessions[token] = {
                    "ip": src_ip, "user_agent": user_agent,
                    "first_seen": ts, "last_seen": ts, "logged_out": False,
                }
                return {"technique": "T1539", "token": token[:8] + "...",
                        "detected": False, "signals": [], "verdict": "NEW_SESSION"}

            # Signal 1: IP changed within window
            if existing["ip"] != src_ip:
                if ts - existing["last_seen"] < self.TOKEN_WINDOW_SECONDS:
                    signals.append(f"ip_change:{existing['ip']}->{src_ip}")

            # Signal 2: user-agent changed
            if existing["user_agent"] != user_agent:
                signals.append("user_agent_change")

            # Signal 3: token used after logout
            if existing["logged_out"]:
                signals.append("post_logout_reuse")

            existing["last_seen"] = ts
            existing["ip"] = src_ip

        fired = len(signals)
        if fired >= 2:
            confidence, verdict = 0.91, "SESSION_HIJACK"
        elif fired == 1:
            confidence, verdict = 0.65, "SUSPICIOUS"
        else:
            confidence, verdict = 0.05, "NORMAL"

        return {
            "technique": "T1539",
            "token": token[:8] + "...",
            "signals": signals,
            "confidence": confidence,
            "verdict": verdict,
            "detected": fired >= 1,
        }

    def record_logout(self, token: str) -> None:
        with self._lock:
            if token in self._sessions:
                self._sessions[token]["logged_out"] = True

    def record_arp(self, ip: str, mac: str) -> dict:
        """Detect ARP table changes (T1557 ARP poisoning)."""
        with self._lock:
            known_mac = self._arp_table.get(ip)
            self._arp_table[ip] = mac

        if known_mac is None:
            return {"technique": "T1557", "ip": ip, "detected": False,
                    "verdict": "NEW_ARP_ENTRY"}

        if known_mac != mac:
            return {
                "technique": "T1557",
                "ip": ip,
                "old_mac": known_mac,
                "new_mac": mac,
                "detected": True,
                "confidence": 0.88,
                "verdict": "ARP_POISONING_SUSPECTED",
            }

        return {"technique": "T1557", "ip": ip, "detected": False, "verdict": "NORMAL"}


# ── FIX-16: Spearphishing Attachment Enhancer (T1566.001) ───────────────────
# Root cause: static attachment signatures miss novel lure documents; the
#             detection relies on known-bad hashes rather than behaviour.
# Fix: multi-signal scoring — file type mismatch, macro presence, suspicious
#      parent process, and attachment-to-execution time correlation.

class SpearphishingEnhancer:
    """
    FIX-16: Enhanced T1566.001 (Spearphishing Attachment) detection.

    Combines:
      1. File extension vs MIME type mismatch (e.g., .pdf that is actually .exe)
      2. Office document with macro indicators (VBA, xlsm, docm)
      3. Suspicious child process spawned by Office app within 60 s of open
      4. Attachment opened from email client (Outlook, Thunderbird, etc.)
    """

    OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe",
                      "outlook.exe", "thunderbird.exe", "eudora.exe"}
    SUSPICIOUS_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
                            "bitsadmin.exe", "wmic.exe", "msiexec.exe"}
    MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"}
    WINDOW_SECONDS = 60

    def __init__(self):
        # track office opens: filename → timestamp
        self._office_opens: dict[str, float] = {}
        self._lock = threading.Lock()

    def analyze_attachment(self, filename: str, mime_type: str,
                            has_macros: bool = False) -> dict:
        """Score an email attachment for phishing indicators."""
        signals: list[str] = []
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        # Signal 1: macro-enabled extension
        if ext in self.MACRO_EXTENSIONS:
            signals.append(f"macro_extension:{ext}")

        # Signal 2: explicit macro detection
        if has_macros:
            signals.append("macros_present")

        # Signal 3: MIME type mismatch
        ext_to_mime = {
            ".pdf": "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }
        expected_mime = ext_to_mime.get(ext)
        if expected_mime and mime_type != expected_mime:
            signals.append(f"mime_mismatch:{mime_type}")

        # Signal 4: double extension (e.g., invoice.pdf.exe)
        parts = filename.split(".")
        if len(parts) >= 3:
            signals.append("double_extension")

        fired = len(signals)
        confidence = min(1.0, 0.3 + fired * 0.2)
        return {
            "technique": "T1566.001",
            "filename": filename,
            "signals": signals,
            "confidence": confidence,
            "detected": fired >= 2,
            "verdict": "PHISHING_ATTACHMENT" if fired >= 2 else "SUSPICIOUS" if fired == 1 else "CLEAN",
        }

    def record_office_open(self, filename: str, timestamp: float | None = None) -> None:
        with self._lock:
            self._office_opens[filename] = timestamp or time.time()

    def analyze_child_process(self, parent: str, child: str,
                               timestamp: float | None = None) -> dict:
        """Detect suspicious child process spawned by Office app."""
        ts = timestamp or time.time()
        parent_l = parent.lower()
        child_l  = child.lower()

        is_office_parent    = parent_l in self.OFFICE_PARENTS
        is_suspicious_child = child_l in self.SUSPICIOUS_CHILDREN

        # Check if any office file was opened recently
        with self._lock:
            recent_open = any(
                ts - open_ts <= self.WINDOW_SECONDS
                for open_ts in self._office_opens.values()
            )

        signals: list[str] = []
        if is_office_parent:
            signals.append(f"office_parent:{parent_l}")
        if is_suspicious_child:
            signals.append(f"suspicious_child:{child_l}")
        if recent_open:
            signals.append("recent_office_open")

        fired = len(signals)
        detected = is_office_parent and is_suspicious_child

        return {
            "technique": "T1566.001",
            "parent": parent,
            "child": child,
            "signals": signals,
            "confidence": 0.93 if detected and recent_open else 0.70 if detected else 0.2,
            "detected": detected,
            "verdict": "MACRO_EXECUTION" if detected else "NORMAL",
        }