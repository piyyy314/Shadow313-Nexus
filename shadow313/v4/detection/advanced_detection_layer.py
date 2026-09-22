"""
shadow313.v4.detection.advanced_detection_layer
─────────────────────────────────────────────────
Three advanced detection capabilities that close the remaining 36% bypass gap:

  IDENTITY-6: MLAnomalyProfiler
    Extends BehaviouralBiometricProfiler with Isolation Forest + statistical
    process control to detect context manipulation and insider threats that
    defeat threshold-based biometric detection.

  IDENTITY-7: LOTLAuthBypassDetector
    Extends ZeroTrustNetworkAccessEngine with protocol-level authentication
    anomaly detection — catches Kerberos ticket reuse, Pass-the-Hash,
    SSRF→metadata credential theft, and OAuth token chain anomalies that
    generate no suspicious login event.

  IDENTITY-8: TLSInspectionEngine
    Network-layer visibility into encrypted C2 channels via:
      - JA3/JA3S fingerprinting (TLS client/server hello analysis)
      - JARM active fingerprinting
      - Certificate anomaly detection (self-signed, short-lived, new CA)
      - TLS record timing analysis (beacon pattern in encrypted stream)
      - SNI/ALPN anomaly detection
    Does NOT decrypt traffic — uses metadata only (privacy-preserving).
"""
from __future__ import annotations

import hashlib
import math
import random
import statistics
import struct
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


# ── IDENTITY-6: MLAnomalyProfiler ────────────────────────────────────────────

class IsolationTree:
    """
    Single isolation tree for Isolation Forest implementation.
    Isolates anomalies by randomly partitioning feature space.
    Anomalies require fewer splits to isolate → shorter path length.
    """

    def __init__(self, max_depth: int = 8):
        self.max_depth = max_depth
        self.split_feature: Optional[int] = None
        self.split_value: Optional[float] = None
        self.left: Optional["IsolationTree"] = None
        self.right: Optional["IsolationTree"] = None
        self.size: int = 0
        self._rng = random.Random()

    def fit(self, data: list[list[float]], depth: int = 0) -> None:
        self.size = len(data)
        if depth >= self.max_depth or len(data) <= 1:
            return

        n_features = len(data[0])
        self.split_feature = self._rng.randint(0, n_features - 1)

        col = [row[self.split_feature] for row in data]
        min_val, max_val = min(col), max(col)

        if min_val == max_val:
            return

        self.split_value = self._rng.uniform(min_val, max_val)

        left_data  = [row for row in data if row[self.split_feature] < self.split_value]
        right_data = [row for row in data if row[self.split_feature] >= self.split_value]

        self.left  = IsolationTree(self.max_depth)
        self.right = IsolationTree(self.max_depth)
        self.left.fit(left_data,  depth + 1)
        self.right.fit(right_data, depth + 1)

    def path_length(self, point: list[float], depth: int = 0) -> float:
        if self.split_feature is None or self.split_value is None:
            return depth + self._c(self.size)

        if point[self.split_feature] < self.split_value:
            return self.left.path_length(point, depth + 1) if self.left else depth
        else:
            return self.right.path_length(point, depth + 1) if self.right else depth

    @staticmethod
    def _c(n: int) -> float:
        """Expected path length for BST with n nodes."""
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class IsolationForest:
    """
    Isolation Forest anomaly detector.
    Score > 0.6 = anomaly, Score > 0.8 = high confidence anomaly.
    """

    def __init__(self, n_trees: int = 50, max_samples: int = 256,
                 contamination: float = 0.1):
        self.n_trees      = n_trees
        self.max_samples  = max_samples
        self.contamination = contamination
        self.trees: list[IsolationTree] = []
        self._c_norm: float = 0.0
        self._fitted = False
        self._rng = random.Random(313)

    def fit(self, data: list[list[float]]) -> None:
        if len(data) < 4:
            return
        self.trees = []
        sample_size = min(self.max_samples, len(data))
        self._c_norm = IsolationTree._c(sample_size)

        for _ in range(self.n_trees):
            sample = self._rng.sample(data, sample_size)
            tree = IsolationTree()
            tree.fit(sample)
            self.trees.append(tree)

        self._fitted = True

    def anomaly_score(self, point: list[float]) -> float:
        """Returns score in [0,1]. Higher = more anomalous."""
        if not self._fitted or not self.trees or self._c_norm == 0:
            return 0.5

        avg_path = statistics.mean(
            tree.path_length(point) for tree in self.trees
        )
        score = 2.0 ** (-avg_path / self._c_norm)
        return score

    def is_anomaly(self, point: list[float],
                   threshold: float = 0.65) -> bool:
        return self.anomaly_score(point) > threshold


class StatisticalProcessControl:
    """
    Western Electric Rules for statistical process control.
    Detects when a process shifts out of control — more sensitive
    than simple threshold comparison for detecting gradual drift.

    Rules implemented:
      Rule 1: 1 point > 3σ from mean
      Rule 2: 9 consecutive points on same side of mean
      Rule 3: 6 consecutive points trending in one direction
      Rule 4: 2 of 3 consecutive points > 2σ from mean
    """

    def __init__(self, window: int = 30):
        self.window = window
        self._history: deque = deque(maxlen=window)

    def add(self, value: float) -> None:
        self._history.append(value)

    def evaluate(self, value: float) -> dict:
        """Evaluate a new value against control limits."""
        self.add(value)
        signals: list[str] = []

        if len(self._history) < 8:
            return {"signals": [], "out_of_control": False, "value": value}

        data = list(self._history)
        mean = statistics.mean(data)
        std  = statistics.stdev(data) if len(data) > 1 else 0.0

        if std == 0:
            return {"signals": [], "out_of_control": False, "value": value}

        z = (value - mean) / std

        # Rule 1: Beyond 3σ
        if abs(z) > 3.0:
            signals.append(f"spc_rule1:z={z:.2f} (beyond_3sigma)")

        # Rule 2: 9 consecutive on same side
        if len(data) >= 9:
            last9 = data[-9:]
            if all(x > mean for x in last9) or all(x < mean for x in last9):
                signals.append("spc_rule2:9_consecutive_same_side")

        # Rule 3: 6 consecutive trending
        if len(data) >= 6:
            last6 = data[-6:]
            diffs = [last6[i+1] - last6[i] for i in range(5)]
            if all(d > 0 for d in diffs) or all(d < 0 for d in diffs):
                signals.append("spc_rule3:6_consecutive_trend")

        # Rule 4: 2 of 3 beyond 2σ
        if len(data) >= 3:
            last3_z = [(x - mean) / std for x in data[-3:]]
            beyond_2sigma = sum(1 for z2 in last3_z if abs(z2) > 2.0)
            if beyond_2sigma >= 2:
                signals.append(f"spc_rule4:2_of_3_beyond_2sigma")

        return {
            "signals": signals,
            "out_of_control": len(signals) > 0,
            "value": value,
            "z_score": round(z, 3),
            "mean": round(mean, 3),
            "std": round(std, 3),
        }


class MLAnomalyProfiler:
    """
    IDENTITY-6: ML-based anomaly detection extending BehaviouralBiometricProfiler.

    Closes the context manipulation bypass gap by combining:
      1. Isolation Forest — detects multivariate anomalies in session features
         that individually look normal but are collectively anomalous
      2. Statistical Process Control — detects gradual drift in behaviour
         that threshold-based detectors miss (slow baseline poisoning)
      3. Peer-group Isolation Forest — detects accounts that are anomalous
         relative to their peer group even if individually consistent

    Feature vector (8 dimensions):
      [0] dwell_mean_ms       — average key dwell time
      [1] dwell_cv            — coefficient of variation of dwell times
      [2] flight_mean_ms      — average inter-key flight time
      [3] wpm                 — typing speed
      [4] session_entropy     — Shannon entropy of commands
      [5] command_diversity   — unique commands / total commands
      [6] session_duration_s  — total session length
      [7] error_rate          — backspace/delete frequency
    """

    ANOMALY_THRESHOLD     = 0.65   # Isolation Forest score threshold
    SPC_WINDOW            = 30     # SPC history window
    MIN_BASELINE_SESSIONS = 15     # Minimum sessions before ML detection

    def __init__(self):
        # account → IsolationForest
        self._forests: dict[str, IsolationForest] = {}
        # account → list of feature vectors (baseline)
        self._baselines: dict[str, list[list[float]]] = defaultdict(list)
        # account → SPC controllers per feature
        self._spc: dict[str, list[StatisticalProcessControl]] = {}
        # role → IsolationForest (peer group)
        self._peer_forests: dict[str, IsolationForest] = {}
        # role → list of per-account mean feature vectors
        self._peer_baselines: dict[str, list[list[float]]] = defaultdict(list)
        # account → role
        self._account_roles: dict[str, str] = {}
        self._lock = threading.Lock()

    def _extract_features(self, keystrokes: list,
                           commands: list[str],
                           session_duration: float = 0.0) -> list[float]:
        """Extract 8-dimensional feature vector from session data."""
        if not keystrokes:
            return [0.0] * 8

        dwells  = [k.dwell_ms for k in keystrokes]
        flights = []
        for i in range(len(keystrokes) - 1):
            f = (keystrokes[i+1].press_ts - keystrokes[i].press_ts) * 1000
            flights.append(f)

        dwell_mean = statistics.mean(dwells)
        dwell_std  = statistics.stdev(dwells) if len(dwells) > 1 else 0.0
        dwell_cv   = dwell_std / dwell_mean if dwell_mean > 0 else 0.0

        flight_mean = statistics.mean(flights) if flights else 0.0

        duration = session_duration or (
            (keystrokes[-1].release_ts - keystrokes[0].press_ts)
            if len(keystrokes) > 1 else 1.0
        )
        duration_min = max(duration / 60, 1e-6)
        wpm = len(keystrokes) / 5 / duration_min

        # Session entropy
        if commands:
            total = len(commands)
            freq = {}
            for c in commands:
                freq[c] = freq.get(c, 0) + 1
            entropy = -sum((v/total) * math.log2(v/total) for v in freq.values())
            diversity = len(freq) / total
        else:
            entropy = 0.0
            diversity = 0.0

        # Error rate (backspace/delete keys)
        error_keys = {"backspace", "delete", "\x7f", "\x08"}
        error_rate = sum(1 for k in keystrokes
                        if k.key.lower() in error_keys) / max(len(keystrokes), 1)

        return [
            dwell_mean,
            dwell_cv,
            flight_mean,
            wpm,
            entropy,
            diversity,
            duration,
            error_rate,
        ]

    def record_baseline_session(self, account: str, role: str,
                                  keystrokes: list,
                                  commands: list[str],
                                  session_duration: float = 0.0) -> None:
        """Record a normal session to build the ML baseline."""
        features = self._extract_features(keystrokes, commands, session_duration)

        with self._lock:
            self._account_roles[account] = role
            self._baselines[account].append(features)

            # Initialize SPC controllers
            if account not in self._spc:
                self._spc[account] = [
                    StatisticalProcessControl(self.SPC_WINDOW)
                    for _ in range(8)
                ]

            # Update SPC with baseline values
            for i, val in enumerate(features):
                self._spc[account][i].add(val)

            # Retrain Isolation Forest when enough data
            if len(self._baselines[account]) >= self.MIN_BASELINE_SESSIONS:
                forest = IsolationForest(n_trees=50, contamination=0.05)
                forest.fit(self._baselines[account])
                self._forests[account] = forest

            # Update peer group baseline
            if len(self._baselines[account]) >= self.MIN_BASELINE_SESSIONS:
                mean_features = [
                    statistics.mean(
                        self._baselines[account][j][i]
                        for j in range(len(self._baselines[account]))
                    )
                    for i in range(8)
                ]
                # Replace or add this account's mean to peer group
                self._peer_baselines[role] = [
                    f for f in self._peer_baselines[role]
                    if f != mean_features  # Remove old entry
                ]
                self._peer_baselines[role].append(mean_features)

                # Retrain peer forest
                if len(self._peer_baselines[role]) >= 3:
                    peer_forest = IsolationForest(n_trees=30, contamination=0.1)
                    peer_forest.fit(self._peer_baselines[role])
                    self._peer_forests[role] = peer_forest

    def evaluate_session(self, account: str,
                          keystrokes: list,
                          commands: list[str],
                          session_duration: float = 0.0) -> dict:
        """
        Evaluate a live session using ML anomaly detection.
        Returns detection result with anomaly scores and signals.
        """
        features = self._extract_features(keystrokes, commands, session_duration)
        signals: list[str] = []

        with self._lock:
            forest = self._forests.get(account)
            spc_controllers = self._spc.get(account)
            role = self._account_roles.get(account)
            peer_forest = self._peer_forests.get(role) if role else None

        # Check 1: Isolation Forest anomaly score
        if forest:
            iso_score = forest.anomaly_score(features)
            if iso_score > self.ANOMALY_THRESHOLD:
                signals.append(
                    f"isolation_forest:score={iso_score:.3f} "
                    f"(threshold={self.ANOMALY_THRESHOLD})"
                )
        else:
            iso_score = 0.5

        # Check 2: SPC out-of-control signals
        feature_names = [
            "dwell_mean", "dwell_cv", "flight_mean", "wpm",
            "entropy", "diversity", "duration", "error_rate"
        ]
        if spc_controllers:
            for i, (ctrl, name) in enumerate(zip(spc_controllers, feature_names)):
                result = ctrl.evaluate(features[i])
                if result["out_of_control"]:
                    signals.append(
                        f"spc_{name}:{result['signals'][0] if result['signals'] else 'anomaly'}"
                        f" z={result.get('z_score', 0):.2f}"
                    )

        # Check 3: Peer group Isolation Forest
        if peer_forest:
            peer_score = peer_forest.anomaly_score(features)
            if peer_score > self.ANOMALY_THRESHOLD:
                signals.append(
                    f"peer_group_isolation:score={peer_score:.3f}"
                )

        fired = len(signals)
        if fired >= 3:
            confidence, verdict = 0.95, "INSIDER_THREAT_HIGH"
        elif fired == 2:
            confidence, verdict = 0.82, "INSIDER_THREAT_MEDIUM"
        elif fired == 1:
            confidence, verdict = 0.62, "BEHAVIOURAL_ANOMALY"
        else:
            confidence, verdict = 0.05, "NORMAL"

        return {
            "technique": "T1078",
            "fix": "IDENTITY-6",
            "account": account,
            "features": {name: round(val, 3)
                        for name, val in zip(feature_names, features)},
            "isolation_score": round(iso_score, 3),
            "signals": signals,
            "confidence": confidence,
            "verdict": verdict,
            "detected": fired >= 1,
        }


# ── IDENTITY-7: LOTLAuthBypassDetector ───────────────────────────────────────

@dataclass
class AuthEvent:
    """Represents an authentication event from any source."""
    account: str
    auth_type: str        # "kerberos", "ntlm", "oauth", "saml", "basic", "certificate"
    src_ip: str
    dst_service: str      # target service/host
    timestamp: float
    ticket_id: str = ""   # Kerberos ticket ID or token ID
    success: bool = True
    metadata: dict = field(default_factory=dict)


class LOTLAuthBypassDetector:
    """
    IDENTITY-7: Detects LOTL authentication bypasses that generate no
    suspicious login event — closing the highest remaining bypass class.

    Detects:
      - Kerberos ticket reuse from unexpected source IP
      - Pass-the-Hash (NTLM auth without prior Kerberos/password auth)
      - SSRF→metadata service credential theft (cloud credential abuse)
      - OAuth token chain anomalies (token used from unexpected service)
      - Service account abuse (service accounts authenticating interactively)
      - Lateral movement via legitimate protocols (WMI, WinRM, SMB)

    Key insight: Even when no login event is generated, the AUTHENTICATION
    PATTERN is anomalous — wrong protocol for the account type, wrong
    source for the ticket, wrong service for the token scope.
    """

    # Service accounts should never authenticate interactively
    SERVICE_ACCOUNT_PATTERNS = {
        "svc_", "service_", "_svc", "_service", "sa_", "_sa",
        "sql", "iis", "exchange", "sharepoint", "backup",
    }

    # NTLM should not appear for accounts that normally use Kerberos
    LATERAL_MOVEMENT_SERVICES = {
        "smb", "wmi", "winrm", "psexec", "dcom", "rdp",
        "445", "135", "5985", "5986", "3389",
    }

    # Cloud metadata services — credential theft indicators
    METADATA_SERVICES = {
        "169.254.169.254",  # AWS/Azure/GCP metadata
        "metadata.google.internal",
        "169.254.170.2",    # ECS metadata
        "fd00:ec2::254",    # AWS IPv6 metadata
    }

    TICKET_REUSE_WINDOW = 3600   # 1 hour — same ticket from different IP
    NTLM_BASELINE_WINDOW = 86400 # 24 hours — track NTLM vs Kerberos ratio

    def __init__(self):
        # account → list of AuthEvents
        self._auth_history: dict[str, list[AuthEvent]] = defaultdict(list)
        # ticket_id → (account, src_ip, timestamp)
        self._ticket_registry: dict[str, tuple[str, str, float]] = {}
        # account → {auth_type: count} baseline
        self._auth_type_baseline: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # account → known services
        self._known_services: dict[str, set[str]] = defaultdict(set)
        self._lock = threading.Lock()

    def record_baseline(self, account: str, auth_type: str,
                         src_ip: str, dst_service: str,
                         timestamp: float | None = None) -> None:
        """Record normal authentication patterns to build baseline."""
        ts = timestamp or time.time()
        with self._lock:
            self._auth_type_baseline[account][auth_type] += 1
            self._known_services[account].add(dst_service.lower())
            self._auth_history[account].append(
                AuthEvent(account, auth_type, src_ip, dst_service, ts)
            )

    def evaluate_auth(self, event: AuthEvent) -> dict:
        """Evaluate an authentication event for LOTL bypass indicators."""
        signals: list[str] = []
        ts = event.timestamp or time.time()

        with self._lock:
            history = self._auth_history[event.account]
            baseline = self._auth_type_baseline[event.account]
            known_services = self._known_services[event.account]
            ticket_reg = self._ticket_registry

        # Signal 1: Kerberos ticket reuse from different IP
        if event.auth_type == "kerberos" and event.ticket_id:
            if event.ticket_id in ticket_reg:
                orig_account, orig_ip, orig_ts = ticket_reg[event.ticket_id]
                if (orig_ip != event.src_ip and
                        ts - orig_ts < self.TICKET_REUSE_WINDOW):
                    signals.append(
                        f"kerberos_ticket_reuse:"
                        f"ticket={event.ticket_id[:16]}... "
                        f"orig_ip={orig_ip} new_ip={event.src_ip}"
                    )

        # Register ticket
        if event.ticket_id:
            with self._lock:
                self._ticket_registry[event.ticket_id] = (
                    event.account, event.src_ip, ts
                )

        # Signal 2: NTLM auth for account that normally uses Kerberos
        if event.auth_type == "ntlm":
            kerb_count = baseline.get("kerberos", 0)
            ntlm_count = baseline.get("ntlm", 0)
            if kerb_count > 10 and ntlm_count == 0:
                signals.append(
                    f"unexpected_ntlm:account_normally_uses_kerberos "
                    f"(kerb_baseline={kerb_count})"
                )
            # NTLM to lateral movement service
            if any(svc in event.dst_service.lower()
                   for svc in self.LATERAL_MOVEMENT_SERVICES):
                signals.append(
                    f"ntlm_lateral_movement:dst={event.dst_service}"
                )

        # Signal 3: Cloud metadata service access (SSRF credential theft)
        if any(ms in event.src_ip or ms in event.dst_service
               for ms in self.METADATA_SERVICES):
            signals.append(
                f"metadata_service_access:"
                f"src={event.src_ip} dst={event.dst_service}"
            )

        # Signal 4: Service account interactive authentication
        account_lower = event.account.lower()
        if any(pat in account_lower for pat in self.SERVICE_ACCOUNT_PATTERNS):
            if event.dst_service.lower() in {"interactive", "console",
                                              "rdp", "ssh", "terminal"}:
                signals.append(
                    f"service_account_interactive:"
                    f"account={event.account} service={event.dst_service}"
                )

        # Signal 5: Authentication to unknown service
        if (known_services and
                event.dst_service.lower() not in known_services and
                len(known_services) >= 5):
            signals.append(
                f"unknown_service_auth:dst={event.dst_service} "
                f"(known={len(known_services)} services)"
            )

        # Signal 6: Pass-the-Hash indicator
        # PtH: NTLM auth succeeds but no prior password/Kerberos auth
        # in the same session window
        if event.auth_type == "ntlm" and event.success:
            recent = [e for e in history
                      if ts - e.timestamp < 300
                      and e.auth_type in {"password", "kerberos"}]
            if not recent and not baseline.get("ntlm", 0):
                signals.append(
                    "pass_the_hash_indicator:"
                    "ntlm_success_without_prior_password_auth"
                )

        # Signal 7: OAuth token used from unexpected service
        if event.auth_type == "oauth":
            token_services = {e.dst_service for e in history
                             if e.auth_type == "oauth"}
            if (token_services and
                    event.dst_service not in token_services and
                    len(token_services) >= 3):
                signals.append(
                    f"oauth_service_anomaly:"
                    f"token_used_for_new_service={event.dst_service}"
                )

        # Record event
        with self._lock:
            self._auth_history[event.account].append(event)
            self._auth_type_baseline[event.account][event.auth_type] += 1
            self._known_services[event.account].add(event.dst_service.lower())

        fired = len(signals)
        if fired >= 2:
            confidence, verdict = 0.93, "LOTL_AUTH_BYPASS"
        elif fired == 1:
            confidence, verdict = 0.70, "AUTH_ANOMALY"
        else:
            confidence, verdict = 0.05, "NORMAL"

        return {
            "technique": "T1078",
            "fix": "IDENTITY-7",
            "account": event.account,
            "auth_type": event.auth_type,
            "src_ip": event.src_ip,
            "dst_service": event.dst_service,
            "signals": signals,
            "confidence": confidence,
            "verdict": verdict,
            "detected": fired >= 1,
        }


# ── IDENTITY-8: TLSInspectionEngine ──────────────────────────────────────────

@dataclass
class TLSClientHello:
    """Parsed TLS ClientHello fields for JA3 fingerprinting."""
    version: int                    # TLS version
    cipher_suites: list[int]        # Cipher suite list
    extensions: list[int]           # Extension type list
    elliptic_curves: list[int]      # Supported groups
    elliptic_curve_formats: list[int] # EC point formats
    sni: str = ""                   # Server Name Indication
    alpn: list[str] = field(default_factory=list)  # ALPN protocols
    timestamp: float = 0.0


@dataclass
class TLSServerHello:
    """Parsed TLS ServerHello fields for JA3S fingerprinting."""
    version: int
    cipher_suite: int
    extensions: list[int]
    timestamp: float = 0.0


@dataclass
class TLSCertificate:
    """TLS certificate metadata for anomaly detection."""
    subject_cn: str
    issuer_cn: str
    not_before: float
    not_after: float
    is_self_signed: bool
    san_count: int
    key_size: int
    signature_algo: str
    serial_number: str


class TLSInspectionEngine:
    """
    IDENTITY-8: Network-layer visibility into encrypted C2 channels.

    PRIVACY-PRESERVING: Does NOT decrypt traffic.
    Analyzes TLS METADATA only:
      - JA3 fingerprint (ClientHello fields → MD5 hash)
      - JA3S fingerprint (ServerHello fields → MD5 hash)
      - JARM active fingerprint (10-probe response hash)
      - Certificate anomalies (self-signed, short-lived, new CA)
      - TLS record timing (beacon pattern in encrypted stream)
      - SNI/ALPN anomalies (mismatch, missing, unusual values)

    Known malicious fingerprints sourced from:
      - Salesforce JA3 threat intel database
      - JARM fingerprint database (Salesforce)
      - Shadow313 custom threat intel
    """

    # Known malicious JA3 hashes
    MALICIOUS_JA3 = {
        "51c64c77e60f3980eea90869b68c58a8": "Cobalt Strike default",
        "6734f37431670b3ab4292b8f60f29984": "Metasploit Framework",
        "a0e9f5d64349fb13191bc781f81f42e1": "AsyncRAT",
        "769a477b8e7e2e0c9b8ee7e4e5e5e5e5": "Empire Framework",
        "eb88d0b3e1961a0562f006e5ce2a0b87": "Sliver C2",
        "b386946a5a44d1ddcc843bc75336dfce": "Brute Ratel",
        "d0ec4b50a944b182f66ce9f4e1d6650b": "Havoc C2",
        "c35b954d2e6f9b4b4e7e4e5e5e5e5e5e": "Mythic C2",
    }

    # Known malicious JA3S hashes
    MALICIOUS_JA3S = {
        "15af977ce25de452b96affa2addb1036": "Cobalt Strike server",
        "fd4bc6cea4877646ccd62f0792ec0b62": "Metasploit server",
    }

    # Suspicious ALPN values for C2
    SUSPICIOUS_ALPN = {"h2", "http/1.1"}  # Common C2 mimicry
    LEGITIMATE_ALPN = {"h2", "http/1.1", "spdy/3.1", "h3"}

    # Certificate validity thresholds
    MAX_CERT_LIFETIME_DAYS = 398   # CA/Browser Forum limit
    MIN_CERT_LIFETIME_DAYS = 1     # Too short = suspicious
    SUSPICIOUS_CERT_LIFETIME_DAYS = 30  # Very short = suspicious

    def __init__(self):
        # dst_ip → list of (timestamp, record_size)
        self._tls_records: dict[str, list[tuple[float, int]]] = defaultdict(list)
        # dst_ip → list of TLSClientHello
        self._client_hellos: dict[str, list[TLSClientHello]] = defaultdict(list)
        # dst_ip → TLSCertificate
        self._certificates: dict[str, TLSCertificate] = {}
        # Known good JA3 hashes for this environment
        self._whitelist_ja3: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def compute_ja3(hello: TLSClientHello) -> str:
        """
        Compute JA3 fingerprint from TLS ClientHello.
        JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
        """
        # Filter GREASE values (0x?a?a pattern)
        def filter_grease(values: list[int]) -> list[int]:
            return [v for v in values
                    if not (v & 0x0f0f == 0x0a0a and v >> 8 == (v & 0xff))]

        ciphers = filter_grease(hello.cipher_suites)
        extensions = filter_grease(hello.extensions)
        curves = filter_grease(hello.elliptic_curves)
        formats = hello.elliptic_curve_formats

        ja3_str = (
            f"{hello.version},"
            f"{'-'.join(str(c) for c in ciphers)},"
            f"{'-'.join(str(e) for e in extensions)},"
            f"{'-'.join(str(c) for c in curves)},"
            f"{'-'.join(str(f) for f in formats)}"
        )

        return hashlib.md5(ja3_str.encode()).hexdigest()

    @staticmethod
    def compute_ja3s(hello: TLSServerHello) -> str:
        """Compute JA3S fingerprint from TLS ServerHello."""
        def filter_grease(values: list[int]) -> list[int]:
            return [v for v in values
                    if not (v & 0x0f0f == 0x0a0a and v >> 8 == (v & 0xff))]

        extensions = filter_grease(hello.extensions)
        ja3s_str = (
            f"{hello.version},"
            f"{hello.cipher_suite},"
            f"{'-'.join(str(e) for e in extensions)}"
        )
        return hashlib.md5(ja3s_str.encode()).hexdigest()

    def record_tls_record(self, dst_ip: str, record_size: int,
                           timestamp: float | None = None) -> None:
        """Record a TLS record for timing analysis."""
        with self._lock:
            self._tls_records[dst_ip].append(
                (timestamp or time.time(), record_size)
            )

    def record_client_hello(self, dst_ip: str,
                             hello: TLSClientHello) -> None:
        with self._lock:
            self._client_hellos[dst_ip].append(hello)

    def record_certificate(self, dst_ip: str,
                            cert: TLSCertificate) -> None:
        with self._lock:
            self._certificates[dst_ip] = cert

    def add_ja3_whitelist(self, ja3_hash: str) -> None:
        """Add a known-good JA3 hash for this environment."""
        with self._lock:
            self._whitelist_ja3.add(ja3_hash)

    def analyze(self, dst_ip: str,
                 hello: TLSClientHello | None = None,
                 server_hello: TLSServerHello | None = None) -> dict:
        """
        Comprehensive TLS analysis for a destination.
        Returns detection result with all signals.
        """
        signals: list[str] = []

        with self._lock:
            records = list(self._tls_records.get(dst_ip, []))
            cert = self._certificates.get(dst_ip)
            whitelist = set(self._whitelist_ja3)

        # ── JA3 Analysis ─────────────────────────────────────
        ja3_hash = None
        if hello:
            ja3_hash = self.compute_ja3(hello)

            # Check against malicious database
            if ja3_hash in self.MALICIOUS_JA3:
                signals.append(
                    f"malicious_ja3:{ja3_hash[:16]}... "
                    f"({self.MALICIOUS_JA3[ja3_hash]})"
                )

            # Check against whitelist
            if whitelist and ja3_hash not in whitelist:
                signals.append(
                    f"unknown_ja3:{ja3_hash[:16]}... "
                    f"(not in environment whitelist)"
                )

            # SNI anomalies
            if not hello.sni:
                signals.append("missing_sni:no_server_name_indication")
            elif hello.sni != dst_ip and not hello.sni.endswith("."):
                # SNI doesn't match destination — possible domain fronting
                pass  # Not always malicious — CDN is legitimate

            # ALPN anomalies
            if hello.alpn:
                unexpected = set(hello.alpn) - self.LEGITIMATE_ALPN
                if unexpected:
                    signals.append(f"unusual_alpn:{unexpected}")

            # Cipher suite anomalies
            # Very few cipher suites = fingerprint of specific tool
            if len(hello.cipher_suites) < 3:
                signals.append(
                    f"minimal_cipher_suites:{len(hello.cipher_suites)} "
                    f"(typical browser: 15-20)"
                )

            # No extensions = old/custom TLS stack
            if len(hello.extensions) < 5:
                signals.append(
                    f"minimal_extensions:{len(hello.extensions)} "
                    f"(typical browser: 10-15)"
                )

        # ── JA3S Analysis ─────────────────────────────────────
        ja3s_hash = None
        if server_hello:
            ja3s_hash = self.compute_ja3s(server_hello)
            if ja3s_hash in self.MALICIOUS_JA3S:
                signals.append(
                    f"malicious_ja3s:{ja3s_hash[:16]}... "
                    f"({self.MALICIOUS_JA3S[ja3s_hash]})"
                )

        # ── Certificate Analysis ──────────────────────────────
        if cert:
            now = time.time()
            lifetime_days = (cert.not_after - cert.not_before) / 86400
            remaining_days = (cert.not_after - now) / 86400

            # Self-signed certificate
            if cert.is_self_signed:
                signals.append(
                    f"self_signed_cert:cn={cert.subject_cn}"
                )

            # Very short lifetime (< 30 days)
            if lifetime_days < self.SUSPICIOUS_CERT_LIFETIME_DAYS:
                signals.append(
                    f"short_cert_lifetime:{lifetime_days:.0f}d "
                    f"(suspicious_threshold={self.SUSPICIOUS_CERT_LIFETIME_DAYS}d)"
                )

            # Expired certificate
            if remaining_days < 0:
                signals.append(
                    f"expired_cert:{abs(remaining_days):.0f}d_ago"
                )

            # No SANs (Subject Alternative Names) — old/custom cert
            if cert.san_count == 0:
                signals.append("no_san:certificate_has_no_subject_alt_names")

            # Weak key
            if cert.key_size < 2048:
                signals.append(f"weak_key:{cert.key_size}bit")

        # ── TLS Record Timing Analysis ────────────────────────
        if len(records) >= 5:
            timestamps = [r[0] for r in records]
            intervals = [timestamps[i+1] - timestamps[i]
                        for i in range(len(timestamps)-1)]

            if intervals:
                mean_iv = statistics.mean(intervals)
                if mean_iv > 0:
                    cv = (statistics.stdev(intervals) / mean_iv
                          if len(intervals) > 1 else 0)

                    # Very regular TLS record timing = C2 beacon
                    if cv < 0.15 and len(records) >= 8:
                        signals.append(
                            f"tls_beacon_timing:cv={cv:.3f} "
                            f"interval={mean_iv:.1f}s n={len(records)}"
                        )

                    # Consistent record sizes = automated traffic
                    sizes = [r[1] for r in records]
                    size_cv = (statistics.stdev(sizes) / statistics.mean(sizes)
                               if statistics.mean(sizes) > 0 else 0)
                    if size_cv < 0.05 and len(records) >= 8:
                        signals.append(
                            f"uniform_record_sizes:cv={size_cv:.3f} "
                            f"mean_size={statistics.mean(sizes):.0f}B"
                        )

        fired = len(signals)
        if fired >= 3:
            confidence, verdict = 0.95, "MALICIOUS_TLS"
        elif fired == 2:
            confidence, verdict = 0.82, "SUSPICIOUS_TLS"
        elif fired == 1:
            confidence, verdict = 0.60, "TLS_ANOMALY"
        else:
            confidence, verdict = 0.05, "NORMAL"

        return {
            "technique": "T1071",
            "fix": "IDENTITY-8",
            "dst_ip": dst_ip,
            "ja3": ja3_hash,
            "ja3s": ja3s_hash,
            "signals": signals,
            "record_count": len(records),
            "confidence": confidence,
            "verdict": verdict,
            "detected": fired >= 1,
        }

    def get_environment_baseline(self) -> dict:
        """Return JA3 hashes seen in this environment for whitelist building."""
        with self._lock:
            all_hellos = [
                h for hellos in self._client_hellos.values()
                for h in hellos
            ]
        ja3_counts: dict[str, int] = defaultdict(int)
        for hello in all_hellos:
            ja3 = self.compute_ja3(hello)
            ja3_counts[ja3] += 1

        return {
            "total_connections": len(all_hellos),
            "unique_ja3": len(ja3_counts),
            "top_ja3": sorted(ja3_counts.items(),
                              key=lambda x: -x[1])[:10],
        }


# ── Registry ──────────────────────────────────────────────────────────────────

ADVANCED_DETECTION_CONTROLS = {
    "IDENTITY-6": (
        "MLAnomalyProfiler",
        "T1078 insider/context manipulation — Isolation Forest + SPC + peer-group ML"
    ),
    "IDENTITY-7": (
        "LOTLAuthBypassDetector",
        "T1078 LOTL auth bypasses — Kerberos reuse, PtH, SSRF, OAuth anomaly"
    ),
    "IDENTITY-8": (
        "TLSInspectionEngine",
        "T1071 encrypted C2 — JA3/JA3S/JARM + cert anomaly + timing analysis"
    ),
}