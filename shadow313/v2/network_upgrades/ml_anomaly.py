"""
shadow313.v2.network_upgrades.ml_anomaly
Feature #7 — ML Anomaly Detection
Isolation Forest + ONNX runtime for network flow anomaly detection.
Replaces v1 heuristic rules with trained ML model.
"""
from __future__ import annotations
import json
import math
import os
import struct
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

try:
    import onnxruntime as ort
    _HAS_ORT = True
except ImportError:
    _HAS_ORT = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False


# ---------------------------------------------------------------------------
# Feature extraction from network flows
# ---------------------------------------------------------------------------

FLOW_FEATURES = [
    "duration_s",       # Connection duration
    "pkt_count",        # Total packets
    "byte_count",       # Total bytes
    "avg_pkt_size",     # Average packet size
    "bytes_per_sec",    # Throughput
    "pkts_per_sec",     # Packet rate
    "dst_port",         # Destination port (normalized)
    "protocol_tcp",     # 1 if TCP else 0
    "protocol_udp",     # 1 if UDP else 0
    "protocol_icmp",    # 1 if ICMP else 0
    "is_internal_src",  # Source IP is RFC1918
    "is_internal_dst",  # Dest IP is RFC1918
    "port_well_known",  # Dest port < 1024
    "port_ephemeral",   # Dest port >= 49152
]

ANOMALY_LABELS = {
    "beaconing":       "Regular intervals to external host — possible C2",
    "data_exfil":      "High outbound bytes to single destination",
    "port_scan":       "Many ports on one host in short window",
    "suspicious_port": "Traffic on uncommon/dangerous port",
    "ml_anomaly":      "Statistical outlier detected by Isolation Forest",
}

DANGEROUS_PORTS = {
    4444, 4445, 1337, 31337, 6666, 6667, 6668, 6669,  # Metasploit/IRC
    9001, 9030,                                          # Tor
    3389, 5900, 5901,                                    # RDP/VNC
    2375, 2376,                                          # Docker API
    6443, 8443, 10250,                                   # K8s
    23, 21,                                              # Telnet/FTP
}

RFC1918_PREFIXES = [
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
]


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in RFC1918_PREFIXES)


def _extract_features(flow: dict) -> list[float]:
    """Extract normalized ML features from a flow dict."""
    dur  = max(0.001, float(flow.get("duration_s", 0.001)))
    pkts = max(1, int(flow.get("pkt_count", 1)))
    byt  = max(0, int(flow.get("byte_count", 0)))
    port = int(flow.get("dst_port", 0))
    proto= str(flow.get("protocol", "")).upper()
    src  = str(flow.get("src_ip", ""))
    dst  = str(flow.get("dst_ip", ""))

    return [
        min(dur, 3600),          # cap at 1 hour
        min(pkts, 100000),
        min(byt, 1e9),
        byt / pkts,
        byt / dur,
        pkts / dur,
        port / 65535.0,          # normalize port
        1.0 if proto == "TCP" else 0.0,
        1.0 if proto == "UDP" else 0.0,
        1.0 if proto == "ICMP" else 0.0,
        1.0 if _is_internal(src) else 0.0,
        1.0 if _is_internal(dst) else 0.0,
        1.0 if port < 1024 else 0.0,
        1.0 if port >= 49152 else 0.0,
    ]


# ---------------------------------------------------------------------------
# Pure-Python fallback anomaly detector (no sklearn/onnx)
# ---------------------------------------------------------------------------

class _StatisticalAnomalyDetector:
    """Z-score based anomaly detection — runs without any ML library."""

    def __init__(self) -> None:
        self._stats: dict[str, dict] = {}   # feature → {mean, std, n}

    def fit(self, flows: list[dict]) -> None:
        features_list = [_extract_features(f) for f in flows]
        if not features_list:
            return
        n = len(features_list)
        k = len(FLOW_FEATURES)
        means = [sum(f[i] for f in features_list) / n for i in range(k)]
        stds  = [
            math.sqrt(sum((f[i] - means[i]) ** 2 for f in features_list) / max(1, n - 1))
            for i in range(k)
        ]
        for i, fname in enumerate(FLOW_FEATURES):
            self._stats[fname] = {"mean": means[i], "std": max(stds[i], 1e-9), "n": n}

    def score(self, flow: dict) -> float:
        """Returns anomaly score 0-1. Higher = more anomalous."""
        feats = _extract_features(flow)
        if not self._stats:
            return 0.0
        z_scores = []
        for i, fname in enumerate(FLOW_FEATURES):
            s = self._stats.get(fname, {"mean": 0, "std": 1})
            z = abs(feats[i] - s["mean"]) / s["std"]
            z_scores.append(z)
        # Normalize: 3σ = score 1.0
        avg_z = sum(z_scores) / len(z_scores)
        return min(1.0, avg_z / 3.0)

    def predict(self, flows: list[dict], threshold: float = 0.6) -> list[dict]:
        return [{"flow": f, "score": self.score(f), "is_anomaly": self.score(f) >= threshold}
                for f in flows]


# ---------------------------------------------------------------------------
# IsolationForestDetector — sklearn backed
# ---------------------------------------------------------------------------

class IsolationForestDetector:
    """
    Isolation Forest anomaly detector (sklearn).
    Serializable to disk via joblib for persistence.
    """

    MODEL_PATH = Path("~/.shadow313/models/isolation_forest.joblib")
    SCALER_PATH = Path("~/.shadow313/models/if_scaler.joblib")

    def __init__(self, contamination: float = 0.05,
                 n_estimators: int = 100, random_state: int = 42) -> None:
        self.contamination = contamination
        self.n_estimators  = n_estimators
        self.random_state  = random_state
        self._model  = None
        self._scaler = None
        self._fitted = False

    def fit(self, flows: list[dict]) -> dict:
        if not _HAS_SKLEARN:
            raise ImportError("pip install scikit-learn joblib")
        X = [_extract_features(f) for f in flows]
        if len(X) < 10:
            return {"status": "insufficient_data", "samples": len(X)}
        if _HAS_NUMPY:
            X_arr = np.array(X, dtype=np.float32)
        else:
            X_arr = X

        self._scaler = StandardScaler()
        X_scaled     = self._scaler.fit_transform(X_arr)
        self._model  = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._fitted = True
        return {"status": "fitted", "samples": len(X),
                "contamination": self.contamination}

    def save(self, model_path: Path | None = None,
             scaler_path: Path | None = None) -> dict:
        if not _HAS_SKLEARN or not self._fitted:
            return {"status": "not_fitted"}
        mp = Path(model_path or self.MODEL_PATH).expanduser()
        sp = Path(scaler_path or self.SCALER_PATH).expanduser()
        mp.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model,  str(mp))
        joblib.dump(self._scaler, str(sp))
        return {"status": "saved", "model": str(mp), "scaler": str(sp)}

    def load(self, model_path: Path | None = None,
             scaler_path: Path | None = None) -> bool:
        if not _HAS_SKLEARN:
            return False
        mp = Path(model_path or self.MODEL_PATH).expanduser()
        sp = Path(scaler_path or self.SCALER_PATH).expanduser()
        if mp.exists() and sp.exists():
            self._model  = joblib.load(str(mp))
            self._scaler = joblib.load(str(sp))
            self._fitted = True
            return True
        return False

    def predict(self, flows: list[dict]) -> list[dict]:
        if not self._fitted:
            raise RuntimeError("Model not fitted. Call fit() or load() first.")
        X = [_extract_features(f) for f in flows]
        if _HAS_NUMPY:
            X_arr = np.array(X, dtype=np.float32)
        else:
            X_arr = X
        X_scaled = self._scaler.transform(X_arr)
        labels   = self._model.predict(X_scaled)        # 1=normal, -1=anomaly
        scores   = self._model.score_samples(X_scaled)  # raw scores

        results = []
        for i, flow in enumerate(flows):
            is_anomaly = labels[i] == -1
            # Normalize anomaly score to 0-1 (more positive = more anomalous)
            raw_score = float(scores[i])
            norm_score = max(0.0, min(1.0, (-raw_score + 0.5)))
            results.append({
                "flow":       flow,
                "is_anomaly": is_anomaly,
                "score":      round(norm_score, 4),
                "label":      "anomaly" if is_anomaly else "normal",
            })
        return results

    def export_onnx(self, output_path: str = "~/.shadow313/models/isolation_forest.onnx") -> str:
        """Export model to ONNX format for runtime inference."""
        if not self._fitted:
            raise RuntimeError("Model not fitted")
        try:
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType
            initial_type = [("float_input", FloatTensorType([None, len(FLOW_FEATURES)]))]
            onnx_model = convert_sklearn(self._model, initial_types=initial_type)
            path = Path(output_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(onnx_model.SerializeToString())
            return str(path)
        except ImportError:
            return ""


# ---------------------------------------------------------------------------
# ONNXAnomalyDetector — inference-only via ONNX runtime
# ---------------------------------------------------------------------------

class ONNXAnomalyDetector:
    """Load and run a pre-exported ONNX model for anomaly scoring."""

    def __init__(self, model_path: str = "~/.shadow313/models/isolation_forest.onnx") -> None:
        self.model_path = Path(model_path).expanduser()
        self._session: Any = None
        self._input_name: str = ""
        if _HAS_ORT and self.model_path.exists():
            self._load()

    def _load(self) -> None:
        self._session    = ort.InferenceSession(str(self.model_path))
        self._input_name = self._session.get_inputs()[0].name

    def is_ready(self) -> bool:
        return self._session is not None

    def predict(self, flows: list[dict]) -> list[dict]:
        if not self.is_ready() or not _HAS_NUMPY:
            return []
        X = np.array([_extract_features(f) for f in flows], dtype=np.float32)
        outputs = self._session.run(None, {self._input_name: X})
        labels  = outputs[0]   # -1 or 1
        results = []
        for i, flow in enumerate(flows):
            results.append({
                "flow":       flow,
                "is_anomaly": int(labels[i]) == -1,
                "label":      "anomaly" if int(labels[i]) == -1 else "normal",
                "score":      0.8 if int(labels[i]) == -1 else 0.2,
            })
        return results


# ---------------------------------------------------------------------------
# MLAnomalyDetector — unified facade
# ---------------------------------------------------------------------------

class MLAnomalyDetector:
    """
    Unified ML anomaly detector for Shadow313 v2.
    Tries sklearn IsolationForest → ONNX runtime → statistical fallback.
    """

    def __init__(self, model_dir: str = "~/.shadow313/models") -> None:
        self.model_dir = Path(model_dir).expanduser()
        self._if    = IsolationForestDetector()
        self._onnx  = ONNXAnomalyDetector(
            str(self.model_dir / "isolation_forest.onnx")
        )
        self._stat  = _StatisticalAnomalyDetector()
        self._backend = "none"
        self._fitted  = False

        # Auto-load persisted model
        if self._if.load(self.model_dir / "isolation_forest.joblib",
                         self.model_dir / "if_scaler.joblib"):
            self._backend = "sklearn"
            self._fitted  = True
        elif self._onnx.is_ready():
            self._backend = "onnx"
            self._fitted  = True

    def train(self, flows: list[dict]) -> dict:
        """Train on historical flows. Saves model to disk."""
        result: dict[str, Any] = {"backend": "none"}
        if _HAS_SKLEARN:
            res = self._if.fit(flows)
            if res.get("status") == "fitted":
                self._if.save(self.model_dir / "isolation_forest.joblib",
                              self.model_dir / "if_scaler.joblib")
                self._if.export_onnx(str(self.model_dir / "isolation_forest.onnx"))
                self._backend = "sklearn"
                self._fitted  = True
                result = {"backend": "sklearn", **res}
        else:
            self._stat.fit(flows)
            self._backend = "statistical"
            self._fitted  = True
            result = {"backend": "statistical", "samples": len(flows)}
        return result

    def predict(self, flows: list[dict], threshold: float = 0.5) -> list[dict]:
        """Detect anomalies in a list of flows."""
        if not self._fitted:
            # Train on the data itself as baseline (unsupervised)
            self._stat.fit(flows)
            self._backend = "statistical"
            self._fitted  = True

        if self._backend == "sklearn":
            return self._if.predict(flows)
        if self._backend == "onnx":
            return self._onnx.predict(flows)
        return self._stat.predict(flows, threshold=threshold)

    def detect_anomalies(self, flows: list[dict]) -> list[dict]:
        """Return only anomalous flows with enriched context."""
        all_results = self.predict(flows)
        anomalies   = [r for r in all_results if r.get("is_anomaly")]
        for a in anomalies:
            a["description"] = self._describe_anomaly(a["flow"])
            a["severity"]    = self._severity(a.get("score", 0.5))
        return anomalies

    def _describe_anomaly(self, flow: dict) -> str:
        src    = flow.get("src_ip", "?")
        dst    = flow.get("dst_ip", "?")
        port   = flow.get("dst_port", 0)
        byt    = flow.get("byte_count", 0)
        if port in DANGEROUS_PORTS:
            return f"Traffic to suspicious port {port} ({src}→{dst})"
        if byt > 10_000_000 and not _is_internal(dst):
            return f"Large data transfer ({byt//1024}KB) to external {dst}"
        return f"Statistical outlier: {src}→{dst}:{port}"

    def _severity(self, score: float) -> str:
        if score >= 0.9: return "CRITICAL"
        if score >= 0.7: return "HIGH"
        if score >= 0.5: return "MEDIUM"
        return "LOW"

    @property
    def backend(self) -> str:
        return self._backend
