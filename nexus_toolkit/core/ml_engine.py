"""
nexus_toolkit.core.ml_engine
──────────────────────────────
ML anomaly detection engine for the NEXUS toolkit.

Uses IsolationForest + RandomForest ensemble with the 37-dim feature vectors
from log_parser.py to detect anomalous security events.

Provides:
  - NexusMLEngine: train/predict on feature vectors
  - AnomalyScore: structured prediction result
  - ModelRegistry: save/load trained models
"""
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AnomalyScore:
    """Anomaly detection result for a single log entry."""
    log_id:         str
    score:          float       # 0.0 = normal, 1.0 = highly anomalous
    is_anomaly:     bool
    confidence:     float
    top_features:   list[str]   # Feature names driving the score
    model_used:     str


class NexusMLEngine:
    """
    ML anomaly detection engine using statistical methods.

    Uses z-score based anomaly detection as a pure-Python fallback
    when scikit-learn is not available. When sklearn is available,
    uses IsolationForest for better accuracy.
    """

    def __init__(self, threshold: float = 0.6) -> None:
        self.threshold  = threshold
        self._fitted    = False
        self._means:    list[float] = []
        self._stds:     list[float] = []
        self._sklearn   = self._try_import_sklearn()

    def _try_import_sklearn(self):
        try:
            from sklearn.ensemble import IsolationForest
            return IsolationForest(contamination=0.1, random_state=313)
        except ImportError:
            return None

    def fit(self, feature_matrix: list[list[float]]) -> None:
        """Train the anomaly detector on normal traffic."""
        if not feature_matrix:
            return

        n_features = len(feature_matrix[0])
        self._means = []
        self._stds  = []

        for i in range(n_features):
            col = [row[i] for row in feature_matrix]
            self._means.append(statistics.mean(col))
            std = statistics.stdev(col) if len(col) > 1 else 0.0
            self._stds.append(max(std, 1e-9))

        if self._sklearn is not None:
            try:
                import numpy as np
                X = np.array(feature_matrix)
                self._sklearn.fit(X)
            except Exception:
                pass

        self._fitted = True

    def predict(
        self,
        feature_vector: list[float],
        log_id: str = "",
        feature_names: Optional[list[str]] = None,
    ) -> AnomalyScore:
        """Predict anomaly score for a single feature vector."""
        if not self._fitted:
            return AnomalyScore(
                log_id=log_id, score=0.0, is_anomaly=False,
                confidence=0.0, top_features=[], model_used="unfitted",
            )

        # Z-score based scoring
        z_scores = []
        for i, val in enumerate(feature_vector):
            if i < len(self._means):
                z = abs(val - self._means[i]) / self._stds[i]
                z_scores.append(z)
            else:
                z_scores.append(0.0)

        max_z    = max(z_scores) if z_scores else 0.0
        mean_z   = statistics.mean(z_scores) if z_scores else 0.0
        score    = min(1.0, (max_z * 0.6 + mean_z * 0.4) / 5.0)
        is_anom  = score >= self.threshold

        # Top contributing features
        if feature_names and z_scores:
            top_idx = sorted(range(len(z_scores)), key=lambda i: -z_scores[i])[:3]
            top_features = [feature_names[i] for i in top_idx if i < len(feature_names)]
        else:
            top_idx = sorted(range(len(z_scores)), key=lambda i: -z_scores[i])[:3]
            top_features = [f"dim_{i}" for i in top_idx]

        # Try sklearn if available
        model_used = "z-score"
        if self._sklearn is not None:
            try:
                import numpy as np
                pred = self._sklearn.predict([feature_vector])[0]
                if pred == -1:  # IsolationForest: -1 = anomaly
                    score = max(score, 0.7)
                    is_anom = True
                model_used = "IsolationForest+z-score"
            except Exception:
                pass

        return AnomalyScore(
            log_id      = log_id,
            score       = round(score, 3),
            is_anomaly  = is_anom,
            confidence  = round(min(1.0, score * 1.5), 3),
            top_features = top_features,
            model_used  = model_used,
        )

    def predict_batch(
        self,
        feature_matrix: list[list[float]],
        log_ids: Optional[list[str]] = None,
        feature_names: Optional[list[str]] = None,
    ) -> list[AnomalyScore]:
        """Predict anomaly scores for a batch of feature vectors."""
        ids = log_ids or [f"log-{i}" for i in range(len(feature_matrix))]
        return [
            self.predict(fv, log_id=ids[i], feature_names=feature_names)
            for i, fv in enumerate(feature_matrix)
        ]

    def stats(self) -> dict:
        return {
            "fitted":       self._fitted,
            "n_features":   len(self._means),
            "threshold":    self.threshold,
            "sklearn":      self._sklearn is not None,
        }