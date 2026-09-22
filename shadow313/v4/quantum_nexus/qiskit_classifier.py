"""
Shadow313 — Qiskit ML Alert Classifier
=======================================
Uses a real Quantum Support Vector Classifier (QSVC) with a
FidelityQuantumKernel to classify security alerts into severity tiers.

Honest capability statement:
  - Runs on Qiskit's statevector simulator by default
  - Can be pointed at IBM Quantum hardware via QiskitRuntimeService
  - Realistic scale: 4 features, up to ~200 training samples
  - Classical SVM with RBF kernel will outperform this on large datasets
  - Useful for: research, small high-value classification tasks,
    demonstrating quantum kernel expressibility on security data

The quantum kernel computes inner products in a high-dimensional
Hilbert space via the ZZFeatureMap — a 2-local entangling feature map
that creates correlations classical kernels cannot easily replicate.
"""

from __future__ import annotations

import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from typing import Optional, List

# Qiskit ML imports
from qiskit.circuit.library import ZZFeatureMap
from qiskit_machine_learning.kernels import FidelityQuantumKernel
from qiskit_machine_learning.algorithms import QSVC

# Qiskit statevector sampler (no IBM account needed)
from qiskit.primitives import StatevectorSampler
from qiskit_machine_learning.state_fidelities import ComputeUncompute


# ── Severity label mapping ──────────────────────────────────────────────────
SEVERITY_LABELS = {0: "NORMAL", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
SEVERITY_COLORS = {0: "green", 1: "yellow", 2: "orange", 3: "red"}


class QiskitAlertClassifier:
    """
    Quantum kernel SVM for classifying NEXUS security alerts.

    The ZZFeatureMap encodes 4 alert features into a quantum state.
    The FidelityQuantumKernel computes pairwise state overlaps as the
    kernel matrix — replacing the classical RBF kernel in the SVM.

    Features used (4 dimensions — realistic VQC scale):
        [0] anomaly_score      — from Isolation Forest / PennyLane VQC
        [1] ensemble_score     — from RF + GB ensemble
        [2] log_velocity       — events per minute (normalized)
        [3] entropy_score      — command/process entropy

    Usage:
        clf = QiskitAlertClassifier()
        clf.fit(X_train, y_train)
        predictions = clf.predict(X_test)
        report = clf.evaluate(X_test, y_test)
    """

    N_FEATURES = 4   # ZZFeatureMap dimension — must match input features
    REPS = 2         # Feature map repetitions (depth vs. expressibility tradeoff)

    def __init__(
        self,
        n_features: int = N_FEATURES,
        reps: int = REPS,
        random_state: int = 42,
    ):
        self.n_features = n_features
        self.reps = reps
        self.random_state = random_state

        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_fitted = False

        # Build the quantum kernel
        self._feature_map = ZZFeatureMap(
            feature_dimension=n_features,
            reps=reps,
            entanglement="linear",   # linear entanglement: realistic for NISQ
        )

        # StatevectorSampler: exact simulation, no noise, no IBM account needed
        sampler = StatevectorSampler()
        fidelity = ComputeUncompute(sampler=sampler)

        self._kernel = FidelityQuantumKernel(
            feature_map=self._feature_map,
            fidelity=fidelity,
        )

        # The actual classifier: SVM with quantum kernel
        self._qsvc = QSVC(quantum_kernel=self._kernel)

        self._feature_selector: Optional[np.ndarray] = None
        self._classes: Optional[List[int]] = None

    # ── Feature selection ───────────────────────────────────────────────────
    def _select_features(self, X: np.ndarray) -> np.ndarray:
        """Select top-N_FEATURES features by variance."""
        variances = np.var(X, axis=0)
        return np.argsort(variances)[::-1][:self.n_features]

    def _preprocess(self, X: np.ndarray) -> np.ndarray:
        """Scale and select features. Clip to [-π, π] for angle encoding."""
        X_scaled = self.scaler.transform(X)
        X_sel = X_scaled[:, self._feature_selector]
        return np.clip(X_sel, -np.pi, np.pi)

    # ── Training ────────────────────────────────────────────────────────────
    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        verbose: bool = True,
    ) -> "QiskitAlertClassifier":
        """
        Train the QSVC on labeled alert data.

        Args:
            X: shape (n_samples, n_features) — alert feature vectors
            y: shape (n_samples,) — integer severity labels (0–3)
            verbose: print training info

        Returns:
            self (fitted classifier)

        Note:
            Training time scales as O(n²) in kernel matrix computation.
            Keep n_samples ≤ 200 for reasonable runtime on simulation.
        """
        if len(X) > 300:
            print(f"[QSVC] Warning: {len(X)} samples is large for quantum kernel SVM.")
            print(f"[QSVC] Subsampling to 200 samples for realistic runtime.")
            idx = np.random.RandomState(self.random_state).choice(len(X), 200, replace=False)
            X, y = X[idx], y[idx]

        self.scaler.fit(X)
        self._feature_selector = self._select_features(X)
        X_proc = self._preprocess(X)

        self._classes = sorted(np.unique(y).tolist())

        if verbose:
            print(f"[Qiskit QSVC] Training on {len(X_proc)} samples")
            print(f"[Qiskit QSVC] Feature map: ZZFeatureMap(dim={self.n_features}, reps={self.reps})")
            print(f"[Qiskit QSVC] Backend: StatevectorSampler (exact simulation)")
            print(f"[Qiskit QSVC] Classes: {[SEVERITY_LABELS.get(c, c) for c in self._classes]}")
            print(f"[Qiskit QSVC] Computing quantum kernel matrix ({len(X_proc)}×{len(X_proc)})...")
            print(f"[Qiskit QSVC] This may take 30–120s for ~100 samples on simulation.")

        self._qsvc.fit(X_proc, y)
        self.is_fitted = True

        if verbose:
            train_acc = accuracy_score(y, self._qsvc.predict(X_proc))
            print(f"[Qiskit QSVC] Training accuracy: {train_acc:.3f}")
            print(f"[Qiskit QSVC] Training complete.")

        return self

    # ── Inference ───────────────────────────────────────────────────────────
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict severity labels for alert feature vectors.

        Args:
            X: shape (n_samples, n_features)

        Returns:
            labels: shape (n_samples,) — integer severity (0=NORMAL, 3=CRITICAL)
        """
        if not self.is_fitted:
            raise RuntimeError("Call fit() before predict().")
        X_proc = self._preprocess(X)
        return self._qsvc.predict(X_proc)

    def predict_named(self, X: np.ndarray) -> List[str]:
        """Return human-readable severity labels."""
        return [SEVERITY_LABELS.get(int(p), "UNKNOWN") for p in self.predict(X)]

    # ── Evaluation ──────────────────────────────────────────────────────────
    def evaluate(self, X: np.ndarray, y_true: np.ndarray) -> dict:
        """
        Evaluate classifier performance.

        Args:
            X:      feature matrix
            y_true: ground truth severity labels

        Returns:
            dict with accuracy, per-class metrics, and backend info
        """
        y_pred = self.predict(X)
        acc = float(accuracy_score(y_true, y_pred))

        report = classification_report(
            y_true, y_pred,
            target_names=[SEVERITY_LABELS.get(c, str(c)) for c in self._classes],
            output_dict=True,
            zero_division=0,
        )

        return {
            "accuracy": round(acc, 4),
            "classification_report": report,
            "backend": "Qiskit StatevectorSampler (exact simulation)",
            "feature_map": f"ZZFeatureMap(dim={self.n_features}, reps={self.reps})",
            "n_training_samples": "≤200 (quantum kernel scale constraint)",
            "honest_note": (
                "Classical SVM with RBF kernel will match or exceed this "
                "on datasets >200 samples. QSVC is research-grade."
            ),
        }

    def circuit_diagram(self) -> str:
        """Return a text diagram of the ZZFeatureMap circuit."""
        return str(self._feature_map.decompose())

    def __repr__(self) -> str:
        status = "fitted" if self.is_fitted else "unfitted"
        return (f"QiskitAlertClassifier("
                f"n_features={self.n_features}, reps={self.reps}, "
                f"status={status})")