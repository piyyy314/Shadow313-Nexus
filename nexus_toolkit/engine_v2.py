"""
NEXUS SECURITY — AI/ML Detection Engine
Multi-model ensemble: Isolation Forest (anomaly) + Random Forest (classifier)
+ Quantum-inspired feature weighting via amplitude encoding simulation.
"""

import numpy as np
import json
import os
import warnings
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field

from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score
import joblib

warnings.filterwarnings("ignore")


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION RESULT
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """Structured output from the ML detection pipeline."""
    entry_id: str
    timestamp: str
    anomaly_score: float          # 0.0 (normal) → 1.0 (highly anomalous)
    threat_class: str             # Predicted threat category
    threat_confidence: float      # 0.0 → 1.0
    risk_level: str               # CRITICAL / HIGH / MEDIUM / LOW / INFO
    attack_techniques: List[str]  # MITRE ATT&CK technique IDs
    attack_tactics: List[str]     # MITRE ATT&CK tactic names
    quantum_weight: float         # Quantum-inspired amplitude weight
    ensemble_score: float         # Combined ensemble confidence
    triggered_features: List[str] # Which features drove the detection
    raw_features: List[float]     # Feature vector for audit trail
    explanation: str              # Human-readable explanation
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "anomaly_score": round(self.anomaly_score, 4),
            "threat_class": self.threat_class,
            "threat_confidence": round(self.threat_confidence, 4),
            "risk_level": self.risk_level,
            "attack_techniques": self.attack_techniques,
            "attack_tactics": self.attack_tactics,
            "quantum_weight": round(self.quantum_weight, 4),
            "ensemble_score": round(self.ensemble_score, 4),
            "triggered_features": self.triggered_features,
            "explanation": self.explanation,
            "recommended_actions": self.recommended_actions,
        }


# ─────────────────────────────────────────────────────────────────────────────
# QUANTUM-INSPIRED FEATURE WEIGHTING
# ─────────────────────────────────────────────────────────────────────────────

class QuantumFeatureWeighter:
    """
    Quantum-inspired amplitude encoding for feature importance weighting.

    Simulates quantum superposition principles to assign probabilistic
    weights to feature dimensions, enhancing sensitivity to subtle
    multi-feature correlations that classical models may underweight.

    Based on: Amplitude Encoding (Schuld & Petruccione, 2018)
    Adapted for classical simulation on standard hardware.
    """

    def __init__(self, n_features: int = 32, n_qubits: int = 6):
        self.n_features = n_features
        self.n_qubits = n_qubits
        self.n_states = 2 ** n_qubits  # 64 quantum states
        self._initialize_amplitudes()

    def _initialize_amplitudes(self):
        """Initialize quantum state amplitudes with security-domain priors."""
        # Prior weights based on security domain knowledge:
        # Higher weight = more security-relevant feature dimension
        domain_priors = np.array([
            0.3,  # [0]  hour_normalized       — temporal anomaly
            0.2,  # [1]  dow_normalized         — temporal anomaly
            0.8,  # [2]  after_hours            — HIGH: off-hours activity
            0.7,  # [3]  weekend                — HIGH: weekend activity
            0.5,  # [4]  event_id_norm          — medium relevance
            0.95, # [5]  suspicious_process     — CRITICAL: known bad process
            0.90, # [6]  lolbas                 — CRITICAL: LOLBin abuse
            0.92, # [7]  cmd_patterns           — CRITICAL: malicious patterns
            0.4,  # [8]  cmd_length             — moderate signal
            0.95, # [9]  encoded_cmd            — CRITICAL: obfuscation
            0.88, # [10] sensitive_registry     — HIGH: credential access
            0.3,  # [11] dest_port_norm         — low alone
            0.75, # [12] sensitive_port         — HIGH: risky port
            0.4,  # [13] internal_src           — context only
            0.4,  # [14] internal_dst           — context only
            0.85, # [15] privileged_user        — HIGH: privilege abuse
            0.6,  # [16] service_account        — medium: lateral movement
            0.7,  # [17] system_account         — HIGH: system-level activity
            0.3,  # [18] path_depth             — low signal
            0.8,  # [19] temp_path              — HIGH: staging indicator
            0.65, # [20] user_writable_path     — medium: persistence
            0.92, # [21] parent_child_anomaly   — CRITICAL: process injection
            0.88, # [22] network_from_lolbas    — HIGH: C2 indicator
            0.9,  # [23] high_severity          — HIGH: severity signal
            0.5,  # [24] event_category         — context
            0.95, # [25] lsass_access           — CRITICAL: credential dump
            0.85, # [26] kerberos_event         — HIGH: Kerberoasting
            0.6,  # [27] logon_event            — medium: auth activity
            0.7,  # [28] process_creation       — HIGH: execution
            0.75, # [29] registry_event         — HIGH: persistence
            0.6,  # [30] file_event             — medium: collection
            0.7,  # [31] network_event          — HIGH: C2/exfil
        ], dtype=np.float64)

        # Normalize to unit vector (quantum normalization constraint: ||ψ||² = 1)
        norm = np.linalg.norm(domain_priors)
        self.amplitudes = domain_priors / norm

        # Compute interference pattern (simulates quantum interference)
        self.interference_matrix = self._compute_interference_matrix()

    def _compute_interference_matrix(self) -> np.ndarray:
        """
        Simulate quantum interference between feature pairs.
        Features that co-occur in real attacks create constructive interference.
        """
        n = self.n_features
        matrix = np.eye(n, dtype=np.float64)

        # Known high-correlation attack feature pairs (constructive interference)
        high_correlation_pairs = [
            (5, 21),   # suspicious_process + parent_child_anomaly
            (6, 22),   # lolbas + network_from_lolbas
            (9, 7),    # encoded_cmd + cmd_patterns
            (25, 10),  # lsass_access + sensitive_registry
            (26, 15),  # kerberos_event + privileged_user
            (2, 15),   # after_hours + privileged_user
            (19, 28),  # temp_path + process_creation
            (21, 25),  # parent_child_anomaly + lsass_access
            (6, 9),    # lolbas + encoded_cmd
            (3, 22),   # weekend + network_from_lolbas
        ]

        for i, j in high_correlation_pairs:
            if i < n and j < n:
                # Constructive interference: amplify co-occurring features
                matrix[i][j] = 0.3
                matrix[j][i] = 0.3

        return matrix

    def compute_quantum_weight(self, feature_vector: np.ndarray) -> float:
        """
        Compute quantum-inspired amplitude weight for a feature vector.

        Simulates: ⟨ψ|φ⟩ inner product between domain prior state |ψ⟩
        and input feature state |φ⟩, with interference correction.

        Returns: float in [0, 1] representing quantum threat amplitude
        """
        # Normalize input to unit vector (amplitude encoding)
        norm = np.linalg.norm(feature_vector)
        if norm < 1e-10:
            return 0.0
        phi = feature_vector / norm

        # Quantum inner product: ⟨ψ|φ⟩
        inner_product = np.dot(self.amplitudes, phi)

        # Apply interference correction
        interference = phi @ self.interference_matrix @ phi

        # Probability amplitude: |⟨ψ|φ⟩|² + interference term
        probability = (inner_product ** 2) + (0.15 * interference)

        # Phase rotation simulation (Hadamard-inspired mixing)
        phase_factor = np.cos(np.pi * inner_product / 2) ** 2

        # Final quantum weight (bounded [0,1])
        quantum_weight = float(np.clip(probability * phase_factor * 2.5, 0.0, 1.0))

        return quantum_weight

    def get_feature_importances(self) -> np.ndarray:
        """Return squared amplitudes as feature importance probabilities."""
        return self.amplitudes ** 2


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTOR (Unsupervised)
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector.
    Trained on baseline 'normal' behavior to detect deviations.
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 200):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
            warm_start=False
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.training_samples = 0

    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """Train on baseline normal behavior."""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        self.training_samples = len(X)
        return self

    def score(self, x: np.ndarray) -> float:
        """
        Return anomaly score in [0, 1].
        0 = normal, 1 = highly anomalous.
        """
        if not self.is_fitted:
            return 0.5  # Uncertain if not trained

        x_scaled = self.scaler.transform(x.reshape(1, -1))
        # Isolation Forest returns negative scores for anomalies
        raw_score = self.model.score_samples(x_scaled)[0]
        # Convert to [0,1] where 1 = most anomalous
        # Typical range: [-0.5, 0.5] → invert and normalize
        normalized = float(np.clip((-raw_score - 0.1) / 0.6, 0.0, 1.0))
        return normalized

    def predict(self, x: np.ndarray) -> int:
        """Return 1 (anomaly) or 0 (normal)."""
        if not self.is_fitted:
            return 0
        x_scaled = self.scaler.transform(x.reshape(1, -1))
        result = self.model.predict(x_scaled)[0]
        return 1 if result == -1 else 0


# ─────────────────────────────────────────────────────────────────────────────
# THREAT CLASSIFIER (Supervised)
# ─────────────────────────────────────────────────────────────────────────────

class ThreatClassifier:
    """
    Ensemble classifier: Random Forest + Gradient Boosting.
    Classifies security events into threat categories.
    """

    THREAT_CLASSES = [
        "NORMAL",
        "CREDENTIAL_ACCESS",
        "LATERAL_MOVEMENT",
        "DEFENSE_EVASION",
        "EXECUTION",
        "PERSISTENCE",
        "PRIVILEGE_ESCALATION",
        "DISCOVERY",
        "COLLECTION",
        "COMMAND_AND_CONTROL",
        "EXFILTRATION",
        "IMPACT",
    ]

    def __init__(self):
        self.rf_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
        self.gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42
        )
        self.scaler = MinMaxScaler()
        self.is_fitted = False
        self.feature_importances_ = None

    def _generate_synthetic_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic labeled training data based on known attack patterns.
        In production: replace with real labeled SIEM data.
        """
        np.random.seed(42)
        samples_per_class = 300
        X_list, y_list = [], []

        # Class 0: NORMAL — baseline benign activity
        for _ in range(samples_per_class * 3):
            x = np.random.normal(0.1, 0.05, 32)
            x = np.clip(x, 0, 1)
            x[2] = np.random.choice([0, 1], p=[0.85, 0.15])  # mostly business hours
            x[5] = 0.0   # no suspicious process
            x[6] = 0.0   # no lolbas
            x[7] = 0.0   # no cmd patterns
            x[9] = 0.0   # no encoding
            x[21] = 0.0  # no parent-child anomaly
            X_list.append(x)
            y_list.append(0)

        # Class 1: CREDENTIAL_ACCESS — LSASS, Kerberoasting, SAM dump
        for _ in range(samples_per_class):
            x = np.random.normal(0.2, 0.1, 32)
            x = np.clip(x, 0, 1)
            x[25] = np.random.choice([0.8, 1.0])  # lsass_access
            x[26] = np.random.choice([0.0, 1.0])  # kerberos_event
            x[10] = np.random.choice([0.7, 1.0])  # sensitive_registry
            x[15] = np.random.choice([0.0, 1.0])  # privileged_user
            x[5] = np.random.choice([0.5, 1.0])   # suspicious_process
            X_list.append(x)
            y_list.append(1)

        # Class 2: LATERAL_MOVEMENT — Pass-the-hash, RDP, SMB
        for _ in range(samples_per_class):
            x = np.random.normal(0.2, 0.1, 32)
            x = np.clip(x, 0, 1)
            x[12] = 1.0   # sensitive_port (RDP/SMB)
            x[27] = 1.0   # logon_event
            x[13] = 1.0   # internal_src
            x[14] = 1.0   # internal_dst
            x[16] = np.random.choice([0.0, 1.0])  # service_account
            x[2] = np.random.choice([0.5, 1.0])   # after_hours
            X_list.append(x)
            y_list.append(2)

        # Class 3: DEFENSE_EVASION — LOLBins, obfuscation, log clearing
        for _ in range(samples_per_class):
            x = np.random.normal(0.15, 0.08, 32)
            x = np.clip(x, 0, 1)
            x[6] = 1.0    # lolbas
            x[9] = np.random.choice([0.7, 1.0])   # encoded_cmd
            x[7] = np.random.uniform(0.6, 1.0)    # cmd_patterns
            x[21] = np.random.choice([0.0, 1.0])  # parent_child_anomaly
            x[22] = np.random.choice([0.5, 1.0])  # network_from_lolbas
            X_list.append(x)
            y_list.append(3)

        # Class 4: EXECUTION — Malicious process, script execution
        for _ in range(samples_per_class):
            x = np.random.normal(0.2, 0.1, 32)
            x = np.clip(x, 0, 1)
            x[5] = np.random.choice([0.7, 1.0])   # suspicious_process
            x[28] = 1.0   # process_creation
            x[7] = np.random.uniform(0.4, 1.0)    # cmd_patterns
            x[21] = np.random.choice([0.5, 1.0])  # parent_child_anomaly
            x[19] = np.random.choice([0.0, 1.0])  # temp_path
            X_list.append(x)
            y_list.append(4)

        # Class 5: PERSISTENCE — Registry, scheduled tasks, services
        for _ in range(samples_per_class):
            x = np.random.normal(0.15, 0.08, 32)
            x = np.clip(x, 0, 1)
            x[29] = 1.0   # registry_event
            x[10] = np.random.choice([0.5, 1.0])  # sensitive_registry
            x[20] = np.random.choice([0.5, 1.0])  # user_writable_path
            x[28] = np.random.choice([0.0, 1.0])  # process_creation
            X_list.append(x)
            y_list.append(5)

        # Class 6: PRIVILEGE_ESCALATION — Token impersonation, UAC bypass
        for _ in range(samples_per_class):
            x = np.random.normal(0.2, 0.1, 32)
            x = np.clip(x, 0, 1)
            x[15] = 1.0   # privileged_user
            x[17] = np.random.choice([0.5, 1.0])  # system_account
            x[5] = np.random.choice([0.5, 1.0])   # suspicious_process
            x[7] = np.random.uniform(0.3, 0.8)    # cmd_patterns
            X_list.append(x)
            y_list.append(6)

        # Class 7: DISCOVERY — Network scanning, AD enumeration
        for _ in range(samples_per_class):
            x = np.random.normal(0.15, 0.08, 32)
            x = np.clip(x, 0, 1)
            x[31] = 1.0   # network_event
            x[11] = np.random.uniform(0.3, 0.9)   # dest_port_norm (scanning)
            x[13] = 1.0   # internal_src
            x[8] = np.random.uniform(0.3, 0.7)    # cmd_length
            X_list.append(x)
            y_list.append(7)

        # Class 8: COLLECTION — File access, keylogging, screen capture
        for _ in range(samples_per_class):
            x = np.random.normal(0.15, 0.08, 32)
            x = np.clip(x, 0, 1)
            x[30] = 1.0   # file_event
            x[20] = np.random.choice([0.5, 1.0])  # user_writable_path
            x[8] = np.random.uniform(0.4, 0.8)    # cmd_length
            X_list.append(x)
            y_list.append(8)

        # Class 9: COMMAND_AND_CONTROL — C2 beaconing, DNS tunneling
        for _ in range(samples_per_class):
            x = np.random.normal(0.2, 0.1, 32)
            x = np.clip(x, 0, 1)
            x[22] = 1.0   # network_from_lolbas
            x[31] = 1.0   # network_event
            x[14] = 0.0   # external_dst (not internal)
            x[12] = np.random.choice([0.5, 1.0])  # sensitive_port
            x[2] = np.random.choice([0.5, 1.0])   # after_hours
            X_list.append(x)
            y_list.append(9)

        # Class 10: EXFILTRATION — Large data transfer, cloud upload
        for _ in range(samples_per_class):
            x = np.random.normal(0.2, 0.1, 32)
            x = np.clip(x, 0, 1)
            x[31] = 1.0   # network_event
            x[14] = 0.0   # external destination
            x[30] = 1.0   # file_event
            x[8] = np.random.uniform(0.6, 1.0)    # large cmd
            x[2] = np.random.choice([0.5, 1.0])   # after_hours
            X_list.append(x)
            y_list.append(10)

        # Class 11: IMPACT — Ransomware, data destruction
        for _ in range(samples_per_class):
            x = np.random.normal(0.3, 0.1, 32)
            x = np.clip(x, 0, 1)
            x[23] = 1.0   # high_severity
            x[30] = 1.0   # file_event (mass file modification)
            x[7] = np.random.uniform(0.5, 1.0)    # cmd_patterns
            x[5] = np.random.choice([0.5, 1.0])   # suspicious_process
            x[29] = np.random.choice([0.5, 1.0])  # registry_event
            X_list.append(x)
            y_list.append(11)

        return np.array(X_list), np.array(y_list)

    def fit(self, X: Optional[np.ndarray] = None,
            y: Optional[np.ndarray] = None) -> "ThreatClassifier":
        """Train classifier. Uses synthetic data if none provided."""
        if X is None or y is None:
            X, y = self._generate_synthetic_training_data()

        X_scaled = self.scaler.fit_transform(X)

        self.rf_model.fit(X_scaled, y)
        self.gb_model.fit(X_scaled, y)
        self.feature_importances_ = self.rf_model.feature_importances_
        self.is_fitted = True
        return self

    def predict(self, x: np.ndarray) -> Tuple[str, float, np.ndarray]:
        """
        Predict threat class with ensemble confidence.
        Returns: (class_name, confidence, class_probabilities)
        """
        if not self.is_fitted:
            return "UNKNOWN", 0.0, np.zeros(len(self.THREAT_CLASSES))

        x_scaled = self.scaler.transform(x.reshape(1, -1))

        # Get probabilities from both models
        rf_proba = self.rf_model.predict_proba(x_scaled)[0]
        gb_proba = self.gb_model.predict_proba(x_scaled)[0]

        # Weighted ensemble: RF 60%, GB 40%
        ensemble_proba = (0.6 * rf_proba) + (0.4 * gb_proba)

        predicted_idx = int(np.argmax(ensemble_proba))
        confidence = float(ensemble_proba[predicted_idx])
        class_name = self.THREAT_CLASSES[predicted_idx]

        return class_name, confidence, ensemble_proba

    def get_top_features(self, x: np.ndarray,
                          feature_names: List[str],
                          top_n: int = 5) -> List[str]:
        """Return top contributing features for this prediction."""
        if self.feature_importances_ is None:
            return []
        # Weight importances by actual feature values
        weighted = self.feature_importances_ * x
        top_indices = np.argsort(weighted)[::-1][:top_n]
        return [feature_names[i] for i in top_indices
                if weighted[i] > 0.01]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ML ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class NexusMLEngine:
    """
    Main ML detection engine combining:
    - Isolation Forest anomaly detection
    - Ensemble threat classification
    - Quantum-inspired feature weighting
    """

    MODEL_PATH = "nexus_toolkit/data/models"

    def __init__(self):
        self.anomaly_detector = AnomalyDetector(contamination=0.05)
        self.threat_classifier = ThreatClassifier()
        self.quantum_weighter = QuantumFeatureWeighter(n_features=32)
        self.is_ready = False
        self._detection_count = 0
        self._alert_count = 0

    def initialize(self, baseline_data: Optional[np.ndarray] = None) -> None:
        """
        Initialize and train all models.
        Uses synthetic baseline if no real data provided.
        """
        os.makedirs(self.MODEL_PATH, exist_ok=True)

        # Generate synthetic baseline for anomaly detector
        if baseline_data is None:
            np.random.seed(42)
            # Simulate 2000 normal log entries
            baseline_data = np.random.normal(0.1, 0.05, (2000, 32))
            baseline_data = np.clip(baseline_data, 0, 1)
            # Normal entries: low scores on threat indicators
            baseline_data[:, 5] = 0.0   # no suspicious process
            baseline_data[:, 6] = 0.0   # no lolbas
            baseline_data[:, 9] = 0.0   # no encoding
            baseline_data[:, 21] = 0.0  # no parent-child anomaly
            baseline_data[:, 25] = 0.0  # no lsass access

        self.anomaly_detector.fit(baseline_data)
        self.threat_classifier.fit()  # Uses synthetic labeled data
        self.is_ready = True

    def analyze(self, entry_id: str, timestamp: str,
                feature_vector: np.ndarray,
                feature_names: List[str],
                attack_mapper) -> DetectionResult:
        """
        Full analysis pipeline for a single log entry.
        Returns a DetectionResult with all detection signals.
        """
        if not self.is_ready:
            self.initialize()

        self._detection_count += 1

        # 1. Anomaly score
        anomaly_score = self.anomaly_detector.score(feature_vector)

        # 2. Threat classification
        threat_class, confidence, class_proba = \
            self.threat_classifier.predict(feature_vector)

        # 3. Quantum weight
        quantum_weight = self.quantum_weighter.compute_quantum_weight(
            feature_vector)

        # 4. Ensemble score (combine all signals)
        ensemble_score = self._compute_ensemble_score(
            anomaly_score, confidence, quantum_weight, threat_class)

        # 5. Risk level
        risk_level = self._compute_risk_level(ensemble_score, threat_class)

        # 6. ATT&CK mapping
        techniques, tactics = attack_mapper.map_features_to_attack(
            feature_vector, threat_class)

        # 7. Top triggered features
        triggered = self.threat_classifier.get_top_features(
            feature_vector, feature_names, top_n=5)

        # 8. Explanation
        explanation = self._generate_explanation(
            threat_class, anomaly_score, quantum_weight,
            triggered, risk_level)

        # 9. Recommended actions
        actions = self._get_recommended_actions(threat_class, risk_level)

        if risk_level in ("CRITICAL", "HIGH"):
            self._alert_count += 1

        return DetectionResult(
            entry_id=entry_id,
            timestamp=timestamp,
            anomaly_score=anomaly_score,
            threat_class=threat_class,
            threat_confidence=confidence,
            risk_level=risk_level,
            attack_techniques=techniques,
            attack_tactics=tactics,
            quantum_weight=quantum_weight,
            ensemble_score=ensemble_score,
            triggered_features=triggered,
            raw_features=feature_vector.tolist(),
            explanation=explanation,
            recommended_actions=actions,
        )

    def _compute_ensemble_score(self, anomaly: float, confidence: float,
                                 quantum: float, threat_class: str) -> float:
        """Weighted combination of all detection signals."""
        # Normal events get lower ensemble weight
        if threat_class == "NORMAL":
            class_weight = 0.1
        else:
            class_weight = confidence

        # Weighted ensemble: anomaly 35%, classifier 40%, quantum 25%
        score = (0.35 * anomaly) + (0.40 * class_weight) + (0.25 * quantum)
        return float(np.clip(score, 0.0, 1.0))

    def _compute_risk_level(self, ensemble_score: float,
                             threat_class: str) -> str:
        """Map ensemble score to risk level."""
        critical_classes = {
            "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT",
            "COMMAND_AND_CONTROL", "IMPACT"
        }
        high_classes = {
            "DEFENSE_EVASION", "PRIVILEGE_ESCALATION",
            "EXECUTION", "EXFILTRATION"
        }

        if ensemble_score >= 0.75 or (
                ensemble_score >= 0.60 and threat_class in critical_classes):
            return "CRITICAL"
        elif ensemble_score >= 0.55 or (
                ensemble_score >= 0.45 and threat_class in critical_classes):
            return "HIGH"
        elif ensemble_score >= 0.35 or (
                ensemble_score >= 0.25 and threat_class in high_classes):
            return "MEDIUM"
        elif ensemble_score >= 0.15:
            return "LOW"
        else:
            return "INFO"

    def _generate_explanation(self, threat_class: str, anomaly: float,
                               quantum: float, features: List[str],
                               risk: str) -> str:
        """Generate human-readable detection explanation."""
        feature_str = ", ".join(features) if features else "baseline deviation"
        return (
            f"[{risk}] {threat_class} detected. "
            f"Anomaly score: {anomaly:.2f}, "
            f"Quantum amplitude: {quantum:.2f}. "
            f"Key indicators: {feature_str}."
        )

    def _get_recommended_actions(self, threat_class: str,
                                  risk_level: str) -> List[str]:
        """Return SOC response recommendations."""
        actions_map = {
            "CREDENTIAL_ACCESS": [
                "Isolate affected endpoint immediately",
                "Reset credentials for affected accounts",
                "Check for lateral movement from this host",
                "Review LSASS access logs and Kerberos ticket requests",
                "Enable Credential Guard if not already active",
            ],
            "LATERAL_MOVEMENT": [
                "Block source IP at network perimeter",
                "Audit all authentication events from source host",
                "Check for new accounts or privilege changes",
                "Review SMB/RDP connection logs",
                "Initiate network segmentation review",
            ],
            "DEFENSE_EVASION": [
                "Capture memory image of affected endpoint",
                "Review PowerShell Script Block logs",
                "Check for disabled security tools or cleared logs",
                "Analyze LOLBin execution chain",
                "Escalate to Tier 2 for forensic analysis",
            ],
            "EXECUTION": [
                "Quarantine affected endpoint",
                "Capture process memory and disk image",
                "Review parent-child process chain",
                "Check for persistence mechanisms",
                "Submit suspicious files to sandbox",
            ],
            "COMMAND_AND_CONTROL": [
                "Block C2 IP/domain at firewall and proxy",
                "Capture network traffic from affected host",
                "Check for other hosts communicating with same C2",
                "Review DNS query logs for tunneling indicators",
                "Initiate full incident response procedure",
            ],
            "EXFILTRATION": [
                "Block outbound connections from affected host",
                "Identify and quantify data accessed/transferred",
                "Notify data protection officer if PII involved",
                "Preserve network flow logs as evidence",
                "Initiate breach notification assessment",
            ],
            "IMPACT": [
                "IMMEDIATE: Isolate all affected systems",
                "Activate incident response team",
                "Initiate backup restoration assessment",
                "Preserve all evidence before remediation",
                "Notify executive leadership and legal counsel",
            ],
        }
        default_actions = [
            "Investigate and triage alert",
            "Correlate with other events from same source",
            "Document findings in incident ticket",
        ]
        base = actions_map.get(threat_class, default_actions)
        if risk_level == "CRITICAL":
            base.insert(0, "🚨 CRITICAL: Escalate to senior analyst immediately")
        return base

    def get_stats(self) -> Dict:
        return {
            "total_analyzed": self._detection_count,
            "total_alerts": self._alert_count,
            "alert_rate": round(
                self._alert_count / max(self._detection_count, 1), 4),
            "models_ready": self.is_ready,
        }

    def save_models(self) -> None:
        """Persist trained models to disk."""
        os.makedirs(self.MODEL_PATH, exist_ok=True)
        joblib.dump(self.anomaly_detector,
                    f"{self.MODEL_PATH}/anomaly_detector.pkl")
        joblib.dump(self.threat_classifier,
                    f"{self.MODEL_PATH}/threat_classifier.pkl")

    def load_models(self) -> bool:
        """Load persisted models from disk."""
        try:
            self.anomaly_detector = joblib.load(
                f"{self.MODEL_PATH}/anomaly_detector.pkl")
            self.threat_classifier = joblib.load(
                f"{self.MODEL_PATH}/threat_classifier.pkl")
            self.is_ready = True
            return True
        except FileNotFoundError:
            return False