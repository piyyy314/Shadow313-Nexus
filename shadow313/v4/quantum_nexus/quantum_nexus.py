"""
shadow313.v4.quantum_nexus.quantum_nexus  — NEXUS Complete
Quantum NEXUS: Advanced quantum security module.

Features:
  HNDL:         Harvest-Now-Decrypt-Later stream prioritization with CRQC 2032 timeline
  QKD:          QKD downgrade attack detection (QBER spike threshold: 8%/11%)
  Sensor Fusion: Quantum sensor fusion with trust weights
  ML-KEM:       ML-KEM side-channel timing variance detection
  PQC Readiness: Organization-wide PQC readiness assessment
"""
from __future__ import annotations
import hashlib
import json
import math
import random
import statistics
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
# HNDL: Harvest-Now-Decrypt-Later Stream Prioritization
# ═══════════════════════════════════════════════════════════════════════════════

# CRQC arrival timeline (community consensus)
CRQC_ARRIVAL_YEAR = 2032
CURRENT_YEAR      = 2026
YEARS_TO_CRQC     = CRQC_ARRIVAL_YEAR - CURRENT_YEAR  # 6 years

# Data sensitivity classifications for HNDL prioritization
DATA_SENSITIVITY = {
    "TOP_SECRET":    {"retention_years": 75, "hndl_priority": "CRITICAL", "score": 100},
    "SECRET":        {"retention_years": 50, "hndl_priority": "CRITICAL", "score": 90},
    "CONFIDENTIAL":  {"retention_years": 25, "hndl_priority": "HIGH",     "score": 70},
    "SENSITIVE":     {"retention_years": 10, "hndl_priority": "HIGH",     "score": 60},
    "INTERNAL":      {"retention_years": 7,  "hndl_priority": "MEDIUM",   "score": 40},
    "PUBLIC":        {"retention_years": 0,  "hndl_priority": "LOW",      "score": 10},
}

# Algorithm vulnerability to quantum attacks
ALGORITHM_QUANTUM_RISK = {
    "RSA-2048":    {"risk": "CRITICAL", "years_safe": 0,  "shor_vulnerable": True},
    "RSA-4096":    {"risk": "CRITICAL", "years_safe": 0,  "shor_vulnerable": True},
    "ECDSA-P256":  {"risk": "CRITICAL", "years_safe": 0,  "shor_vulnerable": True},
    "ECDH-P384":   {"risk": "CRITICAL", "years_safe": 0,  "shor_vulnerable": True},
    "Ed25519":     {"risk": "CRITICAL", "years_safe": 0,  "shor_vulnerable": True},
    "DH-2048":     {"risk": "CRITICAL", "years_safe": 0,  "shor_vulnerable": True},
    "AES-128":     {"risk": "HIGH",     "years_safe": 5,  "shor_vulnerable": False},
    "AES-256":     {"risk": "LOW",      "years_safe": 50, "shor_vulnerable": False},
    "SHA-256":     {"risk": "MEDIUM",   "years_safe": 10, "shor_vulnerable": False},
    "SHA-512":     {"risk": "LOW",      "years_safe": 50, "shor_vulnerable": False},
    "ML-KEM-768":  {"risk": "SAFE",     "years_safe": 50, "shor_vulnerable": False},
    "ML-DSA-65":   {"risk": "SAFE",     "years_safe": 50, "shor_vulnerable": False},
    "SLH-DSA-128f":{"risk": "SAFE",     "years_safe": 50, "shor_vulnerable": False},
}


@dataclass
class HNDLAsset:
    """An asset assessed for HNDL risk."""
    asset_id:        str
    name:            str
    algorithm:       str
    data_sensitivity:str
    data_volume_gb:  float
    hndl_priority:   str
    hndl_score:      float
    years_at_risk:   float
    recommendation:  str
    migrate_by:      str


class HNDLAnalyzer:
    """
    HNDL stream prioritization engine.
    Identifies which encrypted data streams are most at risk from
    future quantum computers and prioritizes migration accordingly.
    """

    def analyze_asset(
        self,
        name:             str,
        algorithm:        str,
        data_sensitivity: str,
        data_volume_gb:   float = 1.0,
        retention_years:  int   = 10,
    ) -> HNDLAsset:
        """Analyze a single asset for HNDL risk."""
        import uuid

        algo_risk = ALGORITHM_QUANTUM_RISK.get(algorithm, {
            "risk": "UNKNOWN", "years_safe": 0, "shor_vulnerable": True
        })
        sensitivity = DATA_SENSITIVITY.get(data_sensitivity, DATA_SENSITIVITY["INTERNAL"])

        # Compute HNDL score
        # Higher score = more urgent to migrate
        algo_score  = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 10, "SAFE": 0, "UNKNOWN": 50}.get(algo_risk["risk"], 50)
        sens_score  = sensitivity["score"]
        volume_score= min(math.log10(max(data_volume_gb, 0.1) + 1) * 20, 30)
        retention_score = min(retention_years / YEARS_TO_CRQC * 30, 30)

        hndl_score = (algo_score * 0.4 + sens_score * 0.3 + volume_score * 0.15 + retention_score * 0.15)
        hndl_score = round(min(hndl_score, 100), 1)

        # Determine priority
        if hndl_score >= 80:
            priority = "CRITICAL — Migrate immediately"
        elif hndl_score >= 60:
            priority = "HIGH — Migrate within 6 months"
        elif hndl_score >= 40:
            priority = "MEDIUM — Migrate within 18 months"
        else:
            priority = "LOW — Migrate within 3 years"

        # Years at risk (how long data will be vulnerable after CRQC arrives)
        years_at_risk = max(0, retention_years - YEARS_TO_CRQC)

        # Migration recommendation
        if algo_risk["shor_vulnerable"]:
            if "RSA" in algorithm or "DH" in algorithm:
                rec = "Replace with ML-KEM-768 (FIPS 203) for key exchange"
            elif "ECDSA" in algorithm or "Ed25519" in algorithm:
                rec = "Replace with ML-DSA-65 (FIPS 204) for signatures"
            else:
                rec = "Replace with NIST PQC standard algorithm"
        elif algo_risk["risk"] in ("HIGH", "MEDIUM"):
            rec = "Upgrade to AES-256 or SHA-512 for Grover resistance"
        else:
            rec = "Algorithm is quantum-safe — no migration required"

        # Migrate-by date
        if hndl_score >= 80:
            migrate_by = f"{CURRENT_YEAR + 1}-Q1"
        elif hndl_score >= 60:
            migrate_by = f"{CURRENT_YEAR + 1}-Q3"
        elif hndl_score >= 40:
            migrate_by = f"{CURRENT_YEAR + 2}-Q2"
        else:
            migrate_by = f"{CURRENT_YEAR + 3}-Q4"

        return HNDLAsset(
            asset_id        = str(uuid.uuid4())[:8],
            name            = name,
            algorithm       = algorithm,
            data_sensitivity= data_sensitivity,
            data_volume_gb  = data_volume_gb,
            hndl_priority   = priority,
            hndl_score      = hndl_score,
            years_at_risk   = years_at_risk,
            recommendation  = rec,
            migrate_by      = migrate_by,
        )

    def prioritize_portfolio(self, assets: list[HNDLAsset]) -> list[HNDLAsset]:
        """Sort assets by HNDL score (highest risk first)."""
        return sorted(assets, key=lambda a: -a.hndl_score)

    def portfolio_summary(self, assets: list[HNDLAsset]) -> dict:
        """Generate portfolio-level HNDL summary."""
        if not assets:
            return {"error": "No assets to analyze"}

        critical = [a for a in assets if a.hndl_score >= 80]
        high     = [a for a in assets if 60 <= a.hndl_score < 80]
        medium   = [a for a in assets if 40 <= a.hndl_score < 60]
        low      = [a for a in assets if a.hndl_score < 40]

        total_volume = sum(a.data_volume_gb for a in assets)
        at_risk_volume = sum(a.data_volume_gb for a in critical + high)

        return {
            "total_assets":      len(assets),
            "critical_count":    len(critical),
            "high_count":        len(high),
            "medium_count":      len(medium),
            "low_count":         len(low),
            "total_volume_gb":   round(total_volume, 2),
            "at_risk_volume_gb": round(at_risk_volume, 2),
            "at_risk_percent":   round(at_risk_volume / max(total_volume, 1) * 100, 1),
            "crqc_arrival":      f"{CRQC_ARRIVAL_YEAR} (estimated)",
            "years_remaining":   YEARS_TO_CRQC,
            "harvest_now_threat":"Active — state actors may already be collecting encrypted data",
        }


# ═══════════════════════════════════════════════════════════════════════════════
# QKD: Quantum Key Distribution Downgrade Detection
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class QKDSession:
    """A QKD session with QBER monitoring."""
    session_id:  str
    protocol:    str  # BB84 | E91 | B92
    qber:        float  # Quantum Bit Error Rate (%)
    key_rate:    float  # bits/second
    status:      str    # secure | warning | attack_detected | compromised
    alert:       str    = ""
    timestamp:   str    = field(default_factory=_now_iso)


class QKDMonitor:
    """
    QKD downgrade attack detection.
    Monitors QBER (Quantum Bit Error Rate) for attack indicators.

    Thresholds:
      QBER < 8%:  Secure — normal operation
      QBER 8-11%: WARNING — investigate immediately
      QBER > 11%: ATTACK DETECTED — session compromised
    """

    QBER_WARNING_THRESHOLD = 8.0   # % — investigation required
    QBER_ATTACK_THRESHOLD  = 11.0  # % — session compromised

    # BB84 theoretical QBER under attack
    BB84_INTERCEPT_QBER = 25.0  # % — intercept-resend attack

    def __init__(self) -> None:
        self._sessions: list[QKDSession] = []

    def monitor_session(
        self,
        session_id: str,
        protocol:   str   = "BB84",
        qber:       float = 0.0,
        key_rate:   float = 1000.0,
    ) -> QKDSession:
        """Monitor a QKD session and detect attacks."""
        if qber < self.QBER_WARNING_THRESHOLD:
            status = "secure"
            alert  = ""
        elif qber < self.QBER_ATTACK_THRESHOLD:
            status = "warning"
            alert  = (
                f"QBER {qber:.1f}% exceeds warning threshold ({self.QBER_WARNING_THRESHOLD}%). "
                f"Possible eavesdropping or channel degradation. Investigate immediately."
            )
        else:
            status = "attack_detected"
            alert  = (
                f"QBER {qber:.1f}% exceeds attack threshold ({self.QBER_ATTACK_THRESHOLD}%). "
                f"QKD session COMPROMISED. Terminate and re-establish on alternate channel. "
                f"Possible intercept-resend attack (theoretical QBER: {self.BB84_INTERCEPT_QBER}%)."
            )

        session = QKDSession(
            session_id = session_id,
            protocol   = protocol,
            qber       = qber,
            key_rate   = key_rate,
            status     = status,
            alert      = alert,
        )
        self._sessions.append(session)
        return session

    def simulate_bb84(self, n_qubits: int = 1000, eavesdrop: bool = False) -> dict:
        """
        Simulate BB84 QKD protocol with optional eavesdropping.
        Returns QBER and key generation statistics.
        """
        # BB84 simulation
        alice_bits   = [random.randint(0, 1) for _ in range(n_qubits)]
        alice_bases  = [random.randint(0, 1) for _ in range(n_qubits)]
        bob_bases    = [random.randint(0, 1) for _ in range(n_qubits)]

        # Eve intercepts (if eavesdropping)
        eve_bases = [random.randint(0, 1) for _ in range(n_qubits)] if eavesdrop else []

        # Bob measures
        bob_bits = []
        for i in range(n_qubits):
            if alice_bases[i] == bob_bases[i]:
                if eavesdrop and eve_bases[i] != alice_bases[i]:
                    # Eve disturbed the qubit — 50% chance of error
                    bob_bits.append(alice_bits[i] if random.random() > 0.5 else 1 - alice_bits[i])
                else:
                    bob_bits.append(alice_bits[i])
            else:
                bob_bits.append(random.randint(0, 1))

        # Sift key (matching bases)
        sifted_alice = [alice_bits[i] for i in range(n_qubits) if alice_bases[i] == bob_bases[i]]
        sifted_bob   = [bob_bits[i]   for i in range(n_qubits) if alice_bases[i] == bob_bases[i]]

        # Compute QBER
        if not sifted_alice:
            return {"error": "No matching bases"}

        errors = sum(1 for a, b in zip(sifted_alice, sifted_bob) if a != b)
        qber   = (errors / len(sifted_alice)) * 100

        return {
            "protocol":       "BB84",
            "n_qubits":       n_qubits,
            "sifted_key_len": len(sifted_alice),
            "qber":           round(qber, 2),
            "eavesdropped":   eavesdrop,
            "status":         "attack_detected" if qber > self.QBER_ATTACK_THRESHOLD else
                              "warning" if qber > self.QBER_WARNING_THRESHOLD else "secure",
            "theoretical_qber_no_eve":  "~1-3% (channel noise only)",
            "theoretical_qber_with_eve":f"~{self.BB84_INTERCEPT_QBER}% (intercept-resend)",
        }

    def get_sessions(self) -> list[dict]:
        return [asdict(s) for s in self._sessions]


# ═══════════════════════════════════════════════════════════════════════════════
# Quantum Sensor Fusion
# ═══════════════════════════════════════════════════════════════════════════════

class QuantumSensorFusion:
    """
    Quantum sensor fusion with trust weights.
    Combines multiple sensor inputs for threat detection.

    Sensor trust weights (from NEXUS analysis):
      Gravimeter:    0.95 (highest precision)
      NV Magnetometer: 0.85
      Classical RF:  0.15 (lowest trust — easily spoofed)
    """

    SENSOR_TRUST_WEIGHTS = {
        "gravimeter":      0.95,
        "nv_magnetometer": 0.85,
        "atomic_clock":    0.90,
        "quantum_radar":   0.80,
        "classical_rf":    0.15,
        "gps":             0.40,
        "lidar":           0.70,
    }

    def fuse(self, sensor_readings: dict[str, float]) -> dict:
        """
        Fuse multiple sensor readings using trust-weighted averaging.
        Returns fused threat score and confidence.
        """
        if not sensor_readings:
            return {"error": "No sensor readings provided"}

        weighted_sum   = 0.0
        total_weight   = 0.0
        sensor_details = []

        for sensor, reading in sensor_readings.items():
            weight = self.SENSOR_TRUST_WEIGHTS.get(sensor, 0.5)
            weighted_sum += reading * weight
            total_weight += weight
            sensor_details.append({
                "sensor":  sensor,
                "reading": reading,
                "weight":  weight,
                "contribution": round(reading * weight, 3),
            })

        if total_weight == 0:
            return {"error": "No valid sensors"}

        fused_score = weighted_sum / total_weight
        confidence  = min(total_weight / len(sensor_readings), 1.0)

        # Detect spoofing: high classical RF + low quantum sensors
        classical_rf = sensor_readings.get("classical_rf", 0)
        quantum_avg  = statistics.mean([
            v for k, v in sensor_readings.items()
            if k in ("gravimeter", "nv_magnetometer", "atomic_clock")
        ]) if any(k in sensor_readings for k in ("gravimeter", "nv_magnetometer", "atomic_clock")) else 0

        spoofing_detected = classical_rf > 0.7 and quantum_avg < 0.3

        return {
            "fused_score":       round(fused_score, 4),
            "confidence":        round(confidence, 3),
            "threat_level":      "HIGH" if fused_score > 0.7 else "MEDIUM" if fused_score > 0.4 else "LOW",
            "spoofing_detected": spoofing_detected,
            "spoofing_alert":    "GPS/RF spoofing detected — quantum sensors disagree with classical sensors" if spoofing_detected else "",
            "sensor_details":    sensor_details,
            "dominant_sensor":   max(sensor_details, key=lambda s: s["contribution"])["sensor"],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# ML-KEM Side-Channel Detection
# ═══════════════════════════════════════════════════════════════════════════════

class MLKEMSideChannelDetector:
    """
    ML-KEM side-channel timing variance detection.
    Detects timing attacks against ML-KEM implementations.
    """

    # Expected timing variance for constant-time ML-KEM implementations
    EXPECTED_VARIANCE_MS = 0.5   # ms — constant-time should have low variance
    ATTACK_VARIANCE_MS   = 5.0   # ms — high variance indicates timing attack

    def measure_timing(self, n_samples: int = 100) -> dict:
        """
        Measure ML-KEM operation timing to detect side-channel attacks.
        In production: would measure actual ML-KEM operations.
        Here: simulates timing measurements.
        """
        # Simulate timing measurements
        # Constant-time implementation: low variance
        # Vulnerable implementation: variance correlates with secret key bits
        timings = []
        for _ in range(n_samples):
            # Simulate ~1ms operation with small noise
            base_time = 1.0
            noise     = random.gauss(0, 0.1)  # Small noise for constant-time
            timings.append(max(0.1, base_time + noise))

        mean_ms   = statistics.mean(timings)
        stdev_ms  = statistics.stdev(timings) if len(timings) > 1 else 0
        variance  = stdev_ms ** 2

        # Detect timing attack
        is_vulnerable = stdev_ms > self.EXPECTED_VARIANCE_MS

        return {
            "n_samples":        n_samples,
            "mean_ms":          round(mean_ms, 4),
            "stdev_ms":         round(stdev_ms, 4),
            "variance_ms2":     round(variance, 6),
            "expected_stdev":   self.EXPECTED_VARIANCE_MS,
            "attack_threshold": self.ATTACK_VARIANCE_MS,
            "timing_attack_detected": is_vulnerable,
            "status":           "VULNERABLE" if is_vulnerable else "CONSTANT_TIME",
            "recommendation":   (
                "Implementation may be vulnerable to timing attacks. "
                "Ensure ML-KEM operations use constant-time arithmetic."
                if is_vulnerable else
                "Implementation appears to use constant-time operations."
            ),
        }

    def analyze_correlation(self, timings: list[float], key_bits: list[int]) -> dict:
        """
        Analyze correlation between timing and key bits.
        High correlation indicates a timing side-channel.
        """
        if len(timings) != len(key_bits) or not timings:
            return {"error": "Timing and key bit arrays must be same length"}

        # Compute Pearson correlation
        n = len(timings)
        mean_t = statistics.mean(timings)
        mean_k = statistics.mean(key_bits)

        numerator   = sum((t - mean_t) * (k - mean_k) for t, k in zip(timings, key_bits))
        denom_t     = math.sqrt(sum((t - mean_t)**2 for t in timings))
        denom_k     = math.sqrt(sum((k - mean_k)**2 for k in key_bits))

        if denom_t == 0 or denom_k == 0:
            correlation = 0.0
        else:
            correlation = numerator / (denom_t * denom_k)

        return {
            "pearson_correlation": round(correlation, 4),
            "attack_detected":     abs(correlation) > 0.3,
            "severity":            "CRITICAL" if abs(correlation) > 0.5 else
                                   "HIGH" if abs(correlation) > 0.3 else "LOW",
            "interpretation":      (
                f"Correlation {correlation:.3f} indicates timing side-channel — "
                f"key bits are leaking through timing variations."
                if abs(correlation) > 0.3 else
                f"Correlation {correlation:.3f} — no significant timing side-channel detected."
            ),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Quantum NEXUS Module
# ═══════════════════════════════════════════════════════════════════════════════

class QuantumNEXUSModule:
    """shadow313.v4.quantum_nexus — Quantum NEXUS. Registered: quantum_nexus"""

    def __init__(self, kernel) -> None:
        self.kernel    = kernel
        self.out       = kernel.out
        self.session   = kernel.session
        self.hndl      = HNDLAnalyzer()
        self.qkd       = QKDMonitor()
        self.sensor    = QuantumSensorFusion()
        self.mlkem     = MLKEMSideChannelDetector()

    def register(self, kernel) -> None:
        kernel.register("quantum_nexus", self.run)

    def run(
        self,
        # HNDL
        hndl_analyze:  bool = False,
        algorithm:     str  = "RSA-2048",
        sensitivity:   str  = "CONFIDENTIAL",
        volume_gb:     float= 1.0,
        retention:     int  = 10,
        # QKD
        qkd_monitor:   bool = False,
        qber:          float= 0.0,
        simulate_bb84: bool = False,
        eavesdrop:     bool = False,
        # Sensor Fusion
        fuse_sensors:  bool = False,
        # ML-KEM
        mlkem_timing:  bool = False,
        # General
        full_assessment:bool= False,
        stats:         bool = False,
    ) -> dict:
        self.out.section("QUANTUM NEXUS — ADVANCED QUANTUM SECURITY")
        result: dict[str, Any] = {}

        if hndl_analyze or full_assessment:
            self.out.info(f"HNDL Analysis: {algorithm} | {sensitivity} | {volume_gb}GB | {retention}yr retention")
            asset = self.hndl.analyze_asset(
                name             = f"Asset-{algorithm}",
                algorithm        = algorithm,
                data_sensitivity = sensitivity,
                data_volume_gb   = volume_gb,
                retention_years  = retention,
            )
            self.out.result({
                "hndl_score":    asset.hndl_score,
                "priority":      asset.hndl_priority,
                "years_at_risk": asset.years_at_risk,
                "migrate_by":    asset.migrate_by,
                "recommendation":asset.recommendation,
            }, "HNDL Assessment")
            result["hndl"] = asdict(asset)

        if qkd_monitor or full_assessment:
            self.out.info(f"QKD Monitoring: QBER={qber}%")
            session = self.qkd.monitor_session(
                session_id = "qkd-session-001",
                protocol   = "BB84",
                qber       = qber,
            )
            if session.status == "attack_detected":
                self.out.warn(f"QKD ATTACK: {session.alert}")
            elif session.status == "warning":
                self.out.warn(f"QKD WARNING: {session.alert}")
            else:
                self.out.success(f"QKD Secure: QBER={qber}% (threshold: {self.qkd.QBER_WARNING_THRESHOLD}%)")
            result["qkd"] = asdict(session)

        if simulate_bb84:
            self.out.info(f"Simulating BB84 QKD (eavesdrop={eavesdrop}) …")
            sim = self.qkd.simulate_bb84(n_qubits=1000, eavesdrop=eavesdrop)
            self.out.result(sim, "BB84 Simulation")
            result["bb84_simulation"] = sim

        if fuse_sensors or full_assessment:
            # Simulate sensor readings
            sensor_readings = {
                "gravimeter":      random.uniform(0.1, 0.9),
                "nv_magnetometer": random.uniform(0.1, 0.9),
                "classical_rf":    random.uniform(0.1, 0.9),
                "gps":             random.uniform(0.1, 0.9),
            }
            self.out.info("Fusing quantum sensor readings …")
            fusion = self.sensor.fuse(sensor_readings)
            if fusion.get("spoofing_detected"):
                self.out.warn(f"SPOOFING: {fusion['spoofing_alert']}")
            self.out.result(fusion, "Sensor Fusion Result")
            result["sensor_fusion"] = fusion

        if mlkem_timing or full_assessment:
            self.out.info("Measuring ML-KEM timing variance …")
            timing = self.mlkem.measure_timing(n_samples=100)
            if timing["timing_attack_detected"]:
                self.out.warn(f"TIMING ATTACK: {timing['recommendation']}")
            else:
                self.out.success(f"ML-KEM: {timing['status']}")
            result["mlkem_timing"] = timing

        if stats:
            s = {
                "crqc_arrival":    CRQC_ARRIVAL_YEAR,
                "years_remaining": YEARS_TO_CRQC,
                "qkd_sessions":    len(self.qkd.get_sessions()),
                "algorithms_safe": sum(1 for a in ALGORITHM_QUANTUM_RISK.values() if a["risk"] == "SAFE"),
                "algorithms_vulnerable": sum(1 for a in ALGORITHM_QUANTUM_RISK.values() if a["shor_vulnerable"]),
            }
            self.out.result(s, "Quantum NEXUS Statistics")
            result["stats"] = s

        if not result:
            self.out.info("Quantum NEXUS subsystems:")
            self.out.info("  --hndl-analyze    Harvest-Now-Decrypt-Later risk assessment")
            self.out.info("  --qkd-monitor     QKD session monitoring (QBER threshold: 8%/11%)")
            self.out.info("  --simulate-bb84   BB84 protocol simulation")
            self.out.info("  --fuse-sensors    Quantum sensor fusion")
            self.out.info("  --mlkem-timing    ML-KEM side-channel detection")
            self.out.info("  --full-assessment Run all subsystems")

        return result