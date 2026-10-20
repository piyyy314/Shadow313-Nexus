"""
shadow313.v4.threat_predictor.predictor
ML Threat Predictor — Markov chain, ORACLE engine, 313-BIND receipts.
"""
from __future__ import annotations
import time, random
from typing import Optional


TRANSITION_MATRIX = {
    "initial_access":    {"execution": 0.7, "persistence": 0.2, "discovery": 0.1},
    "execution":         {"persistence": 0.4, "privilege_escalation": 0.35, "defense_evasion": 0.25},
    "persistence":       {"privilege_escalation": 0.5, "credential_access": 0.3, "lateral_movement": 0.2},
    "privilege_escalation": {"credential_access": 0.45, "lateral_movement": 0.35, "collection": 0.2},
    "credential_access": {"lateral_movement": 0.6, "collection": 0.25, "exfiltration": 0.15},
    "lateral_movement":  {"collection": 0.5, "exfiltration": 0.3, "impact": 0.2},
    "collection":        {"exfiltration": 0.7, "impact": 0.3},
    "exfiltration":      {"impact": 0.8, "initial_access": 0.2},
    "impact":            {"initial_access": 0.3, "exfiltration": 0.7},
    "defense_evasion":   {"execution": 0.4, "persistence": 0.35, "lateral_movement": 0.25},
    "discovery":         {"lateral_movement": 0.5, "credential_access": 0.3, "collection": 0.2},
}


class ThreatPredictor:
    """Markov chain threat predictor with ORACLE engine integration."""

    def __init__(self):
        self.prediction_history: list = []
        self.current_state: str = "initial_access"

    def predict_next(self, current_state: Optional[str] = None) -> dict:
        state = current_state or self.current_state
        transitions = TRANSITION_MATRIX.get(state, {})
        if not transitions:
            return {"state": state, "next": None, "probability": 0.0}
        sorted_t = sorted(transitions.items(), key=lambda x: x[1], reverse=True)
        top_next, top_prob = sorted_t[0]
        prediction = {
            "current_state": state,
            "predicted_next": top_next,
            "probability": top_prob,
            "alternatives": [{"state": s, "prob": p} for s, p in sorted_t[1:]],
            "confidence": "HIGH" if top_prob > 0.5 else "MEDIUM",
            "timestamp": time.time(),
        }
        self.prediction_history.append(prediction)
        return prediction

    def simulate_path(self, start: str = "initial_access", steps: int = 6) -> list:
        path = [start]
        state = start
        for _ in range(steps):
            transitions = TRANSITION_MATRIX.get(state, {})
            if not transitions:
                break
            states = list(transitions.keys())
            probs = list(transitions.values())
            state = random.choices(states, weights=probs)[0]
            path.append(state)
        return path

    def score_threat(self, events: list) -> dict:
        """Score a sequence of events for threat likelihood."""
        if not events:
            return {"score": 0.0, "risk": "LOW"}
        tactics = set(e.get("tactic", "unknown") for e in events)
        score = min(1.0, len(tactics) * 0.15 + len(events) * 0.05)
        risk = "CRITICAL" if score > 0.8 else "HIGH" if score > 0.6 else "MEDIUM" if score > 0.3 else "LOW"
        return {"score": round(score, 3), "risk": risk, "tactics_seen": list(tactics), "event_count": len(events)}

    def recommend_predeployment(self, predicted_next: str) -> list:
        recommendations = {
            "lateral_movement": ["Deploy honeytokens on admin shares", "Enable SMB signing", "Alert on PsExec/WMI"],
            "credential_access": ["Enable LSASS protection", "Deploy MFA", "Monitor 4769 Kerberoasting"],
            "exfiltration": ["Enable DLP", "Monitor large outbound transfers", "Block DNS tunneling"],
            "impact": ["Backup verification", "VSS protection", "Ransomware canaries"],
        }
        return recommendations.get(predicted_next, ["Monitor all activity", "Increase logging verbosity"])

    def status(self) -> dict:
        return {"predictions_made": len(self.prediction_history), "current_state": self.current_state}