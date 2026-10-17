from __future__ import annotations
"""
shadow313.v4.quantum_nexus.lif_snn
LIF SNN — Leaky Integrate-and-Fire Spiking Neural Network for APT beacon detection.
"""
import numpy as np
import time

class LIFNeuronSOC:
    """Neuromorphic LIF neuron for low-and-slow APT detection."""

    def __init__(self, threshold: float = 1.0, leak_rate: float = 0.95):
        self.voltage = 0.0
        self.threshold = threshold
        self.leak_rate = leak_rate
        self.spike_history: list = []

    def process_stream(self, packet_weights: list) -> dict:
        spikes = []
        voltage_history = []
        for t, weight in enumerate(packet_weights):
            self.voltage *= self.leak_rate
            self.voltage += weight
            if self.voltage >= self.threshold:
                spikes.append(t)
                self.voltage = 0.0
            voltage_history.append(round(self.voltage, 4))

        self.spike_history.extend(spikes)
        return {
            "spikes": spikes,
            "spike_count": len(spikes),
            "voltage_history": voltage_history,
            "max_voltage": round(max(voltage_history) if voltage_history else 0, 4),
            "detection": len(spikes) > 0,
        }

    def reset(self) -> None:
        self.voltage = 0.0

class APTBeaconDetector:
    """Full APT beacon detection using LIF SNN vs standard SIEM comparison."""

    def __init__(self, threshold: float = 0.8, leak_rate: float = 0.85):
        self.snn = LIFNeuronSOC(threshold=threshold, leak_rate=leak_rate)
        self.detection_log: list = []

    def analyze_traffic(self, traffic_stream: list, beacon_indices: list) -> dict:
        """Compare SNN vs threshold-based SIEM detection."""
        # Standard SIEM: single-event threshold
        siem_threshold = 0.5
        siem_alerts = [i for i, w in enumerate(traffic_stream) if w >= siem_threshold]

        # SNN detection
        snn_result = self.snn.process_stream(traffic_stream)
        snn_alerts = snn_result["spikes"]

        # Evaluate against known beacon positions
        true_positives_snn = len(set(snn_alerts) & set(beacon_indices))
        true_positives_siem = len(set(siem_alerts) & set(beacon_indices))

        result = {
            "traffic_length": len(traffic_stream),
            "beacon_count": len(beacon_indices),
            "siem_alerts": len(siem_alerts),
            "siem_true_positives": true_positives_siem,
            "snn_alerts": len(snn_alerts),
            "snn_true_positives": true_positives_snn,
            "snn_advantage": true_positives_snn > true_positives_siem,
            "timestamp": time.time(),
        }
        self.detection_log.append(result)
        return result

    def status(self) -> dict:
        return {
            "analyses_run": len(self.detection_log),
            "snn_wins": sum(1 for r in self.detection_log if r["snn_advantage"]),
        }
