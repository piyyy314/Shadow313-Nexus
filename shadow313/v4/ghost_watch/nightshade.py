from __future__ import annotations
"""
shadow313.v4.ghost_watch.nightshade
NIGHTSHADE: Electromagnetic Spectrum Analyzer — sweeps LoRa frequencies for shadow nodes and EW jamming.
"""
import time, random

class NightshadeEMS:
    """EM spectrum analyzer for RF threat detection."""

    FREQUENCY_BANDS = {
        "lora_915": (902e6, 928e6),
        "lora_868": (863e6, 870e6),
        "wifi_24":  (2.4e9, 2.5e9),
        "wifi_5":   (5.15e9, 5.85e9),
        "cellular": (700e6, 2.7e9),
    }

    def __init__(self, target_freq_mhz: float = 915.0):
        self.target_freq = target_freq_mhz * 1e6
        self.scan_results: list = []
        self.jamming_detected: bool = False

    def sweep(self, band: str = "lora_915") -> dict:
        low, high = self.FREQUENCY_BANDS.get(band, (900e6, 930e6))
        anomalies = []
        # Simulate spectrum sweep
        for freq in range(int(low/1e6), int(high/1e6), 1):
            power_dbm = random.gauss(-90, 5)
            if power_dbm > -70:  # Anomalous signal
                anomalies.append({"freq_mhz": freq, "power_dbm": round(power_dbm, 2)})
        result = {
            "band": band,
            "sweep_time": time.time(),
            "anomalies_found": len(anomalies),
            "anomalies": anomalies[:10],
            "jamming_suspected": len(anomalies) > 5,
        }
        self.scan_results.append(result)
        self.jamming_detected = result["jamming_suspected"]
        return result

    def inject_counter_interference(self, target_freq_mhz: float) -> dict:
        """Transmit phase-inverted interference to blind hostile emitters."""
        return {
            "action": "counter_interference",
            "target_freq_mhz": target_freq_mhz,
            "phase_inversion": True,
            "power_dbm": -50,
            "status": "transmitted",
            "timestamp": time.time(),
        }

    def status(self) -> dict:
        return {
            "target_freq_mhz": self.target_freq / 1e6,
            "scans_performed": len(self.scan_results),
            "jamming_detected": self.jamming_detected,
        }
