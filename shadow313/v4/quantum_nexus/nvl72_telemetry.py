"""
Shadow313 NEXUS — NVL72 30TB Unified VRAM Telemetry Monitor
Monitors GB200 NVL72 exascale compute for quantum simulation workloads.
Total VRAM: 30000 GB | Peak: 26506 GB | Max Threads: 353894
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, List

NVL72_SPECS = {
    "total_vram_gb":     30000,
    "total_vram_tb":     30.0,
    "peak_allocated_gb": 26506,
    "purge_threshold_gb": 25500,
    "max_threads":       353894,
    "architecture":      "NVIDIA GB200 NVL72",
}

class NVL72TelemetryMonitor:
    """Monitor NVL72 VRAM usage for quantum simulation workloads."""

    SPIKE_THRESHOLD_GB   = 500
    CRITICAL_THRESHOLD_PCT = 90.0

    def __init__(self):
        self._samples: List[Dict] = []
        self._spikes:  List[Dict] = []

    def record_sample(self, allocated_gb: float, threads: int) -> Dict:
        utilization = (allocated_gb / NVL72_SPECS["total_vram_gb"]) * 100
        is_spike = (len(self._samples) > 0 and
                    abs(allocated_gb - self._samples[-1]["allocated_gb"]) > self.SPIKE_THRESHOLD_GB)
        sample = {
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "allocated_gb":    allocated_gb,
            "utilization_pct": round(utilization, 2),
            "threads":         threads,
            "is_spike":        is_spike,
            "status":          "CRITICAL" if utilization > self.CRITICAL_THRESHOLD_PCT else "NOMINAL"
        }
        self._samples.append(sample)
        if is_spike:
            self._spikes.append(sample)
        return sample

    def omega_purge_check(self, current_gb: float) -> bool:
        return current_gb > NVL72_SPECS["purge_threshold_gb"]

    def get_summary(self) -> Dict:
        if not self._samples:
            return {"error": "No samples"}
        allocs = [s["allocated_gb"] for s in self._samples]
        return {
            "samples": len(self._samples), "peak_gb": max(allocs),
            "avg_gb": round(sum(allocs)/len(allocs), 1),
            "spikes": len(self._spikes),
            "capacity_gb": NVL72_SPECS["total_vram_gb"]
        }
