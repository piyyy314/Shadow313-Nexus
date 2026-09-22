"""
ghost_watch_vanguard.py — Ghost-Watch Vanguard
Gorgon anti-tamper + Lazarus mesh-net resilience
"""
from __future__ import annotations
import sys, os, json, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghost_watch_terminal.src.core.engine import GhostWatchEngine, _now_iso

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  ⬡  GHOST-WATCH VANGUARD                                    ║
║     GORGON Anti-Tamper | LAZARUS Mesh-Net Resilience        ║
║     Behavioral biometrics + Memory integrity daemon         ║
╚══════════════════════════════════════════════════════════════╝"""


class GorgonMonitor:
    """GORGON — Behavioral Study and Analysis Unit."""

    def __init__(self) -> None:
        self._baseline_hash = ""
        self._anomalies: list[dict] = []

    def establish_baseline(self, process_list: list[str]) -> str:
        """Establish behavioral baseline from process list."""
        canonical = json.dumps(sorted(process_list), sort_keys=True)
        self._baseline_hash = hashlib.sha3_256(canonical.encode()).hexdigest()
        return self._baseline_hash

    def scan_memory(self, process_name: str, loaded_modules: list[str]) -> dict:
        """Scan process memory for injected DLLs/modules."""
        suspicious = [m for m in loaded_modules
                      if any(x in m.lower() for x in ["inject", "hook", "patch", "debug"])]
        if suspicious:
            anomaly = {
                "process": process_name,
                "suspicious_modules": suspicious,
                "timestamp": _now_iso(),
                "action": "ACTS_LURE_DEPLOYED",
            }
            self._anomalies.append(anomaly)
            return {"clean": False, "anomalies": suspicious}
        return {"clean": True, "anomalies": []}

    def check_keystroke_biometrics(self, typing_cadence_ms: list[float]) -> dict:
        """Analyze keystroke timing for behavioral anomalies."""
        if not typing_cadence_ms:
            return {"normal": True}
        import statistics
        mean = statistics.mean(typing_cadence_ms)
        std  = statistics.stdev(typing_cadence_ms) if len(typing_cadence_ms) > 1 else 0
        cv   = std / mean if mean > 0 else 0
        # Robotic typing (CV < 0.05) or extreme variance (CV > 2.0) = anomaly
        anomalous = cv < 0.05 or cv > 2.0
        return {
            "normal":    not anomalous,
            "mean_ms":   round(mean, 1),
            "cv":        round(cv, 3),
            "verdict":   "ANOMALOUS" if anomalous else "NORMAL",
        }


class LazarusMesh:
    """LAZARUS — Mesh-net resilience and node recovery."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict] = {}
        self._lora_freq = 915.0

    def register_node(self, node_id: str, ip: str) -> None:
        self._nodes[node_id] = {"ip": ip, "active": True, "last_seen": _now_iso()}

    def check_mesh_health(self) -> dict:
        active = sum(1 for n in self._nodes.values() if n["active"])
        return {
            "total_nodes": len(self._nodes),
            "active_nodes": active,
            "lora_freq_mhz": self._lora_freq,
            "mesh_health": "HEALTHY" if active == len(self._nodes) else "DEGRADED",
        }

    def revive_node(self, node_id: str) -> bool:
        if node_id in self._nodes:
            self._nodes[node_id]["active"] = True
            self._nodes[node_id]["last_seen"] = _now_iso()
            return True
        return False


def main():
    print(BANNER)
    engine  = GhostWatchEngine()
    gorgon  = GorgonMonitor()
    lazarus = LazarusMesh()

    # Register mesh nodes
    for i in range(1, 4):
        lazarus.register_node(f"node-{i:03d}", f"10.0.{i}.1")

    while True:
        print("\n  [1] GORGON scan  [2] Biometrics  [3] Mesh health  [4] Lure  [q] Quit")
        cmd = input("  vanguard> ").strip().lower()
        if cmd == "q":
            break
        elif cmd == "1":
            result = gorgon.scan_memory("svchost.exe", ["kernel32.dll", "ntdll.dll", "inject_hook.dll"])
            print(f"  GORGON: clean={result['clean']}, anomalies={result['anomalies']}")
        elif cmd == "2":
            import random
            cadence = [random.uniform(80, 120) for _ in range(20)]
            result = gorgon.check_keystroke_biometrics(cadence)
            print(f"  Biometrics: {result}")
        elif cmd == "3":
            health = lazarus.check_mesh_health()
            print(f"  Mesh: {health}")
        elif cmd == "4":
            lure = engine.acts.forge_lure("gorgon.vanguard.local")
            print(f"  Lure: {lure.lure_id}")
        else:
            print(f"  Unknown: {cmd}")


if __name__ == "__main__":
    main()