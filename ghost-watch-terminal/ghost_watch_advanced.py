"""
ghost_watch_advanced.py — Ghost-Watch Advanced CLI (9 modules)
Advanced interface with TARTARUS, ORACLE, NIGHTSHADE, CERBERUS.
"""
from __future__ import annotations
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghost_watch_terminal.src.core.engine import GhostWatchEngine, _now_iso

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  ⬡  GHOST-WATCH ADVANCED — 9 Module Interface               ║
║     ACTS | CADL | TARTARUS | ORACLE | NIGHTSHADE | CERBERUS  ║
╚══════════════════════════════════════════════════════════════╝"""


def main():
    print(BANNER)
    engine = GhostWatchEngine()

    try:
        from shadow313.v4.ghost_watch.tartarus import TARTARUSEngine
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        tartarus  = TARTARUSEngine()
        predictor = ThreatPredictor()
        advanced_ok = True
    except ImportError as e:
        print(f"  [!] Advanced modules unavailable: {e}")
        advanced_ok = False

    while True:
        print("\n  [1] WE-FORGE  [2] CADL  [3] TARTARUS  [4] ORACLE  [5] Status  [q] Quit")
        cmd = input("  ghost-watch-adv> ").strip().lower()
        if cmd == "q":
            break
        elif cmd == "1":
            lure = engine.acts.forge_lure("adversary.c2.local")
            print(f"  Lure deployed: {lure.lure_id}")
        elif cmd == "2":
            event = engine.cadl.escalate("adversary.c2.local", "advanced test", level=3)
            print(f"  CADL L{event.level} {event.action}")
        elif cmd == "3" and advanced_ok:
            intercepted, noise = tartarus.inspect_egress(
                "10.0.1.10", "185.220.101.47", 4444, b"X" * 10000
            )
            print(f"  TARTARUS: intercepted={intercepted}, noise={len(noise)}B")
        elif cmd == "4" and advanced_ok:
            predictor.ingest_behavioral("10.0.1.10", 0.85, ["T1003.001"])
            f = predictor.forecast_host("10.0.1.10")
            print(f"  ORACLE: risk={f.overall_risk:.3f} level={f.risk_level}")
        elif cmd == "5":
            print(f"  {json.dumps(engine.status(), indent=2)}")
        else:
            print(f"  Unknown or module unavailable: {cmd}")


if __name__ == "__main__":
    main()