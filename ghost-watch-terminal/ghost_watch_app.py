"""
ghost_watch_app.py — Ghost-Watch Basic CLI (5 modules)
Basic interactive interface for core Ghost-Watch operations.
"""
from __future__ import annotations
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghost_watch_terminal.src.core.engine import GhostWatchEngine, _now_iso

BANNER = """
╔══════════════════════════════════════════════════════╗
║  ⬡  GHOST-WATCH — Basic Operations Interface        ║
║     5 Core Modules | HB-9982-AX-2026                ║
╚══════════════════════════════════════════════════════╝"""

MODULES_5 = {
    "1": ("ACTS/WE-FORGE", "Canary trap + watermarking"),
    "2": ("CADL Engine",   "5-tier deception escalation"),
    "3": ("CHRONOS",       "Temporal snapshot recovery"),
    "4": ("ORACLE",        "Threat pathfinding"),
    "5": ("NIGHTSHADE",    "EM spectrum analysis"),
}


def main():
    print(BANNER)
    print(f"\n  Initialized: {_now_iso()}")
    engine = GhostWatchEngine()

    while True:
        print("\n  [1] WE-FORGE lure  [2] CADL escalate  [3] Status  [q] Quit")
        cmd = input("  ghost-watch> ").strip().lower()
        if cmd == "q":
            break
        elif cmd == "1":
            lure = engine.acts.forge_lure("test.target.local")
            print(f"  Lure: {lure.lure_id} → {lure.target}")
        elif cmd == "2":
            event = engine.cadl.escalate("test.adversary", "manual test")
            print(f"  CADL L{event.level} {event.action}: executed={event.executed}")
        elif cmd == "3":
            print(f"  Status: {json.dumps(engine.status(), indent=2)}")
        else:
            print(f"  Unknown: {cmd}")


if __name__ == "__main__":
    main()