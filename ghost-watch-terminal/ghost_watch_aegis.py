"""
ghost_watch_aegis.py — Ghost-Watch Vault Aegis Q-EAI Integration
Quantum-Enhanced Active Intelligence with Vault Aegis binding.
"""
from __future__ import annotations
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghost_watch_terminal.src.core.engine import GhostWatchEngine, _now_iso

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  ⬡  GHOST-WATCH VAULT AEGIS — Q-EAI Integration             ║
║     Quantum-Enhanced Active Intelligence                     ║
║     VAULT AEGIS: ENFORCING | HB-9982-AX-2026                ║
╚══════════════════════════════════════════════════════════════╝"""


def main():
    print(BANNER)
    engine = GhostWatchEngine()

    try:
        from shadow313.v4.satellite.ground_segment_sweep import run_ground_segment_sweep
        from shadow313.v4.satellite.cwmp_hardening import run_cwmp_hardening_assessment
        aegis_ok = True
    except ImportError as e:
        print(f"  [!] Aegis modules: {e}")
        aegis_ok = False

    while True:
        print("\n  [1] VSAT sweep  [2] CWMP audit  [3] PQC status  [4] Lure  [q] Quit")
        cmd = input("  vault-aegis> ").strip().lower()
        if cmd == "q":
            break
        elif cmd == "1" and aegis_ok:
            result = run_ground_segment_sweep(verbose=False)
            print(f"  VSAT sweep: {result.critical_count} CRITICAL, {result.high_count} HIGH")
            for f in result.findings[:3]:
                print(f"    [{f.severity}] {f.finding[:60]}")
        elif cmd == "2" and aegis_ok:
            result = run_cwmp_hardening_assessment(verbose=False)
            print(f"  CWMP: {result['critical']} critical gaps, {result['passed']}/{len(result['checks'])} passed")
        elif cmd == "3":
            pqc = engine.pqc.status()
            print(f"  PQC: {pqc['slh']} | {pqc['kem']} | {pqc['dsa']}")
        elif cmd == "4":
            lure = engine.acts.forge_lure("vault.aegis.local", "VAULT AEGIS Q-EAI Secret Key Material")
            print(f"  Lure: {lure.lure_id}")
        else:
            print(f"  Unknown or module unavailable: {cmd}")


if __name__ == "__main__":
    main()