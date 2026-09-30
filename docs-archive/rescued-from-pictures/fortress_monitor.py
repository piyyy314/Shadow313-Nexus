import time
import os
from fortress_config import LOG_MASTER, LOG_DEFENSIVE, LOG_OFFENSIVE, LOG_INTEL, DASHBOARD_REFRESH

def tail(filename, n=10):
    if not os.path.exists(filename):
        return []
    with open(filename, "r") as f:
        return f.readlines()[-n:]

def show_dashboard():
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=== FORTRESS LIVE MONITOR DASHBOARD ===\n")
            print(">> Recent Defensive Events:")
            for l in tail(LOG_DEFENSIVE):
                print("  ", l.strip())
            print("\n>> Recent Offensive Events:")
            for l in tail(LOG_OFFENSIVE):
                print("  ", l.strip())
            print("\n>> Recent Threat Intel:")
            for l in tail(LOG_INTEL):
                print("  ", l.strip())
            print("\n>> Fortress Activity Summary:")
            for l in tail(LOG_MASTER):
                print("  ", l.strip())
            print(f"\n--- Refreshing every {DASHBOARD_REFRESH}s. Press CTRL+C to quit. ---")
            time.sleep(DASHBOARD_REFRESH)
    except KeyboardInterrupt:
        print("\n[!] Dashboard terminated.")

if __name__ == "__main__":
    show_dashboard()