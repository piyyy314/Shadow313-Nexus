import threading
import subprocess
import time
import sys
from datetime import datetime

# --- Configuration ---
# Adjust the file paths as needed for your project structure
DEFENSIVE_MODULES = [
    {"name": "Network Tarpit", "file": "sensors/tarpit.py"},
    {"name": "Process Sentinel", "file": "tools/process_sentinel.py"},
    {"name": "Canary Listener", "file": "sensors/canary_listener.py"}
]

def launch_module(module_name, file_name):
    """
    Launches a defensive script and restarts it if it fails.
    """
    while True:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [SYSTEM] Launching {module_name}...")
        try:
            process = subprocess.Popen([sys.executable, file_name])
            process.wait()
            print(f"[!] WARNING: {module_name} stopped. Restarting in 3 seconds...")
            time.sleep(3)
        except Exception as e:
            print(f"[X] ERROR in {module_name}: {e}")
            time.sleep(10)

def display_banner():
    banner = """
    ==================================================
    |        FORTRESS COMMAND CENTER v1.0            |
    |    Status: ACTIVE | Security Level: 1000%      |
    ==================================================
    """
    print(banner)

def start_war_room():
    display_banner()
    threads = []
    for module in DEFENSIVE_MODULES:
        t = threading.Thread(
            target=launch_module,
            args=(module["name"], module["file"]),
            daemon=True
        )
        t.start()
        threads.append(t)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down all defensive systems. Stay safe.")

if __name__ == "__main__":
    start_war_room()