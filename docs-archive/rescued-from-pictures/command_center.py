import threading
import subprocess
import time
import sys
from datetime import datetime

# --- Configuration ---
# List of scripts to keep alive 24/7
DEFENSIVE_MODULES = [
    {"name": "Network Tarpit", "file": "tarpit.py"},
    {"name": "Process Sentinel", "file": "sentinel.py"},
    {"name": "Canary Listener", "file": "canary_listener.py"}
]

def launch_module(module_name, file_name):
    """
    Launches a defensive script and restarts it if it fails.
    """
    while True:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [SYSTEM] Launching {module_name}...")
        
        try:
            # We use sys.executable to ensure we use the same Python version
            process = subprocess.Popen([sys.executable, file_name])
            
            # Wait for the process to finish (it shouldn't, unless it crashes)
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
    
    # Start each module in its own monitoring thread
    for module in DEFENSIVE_MODULES:
        t = threading.Thread(
            target=launch_module, 
            args=(module["name"], module["file"]),
            daemon=True # This ensures they close if the main center is closed
        )
        t.start()
        threads.append(t)

    # Main loop to keep the Command Center UI alive
    try:
        while True:
            # Here you could add code to read and summarize logs from all scripts
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down all defensive systems. Stay safe.")

if __name__ == "__main__":
    start_war_room()