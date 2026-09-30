import psutil
import os
import time
from datetime import datetime

# --- Configuration ---
# Add names of tools you want to ban on your system
BLACKLIST = [
    "nc.exe", "netcat", "nmap", "wireshark", "tshark", 
    "mimikatz", "putty", "vnc", "ophcrack"
]

LOG_FILE = "sentinel_actions.txt"

def log_incident(proc_name, pid):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] KILLED MALICIOUS PROCESS: {proc_name} (PID: {pid})\n"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def process_sentinel():
    print("--- PROCESS SENTINEL ACTIVE: PROTECTING SYSTEM ---")
    print(f"Monitoring for: {', '.join(BLACKLIST)}")
    print("-" * 50)

    while True:
        # Iterate over all running processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                
                # Check if process name is in our blacklist
                if any(bad_tool in proc_name for bad_tool in BLACKLIST):
                    pid = proc.info['pid']
                    
                    # Kill the process
                    p = psutil.Process(pid)
                    p.terminate() # Or p.kill() for a more forceful stop
                    
                    log_incident(proc_name, pid)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # These errors occur if a process closes before we can check it
                continue
        
        # Sleep for a short duration to save CPU, but fast enough to catch hackers
        time.sleep(1)

if __name__ == "__main__":
    try:
        process_sentinel()
    except KeyboardInterrupt:
        print("\n[!] Sentinel deactivated.")