import socket
import threading
from fortress_config import INTERNAL_NET

COMMON_INTERNAL_PORTS = [21, 22, 80, 443, 445, 3389]

def scan_host(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f" [!] Internal Discovery: {ip} is OPEN on port {port}")
        s.close()
    except:
        pass

def start_pivot_scan():
    print(f"[*] Starting Stealth Pivot Scan on {INTERNAL_NET}0/24...")
    print("[-] Searching for internal servers and lateral moves...")
    
    threads = []
    for i in range(1, 51):
        target_ip = f"{INTERNAL_NET}{i}"
        for port in COMMON_INTERNAL_PORTS:
            t = threading.Thread(target=scan_host, args=(target_ip, port))
            t.start()
            threads.append(t)
            if len(threads) > 20:
                for t in threads:
                    t.join()
                threads = []

if __name__ == "__main__":
    start_pivot_scan()