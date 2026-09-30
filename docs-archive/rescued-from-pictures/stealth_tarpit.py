import socket
import threading
import time

# --- Configuration ---
BIND_IP = "0.0.0.0"
BIND_PORT = 8080  # Common port for web proxies, very attractive to hackers
MAX_DELAY = 3600  # Keep them waiting for an hour if possible

def handle_stealth_trap(client_socket, address):
    ip, port = address
    print(f"[+] Stealth Trap: Connection from {ip}:{port} - Freezing their thread...")
    
    try:
        # We perform NO send() and NO recv()
        # We simply keep the socket object alive in memory
        while True:
            # Check if the client is still there without sending data
            # This 'peek' keeps the connection technically active
            data = client_socket.recv(1, socket.MSG_PEEK)
            if not data:
                break
            time.sleep(MAX_DELAY)
            
    except Exception:
        pass
    finally:
        client_socket.close()
        print(f"[-] Stealth Trap: {ip} finally timed out.")

def start_stealth_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(500) # Increased capacity to trap a small botnet
    
    print(f"[*] Stealth Tarpit running on {BIND_PORT}...")
    print("[*] This script will say nothing to the attacker, just hang their connection.")

    while True:
        client, addr = server.accept()
        # Each "fly" gets stuck in the web
        threading.Thread(target=handle_stealth_trap, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    start_stealth_server()