import socket
import time
import threading
from alerts import send_alert
from fortress_config import TARPIT_PORT

BIND_IP = "0.0.0.0"
BIND_PORT = TARPIT_PORT
DELAY = 10

def sticky_trap(client_socket, address):
    ip, port = address
    print(f"[!] Target trapped: {ip}:{port}")
    send_alert(f"Tarpit: Target trapped at {ip}:{port}")
    try:
        message = "WARNING: Unauthorized access detected. Initiating secure trace..."
        for char in message:
            client_socket.send(char.encode())
            time.sleep(DELAY)
    except (ConnectionResetError, BrokenPipeError):
        print(f"[-] Target {ip} got frustrated and disconnected.")
    finally:
        client_socket.close()

def start_tarpit():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(100)
    print(f"[*] Tarpit active on port {BIND_PORT}. Waiting for 'flies'...")
    while True:
        client, addr = server.accept()
        trap_thread = threading.Thread(target=sticky_trap, args=(client, addr))
        trap_thread.start()

if __name__ == "__main__":
    start_tarpit()