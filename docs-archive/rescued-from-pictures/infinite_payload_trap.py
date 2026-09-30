import socket
import threading

# --- Configuration ---
BIND_IP = "0.0.0.0"
BIND_PORT = 80  # Mimics a standard Web Server
CHUNK_SIZE = 1024 * 64  # 64KB chunks of data
FAKE_FILE_NAME = "backup_database.sql.gz"

def handle_attacker(client_socket, address):
    ip, port = address
    print(f"[!] Attacker {ip} is attempting to download the 'bait'...")

    try:
        # 1. Receive their request (e.g., "GET /backup_database.sql.gz HTTP/1.1")
        request = client_socket.recv(1024)
        
        # 2. Send fake HTTP headers telling them a massive file is coming
        header = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Disposition: attachment; filename=\"{FAKE_FILE_NAME}\"\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Connection: keep-alive\r\n\r\n"
        )
        client_socket.send(header.encode())

        # 3. The Trap: Infinite Loop
        # We send 64KB of zeros repeatedly forever.
        # This will eventually crash their automated downloader or fill their RAM.
        zero_chunk = b"\x00" * CHUNK_SIZE
        print(f"[*] Sending infinite 'Zero-Data' to {ip}...")
        
        while True:
            client_socket.send(zero_chunk)
            
    except (ConnectionResetError, BrokenPipeError):
        print(f"[-] {ip} crashed or disconnected after being flooded.")
    except Exception as e:
        print(f"[-] Connection with {ip} ended: {e}")
    finally:
        client_socket.close()

def start_trap_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(5)

    print(f"[*] Infinite Payload Trap active on port {BIND_PORT}...")
    print(f"[*] Bait: http://your-ip/{FAKE_FILE_NAME}")

    while True:
        client, addr = server.accept()
        # Launch the 'bomb' in a new thread
        t = threading.Thread(target=handle_attacker, args=(client, addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    start_trap_server()