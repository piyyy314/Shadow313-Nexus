import socket
from datetime import datetime
from alerts import send_alert
from fortress_config import CANARY_LISTEN_PORT, LOG_INTEL

LHOST = "0.0.0.0"
LPORT = CANARY_LISTEN_PORT

def start_canary_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((LHOST, LPORT))
        server.listen(5)
        print(f"[*] Canary Listener active on port {LPORT}...")
        print(f"[*] Waiting for document to be opened...")
        while True:
            client, addr = server.accept()
            ip = addr[0]
            request = client.recv(1024).decode('utf-8', errors='ignore')
            user_agent = "Unknown"
            for line in request.split('\n'):
                if "User-Agent:" in line:
                    user_agent = line.replace("User-Agent:", "").strip()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_msg = f"[!!!] ALERT: Document opened by {ip} at {timestamp}\n    Device Info: {user_agent}\n"
            print(alert_msg)
            send_alert(f"Canary Document opened by {ip} ({user_agent})")
            with open(LOG_INTEL, "a") as f:
                f.write(alert_msg + "-"*30 + "\n")
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: image/gif\r\n"
                "Content-Length: 43\r\n\r\n"
                "GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
            )
            client.send(response.encode('latin-1'))
            client.close()
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_canary_listener()