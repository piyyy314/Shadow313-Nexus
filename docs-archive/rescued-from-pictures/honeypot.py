import socket, threading
from ..core.log_util import log_event

def honeypot(bind_ip='0.0.0.0', port=2222, rc=None):
    def handle_client(client_socket, address):
        log_event(f"[HONEYPOT] Caught connection from {address[0]}")
        if rc:
            rc.handle_alert("suspicious_ip", {"ip": address[0]})
        client_socket.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_ip, port))
    s.listen(10)
    log_event(f"[HONEYPOT] Listening on {bind_ip}:{port}")
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()