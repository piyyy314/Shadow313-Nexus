import socket
import threading
import os
import platform
import subprocess

# --- Configuration ---
BIND_IP = "0.0.0.0"
BIND_PORT = 9999
WHITELIST = ["127.0.0.1"] # Never block yourself!

def block_ip(ip):
    """
    Executes system commands to block an IP address.
    """
    if ip in WHITELIST:
        return

    print(f"[!!!] COMMANDING FIREWALL TO BLOCK: {ip}")
    
    current_os = platform.system()
    
    try:
        if current_os == "Linux":
            # Uses iptables to DROP all traffic from the IP
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        elif current_os == "Windows":
            # Uses netsh to create a firewall rule
            rule_name = f"BLOCK_ATTACKER_{ip}"
            cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip}"
            subprocess.run(cmd, shell=True, check=True)
            
        print(f"[√] {ip} has been successfully neutralized.")
    except Exception as e:
        print(f"[X] Failed to block {ip}: {e}")

def handle_intruder(client_socket, address):
    ip, port = address
    print(f"[*] Intruder detected from {ip}. Initiating lockdown...")
    
    # 1. Block them immediately
    block_ip(ip)
    
    # 2. Keep the current connection 'stuck' for a while before closing
    try:
        client_socket.send(b"Connection Refused. Security protocols engaged.")
    except:
        pass
    finally:
        client_socket.close()

def start_reflexive_system():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((BIND_IP, BIND_PORT))
        server.listen(100)
        print(f"--- REFLEXIVE DEFENSE SYSTEM ACTIVE ON PORT {BIND_PORT} ---")
        
        while True:
            client, addr = server.accept()
            # Start the blocking process in a new thread
            threading.Thread(target=handle_intruder, args=(client, addr)).start()
            
    except PermissionError:
        print("[X] ERROR: You must run this script with Administrator/Root privileges to modify firewall rules!")

if __name__ == "__main__":
    start_reflexive_system()