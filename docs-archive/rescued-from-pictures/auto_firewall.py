import platform
import subprocess

def block_ip(ip):
    """
    Blocks the specified IP address using the system firewall.
    Supports Linux (iptables) and Windows (netsh).
    """
    os_type = platform.system()
    try:
        if os_type == "Linux":
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        elif os_type == "Windows":
            rule = f'netsh advfirewall firewall add rule name="FortressBlock_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(rule, shell=True)
        print(f"[Auto-Firewall] Blocked IP: {ip}")
    except Exception as e:
        print(f"[Auto-Firewall] Error blocking {ip}: {e}")

# Example usage:
if __name__ == "__main__":
    test_ip = "192.168.1.100"  # Replace with the target IP you want to block
    block_ip(test_ip)