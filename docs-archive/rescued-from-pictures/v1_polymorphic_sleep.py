import time
import random

def polymorphic_sleep(base_seconds):
    """
    Sleeps for a random duration with ±40% jitter to evade pattern-based detection systems.
    """
    jitter = random.uniform(0.6, 1.4)
    sleep_time = base_seconds * jitter
    print(f"[!] Sleeping for {sleep_time:.2f}s to avoid AI pattern detection...")
    time.sleep(sleep_time)

if __name__ == "__main__":
    import sys
    base = float(sys.argv[1]) if len(sys.argv) > 1 else 60
    print("[*] Demo: Polymorphic sleep with base of", base, "seconds.")
    polymorphic_sleep(base)