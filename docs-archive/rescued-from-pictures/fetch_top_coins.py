import requests
import json

NUM_COINS = 100
REGISTRY_OUTFILE = "coin_registry.json"

# You can edit these to add custom logic per coin
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
    # Add more unique SDKs here as needed
}

def main():
    print(f"[*] Fetching top {NUM_COINS} coins by market cap from CoinGecko...")
    url = f"https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page={NUM_COINS}&page=1&sparkline=false"
    coins = requests.get(url).json()
    registry = []
    for c in coins:
        # Try mapping by id
        entry = {"name": c['name'], "symbol": c['symbol'].upper()}
        coin_id = c['id']
        # UTXO/SDK mapping
        if coin_id in UTXO_COINS:
            entry.update(UTXO_COINS[coin_id])
        elif coin_id in EVM_CHAINS:
            entry.update(EVM_CHAINS[coin_id])
        elif coin_id in SDK_HOOKS:
            entry.update(SDK_HOOKS[coin_id])
        elif 'platforms' in c and c['platforms'].get('ethereum'):
            # Platform tokens: Note, you must manually add contract and decimals later!
            entry.update(EVM_CHAINS['ethereum'])
            entry['contract'] = c['platforms']['ethereum']
            entry['decimals'] = 18   # May need manual fix
        else:
            entry['type'] = 'unknown'
        registry.append(entry)
    
    # Extra: Print out unknowns for your manual review
    unknowns = [e for e in registry if e['type'] == 'unknown']
    if unknowns:
        print(f"\n[!] {len(unknowns)} coins not mapped to a type. Review these manually:")
        for u in unknowns:
            print(f" - {u['name']} ({u['symbol']})")

    # Save registry
    with open(REGISTRY_OUTFILE, 'w') as f:
        json.dump(registry, f, indent=4)
    print(f"[√] Coin registry saved to {REGISTRY_OUTFILE}.")

if __name__ == '__main__':
    main()