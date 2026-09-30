from bitcoinlib.wallets import Wallet
from bitcoinlib.services.services import Service

def send_coin(coin, wif_or_seed, to_addr, amount):
    # coin: "bitcoin" or "litecoin"
    # wif_or_seed: WIF (Wallet Import Format) private key or mnemonic seed phrase
    print(f"[+] {coin.upper()} transfer requested: {amount} --> {to_addr}")
    # Create or load temp wallet
    wallet_name = f"temp_{coin}_"
    try:
        # Try as WIF first
        w = Wallet.create(wallet_name, keys=wif_or_seed, network=coin, witness_type='segwit', db_uri=':memory:')
    except Exception:
        # Then try as BIP39 seed
        w = Wallet.create(wallet_name, keys=wif_or_seed, network=coin, witness_type='segwit', db_uri=':memory:', is_mnemonic=True)
    try:
        tx = w.send_to(to_addr, amount, fee=5000)
        print(f"[√] {coin} sent, txid: {tx.txid}")
        return tx.txid
    except Exception as e:
        print(f"[X] Send failed: {e}")