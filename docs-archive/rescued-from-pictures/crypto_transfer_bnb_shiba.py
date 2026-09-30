from web3 import Web3

# For BNB on BSC or SHIBA on ETH/BSC chain
BSC_URL = "https://bsc-dataseed.binance.org/"
ETH_URL = "https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY"

def send_bnb(priv_key, to_addr, value_bnb, use_bsc=True):
    url = BSC_URL if use_bsc else ETH_URL
    w3 = Web3(Web3.HTTPProvider(url))
    acct = w3.eth.account.privateKeyToAccount(priv_key)
    nonce = w3.eth.get_transaction_count(acct.address)
    tx = {
        'nonce': nonce,
        'to': to_addr,
        'value': w3.to_wei(value_bnb, "ether"),
        'gas': 21000,
        'gasPrice': w3.to_wei("5", "gwei"),
        'chainId': 56 if use_bsc else 1
    }
    signed_tx = w3.eth.account.sign_transaction(tx, priv_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"[+] BNB sent TxHash: {tx_hash.hex()}")
    return tx_hash.hex()

def send_shiba(priv_key, to_addr, value_token, use_bsc=False):
    w3 = Web3(Web3.HTTPProvider(BSC_URL if use_bsc else ETH_URL))
    acct = w3.eth.account.privateKeyToAccount(priv_key)
    nonce = w3.eth.get_transaction_count(acct.address)
    # SHIBA contract for ETH, update if needed for BSC
    SHIBA_CONTRACT = w3.to_checksum_address("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE")
    abi = '[{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]'
    contract = w3.eth.contract(address=SHIBA_CONTRACT, abi=abi)
    tx = contract.functions.transfer(to_addr, int(float(value_token)*1e18)).build_transaction({
        'chainId': 1,
        'gas': 60000,
        'gasPrice': w3.to_wei('5',"gwei"),
        'nonce': nonce,
    })
    signed_tx = w3.eth.account.sign_transaction(tx, priv_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"[+] SHIBA sent TxHash: {tx_hash.hex()}")
    return tx_hash.hex()