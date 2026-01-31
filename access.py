from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
import json

# Connect to Python-only blockchain
w3 = Web3(EthereumTesterProvider())

# Load ABI
with open("abi.json", "r") as f:
    abi = json.load(f)

# Load contract address
with open("contract_address.txt", "r") as f:
    contract_address = f.read().strip()

contract = w3.eth.contract(address=contract_address, abi=abi)

admin = w3.eth.accounts[0]
user = w3.eth.accounts[1]

# Authorize user
tx = contract.functions.authorizeUser(user).transact({"from": admin})
w3.eth.wait_for_transaction_receipt(tx)

# Check access (Zero-Trust decision)
result = contract.functions.checkAccess(user).call()

print("Access Allowed:", result)
