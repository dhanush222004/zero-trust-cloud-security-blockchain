from solcx import compile_standard, install_solc
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
import json

# Install Solidity compiler
install_solc("0.8.0")

# Read contract
with open("ZeroTrust.sol", "r") as file:
    contract_source = file.read()

# Compile contract
compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {"ZeroTrust.sol": {"content": contract_source}},
        "settings": {
            "outputSelection": {
                "*": {"*": ["abi", "evm.bytecode"]}
            }
        },
    },
    solc_version="0.8.0",
)

abi = compiled_sol["contracts"]["ZeroTrust.sol"]["ZeroTrust"]["abi"]
bytecode = compiled_sol["contracts"]["ZeroTrust.sol"]["ZeroTrust"]["evm"]["bytecode"]["object"]

# Save ABI
with open("abi.json", "w") as f:
    json.dump(abi, f)

# 🔥 Python-only blockchain
w3 = Web3(EthereumTesterProvider())

account = w3.eth.accounts[0]

ZeroTrust = w3.eth.contract(abi=abi, bytecode=bytecode)

# Deploy contract
tx_hash = ZeroTrust.constructor().transact({"from": account})
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

contract_address = tx_receipt.contractAddress

# Save contract address
with open("contract_address.txt", "w") as f:
    f.write(contract_address)

print("Contract deployed at:", contract_address)
