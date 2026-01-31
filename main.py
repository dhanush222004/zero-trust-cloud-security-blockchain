from solcx import compile_standard, install_solc
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
import hashlib
import time

install_solc("0.8.0")

with open("ZeroTrust.sol", "r") as file:
    source = file.read()

compiled = compile_standard(
    {
        "language": "Solidity",
        "sources": {"ZeroTrust.sol": {"content": source}},
        "settings": {"outputSelection": {"*": {"*": ["abi", "evm.bytecode"]}}},
    },
    solc_version="0.8.0",
)

abi = compiled["contracts"]["ZeroTrust.sol"]["ZeroTrust"]["abi"]
bytecode = compiled["contracts"]["ZeroTrust.sol"]["ZeroTrust"]["evm"]["bytecode"]["object"]

w3 = Web3(EthereumTesterProvider())

admin = w3.eth.accounts[0]
user = w3.eth.accounts[1]

ZeroTrust = w3.eth.contract(abi=abi, bytecode=bytecode)
tx = ZeroTrust.constructor().transact({"from": admin})
receipt = w3.eth.wait_for_transaction_receipt(tx)

contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)

print("Contract deployed at:", receipt.contractAddress)

identity = "user@example.com"
identity_hash = hashlib.sha256(identity.encode()).digest()

contract.functions.registerIdentity(user, identity_hash).transact({"from": admin})
contract.functions.authorizeUser(user).transact({"from": admin})

result = contract.functions.verifyAccess(user, identity_hash).call()
print("Access Allowed:", result)

# 🔍 Read audit logs
log_count = contract.functions.getLogCount().call()
print("\nAudit Logs:")
for i in range(log_count):
    log = contract.functions.getLog(i).call()
    print(f"User: {log[0]}, Access: {log[1]}, Time: {time.ctime(log[2])}")
