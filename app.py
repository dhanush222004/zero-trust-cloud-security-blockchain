from flask import Flask, request, jsonify
from solcx import compile_standard, install_solc
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
import hashlib
import time

app = Flask(__name__)

# ----------------------------
# Compile Contract
# ----------------------------
install_solc("0.8.0")

with open("ZeroTrust.sol", "r") as f:
    source = f.read()

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

# ----------------------------
# Blockchain
# ----------------------------
w3 = Web3(EthereumTesterProvider())
accounts = w3.eth.accounts

admin = accounts[0]
user = accounts[1]
attacker = accounts[2]

contract = w3.eth.contract(abi=abi, bytecode=bytecode)
tx = contract.constructor().transact({"from": admin})
receipt = w3.eth.wait_for_transaction_receipt(tx)
contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)

# ----------------------------
# HOME
# ----------------------------
@app.route("/")
def home():
    return jsonify({
        "project": "Zero-Trust Cloud Security using Blockchain",
        "status": "Running",
        "endpoints": {
            "POST /register": "Admin registers user",
            "POST /access": "User access request",
            "POST /attack": "Unauthorized attack simulation",
            "GET /logs": "Blockchain audit logs"
        }
    })

# ----------------------------
# REGISTER USER (ADMIN)
# ----------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    identity = data["identity"]
    role = data["role"]  # USER only

    identity_hash = hashlib.sha256(identity.encode()).digest()
    role_enum = 2  # USER

    contract.functions.registerUser(
        user, identity_hash, role_enum
    ).transact({"from": admin})

    return jsonify({"status": "User registered by admin"})

# ----------------------------
# USER ACCESS
# ----------------------------
@app.route("/access", methods=["POST"])
def access():
    data = request.json
    identity_hash = hashlib.sha256(data["identity"].encode()).digest()

    result = contract.functions.verifyAccess(
        user, identity_hash
    ).call()

    return jsonify({"access": result})

# ----------------------------
# ATTACK SIMULATION
# ----------------------------
@app.route("/attack", methods=["POST"])
def attack():
    data = request.json
    fake_hash = hashlib.sha256(data["identity"].encode()).digest()

    result = contract.functions.verifyAccess(
        attacker, fake_hash
    ).call()

    return jsonify({
        "attack": "Unauthorized attempt",
        "access": result
    })

# ----------------------------
# AUDIT LOGS
# ----------------------------
@app.route("/logs", methods=["GET"])
def logs():
    count = contract.functions.getLogCount().call()
    records = []

    for i in range(count):
        log = contract.functions.getLog(i).call()
        records.append({
            "user": log[0],
            "role": ["NONE", "ADMIN", "USER"][log[1]],
            "access": log[2],
            "time": time.ctime(log[3])
        })

    return jsonify(records)

# ----------------------------
# RUN
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)
