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
# Patched: each registered identity gets its own account (accounts[1..7]);
# accounts[8] probes identities that were never registered, accounts[9] is the simulated attacker.
USER_SLOTS = list(accounts[1:8])
PROBE = accounts[8]
attacker = accounts[9]

contract = w3.eth.contract(abi=abi, bytecode=bytecode)
tx = contract.constructor().transact({"from": admin})
receipt = w3.eth.wait_for_transaction_receipt(tx)
contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)

# ----------------------------
# PATCH NOTES (private demo copy; original app.py is in ../repo, unchanged)
# 1) /register now maps each identity to its OWN account (was: always one fixed account).
# 2) Access checks now SEND a transaction, so the contract's own audit log is written on the chain
#    (was: read-only .call(), nothing stored). The chain is the in-memory Ethereum Tester chain.
# 3) Every register/access/attack is also appended to audit_log.jsonl so history survives restarts.
#    Registrations are replayed from that file on start. Raw identities are NOT stored, only SHA-256 hashes.
# ----------------------------
import os, json
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.jsonl")
ROLES = ["NONE", "ADMIN", "USER"]
slot_of = {}   # identity sha256 hex -> account address

def _hash(identity):
    return hashlib.sha256(identity.encode()).digest()

PERSIST_ERROR = None

def _lines():
    with open(LOG_FILE, encoding="utf-8") as _f:
        return _f.readlines()

def _persist(entry):
    global PERSIST_ERROR
    entry["saved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        PERSIST_ERROR = None
    except OSError as e:
        PERSIST_ERROR = str(e)
        print("WARNING: could not save audit entry to", LOG_FILE, "-", e, flush=True)

try:
    open(LOG_FILE, "a", encoding="utf-8").close()
except OSError as e:
    PERSIST_ERROR = str(e)
print("Audit file (saved history):", LOG_FILE, flush=True)

def _do_register(h, record=True):
    hx = h.hex()
    if hx not in slot_of:
        if len(slot_of) >= len(USER_SLOTS):
            return None
        slot_of[hx] = USER_SLOTS[len(slot_of)]
    acct = slot_of[hx]
    tx = contract.functions.registerUser(acct, h, 2).transact({"from": admin})
    w3.eth.wait_for_transaction_receipt(tx)
    if record:
        _persist({"event": "register", "identity_sha256": hx, "account": acct})
    return acct

def _check(identity, acct, event):
    h = _hash(identity)
    allowed = contract.functions.verifyAccess(acct, h).call()          # what the answer will be
    tx = contract.functions.verifyAccess(acct, h).transact({"from": admin})  # writes the on-chain audit entry
    rc = w3.eth.wait_for_transaction_receipt(tx)
    _persist({"event": event, "identity_sha256": h.hex(), "account": acct, "access": bool(allowed),
              "tx": rc.transactionHash.hex(), "block": rc.blockNumber})
    return bool(allowed), rc

# replay registrations from a previous run (hash only; the chain itself is in memory)
if os.path.exists(LOG_FILE):
    for line in _lines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event") == "register":
            _do_register(bytes.fromhex(e["identity_sha256"]), record=False)

@app.route("/")
def home():
    return jsonify({
        "project": "Zero-Trust Cloud Security using Blockchain",
        "status": "Running (patched demo copy, v4)",
        "endpoints": {
            "POST /register": "Admin registers an identity (own account per identity)",
            "POST /access": "Access request, logged on the test chain and in audit_log.jsonl",
            "POST /attack": "Unauthorized attack simulation, also logged",
            "GET /challenge?purpose=access|enroll": "v4: one-time challenge to sign (60 s, single use)",
            "POST /enroll": "v4: bind a public key after a signed proof of key ownership",
            "POST /access/signed": "v4: access request proven by a signature",
            "GET /logs": "Audit log read from the contract on the test chain",
            "GET /logs/history": "Entries saved in audit_log.jsonl (survives restarts)"
        }
    })

@app.route("/register", methods=["POST"])
def register():
    identity = request.json["identity"]
    acct = _do_register(_hash(identity))
    if acct is None:
        return jsonify({"status": "No free demo account slots (max %d identities)" % len(USER_SLOTS)}), 409
    return jsonify({"status": "User registered by admin", "account": acct[:10] + "..."})

@app.route("/access", methods=["POST"])
def access():
    identity = request.json["identity"]
    acct = slot_of.get(_hash(identity).hex(), PROBE)
    allowed, rc = _check(identity, acct, "access")
    return jsonify({"access": allowed, "block": rc.blockNumber})

@app.route("/attack", methods=["POST"])
def attack():
    identity = request.json["identity"]
    allowed, rc = _check(identity, attacker, "attack")
    return jsonify({"attack": "Unauthorized attempt", "access": allowed, "block": rc.blockNumber})

@app.route("/logs", methods=["GET"])
def logs():
    count = contract.functions.getLogCount().call()
    out = []
    for i in range(count):
        log = contract.functions.getLog(i).call()
        out.append({"user": log[0], "role": ROLES[log[1]], "access": log[2], "time": time.ctime(log[3])})
    return jsonify(out)

@app.route("/logs/history", methods=["GET"])
def history():
    rows = []
    if os.path.exists(LOG_FILE):
        for line in _lines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return jsonify(rows)

@app.route("/logs/file", methods=["GET"])
def logs_file():
    n = 0
    if os.path.exists(LOG_FILE):
        n = len(_lines())
    return jsonify({"path": LOG_FILE, "exists": os.path.exists(LOG_FILE), "lines": n, "last_save_error": PERSIST_ERROR})


# ----------------------------
# v4: KEY-BASED IDENTITY PROOF (challenge-signature). Typed /register and /access above are kept as "simulation".
# A caller proves it holds a private key by signing a one-time challenge. The private key never leaves the caller.
# What this adds: a typed name alone can no longer pass the signed route; a captured signature cannot be replayed
# (single-use nonce, 60 s expiry); a signature made by another key is rejected.
# What it does NOT add: nothing links a key to a real person (anyone may enroll a key), no TLS on localhost,
# the admin account is still held by this API process, the log file is editable, the chain is in memory.
# ----------------------------
import secrets
from eth_account import Account
from eth_account.messages import encode_defunct

NONCE_TTL = int(os.environ.get("ZT_NONCE_TTL", "60"))   # env override is for testing only
NONCES = {}   # nonce -> (purpose, expires_at)

def _purge():
    now = time.time()
    for k in [k for k, v in NONCES.items() if v[1] < now]:
        NONCES.pop(k, None)
    while len(NONCES) > 200:
        NONCES.pop(next(iter(NONCES)))

def _msg(purpose, nonce, address):
    # binds: action (purpose), this chain instance (contract address, new on every restart), one-time nonce, caller address
    return "ZeroTrustDemo v4 %s request\ncontract:%s\nnonce:%s\naddress:%s" % (purpose, contract.address.lower(), nonce, address.lower())

def _verify_signed(purpose, d):
    """returns (address_lower, None) if the caller proved the key, else (address_or_None, reason)."""
    try:
        address = str(d["address"]).strip()
        nonce = str(d["nonce"]).strip()
        sig = str(d["signature"]).strip()
    except (KeyError, TypeError):
        return None, "missing_fields"
    if not Web3.is_address(address):
        return None, "bad_address"
    _purge()
    entry = NONCES.pop(nonce, None)          # single use, popped even if the signature is wrong
    if entry is None:
        return address.lower(), "nonce_unknown_expired_or_used"
    if entry[0] != purpose or entry[1] < time.time():
        return address.lower(), "nonce_wrong_purpose_or_expired"
    try:
        signer = Account.recover_message(encode_defunct(text=_msg(purpose, nonce, address)), signature=sig)
    except Exception:
        return address.lower(), "bad_signature_format"
    if signer.lower() != address.lower():
        return address.lower(), "signature_not_from_that_address"
    return address.lower(), None

def _reject(event, address, reason):
    _persist({"event": event, "address": address, "reason": reason, "access": False})
    return jsonify({"access": False, "proof": "rejected", "reason": reason}), 401

@app.route("/challenge", methods=["GET"])
def challenge():
    purpose = request.args.get("purpose", "access")
    if purpose not in ("access", "enroll"):
        return jsonify({"error": "purpose must be access or enroll"}), 400
    _purge()
    nonce = secrets.token_hex(16)
    NONCES[nonce] = (purpose, time.time() + NONCE_TTL)
    return jsonify({"nonce": nonce, "purpose": purpose, "contract": contract.address.lower(), "expires_in_seconds": NONCE_TTL,
                    "sign_this_text": "ZeroTrustDemo v4 %s request\ncontract:%s\nnonce:%s\naddress:<your address, lowercase>" % (purpose, contract.address.lower(), nonce)})

@app.route("/enroll", methods=["POST"])
def enroll():
    d = request.get_json(silent=True) or {}
    addr, why = _verify_signed("enroll", d)
    if why:
        return _reject("enroll_rejected", addr, why)
    acct = _do_register(_hash("key:" + addr))
    if acct is None:
        return jsonify({"status": "No free demo account slots (max %d identities)" % len(USER_SLOTS)}), 409
    return jsonify({"status": "Key enrolled (proof of key ownership checked; no real-world identity check)", "address": addr})

@app.route("/access/signed", methods=["POST"])
def access_signed():
    d = request.get_json(silent=True) or {}
    addr, why = _verify_signed("access", d)
    if why:
        return _reject("signed_rejected", addr, why)
    identity = "key:" + addr
    acct = slot_of.get(_hash(identity).hex(), PROBE)
    allowed, rc = _check(identity, acct, "access_signed")
    return jsonify({"access": allowed, "proof": "signature_ok", "enrolled": allowed, "block": rc.blockNumber})

@app.route("/version", methods=["GET"])
def version():
    return jsonify({"version": "v4 (key-based proof added; typed identity kept as simulation)"})

if __name__ == "__main__":
    app.run(debug=False)
