# Zero-Trust demo v4 client: proves identity with a private key that stays in my_key.json on THIS computer.
# Usage (server must be running):  python client.py demo | keygen | enroll | access | replay-test | impostor-test
import json, os, stat, sys, urllib.request, urllib.error
from eth_account import Account
from eth_account.messages import encode_defunct

BASE = os.environ.get("ZT_URL", "http://127.0.0.1:%s" % os.environ.get("ZT_PORT", "5057"))
HERE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(HERE, "my_key.json")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never go through a browser/system proxy

def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with OPENER.open(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
    except Exception as e:
        print("Could not reach the server at", BASE, "-", e); sys.exit(1)

def load_key():
    if not os.path.exists(KEY_FILE):
        print("No key yet. Run:  python client.py keygen"); sys.exit(1)
    return json.load(open(KEY_FILE))

def sign(purpose, contract, nonce, address, private_key):
    text = "ZeroTrustDemo v4 %s request\ncontract:%s\nnonce:%s\naddress:%s" % (purpose, contract, nonce, address.lower())
    return Account.sign_message(encode_defunct(text=text), private_key=private_key).signature.hex()

def signed_request(purpose, path, k, signer_key=None):
    _, ch = call("GET", "/challenge?purpose=" + purpose)
    sig = sign(purpose, ch["contract"], ch["nonce"], k["address"], signer_key or k["private_key"])
    body = {"address": k["address"], "nonce": ch["nonce"], "signature": sig}
    return body, call("POST", path, body)

def show(label, res):
    print(label, "->", res[0], json.dumps(res[1]))


def demo():
    """One command: key (kept if it exists), enroll only if needed, signed access, replay test, impostor test."""
    ok_all = True
    def check(name, passed, detail=""):
        nonlocal ok_all
        ok_all = ok_all and passed
        print(("PASS  " if passed else "FAIL  ") + name + (("  (" + detail + ")") if detail else ""))
    if os.path.exists(KEY_FILE):
        k = load_key(); print("Using your existing key. Address:", k["address"], "(not overwritten)")
    else:
        acct = Account.create()
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"address": acct.address, "private_key": acct.key.hex()}, f)
        k = load_key(); print("New key created. Address:", k["address"], "(the private key stays in my_key.json on this computer)")
    _, (st, res) = signed_request("access", "/access/signed", k)
    if st == 200 and res.get("access") is True:
        print("INFO  this key is already enrolled, skipping enroll")
    elif st == 200:
        _, (st2, res2) = signed_request("enroll", "/enroll", k)
        if st2 != 200:
            check("enroll", False, "status %s %s. Nothing else was changed. If slots are full (max 7), restart v4 or use a fresh folder" % (st2, json.dumps(res2)))
            return finish(ok_all)
        check("enroll (proves you hold the key)", True)
    else:
        check("first signed request", False, "status %s %s" % (st, json.dumps(res)))
        return finish(ok_all)
    body, (st, res) = signed_request("access", "/access/signed", k)
    check("signed access for the enrolled key -> allowed", st == 200 and res.get("access") is True, json.dumps(res))
    st_b, res_b = call("POST", "/access/signed", body)
    check("replay of the same signature -> rejected", st_b != 200 or res_b.get("access") is not True, "status %s %s" % (st_b, res_b.get("reason", "")))
    other = Account.create()
    _, (st, res) = signed_request("access", "/access/signed", k, signer_key=other.key.hex())
    check("another key claiming your address -> rejected", st != 200 or res.get("access") is not True, "status %s %s" % (st, res.get("reason", "")))
    finish(ok_all)

def finish(ok_all):
    print()
    print("RESULT: ALL CHECKS PASSED" if ok_all else "RESULT: SOME CHECKS FAILED (send a photo of this screen)")
    print("These requests came from the terminal. They do NOT change the page's 'Latest decision' box or the 'This browser session' counters.")
    print("To see them: open the page and press 'Refresh from API' (Audit log), or reload the page to see them as '(earlier)' rows.")
    sys.exit(0 if ok_all else 1)

cmd = sys.argv[1] if len(sys.argv) > 1 else ""
if cmd == "keygen":
    if os.path.exists(KEY_FILE):
        print("my_key.json already exists, not touching it. Address:", load_key()["address"]); sys.exit(0)
    acct = Account.create()
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"address": acct.address, "private_key": acct.key.hex()}, f)
    print("Key created. Public address:", acct.address)
    print("The private key is saved only in my_key.json in this folder. Never share or upload that file.")
elif cmd == "demo":
    demo()
elif cmd == "enroll":
    k = load_key(); _, res = signed_request("enroll", "/enroll", k); show("enroll", (_, res) if False else res)
elif cmd == "access":
    k = load_key(); _, res = signed_request("access", "/access/signed", k); show("access", res)
elif cmd == "replay-test":
    k = load_key(); body, res = signed_request("access", "/access/signed", k); show("first use    ", res)
    show("same signature again (replay)", call("POST", "/access/signed", body))
elif cmd == "impostor-test":
    k = load_key(); other = Account.create()
    _, res = signed_request("access", "/access/signed", k, signer_key=other.key.hex())
    show("claim your address, sign with a different key", res)
else:
    print(__doc__ if __doc__ else "Usage: python client.py demo | keygen | enroll | access | replay-test | impostor-test")
