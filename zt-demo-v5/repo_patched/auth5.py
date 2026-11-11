# v5: accounts, roles, passwords, one-device login, device change, sessions, server-side authorization.
# Separate from the v4 typed/signed routes (those stay as they were). Everything is checked on the server.
import os, json, time, hmac, hashlib, secrets, base64, re, threading, smtplib, ssl
from email.message import EmailMessage
from flask import Blueprint, request, jsonify, make_response, g, send_file
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

bp = Blueprint("v5", __name__, url_prefix="/v5")
HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("ZT_DATA_DIR") or os.path.join(os.path.dirname(HERE), "zt5_data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit5.jsonl")
UI_FILE = os.path.join(os.path.dirname(HERE), "v5.html")
LOCK = threading.RLock()

# ---- settings (env overrides are for testing) ----
SCRYPT_N = int(os.environ.get("ZT_SCRYPT_N", str(2 ** 17)))   # OWASP minimum for scrypt: N=2^17, r=8, p=1
SCRYPT_R, SCRYPT_P = 8, 1
NONCE_TTL = int(os.environ.get("ZT_NONCE_TTL", "60"))
INVITE_TTL = int(os.environ.get("ZT_INVITE_TTL", str(24 * 3600)))
OTP_TTL = int(os.environ.get("ZT_OTP_TTL", "600"))
SESSION_IDLE = int(os.environ.get("ZT_SESSION_IDLE", "900"))
SESSION_MAX = int(os.environ.get("ZT_SESSION_MAX", str(8 * 3600)))
SETUP_TTL = int(os.environ.get("ZT_SETUP_TTL", "1800"))
MAX_FAILS = int(os.environ.get("ZT_MAX_FAILS", "5"))
ROLES = ("admin", "editor", "viewer")
POLICY = {   # role -> resource -> allowed actions. Checked on the server for every protected route.
    "admin": {"users": {"read", "create", "update", "disable", "reset"}, "documents": {"read", "write", "delete"},
              "audit": {"read"}, "device_requests": {"read", "decide"}},
    "editor": {"documents": {"read", "write"}},
    "viewer": {"documents": {"read"}},
}
INSTANCE = secrets.token_hex(8)          # new on every start, signed into device proofs
NONCES = {}                              # nonce -> (purpose, expires)
SESSIONS = {}                            # sha256(token) -> dict
FAILS = {}                               # key -> (count, locked_until, level)
HITS = {}                                # ip -> [timestamps]
OTPS = {}                                # request_id -> dict
SETUP = {"hash": None, "exp": 0, "tries": 0}
DOCS = {}                                # demo resource, in memory only
COMMON = {"password", "password1", "passw0rd", "qwerty123", "letmein123", "1234567890", "12345678910", "admin12345", "welcome123", "iloveyou123"}
DUMMY_SALT = secrets.token_bytes(16)

# ---- storage ----
def _load():
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    with open(USERS_FILE, encoding="utf-8") as f:
        return json.load(f)

def _save(db):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = USERS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=1)
    os.replace(tmp, USERS_FILE)
    os.chmod(USERS_FILE, 0o600)

def audit(event, user=None, **kw):
    os.makedirs(DATA_DIR, exist_ok=True)
    rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, "user": user}
    rec.update(kw)
    new = not os.path.exists(AUDIT_FILE)
    with LOCK, open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    if new:
        os.chmod(AUDIT_FILE, 0o600)

# ---- crypto helpers ----
def pw_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=512 * 1024 * 1024, dklen=32)
    return {"alg": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex(), "hash": h.hex()}

def pw_check(password, rec):
    salt = bytes.fromhex(rec["salt"])
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=rec["n"], r=rec["r"], p=rec["p"], maxmem=512 * 1024 * 1024, dklen=32)
    return hmac.compare_digest(h.hex(), rec["hash"])

def tok_hash(t):
    return hashlib.sha256(t.encode()).hexdigest()

def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def valid_pub(pub):
    try:
        x = int.from_bytes(b64u(pub["x"]), "big"); y = int.from_bytes(b64u(pub["y"]), "big")
        ECC.construct(curve="P-256", point_x=x, point_y=y)
        return {"x": pub["x"], "y": pub["y"]}
    except Exception:
        return None

def sign_text(purpose, nonce, username):
    return "ZT5 %s\ninstance:%s\nnonce:%s\nuser:%s" % (purpose, INSTANCE, nonce, username)

def verify_raw(pub, text, sig_b64):
    try:
        key = ECC.construct(curve="P-256", point_x=int.from_bytes(b64u(pub["x"]), "big"), point_y=int.from_bytes(b64u(pub["y"]), "big"))
        sig = b64u(sig_b64)
        if len(sig) != 64:
            return False
        DSS.new(key, "fips-186-3", encoding="binary").verify(SHA256.new(text.encode()), sig)
        return True
    except Exception:
        return False

REQ_SEEN = {}
def request_proof_ok(username, pub):
    """Every authenticated request must carry a fresh signature from the enrolled device key over method, path and body hash."""
    h = request.headers.get("X-ZT5-Proof", "")
    parts = h.split(".")
    if len(parts) != 3:
        return False
    ts, nonce, sig = parts
    try:
        tsv = int(ts)
    except ValueError:
        return False
    now = time.time()
    if abs(now - tsv) > 60 or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", nonce):
        return False
    for k in [k for k, v in REQ_SEEN.items() if v < now]:
        REQ_SEEN.pop(k, None)
    if nonce in REQ_SEEN or len(REQ_SEEN) > 5000:
        return False
    path = request.full_path.rstrip("?")
    text = "ZT5 req\ninstance:%s\nts:%s\nnonce:%s\nuser:%s\n%s %s\nbody:%s" % (INSTANCE, ts, nonce, username, request.method, path, hashlib.sha256(request.get_data()).hexdigest())
    if not verify_raw(pub, text, sig):
        return False
    REQ_SEEN[nonce] = now + 120
    return True

def verify_device(pub, purpose, nonce, username, sig_b64):
    try:
        key = ECC.construct(curve="P-256", point_x=int.from_bytes(b64u(pub["x"]), "big"), point_y=int.from_bytes(b64u(pub["y"]), "big"))
        sig = b64u(sig_b64)
        if len(sig) != 64:
            return False
        DSS.new(key, "fips-186-3", encoding="binary").verify(SHA256.new(sign_text(purpose, nonce, username).encode()), sig)
        return True
    except Exception:
        return False

def burn_nonce(nonce, purpose):
    now = time.time()
    for k in [k for k, v in NONCES.items() if v[1] < now]:
        NONCES.pop(k, None)
    while len(NONCES) > 500:
        NONCES.pop(next(iter(NONCES)))
    e = NONCES.pop(str(nonce), None)       # single use, removed even when the proof is wrong
    return bool(e and e[0] == purpose and e[1] >= now)

def password_problem(pw, username):
    if not isinstance(pw, str) or len(pw) < 10:
        return "Password must be at least 10 characters."
    if len(pw) > 128:
        return "Password is too long (max 128)."
    if pw.lower() in COMMON or pw.lower() == username:
        return "That password is too common or equals the username."
    return None

# ---- OTP delivery: simulated by default, SMTP only if the owner configures it ----
REAL_MODES = ("smtp", "gmail_api")
def token_file():
    p = os.environ.get("ZT_GMAIL_TOKEN_FILE", "")
    return p if p and os.path.isfile(p) else ""

def otp_mode():
    if os.environ.get("ZT_SMTP_HOST"):
        return "smtp"
    return "gmail_api" if token_file() else "simulated"

def _loopback_or_google(url, default):
    # test override allowed only for a loopback mock server; otherwise the fixed Google endpoint is used
    return url if url and url.startswith("http://127.0.0.1") else default

def gmail_api_send(to_addr, msg):
    """Send with the Gmail API (gmail.send scope only). The token file is created by the owner's own consent on this machine."""
    import urllib.request, urllib.parse
    t = json.load(open(token_file()))
    tok_url = _loopback_or_google(os.environ.get("ZT_GOOGLE_TOKEN_URL"), "https://oauth2.googleapis.com/token")
    send_url = _loopback_or_google(os.environ.get("ZT_GMAIL_SEND_URL"), "https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
    form = {"client_id": t["client_id"], "refresh_token": t["refresh_token"], "grant_type": "refresh_token"}
    if t.get("client_secret"):
        form["client_secret"] = t["client_secret"]
    r = urllib.request.urlopen(urllib.request.Request(tok_url, data=urllib.parse.urlencode(form).encode()), timeout=15)
    access = json.load(r)["access_token"]
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    r = urllib.request.urlopen(urllib.request.Request(send_url, data=json.dumps({"raw": raw}).encode(), headers={"Authorization": "Bearer " + access, "Content-Type": "application/json"}), timeout=15)
    return r.status == 200

def deliver_otp(contact_email, code):
    if otp_mode() == "gmail_api":
        try:
            m = EmailMessage()
            m["To"] = contact_email
            m["Subject"] = "Your device-change code"
            m.set_content("Your one-time code is %s. It expires in %d minutes. If you did not ask for it, ignore this message." % (code, OTP_TTL // 60))
            return "gmail_api" if gmail_api_send(contact_email, m) else "failed"
        except Exception as e:
            audit("otp_delivery_failed", reason=type(e).__name__)
            return "failed"
    if otp_mode() == "smtp":
        try:
            m = EmailMessage()
            m["From"] = os.environ.get("ZT_SMTP_FROM", os.environ.get("ZT_SMTP_USER", "zt-demo@localhost"))
            m["To"] = contact_email
            m["Subject"] = "Your device-change code"
            m.set_content("Your one-time code is %s. It expires in %d minutes. If you did not ask for it, ignore this message." % (code, OTP_TTL // 60))
            host = os.environ["ZT_SMTP_HOST"]; port = int(os.environ.get("ZT_SMTP_PORT", "587"))
            with smtplib.SMTP(host, port, timeout=15) as s:
                if os.environ.get("ZT_SMTP_TLS", "1") == "1":
                    s.starttls(context=ssl.create_default_context())
                if os.environ.get("ZT_SMTP_USER"):
                    s.login(os.environ["ZT_SMTP_USER"], os.environ.get("ZT_SMTP_PASS", ""))
                s.send_message(m)
            return "smtp"
        except Exception as e:
            audit("otp_delivery_failed", reason=type(e).__name__)
            return "failed"
    print("\n  [SIMULATED OTP DELIVERY - NOT REAL VERIFICATION] code for %s: %s\n" % (contact_email, code), flush=True)
    return "simulated"

# ---- request guards ----
def client_ip():
    return request.remote_addr or "?"

def throttle_ip():
    now = time.time(); q = [t for t in HITS.get(client_ip(), []) if t > now - 60]
    q.append(now); HITS[client_ip()] = q
    return len(q) <= HIT_LIMIT

def locked(key):
    c = FAILS.get(key)
    return bool(c and c[1] > time.time())

IP_MAX_FAILS = int(os.environ.get("ZT_IP_MAX_FAILS", "25"))
HIT_LIMIT = int(os.environ.get("ZT_HIT_LIMIT", "120"))

def note_fail(key):
    c = FAILS.get(key, (0, 0, 0)); n = c[0] + 1; lvl = c[2]
    if n >= (IP_MAX_FAILS if key.startswith("ip:") else MAX_FAILS):
        FAILS[key] = (0, time.time() + min(900, 60 * (2 ** lvl)), lvl + 1)
    else:
        FAILS[key] = (n, c[1], lvl)

def clear_fail(key):
    FAILS.pop(key, None)

@bp.before_request
def guard():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.headers.get("X-ZT5") != "1" or not (request.is_json or request.content_length in (None, 0)):
            return jsonify({"error": "bad_request"}), 400
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != request.host:
            return jsonify({"error": "bad_origin"}), 403
    if request.path != "/v5/ui" and not throttle_ip():
        return jsonify({"error": "too_many_requests"}), 429

def body():
    return request.get_json(silent=True) or {}

def uname(v):
    v = str(v or "").strip().lower()
    return v if re.fullmatch(r"[a-z0-9._-]{3,32}", v) else None

def current_session():
    t = request.cookies.get("zt5_session")
    if not t:
        return None
    s = SESSIONS.get(tok_hash(t)); now = time.time()
    if not s or now - s["last"] > SESSION_IDLE or now - s["created"] > SESSION_MAX:
        SESSIONS.pop(tok_hash(t), None); return None
    db = _load(); u = db["users"].get(s["user"])
    if not u or u["status"] != "active":
        SESSIONS.pop(tok_hash(t), None); return None
    if not request_proof_ok(s["user"], (u.get("device") or {}).get("pub") or {}):
        audit("session_proof_failed", s["user"])
        return None
    s["last"] = now
    return {"user": s["user"], "role": u["role"]}

def require(resource, action):
    def deco(fn):
        def wrap(*a, **k):
            s = current_session()
            if not s:
                return jsonify({"error": "not_logged_in"}), 401
            if action not in POLICY.get(s["role"], {}).get(resource, set()):
                audit("denied", s["user"], role=s["role"], resource=resource, action=action)
                return jsonify({"error": "forbidden", "role": s["role"], "resource": resource, "action": action}), 403
            g.sess = s
            return fn(*a, **k)
        wrap.__name__ = fn.__name__
        return wrap
    return deco

def revoke_sessions(user):
    for k in [k for k, v in SESSIONS.items() if v["user"] == user]:
        SESSIONS.pop(k, None)

def new_session(user):
    t = secrets.token_urlsafe(32)
    now = time.time()
    SESSIONS[tok_hash(t)] = {"user": user, "created": now, "last": now}
    r = make_response(jsonify({"ok": True}))
    r.set_cookie("zt5_session", t, httponly=True, samesite="Strict", path="/v5", max_age=SESSION_MAX)
    return r

def new_code():
    return secrets.token_urlsafe(9)

# ---- setup / status ----
def admin_exists(db=None):
    db = db or _load()
    return any(u["role"] == "admin" and u["status"] == "active" for u in db["users"].values())

def init_setup():
    """Called at start. If there is no admin yet, make a one-time setup code and print it in THIS terminal only."""
    with LOCK:
        if admin_exists():
            return
        code = secrets.token_urlsafe(9)
        SETUP.update({"hash": tok_hash(code), "exp": time.time() + SETUP_TTL, "tries": 0})
        print("\n  v5 FIRST-TIME SETUP: no admin exists yet.\n  One-time setup code (valid %d minutes, shown only here): %s\n  Open /v5/ui and use it to create the admin account.\n" % (SETUP_TTL // 60, code), flush=True)

@bp.route("/ui")
def ui():
    return send_file(UI_FILE)

@bp.route("/status")
def status():
    return jsonify({"admin_exists": admin_exists(), "instance": INSTANCE, "otp_delivery": otp_mode(),
                    "device_change_needs_admin": otp_mode() not in REAL_MODES, "version": "v5"})

@bp.route("/challenge")
def challenge():
    purpose = request.args.get("purpose", "login")
    if purpose not in ("login", "device_change", "activate", "setup"):
        return jsonify({"error": "bad_purpose"}), 400
    n = secrets.token_hex(16)
    NONCES[n] = (purpose, time.time() + NONCE_TTL)
    return jsonify({"nonce": n, "instance": INSTANCE, "purpose": purpose, "ttl": NONCE_TTL})

def create_active(db, username, role, password, pub, email):
    db["users"][username] = {"role": role, "status": "active", "pw": pw_hash(password), "invite": None,
                             "device": {"pub": pub, "enrolled_at": time.strftime("%Y-%m-%d %H:%M:%S")},
                             "contact": {"email": email}, "created": time.strftime("%Y-%m-%d %H:%M:%S")}

@bp.route("/setup", methods=["POST"])
def setup():
    d = body(); now = time.time()
    with LOCK:
        db = _load()
        if admin_exists(db) or not SETUP["hash"] or SETUP["exp"] < now or SETUP["tries"] >= 5:
            audit("setup_rejected", reason="not_available")
            return jsonify({"error": "setup_not_available"}), 403
        SETUP["tries"] += 1
        if not hmac.compare_digest(tok_hash(str(d.get("setup_code", ""))), SETUP["hash"]):
            audit("setup_rejected", reason="bad_code")
            return jsonify({"error": "setup_not_available"}), 403
        u = uname(d.get("username")); pub = valid_pub(d.get("device_pub") or {}); email = str(d.get("email", "")).strip()
        prob = password_problem(d.get("password"), u or "")
        if not u or not pub or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or prob:
            return jsonify({"error": "invalid_input", "detail": prob or "username 3-32 chars [a-z0-9._-], valid email and device key needed"}), 400
        if not burn_nonce(d.get("nonce"), "setup") or not verify_device(pub, "setup", d["nonce"], u, d.get("device_sig", "")):
            return jsonify({"error": "device_proof_failed"}), 400
        create_active(db, u, "admin", d["password"], pub, email)
        _save(db); SETUP["hash"] = None
    audit("admin_created", u)
    return jsonify({"ok": True})

# ---- login ----
@bp.route("/login", methods=["POST"])
def login():
    d = body(); u = uname(d.get("username")) or "?"; pw = d.get("password"); key = "u:" + u; ipk = "ip:" + client_ip()
    if locked(key) or locked(ipk):
        audit("login_blocked", u, reason="rate_limited")
        return jsonify({"error": "too_many_attempts", "retry": "wait and try again"}), 429
    if not isinstance(pw, str) or not isinstance(d.get("nonce"), str):
        return jsonify({"error": "invalid_credentials"}), 401
    with LOCK:
        user = _load()["users"].get(u)
    ok_user = bool(user and user["status"] == "active" and user.get("pw"))
    ok_pw = pw_check(pw, user["pw"]) if ok_user else (pw_hash(pw[:128], DUMMY_SALT) and False)   # same work for unknown users
    nonce_ok = burn_nonce(d["nonce"], "login")
    if not (ok_user and ok_pw):
        note_fail(key); note_fail(ipk)
        audit("login_failed", u, reason="credentials")
        return jsonify({"error": "invalid_credentials"}), 401
    sig = d.get("device_sig")
    if not (nonce_ok and isinstance(sig, str) and verify_device(user["device"]["pub"], "login", d["nonce"], u, sig)):
        note_fail(key)
        audit("login_failed", u, reason="device_not_recognized" if nonce_ok else "nonce")
        return jsonify({"error": "device_not_recognized", "next": "This browser is not the enrolled device for this account. Use the device-change request."}), 403
    clear_fail(key)
    audit("login_ok", u)
    return new_session(u)

@bp.route("/logout", methods=["POST"])
def logout():
    t = request.cookies.get("zt5_session")
    if t:
        SESSIONS.pop(tok_hash(t), None)
    r = make_response(jsonify({"ok": True})); r.delete_cookie("zt5_session", path="/v5")
    return r

@bp.route("/me")
def me():
    s = current_session()
    if not s:
        return jsonify({"error": "not_logged_in"}), 401
    return jsonify({"user": s["user"], "role": s["role"], "allowed": {k: sorted(v) for k, v in POLICY[s["role"]].items()}})

# ---- activation of an admin-created account ----
@bp.route("/activate", methods=["POST"])
def activate():
    d = body(); u = uname(d.get("username")); key = "act:" + (u or "?")
    if locked(key):
        return jsonify({"error": "too_many_attempts"}), 429
    with LOCK:
        db = _load(); user = db["users"].get(u) if u else None
        inv = user and user["status"] == "invited" and user.get("invite")
        good = bool(inv and inv["exp"] > time.time() and hmac.compare_digest(tok_hash(str(d.get("code", ""))), inv["hash"]))
        if not good:
            note_fail(key); audit("activate_rejected", u, reason="invite")
            return jsonify({"error": "invalid_invite"}), 403
        pub = valid_pub(d.get("device_pub") or {}); prob = password_problem(d.get("password"), u)
        if not pub or prob:
            return jsonify({"error": "invalid_input", "detail": prob or "device key missing or invalid"}), 400
        if not burn_nonce(d.get("nonce"), "activate") or not verify_device(pub, "activate", d["nonce"], u, d.get("device_sig", "")):
            return jsonify({"error": "device_proof_failed"}), 400
        user.update({"status": "active", "pw": pw_hash(d["password"]), "invite": None,
                     "device": {"pub": pub, "enrolled_at": time.strftime("%Y-%m-%d %H:%M:%S")}})
        _save(db)
    clear_fail(key); audit("activated", u)
    return jsonify({"ok": True})

# ---- device change: password + new-device key proof + OTP (+ admin approval when OTP delivery is only simulated) ----
@bp.route("/device-change/request", methods=["POST"])
def dc_request():
    d = body(); u = uname(d.get("username")) or "?"; key = "dc:" + u
    if locked(key) or locked("ip:" + client_ip()):
        return jsonify({"error": "too_many_attempts"}), 429
    user = _load()["users"].get(u)
    ok_user = bool(user and user["status"] == "active")
    pw = d.get("password") if isinstance(d.get("password"), str) else ""
    ok_pw = pw_check(pw, user["pw"]) if ok_user else (pw_hash(pw[:128], DUMMY_SALT) and False)
    pub = valid_pub(d.get("new_device_pub") or {})
    nonce_ok = burn_nonce(d.get("nonce"), "device_change")
    if not (ok_user and ok_pw and pub and nonce_ok and verify_device(pub, "device_change", d["nonce"], u, d.get("new_sig", ""))):
        note_fail(key); note_fail("ip:" + client_ip()); audit("device_change_rejected", u)
        return jsonify({"error": "request_rejected"}), 403
    code = "%06d" % secrets.randbelow(10 ** 6)
    rid = secrets.token_urlsafe(12)
    mode = deliver_otp(user["contact"]["email"], code)
    if mode == "failed":
        return jsonify({"error": "otp_delivery_failed"}), 502
    OTPS[rid] = {"user": u, "pub": pub, "hash": tok_hash(rid + code), "exp": time.time() + OTP_TTL, "tries": 0,
                 "mode": mode, "otp_ok": False, "admin_ok": mode in REAL_MODES, "state": "waiting_for_code", "created": time.strftime("%Y-%m-%d %H:%M:%S")}
    audit("device_change_requested", u, otp_delivery=mode)
    return jsonify({"request_id": rid, "otp_delivery": mode, "needs_admin_approval": mode not in REAL_MODES,
                    "note": "Code was sent to the registered email." if mode in REAL_MODES else "SIMULATION: no real message was sent. The code was printed in the server terminal. An admin must also approve."})

def maybe_finish(rid):
    r = OTPS.get(rid)
    if r and r["otp_ok"] and r["admin_ok"] and r["state"] != "done":
        with LOCK:
            db = _load(); user = db["users"].get(r["user"])
            if not user or user["status"] != "active":
                return False
            user["device"] = {"pub": r["pub"], "enrolled_at": time.strftime("%Y-%m-%d %H:%M:%S")}
            _save(db)
        revoke_sessions(r["user"]); r["state"] = "done"
        audit("device_changed", r["user"], otp_delivery=r["mode"]); return True
    return False

@bp.route("/device-change/verify", methods=["POST"])
def dc_verify():
    d = body(); rid = str(d.get("request_id", "")); r = OTPS.get(rid)
    if not r or r["exp"] < time.time() or r["state"] != "waiting_for_code" or r["tries"] >= 5:
        return jsonify({"error": "invalid_or_expired"}), 403
    r["tries"] += 1
    if not hmac.compare_digest(tok_hash(rid + str(d.get("code", ""))), r["hash"]):
        audit("device_change_bad_code", r["user"]); return jsonify({"error": "invalid_or_expired"}), 403
    r["otp_ok"] = True; r["state"] = "code_ok"; r["exp"] = time.time() + max(OTP_TTL, 3600)   # admin has up to an hour to decide
    done = maybe_finish(rid)
    audit("device_change_code_ok", r["user"])
    return jsonify({"ok": True, "device_changed": done, "waiting_for_admin": (not done) and not r["admin_ok"]})

@bp.route("/device-change/status")
def dc_status():
    r = OTPS.get(request.args.get("request_id", ""))
    return jsonify({"state": r["state"] if r else "unknown"})

# ---- admin ----
def public_user(n, u):
    return {"username": n, "role": u["role"], "status": u["status"], "email": u["contact"]["email"],
            "device_enrolled": bool(u.get("device")), "device_since": (u.get("device") or {}).get("enrolled_at")}

@bp.route("/admin/users")
@require("users", "read")
def a_list():
    return jsonify({"users": [public_user(n, u) for n, u in _load()["users"].items()]})

@bp.route("/admin/users", methods=["POST"])
@require("users", "create")
def a_create():
    d = body(); u = uname(d.get("username")); role = d.get("role"); email = str(d.get("email", "")).strip()
    if not u or role not in ROLES or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "invalid_input"}), 400
    with LOCK:
        db = _load()
        if u in db["users"]:
            return jsonify({"error": "exists"}), 409
        code = new_code()
        db["users"][u] = {"role": role, "status": "invited", "pw": None, "device": None, "contact": {"email": email},
                          "invite": {"hash": tok_hash(code), "exp": time.time() + INVITE_TTL}, "created": time.strftime("%Y-%m-%d %H:%M:%S")}
        _save(db)
    audit("user_created", g.sess["user"], target=u, role=role)
    return jsonify({"ok": True, "invite_code": code, "note": "Give this one-time code to the user yourself. It is shown only now."})

def _target(name):
    db = _load(); t = db["users"].get(uname(name) or ""); return db, t

def _last_admin(db, name):
    return db["users"][name]["role"] == "admin" and sum(1 for u in db["users"].values() if u["role"] == "admin" and u["status"] == "active") <= 1

@bp.route("/admin/users/<name>/role", methods=["POST"])
@require("users", "update")
def a_role(name):
    role = body().get("role")
    with LOCK:
        db, t = _target(name)
        if not t or role not in ROLES:
            return jsonify({"error": "invalid_input"}), 400
        if t["role"] == "admin" and role != "admin" and _last_admin(db, uname(name)):
            return jsonify({"error": "last_admin"}), 409
        t["role"] = role; _save(db)
    revoke_sessions(uname(name)); audit("role_changed", g.sess["user"], target=uname(name), role=role)
    return jsonify({"ok": True})

@bp.route("/admin/users/<name>/disable", methods=["POST"])
@require("users", "disable")
def a_disable(name):
    with LOCK:
        db, t = _target(name)
        if not t:
            return jsonify({"error": "invalid_input"}), 400
        if _last_admin(db, uname(name)):
            return jsonify({"error": "last_admin"}), 409
        t["status"] = "disabled"; _save(db)
    revoke_sessions(uname(name)); audit("user_disabled", g.sess["user"], target=uname(name))
    return jsonify({"ok": True})

@bp.route("/admin/users/<name>/reset", methods=["POST"])
@require("users", "reset")
def a_reset(name):
    with LOCK:
        db, t = _target(name)
        if not t:
            return jsonify({"error": "invalid_input"}), 400
        if uname(name) == g.sess["user"]:
            return jsonify({"error": "cannot_reset_self"}), 409
        if t["role"] == "admin" and _last_admin(db, uname(name)):
            return jsonify({"error": "last_admin"}), 409
        code = new_code()
        t.update({"status": "invited", "pw": None, "device": None, "invite": {"hash": tok_hash(code), "exp": time.time() + INVITE_TTL}})
        _save(db)
    revoke_sessions(uname(name)); audit("user_reset", g.sess["user"], target=uname(name))
    return jsonify({"ok": True, "invite_code": code, "note": "Password and device were cleared. Give this one-time code to the user."})

@bp.route("/admin/device-requests")
@require("device_requests", "read")
def a_dreq():
    now = time.time()
    return jsonify({"requests": [{"request_id": k, "user": v["user"], "state": v["state"], "otp_delivery": v["mode"], "created": v["created"],
                                  "admin_approved": v["admin_ok"], "code_verified": v["otp_ok"]} for k, v in OTPS.items() if v["exp"] > now and v["state"] != "done"]})

@bp.route("/admin/device-requests/<rid>/<decision>", methods=["POST"])
@require("device_requests", "decide")
def a_decide(rid, decision):
    r = OTPS.get(rid)
    if not r or decision not in ("approve", "deny") or r["exp"] < time.time() or r["state"] == "done":
        return jsonify({"error": "invalid_or_expired"}), 404
    if decision == "deny":
        r["state"] = "denied"; r["exp"] = 0; audit("device_change_denied", g.sess["user"], target=r["user"]); return jsonify({"ok": True})
    r["admin_ok"] = True; audit("device_change_approved", g.sess["user"], target=r["user"])
    return jsonify({"ok": True, "device_changed": maybe_finish(rid)})

@bp.route("/admin/audit")
@require("audit", "read")
def a_audit():
    lines = []
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, encoding="utf-8") as f:
            lines = [json.loads(x) for x in f.read().splitlines()[-40:]]
    return jsonify({"events": lines[::-1]})

# ---- demo resource: documents (in memory) ----
@bp.route("/docs")
@require("documents", "read")
def docs_list():
    return jsonify({"documents": [{"id": k, **v} for k, v in DOCS.items()]})

@bp.route("/docs", methods=["POST"])
@require("documents", "write")
def docs_add():
    t = str(body().get("title", "")).strip()[:80]
    if not t:
        return jsonify({"error": "invalid_input"}), 400
    i = secrets.token_hex(3); DOCS[i] = {"title": t, "by": g.sess["user"]}
    audit("doc_written", g.sess["user"], doc=i)
    return jsonify({"ok": True, "id": i})

@bp.route("/docs/<i>", methods=["DELETE"])
@require("documents", "delete")
def docs_del(i):
    if DOCS.pop(i, None) is None:
        return jsonify({"error": "not_found"}), 404
    audit("doc_deleted", g.sess["user"], doc=i)
    return jsonify({"ok": True})

def init(app):
    app.register_blueprint(bp)
    @app.before_request
    def isolate_v4():
        p = request.path
        if p.startswith("/v5") or p in ("/ui", "/version"):
            return None
        if os.environ.get("ZT_ENABLE_V4_API") == "1":
            return None
        return jsonify({"error": "v4_api_disabled_in_v5", "note": "The unauthenticated v4 demo API is off. Use /v5/ui. Owner can set ZT_ENABLE_V4_API=1 to demo v4 only; it never touches v5 users or documents."}), 403
    init_setup()
