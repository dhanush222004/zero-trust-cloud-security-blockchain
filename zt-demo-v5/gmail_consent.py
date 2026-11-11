"""Run ONCE on your own computer to let this local v5 app send device-change codes through the Gmail API (send-only).
Needs your own Google Cloud OAuth *Desktop* client ID (not secret). Nothing is uploaded; the token file stays here (mode 600).
Usage:  ZT_GOOGLE_CLIENT_ID=... python gmail_consent.py     (optional ZT_GOOGLE_CLIENT_SECRET, ZT_GOOGLE_LOGIN_HINT)
Then start the app with:  ZT_GMAIL_TOKEN_FILE=zt5_data/gmail_token.json bash run_linux_mac.sh
In Google 'Testing' mode the token expires after 7 days; run this again."""
import os, sys, json, base64, hashlib, secrets, urllib.parse, urllib.request, http.server, threading, webbrowser
AUTH = os.environ.get("ZT_GOOGLE_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth")
TOKEN = os.environ.get("ZT_GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token")
SCOPE = "https://www.googleapis.com/auth/gmail.send"
cid = os.environ.get("ZT_GOOGLE_CLIENT_ID", "").strip()
if not cid:
    sys.exit("Set ZT_GOOGLE_CLIENT_ID first (the Desktop OAuth client ID).")
out = os.environ.get("ZT_GMAIL_TOKEN_OUT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "zt5_data", "gmail_token.json"))
ver = secrets.token_urlsafe(48); chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
state = secrets.token_urlsafe(16); got = {}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(s.path).query)
        if q.get("state", [""])[0] == state and "code" in q:
            got["code"] = q["code"][0]; msg = "Done. You can close this tab and return to the terminal."
        else:
            got["err"] = q.get("error", ["bad_state"])[0]; msg = "Not completed."
        s.send_response(200); s.send_header("Content-Type", "text/plain"); s.end_headers(); s.wfile.write(msg.encode())
    def log_message(s, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H); port = srv.server_address[1]
redir = "http://127.0.0.1:%d" % port
url = AUTH + "?" + urllib.parse.urlencode({"client_id": cid, "redirect_uri": redir, "response_type": "code", "scope": SCOPE, "code_challenge": chal,
      "code_challenge_method": "S256", "state": state, "access_type": "offline", "prompt": "consent", "login_hint": os.environ.get("ZT_GOOGLE_LOGIN_HINT", "")})
print("Open this link in your browser and approve 'send email' only:\n" + url + "\n", flush=True)
if not os.environ.get("ZT_NO_BROWSER"):
    try: webbrowser.open(url)
    except Exception: pass
srv.timeout = 300
while not got and srv.timeout:
    srv.handle_request()
    if not got: break
if "code" not in got:
    sys.exit("No approval received: " + got.get("err", "timeout"))
form = {"client_id": cid, "code": got["code"], "code_verifier": ver, "redirect_uri": redir, "grant_type": "authorization_code"}
if os.environ.get("ZT_GOOGLE_CLIENT_SECRET"): form["client_secret"] = os.environ["ZT_GOOGLE_CLIENT_SECRET"]
r = json.load(urllib.request.urlopen(urllib.request.Request(TOKEN, data=urllib.parse.urlencode(form).encode()), timeout=20))
if "refresh_token" not in r or SCOPE not in r.get("scope", SCOPE):
    sys.exit("Google did not return a send-only refresh token.")
os.makedirs(os.path.dirname(out), exist_ok=True)
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump({"client_id": cid, "client_secret": os.environ.get("ZT_GOOGLE_CLIENT_SECRET", ""), "refresh_token": r["refresh_token"], "scope": r.get("scope", SCOPE)}, f)
print("Saved token file (mode 600): " + out)
