ZERO-TRUST DEMO v5 (separate version; v4 is unchanged) - local-only prototype

START (Linux/Mac; tested by the preparer on Linux, Python 3.10 only; NOT run on Windows or Kali)
1. Unzip, open a terminal in the folder, run:  bash run_linux_mac.sh
2. On the very first start the terminal prints a ONE-TIME SETUP CODE (valid 30 min, 5 tries).
3. Open http://localhost:5057/v5/ui -> "First-time setup": enter the code, choose admin username, email, password (10+ chars). This browser becomes the admin device.

WHAT v5 ADDS (tested)
- Admin-only accounts: nobody can self-register. The admin creates a user with a role and gets a one-time invite code; the user sets their OWN password and enrolls their browser. The admin never sees the password.
- Roles enforced on the server on every request: admin / editor / viewer, with resource + action rules (users, documents, audit, device requests). Hiding a button is not the protection.
- Passwords: salted scrypt (N=2^17, r=8, p=1, OWASP minimum for scrypt), constant-time compare. No plaintext password anywhere.
- One enrolled device per user: a P-256 key made by the browser (WebCrypto, non-extractable) signs a single-use 60 s challenge at every login. Password alone is not enough.
- EVERY authenticated request must carry a fresh signature from the enrolled device key (method + path + body hash + 60 s timestamp + single-use nonce). A stolen session cookie alone is refused (tested). Limit: script running inside the logged-in browser (XSS) or someone using the unlocked browser could still make the key sign.
- The old unauthenticated v4 API routes (/register, /access, /attack, /logs, /enroll ...) are switched OFF in v5 (403) so they cannot bypass v5 rules. The owner can set ZT_ENABLE_V4_API=1 to demo v4 only; those routes never read v5 users or documents.
- Device change: a different browser/profile is refused after the correct password; the user can request a change (password + proof of the new key + one-time code). Completing it replaces the device and ends the user's sessions.
- Sessions: random token (only its hash is stored), HttpOnly + SameSite=Strict cookie, 15 min idle / 8 h max, revoked on role change, disable, reset, device change. CSRF header + Origin check. Per-user lockout with backoff, per-IP lockout and rate limit. Audit log without secrets.
- If sending the code fails (SMTP down) the request is refused (502); nothing is stored or claimed as sent.
- Approval timing: a request expires 10 min after the code is sent; after a correct code the admin has up to 60 min. Approving an expired request fails.

GMAIL API ROUTE (code ready, NOT enabled, NOT verified end-to-end with Google): gmail_consent.py lets the owner consent in his own browser (loopback + PKCE, send-only scope gmail.send) and saves a token file (mode 600) locally; the app then sends device-change codes via the Gmail API when ZT_GMAIL_TOKEN_FILE points to it. Tested only against a local mock of Google.
STATUS: a free Google Cloud project with a Desktop OAuth client exists (Testing mode, one test user, no billing). Its Client ID is not a secret but is NOT included in this package.
KNOWN REQUIREMENT (checked against Google's live token endpoint): this Desktop client REJECTS the token exchange without its client secret ('client_secret is missing'), PKCE alone is not accepted. So the consent step needs ZT_GOOGLE_CLIENT_SECRET set on the machine running gmail_consent.py. The secret is NOT in this package and must never be sent over chat. Until the owner supplies it locally, real email delivery is NOT possible and OTP stays in simulation mode.
In Google 'Testing' mode the token expires after 7 days (re-consent). The app can only send mail from the consenting Google account; it does not prove the typed email address belongs to the user.

WHAT IS NOT REAL (read this)
- CODE DELIVERY IS SIMULATED by default: the one-time code prints in the server terminal; no email or SMS is sent. Because that is not real verification, a simulated device change ALSO needs admin approval. Real email works only if the owner sets his own SMTP settings (env ZT_SMTP_HOST, ZT_SMTP_PORT, ZT_SMTP_USER, ZT_SMTP_PASS, ZT_SMTP_FROM, ZT_SMTP_TLS). The SMTP path was tested only against a local test server, never a real mailbox. SMS is not built.
- EMAIL OWNERSHIP IS NOT PROVEN: the admin types the user's email at invite time and v5 does not yet confirm the user owns it. Planned fix: send a code to that address at activation in real-SMTP mode. Not built.
- "Device" = the browser profile, not hardware. No attestation. Clearing site data or a new profile loses the key (use device change). Whether copying a browser profile copies the key was NOT tested. IP address is not used as identity.
- Localhost HTTP only: cookie has no Secure flag. A real deployment needs HTTPS.
- Sessions, challenges and the demo documents are in memory (lost on restart). Users and audit are files (users.json, audit5.jsonl in zt5_data/, mode 600).
- scrypt uses about 128 MB per login attempt.
- Face / fingerprint login is NOT built (future work; WebAuthn passkeys are safer than webcam matching).
- Access control is server-side; the blockchain demo is unchanged from v4. Not production security, not audited, no zero-error claim.

RESET: stop the app, delete the folder zt5_data. A new setup code is printed next start.
SETTINGS (env): ZT_GMAIL_TOKEN_FILE, ZT_PORT, ZT_DATA_DIR, ZT_OTP_TTL, ZT_HIT_LIMIT, ZT_IP_MAX_FAILS, ZT_ENABLE_V4_API.
