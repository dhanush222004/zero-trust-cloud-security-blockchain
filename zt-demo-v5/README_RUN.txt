ZERO-TRUST DEMO - run on your own computer (local only, nothing is uploaded)

WINDOWS (3 steps)
1. Unzip this folder anywhere (for example Desktop).
2. Double-click run_windows.bat  (first run installs packages, then downloads the Solidity compiler: needs internet, ~1-3 min).
3. Your browser opens http://localhost:5057/v5/ui . If it does not, open that address yourself.
Stop: close the black window or press Ctrl+C.

IF IT FAILS
- Window says "python is not recognized" or "No Python": Python is missing. Install Python 3.12 from python.org (tick "Add python.exe to PATH"), then run again.
- Python is found but a step shows red errors or "INSTALL FAILED": that is a package/runtime problem, not missing Python. Send a screenshot of the black window.
- "INSTALL FAILED": your default Python may be too new (3.13/3.14). Install Python 3.12 from python.org, delete the folder "venv", run again. The bat file prefers 3.12 when present.
- If you see a Solidity/"solc" download error: no internet or firewall; connect and run again.
- Port 5057 busy: close the other program using it.
- No internet at the interview: run it once beforehand; the compiler is then cached on your PC (in your user folder, .solcx).

WHAT YOU WILL SEE / SAY (truthful)
- Prototype on a local in-memory test chain (cleared when the app stops), not a production blockchain.
- Each identity gets its own test account (max 7 identities per audit_log.jsonl; delete that file to reset).
- Access checks are written to the contract's audit log (this run) and to audit_log.jsonl (normal local file, survives restarts, NOT tamper-proof).
- Allow/deny decisions are real: registered -> ALLOW, other identity or attacker -> DENY.
- Demo steps: user@example.com -> Register -> bob@example.com -> Register -> user@example.com -> Check access (ALLOW) -> wrong@example.com -> Check access (DENY) -> attacker@evil.com -> Simulate attack (DENY) -> Refresh from API.

FILES: repo_patched/ = the version the demo runs. repo/ = your project, unchanged (from github.com/dhanush222004/zero-trust-cloud-security-blockchain, commit 75edc81). dash.py + index.html = the dashboard. Nothing else is modified or pushed.
Tested by the preparer on Linux with Python 3.10 only, clean install + API calls. NOT run on Windows or Python 3.12 (checked on PyPI instead: every pinned package has a Windows py3.12 wheel or is pure Python). Installs nothing outside the folder "venv" (and the compiler cache).

Set ZT_REPO_DIR=repo to run the untouched original instead.

SAVED LOG FILE (v2): history is saved in  repo_patched/audit_log.jsonl  (inside this folder, created when the app starts; its full path prints in the terminal and shows in the dashboard under "Saved file"). It is flushed to disk on every entry. If it cannot be written (read-only folder), the app keeps running and the dashboard shows SAVE ERROR. Keep the folder somewhere writable, not inside the zip viewer. The file is a normal local file: not tamper-proof.

v3: after a page refresh the "This browser session" table re-reads recent entries from audit_log.jsonl (hash only, marked "earlier"). Buttons show WORKING... while a request runs and report an error if the API does not answer within 20 seconds.

v4 (new version, v3 is unchanged and still works): KEY-BASED IDENTITY PROOF + "Real vs simulated" panel in the page.
- Linux/Kali: extract this zip into a NEW folder (do not overwrite v3), then:  cd zt-demo-v4/zt-demo ; bash run_linux_mac.sh
  If v3 is still running on port 5057, either stop it with Ctrl+C or start v4 on another port:  ZT_PORT=5058 bash run_linux_mac.sh  (then open http://127.0.0.1:5058/ui and use  ZT_PORT=5058 bash run_client.sh ... ).
  Leave that terminal open. Open a SECOND terminal in the same folder and run:
    bash run_client.sh demo           (EASIEST: key + enroll + signed access + replay test + impostor test in one go; keeps an existing my_key.json)
    Or step by step:
    bash run_client.sh keygen         (makes my_key.json; the private key stays on this computer, never share or upload it)
    bash run_client.sh enroll         (proves you hold the key, then binds it)
    bash run_client.sh access         (signed access request -> access true)
    bash run_client.sh replay-test    (same signature sent twice -> second is rejected)
    bash run_client.sh impostor-test  (claims your address but signs with another key -> rejected)
  Then press "Refresh from API" on the page to see signed events.
- What the signed route checks: the caller signs a one-time challenge (60 s, single use). Typed names do not pass it.
- Threat model (plain): protects against someone typing another person's name on the signed route, replaying a captured
  signature, and using a different key. It does NOT protect against: stolen my_key.json, anyone enrolling a key (nothing
  links a key to a real person), the admin account held by this API process, an editable log file, an in-memory chain,
  no TLS on localhost, no rate limiting. Not production security.
- Tested by the preparer on Linux, Python 3.10, clean extract. NOT tested on Windows. The old typed buttons are kept and are a simulation.

NOTE: requests from the terminal do not change the page's "Latest decision" box or the "This browser session" counters. They show in the Audit log after "Refresh from API" and as "(earlier)" rows after a page reload.
