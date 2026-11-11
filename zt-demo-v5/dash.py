# Serves the dashboard at /ui on top of the UNMODIFIED repo/app.py (imports it, adds one route).
import os, sys
HERE=os.path.dirname(os.path.abspath(__file__))
REPO=os.path.join(HERE,os.environ.get("ZT_REPO_DIR","repo_patched")); os.chdir(REPO); sys.path.insert(0,REPO)
from app import app
from flask import send_file, redirect
import auth5
auth5.init(app)
@app.route("/ui")
def ui(): return redirect("/v5/ui")  # old v4 page is off in v5; send people to the v5 page
if __name__=="__main__":
    PORT=int(os.environ.get("ZT_PORT","5057")); print("\n  Open http://localhost:%d/v5/ui in your browser (Ctrl+C to stop)\n"%PORT)
    app.run(host="127.0.0.1", port=PORT, debug=False)
