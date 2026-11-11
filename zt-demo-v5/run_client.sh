#!/bin/bash
cd "$(dirname "$0")"
[ -d venv ] || { echo "Run run_linux_mac.sh once first"; exit 1; }
. venv/bin/activate
python client.py "$@"
