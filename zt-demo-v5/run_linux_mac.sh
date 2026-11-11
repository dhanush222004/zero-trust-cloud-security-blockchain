#!/bin/bash
cd "$(dirname "$0")"
[ -d venv ] || python3 -m venv venv
. venv/bin/activate
python -m pip install --quiet -r requirements-demo.txt || { echo "INSTALL FAILED"; exit 1; }
python dash.py
