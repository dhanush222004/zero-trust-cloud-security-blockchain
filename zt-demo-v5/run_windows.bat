@echo off
cd /d "%~dp0"
echo === Zero-Trust demo: setup and run ===
set PY=python
py -3.12 --version >nul 2>nul
if not errorlevel 1 set PY=py -3.12
echo Using: %PY%
%PY% --version
if errorlevel 1 goto nopy
if not exist venv %PY% -m venv venv
call venv\Scripts\activate.bat
python -m pip install --quiet -r requirements-demo.txt
if errorlevel 1 goto fail
echo Starting. First start downloads the Solidity compiler (needs internet, about 1 minute).
start "" http://localhost:5057/v5/ui
python dash.py
pause
exit /b 0
:nopy
echo PYTHON NOT FOUND - install Python 3.12 from python.org, tick Add to PATH, run again.
pause
exit /b 1
:fail
echo INSTALL FAILED - see README_RUN.txt
pause
exit /b 1
