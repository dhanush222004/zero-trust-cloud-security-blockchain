@echo off
echo ================================
echo Zero-Trust Blockchain Project
echo Starting on Windows
echo ================================

REM Create virtual environment if not exists
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Start Flask application
echo Starting Flask application...
python app.py

pause
