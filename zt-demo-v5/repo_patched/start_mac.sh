#!/bin/bash

echo "==============================="
echo "Zero-Trust Blockchain Project"
echo "Starting on macOS"
echo "==============================="

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Start Flask application
echo "Starting Flask application..."
python app.py
