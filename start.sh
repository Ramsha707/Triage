#!/bin/bash
# Cyber Triage Tool - Backend Startup Script

echo "========================================"
echo "  CYBER TRIAGE TOOL - Backend Server"
echo "  Digital Forensic Intelligence Platform"
echo "========================================"
echo ""

cd "$(dirname "$0")"

echo "Checking Python installation..."
python3 --version || python --version

if [ $? -ne 0 ]; then
    echo "ERROR: Python is not installed or not in PATH"
    echo "Please install Python 3.10+"
    exit 1
fi

echo ""
echo "Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "Starting server..."
echo "API will be available at: http://localhost:8000"
echo "API Documentation: http://localhost:8000/docs"
echo ""

python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
