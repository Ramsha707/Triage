@echo off
echo ========================================
echo   CYBER TRIAGE TOOL - Backend Server
echo   Digital Forensic Intelligence Platform
echo ========================================
echo.

cd /d "%~dp0"

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

echo.
echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Starting server...
echo API will be available at: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo.

python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
