@echo off
rem Ensure Python 3.10+ is available
python --version 2>nul || (
    echo Python not found. Please install Python 3.10+ from python.org and add to PATH.
    pause
    exit /b 1
)

rem Install cryptography if not present
python -c "import cryptography" 2>nul || (
    echo Installing cryptography... &
    pip install cryptography
)

rem Run the server
python server.py
