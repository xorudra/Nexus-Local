@echo off
title Nexus Local Dashboard
echo ========================================
echo  Nexus Local Dashboard - Starting...
echo ========================================
echo.

rem Try python, py launcher, and versioned names (Microsoft Store uses python3.13)
set PYCMD=
python --version >nul 2>&1 && set PYCMD=python
if not defined PYCMD py --version >nul 2>&1 && set PYCMD=py
if not defined PYCMD python3 --version >nul 2>&1 && set PYCMD=python3
if not defined PYCMD python3.13 --version >nul 2>&1 && set PYCMD=python3.13
if not defined PYCMD python3.12 --version >nul 2>&1 && set PYCMD=python3.12
if not defined PYCMD python3.11 --version >nul 2>&1 && set PYCMD=python3.11
if not defined PYCMD python3.10 --version >nul 2>&1 && set PYCMD=python3.10
if not defined PYCMD (
    echo [ERROR] Python not found on your system.
    echo.
    echo Please install Python 3.10 or newer from:
    echo   https://www.python.org/downloads/
    echo.
    echo IMPORTANT: On the first install screen, tick
    echo   "Add python.exe to PATH" before clicking Install.
    echo.
    pause
    exit /b 1
)

echo [OK] Found Python:
%PYCMD% --version
echo.

rem Check the cryptography package (needed for encrypted keys)
%PYCMD% -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo [..] Installing 'cryptography' package (one-time setup)...
    %PYCMD% -m pip install cryptography
    if errorlevel 1 (
        echo.
        echo [ERROR] Could not install 'cryptography'.
        echo Check your internet connection and try running start.bat again.
        echo.
        pause
        exit /b 1
    )
    echo [OK] cryptography installed.
    echo.
)

echo [..] Starting server...
echo      Dashboard will open at: http://127.0.0.1:8080
echo      Keep this window OPEN while using the dashboard.
echo      Press Ctrl+C to stop the server.
echo ========================================
echo.
%PYCMD% server.py
echo.
echo ========================================
echo [INFO] Server has stopped.
echo If it stopped immediately with an error above,
echo take a screenshot and send it for help.
echo ========================================
pause
