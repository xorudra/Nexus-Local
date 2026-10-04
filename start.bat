@echo off
title Nexus Local Dashboard
echo ========================================
echo  Nexus Local Dashboard - Starting...
echo ========================================
echo.

rem --- Find a working Python (GOTO chain avoids && parsing bugs) ---
set PYCMD=
python --version >nul 2>&1
if not errorlevel 1 set PYCMD=python
if defined PYCMD goto :found
py --version >nul 2>&1
if not errorlevel 1 set PYCMD=py
if defined PYCMD goto :found
python3 --version >nul 2>&1
if not errorlevel 1 set PYCMD=python3
if defined PYCMD goto :found
python3.13 --version >nul 2>&1
if not errorlevel 1 set PYCMD=python3.13
if defined PYCMD goto :found
python3.12 --version >nul 2>&1
if not errorlevel 1 set PYCMD=python3.12
if defined PYCMD goto :found
python3.11 --version >nul 2>&1
if not errorlevel 1 set PYCMD=python3.11
if defined PYCMD goto :found
python3.10 --version >nul 2>&1
if not errorlevel 1 set PYCMD=python3.10
if defined PYCMD goto :found
goto :nopython

:found
echo [OK] Using Python command: %PYCMD%
%PYCMD% --version
echo.

rem --- Ensure cryptography is installed ---
%PYCMD% -c "import cryptography" >nul 2>&1
if not errorlevel 1 goto :runserver
echo [..] Installing 'cryptography' package (one-time setup)...
%PYCMD% -m pip install cryptography
if errorlevel 1 goto :pipfail
echo [OK] cryptography installed.
echo.
goto :runserver

:pipfail
echo.
echo [ERROR] Could not install 'cryptography'.
echo Check your internet connection and run start.bat again.
echo.
pause
exit /b 1

:nopython
echo [ERROR] Python not found on your system.
echo.
echo Please install Python 3.10 or newer from:
echo   https://www.python.org/downloads/
echo.
echo IMPORTANT: tick "Add python.exe to PATH" during installation.
echo.
pause
exit /b 1

:runserver
echo [..] Starting server...
echo      Dashboard: http://127.0.0.1:8080
echo      Keep this window OPEN. Press Ctrl+C to stop.
echo ========================================
echo.
%PYCMD% server.py
echo.
echo ========================================
echo [INFO] Server stopped. If it closed immediately,
echo the error message above says why.
echo ========================================
pause
