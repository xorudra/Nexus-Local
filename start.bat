@echo off
title Nexus
cd /d "%~dp0app"

echo ============================================
echo  Nexus - Your Personal AI Dashboard
echo ============================================
echo.

:: Check Python
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python 3.10+ not found.
    echo Download from https://www.python.org/downloads/ (tick "Add to PATH")
    pause
    exit /b 1
)

:: Check Node.js
where node >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js 18+ not found.
    echo Download from https://nodejs.org/
    pause
    exit /b 1
)

:: Setup .env
if not exist ".env" (
    if exist ".env.example" copy ".env.example" ".env" >nul
    echo First run: generating encryption key...
    for /f %%i in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set ENC_KEY=%%i
    powershell -Command "(Get-Content '.env') -replace 'PASTE_64_CHAR_HEX_HERE', '%ENC_KEY%' | Set-Content '.env'"
)

:: Python deps
python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo Installing components...
    pip install cryptography --quiet
)

:: Engine deps
if not exist "engine\server\node_modules" (
    echo Installing engine (first run)...
    cd engine\server
    call npm install --production >nul 2>&1
    cd ..\..
)

:: Start engine
echo Starting engine...
start "Nexus Engine" cmd /k "cd /d "%~dp0app\engine\server" && set PORT=3001 && set HOST=127.0.0.1 && set FREEAPI_DB_PATH=%~dp0app\engine-data\freeapi.db && set FREEAPI_CONFIG_PATH=%~dp0app\freellmapi.config.json && set FREEAPI_ENV_PATH=%~dp0app\.env && node dist\index.js"
timeout /t 6 >nul

:: Start dashboard
echo.
echo Open http://127.0.0.1:8080 in your browser
echo.
start "Nexus Dashboard" cmd /k "cd /d "%~dp0app" && python server.py"
echo Done! Keep both windows open.
pause
