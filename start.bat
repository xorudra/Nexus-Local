@echo off
title Nexus
cd /d "%~dp0app"

echo ============================================
echo  Nexus - Your Personal AI Dashboard
echo ============================================
echo.

:: Check Python - auto-install via winget if missing
where python >nul 2>&1
if errorlevel 1 (
    echo Python not found. Installing via winget...
    winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo ERROR: Auto-install failed.
        echo Please install manually from https://www.python.org/downloads/ (tick "Add to PATH")
        pause
        exit /b 1
    )
    echo Python installed. You may need to restart this script.
    pause
    exit /b 0
)

:: Check Node.js - auto-install via winget if missing
where node >nul 2>&1
if errorlevel 1 (
    echo Node.js not found. Installing via winget...
    winget install -e --id OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo ERROR: Auto-install failed.
        echo Please install manually from https://nodejs.org/
        pause
        exit /b 1
    )
    echo Node.js installed. You may need to restart this script.
    pause
    exit /b 0
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
