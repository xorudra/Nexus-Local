@echo off
title Nexus-Local
cd /d "%~dp0app"
set "TOOLS_DIR=%~dp0tools"

echo ============================================
echo  Nexus-Local - Your Personal AI Dashboard
echo ============================================
echo.

rem --- Python: verify, else download portable ---
where python >nul 2>&1
if errorlevel 1 (
    if exist "%TOOLS_DIR%\python\python.exe" (
        echo Found portable Python.
        set "PATH=%TOOLS_DIR%\python;%TOOLS_DIR%\python\Scripts;%PATH%"
    ) else (
        echo Python not found. Downloading portable Python...
        if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"
        powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip' -OutFile '%TOOLS_DIR%\python.zip'"
        powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\python.zip' -DestinationPath '%TOOLS_DIR%\python' -Force"
        del "%TOOLS_DIR%\python.zip"
        rem Get pip for embeddable python
        powershell -Command "Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%TOOLS_DIR%\python\get-pip.py'"
        "%TOOLS_DIR%\python\python.exe" "%TOOLS_DIR%\python\get-pip.py" --quiet
        rem Enable site-packages in embeddable python
        powershell -Command "(Get-Content '%TOOLS_DIR%\python\python312._pth') -replace '#import site', 'import site' | Set-Content '%TOOLS_DIR%\python\python312._pth'"
        set "PATH=%TOOLS_DIR%\python;%TOOLS_DIR%\python\Scripts;%PATH%"
        echo Python installed.
    )
)

rem --- Node.js: verify, else download portable ---
where node >nul 2>&1
if errorlevel 1 (
    if exist "%TOOLS_DIR%\nodejs\node.exe" (
        echo Found portable Node.js.
        set "PATH=%TOOLS_DIR%\nodejs;%PATH%"
    ) else (
        echo Node.js not found. Downloading portable Node.js...
        if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"
        powershell -Command "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.18.1/node-v20.18.1-win-x64.zip' -OutFile '%TOOLS_DIR%\node.zip'"
        powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\node.zip' -DestinationPath '%TOOLS_DIR%' -Force"
        del "%TOOLS_DIR%\node.zip"
        ren "%TOOLS_DIR%\node-v20.18.1-win-x64" "nodejs"
        set "PATH=%TOOLS_DIR%\nodejs;%PATH%"
        echo Node.js installed.
    )
)

rem Setup .env
if not exist ".env" (
    if exist ".env.example" copy ".env.example" ".env" >nul
    echo First run: generating encryption key...
    for /f %%i in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set ENC_KEY=%%i
    powershell -Command "(Get-Content '.env') -replace 'PASTE_64_CHAR_HEX_HERE', '%ENC_KEY%' | Set-Content '.env'"
)

rem Python deps
python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo Installing Python components...
    python -m pip install cryptography --quiet
)

rem Engine deps
if not exist "engine\server\node_modules" (
    echo Installing engine (first run)...
    cd engine\server
    call npm install --production >nul 2>&1
    cd ..\..
)

rem Start engine
echo Starting engine...
start "Nexus-Local Engine" cmd /k "cd /d "%~dp0app\engine\server" && set PATH=%PATH% && set PORT=3001 && set HOST=127.0.0.1 && set FREEAPI_DB_PATH=%~dp0app\engine-data\freeapi.db && set FREEAPI_CONFIG_PATH=%~dp0app\freellmapi.config.json && set FREEAPI_ENV_PATH=%~dp0app\.env && node dist\index.js"
timeout /t 6 >nul

rem Start dashboard
echo.
echo Open http://127.0.0.1:8080 in your browser
echo.
start "Nexus-Local Dashboard" cmd /k "cd /d "%~dp0app" && set PATH=%PATH% && python server.py"
echo Done! Keep both windows open.
pause
