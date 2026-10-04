@echo off
title Nexus-Local
set "LOG=%~dp0startup.log"
echo [%date% %time%] Starting > "%LOG%"
cd /d "%~dp0app" 2>>"%LOG%"
echo [%date% %time%] Changed to app dir >> "%LOG%"
set "TOOLS_DIR=%~dp0tools"
echo [%date% %time%] TOOLS_DIR=%TOOLS_DIR% >> "%LOG%"

echo ============================================
echo  Nexus-Local - Your Personal AI Dashboard
echo ============================================
echo.

echo [%date% %time%] Checking Python >> "%LOG%"
rem --- Python: verify, else download portable ---
where python >nul 2>&1
echo [%date% %time%] Python check errorlevel=%errorlevel% >> "%LOG%"
if errorlevel 1 (
    echo Python not found, checking portable...
    if exist "%TOOLS_DIR%\python\python.exe" (
        echo Found portable Python.
        set "PATH=%TOOLS_DIR%\python;%TOOLS_DIR%\python\Scripts;%PATH%"
    ) else (
        echo Downloading portable Python...
        echo [%date% %time%] Downloading Python >> "%LOG%"
        if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"
        powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip' -OutFile '%TOOLS_DIR%\python.zip'" 2>>"%LOG%"
        echo [%date% %time%] Python download done >> "%LOG%"
        powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\python.zip' -DestinationPath '%TOOLS_DIR%\python' -Force" 2>>"%LOG%"
        del "%TOOLS_DIR%\python.zip"
        powershell -Command "Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%TOOLS_DIR%\python\get-pip.py'" 2>>"%LOG%"
        "%TOOLS_DIR%\python\python.exe" "%TOOLS_DIR%\python\get-pip.py" --quiet 2>>"%LOG%"
        powershell -Command "(Get-Content '%TOOLS_DIR%\python\python312._pth') -replace '#import site', 'import site' | Set-Content '%TOOLS_DIR%\python\python312._pth'" 2>>"%LOG%"
        set "PATH=%TOOLS_DIR%\python;%TOOLS_DIR%\python\Scripts;%PATH%"
        echo Python installed.
    )
)
echo [%date% %time%] Python OK >> "%LOG%"

echo [%date% %time%] Checking Node >> "%LOG%"
rem --- Node.js: verify, else download portable ---
where node >nul 2>&1
echo [%date% %time%] Node check errorlevel=%errorlevel% >> "%LOG%"
if errorlevel 1 (
    echo Node.js not found, checking portable...
    if exist "%TOOLS_DIR%\nodejs\node.exe" (
        echo Found portable Node.js.
        set "PATH=%TOOLS_DIR%\nodejs;%PATH%"
    ) else (
        echo Downloading portable Node.js...
        echo [%date% %time%] Downloading Node >> "%LOG%"
        if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"
        powershell -Command "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.18.1/node-v20.18.1-win-x64.zip' -OutFile '%TOOLS_DIR%\node.zip'" 2>>"%LOG%"
        powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\node.zip' -DestinationPath '%TOOLS_DIR%' -Force" 2>>"%LOG%"
        del "%TOOLS_DIR%\node.zip"
        ren "%TOOLS_DIR%\node-v20.18.1-win-x64" "nodejs"
        set "PATH=%TOOLS_DIR%\nodejs;%PATH%"
        echo Node.js installed.
    )
)
echo [%date% %time%] Node OK >> "%LOG%"

rem Setup .env
echo [%date% %time%] Setting up .env >> "%LOG%"
if not exist ".env" (
    if exist ".env.example" copy ".env.example" ".env" >nul
    echo First run: generating encryption key...
    for /f %%i in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set ENC_KEY=%%i
    powershell -Command "(Get-Content '.env') -replace 'PASTE_64_CHAR_HEX_HERE', '%ENC_KEY%' | Set-Content '.env'"
)
echo [%date% %time%] .env OK >> "%LOG%"

rem Python deps
python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo Installing Python components...
    python -m pip install cryptography --quiet 2>>"%LOG%"
)
echo [%date% %time%] Python deps OK >> "%LOG%"

rem Engine deps
echo [%date% %time%] Checking engine deps >> "%LOG%"
if exist "engine\server\node_modules" goto :engine_ok
echo [%date% %time%] node_modules missing, installing >> "%LOG%"
echo Installing engine (first run)...
cd engine\server 2>>"%LOG%"
echo [%date% %time%] In server dir >> "%LOG%"
call npm install --production 2>>"%LOG%"
echo [%date% %time%] npm finished >> "%LOG%"
cd ..\.. 2>>"%LOG%"
:engine_ok
echo [%date% %time%] Engine deps OK >> "%LOG%"

rem Start engine
echo [%date% %time%] Starting engine >> "%LOG%"
echo Starting engine...
start "Nexus-Local Engine" cmd /k "cd /d "%~dp0app\engine\server" && set PATH=%PATH% && set PORT=3001 && set HOST=127.0.0.1 && set FREEAPI_DB_PATH=%~dp0app\engine-data\freeapi.db && set FREEAPI_CONFIG_PATH=%~dp0app\freellmapi.config.json && set FREEAPI_ENV_PATH=%~dp0app\.env && node dist\index.js"
timeout /t 6 >nul

rem Start dashboard
echo.
echo Open http://127.0.0.1:8080 in your browser
echo.
echo [%date% %time%] Starting dashboard >> "%LOG%"
start "Nexus-Local Dashboard" cmd /k "cd /d "%~dp0app" && set PATH=%PATH% && python server.py"
echo Done! Keep both windows open.
echo Log saved to startup.log
pause
