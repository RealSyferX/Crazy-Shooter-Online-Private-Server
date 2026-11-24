@echo off
setlocal
set "CS_DIR=C:\Program Files (x86)\CSO Malaysia\System"
set "BISHOP_IP=127.0.0.1"
set "BISHOP_PORT=7451"

if not "%~1"=="" set "BISHOP_IP=%~1"
if not "%~2"=="" set "BISHOP_PORT=%~2"

if not exist "%CS_DIR%\CS.exe" (
    echo [CSG] CS.exe not found at "%CS_DIR%\CS.exe"
    pause
    exit /b 1
)

echo [CSG] Launching CSO Malaysia client -> %BISHOP_IP%:%BISHOP_PORT%
cd /d "%CS_DIR%"
start "" "%CS_DIR%\CS.exe" -updated -BishopIP=%BISHOP_IP% -BishopPort=%BISHOP_PORT%
