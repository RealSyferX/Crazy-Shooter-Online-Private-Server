@echo off
setlocal
cd /d "%~dp0"

if not exist "data\ksg_table.bin" (
    echo [CSG] Extracting game data tables and crypto lookup table from client...
    python tools\extract_client_data.py
    if errorlevel 1 (
        echo [CSG] Extraction failed. Check client_dir in config.json.
        pause
        exit /b 1
    )
)

echo [CSG] Starting CSG Private Server...
python server\main.py --config config.json
pause
