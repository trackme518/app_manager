@echo off
REM Get the directory where this script is located
set SCRIPT_DIR=%~dp0

REM Change to the script's directory
cd /d "%SCRIPT_DIR%"

REM Activate the virtual environment
call "venv\Scripts\activate.bat"

REM Run Python directly in the same shell
python -u "app_manager.py"