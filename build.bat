@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

call venv\Scripts\activate.bat
if errorlevel 1 (
  echo Failed to activate venv.
  exit /b 1
)

rmdir /s /q build dist

pyinstaller --clean --onefile app_manager.py

xcopy /e /i /y "data" "dist\data"
xcopy /e /i /y "www" "dist\www"


endlocal