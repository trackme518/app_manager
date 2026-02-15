@echo off
REM kill comfyUI
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8188') do taskkill /F /PID %%a
REM kill Orchestrator manager server
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :9999') do taskkill /F /PID %%a