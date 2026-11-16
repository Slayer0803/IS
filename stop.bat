@echo off
TITLE Stop VLM Phishing Detection Servers
echo ========================================================
echo   Stopping VLM Backend and Frontend Servers...
echo ========================================================

echo [*] Terminating processes on port 8000 (Backend)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 "') do (
    taskkill /f /pid %%a >nul 2>&1
)

echo [*] Terminating processes on port 5173 (Frontend)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173 "') do (
    taskkill /f /pid %%a >nul 2>&1
)

echo.
echo [*] All servers stopped cleanly.
timeout /t 2 /nobreak >nul

