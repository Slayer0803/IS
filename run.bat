@echo off
TITLE VLM Phishing Detection System - Launcher
cd /d "%~dp0"

echo ======================================================================
echo    VISION-LANGUAGE MODEL (VLM) ZERO-DAY PHISHING DETECTION SYSTEM
echo ======================================================================
echo.

:: 1. Verify Python availability
where python >nul 2>&1
if errorlevel 1 goto :no_python

:: 2. Verify Node.js and npm availability
where npm >nul 2>&1
if errorlevel 1 goto :no_npm

:: 3. Setup Python Virtual Environment if missing
if exist ".venv\Scripts\activate.bat" goto :venv_ok
echo [*] Virtual environment (.venv) not found. Initializing...
python -m venv .venv
if errorlevel 1 goto :venv_failed
echo [*] Installing backend dependencies from requirements.txt...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
:venv_ok
echo [*] Python virtual environment verified.

:: 4. Verify Frontend Dependencies if missing
if exist "frontend\node_modules\" goto :node_ok
echo [*] Frontend dependencies (node_modules) not found. Installing...
cd frontend
call npm install
cd /d "%~dp0"
:node_ok
echo [*] Frontend dependencies verified.

echo.
echo ----------------------------------------------------------------------
echo  Starting Servers in Dedicated Console Windows...
echo ----------------------------------------------------------------------

:: 5. Launch FastAPI Backend in a separate window
echo [*] Launching FastAPI Backend on http://localhost:8000 ...
start "VLM Backend (FastAPI on Port 8000)" cmd /k "call .venv\Scripts\activate.bat && python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"

:: Wait a brief moment to allow backend port binding
timeout /t 2 /nobreak >nul

:: 6. Launch Vite Frontend in a separate window
echo [*] Launching React/Vite Frontend on http://localhost:5173 ...
start "VLM Frontend (Vite on Port 5173)" cmd /k "cd frontend && npm run dev"

:: Wait a brief moment for dev server initialization
timeout /t 3 /nobreak >nul

:: 7. Automatically open the Web Dashboard in default browser
start http://localhost:5173

echo.
echo ======================================================================
echo   SYSTEM LAUNCHED SUCCESSFULLY!
echo ======================================================================
echo   - Web Dashboard:     http://localhost:5173
echo   - Backend Swagger:   http://localhost:8000/docs
echo   - Backend Health:    http://localhost:8000/health
echo   - Test Pages:        http://localhost:8000/api/test-pages
echo ======================================================================
echo.
echo   [INFO] Both servers are now active in their respective windows.
echo   [INFO] To terminate the servers, simply close their terminal windows
echo          or double-click stop.bat.
echo.
echo Press any key to exit this launcher window (servers will stay running)...
pause >nul
exit /b 0

:no_python
echo [ERROR] Python was not found in your PATH.
echo Please install Python 3.11+ and ensure Add Python to PATH is selected.
echo.
pause
exit /b 1

:no_npm
echo [ERROR] Node.js / npm was not found in your PATH.
echo Please install Node.js (v18+) to run the frontend application.
echo.
pause
exit /b 1

:venv_failed
echo [ERROR] Failed to create Python virtual environment.
pause
exit /b 1
