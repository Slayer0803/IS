@echo off
setlocal enabledelayedexpansion

:: Set window title
TITLE VLM Phishing Detection System - Launcher

:: Ensure script runs from the repository root directory
cd /d "%~dp0"

echo ======================================================================
echo    VISION-LANGUAGE MODEL (VLM) ZERO-DAY PHISHING DETECTION SYSTEM
echo ======================================================================
echo.

:: 1. Verify Python availability
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found in your PATH.
    echo Please install Python 3.11+ and ensure "Add Python to PATH" is checked.
    echo.
    pause
    exit /b 1
)

:: 2. Verify Node.js and npm availability
where npm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js / npm was not found in your PATH.
    echo Please install Node.js (v18+) to run the frontend application.
    echo.
    pause
    exit /b 1
)

:: 3. Setup Python Virtual Environment
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Virtual environment (.venv) not found. Initializing...
    python -m venv .venv
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to create Python virtual environment.
        pause
        exit /b 1
    )
    echo [*] Installing backend dependencies from requirements.txt...
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    pip install -r requirements.txt
) else (
    echo [*] Found existing Python virtual environment (.venv).
)

:: 4. Verify Frontend Dependencies
if not exist "frontend\node_modules\" (
    echo [*] Frontend dependencies (node_modules) not found. Installing...
    cd frontend
    call npm install
    cd /d "%~dp0"
) else (
    echo [*] Frontend dependencies verified.
)

echo.
echo ----------------------------------------------------------------------
echo  Starting Servers in Dedicated Console Windows...
echo ----------------------------------------------------------------------

:: 5. Launch FastAPI Backend in a separate window
echo [*] Launching FastAPI Backend on http://localhost:8000 ...
start "VLM Backend (FastAPI on Port 8000)" cmd /k "cd /d ""%~dp0"" && call .venv\Scripts\activate.bat && python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"

:: Wait a brief moment to allow backend port binding
timeout /t 2 /nobreak >nul

:: 6. Launch Vite Frontend in a separate window
echo [*] Launching React/Vite Frontend on http://localhost:5173 ...
start "VLM Frontend (Vite on Port 5173)" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"

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
echo          or press Ctrl+C in each window.
echo.
echo Press any key to exit this launcher window (servers will stay running)...
pause >nul
