@echo off
TITLE VLM Zero-Day Phishing Detection System
echo ========================================================
echo   Starting VLM Zero-Day Phishing Detection System...
echo ========================================================

:: Check if virtual environment exists
if not exist ".venv\Scripts\activate.bat" (
    echo [!] Virtual environment .venv not found. Creating one...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo [*] Starting FastAPI Backend on http://localhost:8000 ...
start "VLM Backend (FastAPI)" cmd /k "call .venv\Scripts\activate.bat && python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"

echo [*] Starting Vite Frontend on http://localhost:5173 ...
start "VLM Frontend (React/Vite)" cmd /k "cd frontend && npm run dev"

echo.
echo ========================================================
echo   System is launching!
echo   - Web Dashboard:  http://localhost:5173
echo   - Backend Docs:   http://localhost:8000/docs
echo ========================================================
echo.
pause

