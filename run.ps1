Set-Location -LiteralPath $PSScriptRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   VISION-LANGUAGE MODEL (VLM) ZERO-DAY PHISHING DETECTION SYSTEM" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify Python availability
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python was not found in your PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.11+ and ensure 'Add Python to PATH' is checked."
    Read-Host "Press Enter to exit"
    exit 1
}

# 2. Verify Node.js / npm availability
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Node.js / npm was not found in your PATH." -ForegroundColor Red
    Write-Host "Please install Node.js (v18+) to run the frontend application."
    Read-Host "Press Enter to exit"
    exit 1
}

# 3. Virtual environment check
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[*] Initializing Python virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip
    & .\.venv\Scripts\pip.exe install -r requirements.txt
} else {
    Write-Host "[*] Python virtual environment verified." -ForegroundColor Gray
}

# 4. Frontend node_modules check
if (-not (Test-Path "frontend\node_modules")) {
    Write-Host "[*] Installing frontend dependencies (node_modules)..." -ForegroundColor Yellow
    npm --prefix frontend install
} else {
    Write-Host "[*] Frontend dependencies verified." -ForegroundColor Gray
}

Write-Host ""
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  Launching Servers in Dedicated Windows..." -ForegroundColor Gray
Write-Host "----------------------------------------------------------------------" -ForegroundColor Gray

# 5. Launch Backend
Write-Host "[*] Starting FastAPI Backend on http://localhost:8000 ..." -ForegroundColor Green
Start-Process cmd.exe -ArgumentList '/k "call .venv\Scripts\activate.bat && python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"'

Start-Sleep -Seconds 2

# 6. Launch Frontend
Write-Host "[*] Starting React/Vite Frontend on http://localhost:5173 ..." -ForegroundColor Green
Start-Process cmd.exe -ArgumentList '/k "cd frontend && npm run dev"'

Start-Sleep -Seconds 3

# 7. Launch browser
Start-Process "http://localhost:5173"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SYSTEM LAUNCHED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  - Web Dashboard:     http://localhost:5173"
Write-Host "  - Backend Swagger:   http://localhost:8000/docs"
Write-Host "  - Backend Health:    http://localhost:8000/health"
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Servers are running in background console windows."
Write-Host "To stop servers, close their windows or run: .\stop.bat"
