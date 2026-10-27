# start-backend.ps1 -- Start the Prompt Injection Firewall backend
# Run from: C:\ProgFiles\Prompt Injection Firewall\

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$uvicorn = Join-Path $root "venv\Scripts\uvicorn.exe"

if (-not (Test-Path $uvicorn)) {
    Write-Error "uvicorn not found. Run: venv\Scripts\pip install -r requirements.txt"
    exit 1
}

Write-Host "Starting Prompt Injection Firewall backend on http://localhost:8000 ..." -ForegroundColor Cyan
Write-Host "Dashboard: http://localhost:8000/dashboard" -ForegroundColor Green
Write-Host "API Docs:  http://localhost:8000/docs" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow

& $uvicorn backend.gateway.main:app --host 0.0.0.0 --port 8000 --reload
