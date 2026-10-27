# start-frontend.ps1 -- Start the Next.js frontend dev server
# Run from: C:\ProgFiles\Prompt Injection Firewall\
# Make sure the backend is running first on port 8000.

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$frontend = Join-Path $root "frontend"
Set-Location $frontend

Write-Host "Starting Next.js frontend on http://localhost:3000 ..." -ForegroundColor Cyan
Write-Host "Make sure backend is running on http://localhost:8000" -ForegroundColor Yellow

npm run dev
