# SNAPESCAPE Setup Script for Windows
# Created By: Pr0Fessor_SnApe

Write-Host @"

   SNAPESCAPE Setup
   Created By: Pr0Fessor_SnApe

"@ -ForegroundColor Cyan

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Check prerequisites
$missing = @()
if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) { $missing += "Rust (https://rustup.rs)" }
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { $missing += "Go (https://go.dev/dl/)" }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { $missing += "Python 3.11+" }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { $missing += "Node.js 20+" }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { $missing += "Docker Desktop (optional)" }

if ($missing.Count -gt 0) {
    Write-Host "[!] Missing prerequisites:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "    - $_" }
    Write-Host ""
}

# Set vault key
if (-not $env:SNAPESCAPE_VAULT_KEY) {
    $env:SNAPESCAPE_VAULT_KEY = "dev-vault-key-change-in-production-32b"
    Write-Host "[*] Set SNAPESCAPE_VAULT_KEY for this session" -ForegroundColor Green
}

# Build Rust engines
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Host "[*] Building Rust engines..." -ForegroundColor Cyan
    Set-Location "$root\engines\rust"
    cargo build --release
    Set-Location $root
}

# Build Go worker
if (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host "[*] Building Go worker..." -ForegroundColor Cyan
    Set-Location "$root\services\go-worker"
    go build -o "$root\bin\snapescape-worker.exe" ./cmd/worker
    Set-Location $root
}

# Python API
if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "[*] Installing Python dependencies..." -ForegroundColor Cyan
    Set-Location "$root\services\python-api"
    python -m pip install -r requirements.txt
    Set-Location $root
}

# Dashboard
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "[*] Installing dashboard dependencies..." -ForegroundColor Cyan
    Set-Location "$root\dashboard"
    npm install
    Set-Location $root
}

# Browser engine
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "[*] Installing browser engine..." -ForegroundColor Cyan
    Set-Location "$root\services\browser-engine"
    npm install
    npx playwright install chromium
    Set-Location $root
}

Write-Host @"

[+] SNAPESCAPE setup complete!

Quick Start:
  1. docker compose up -d redis postgres
  2. cd services\python-api && python -m snapescape_api.main
  3. cd dashboard && npm run dev
  4. Open http://localhost:3000

CLI Scan:
  engines\rust\target\release\snapescape.exe scan -d example.com

"@ -ForegroundColor Green
