# SNAPESCAPE — One-Click Install & Launch (Windows)
# Double-click INSTALL.bat or run: .\INSTALL.ps1

$ErrorActionPreference = "Continue"
$root = $PSScriptRoot
Set-Location $root

Write-Host @"

   ╔═══════════════════════════════════════╗
   ║         SNAPESCAPE INSTALLER          ║
   ║   World's Best Bug Hunting Platform   ║
   ║      Created By: Pr0Fessor_SnApe      ║
   ╚═══════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Find Python
$py = $null
foreach ($c in @("python", "python3", "py")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) {
        $py = $c
        break
    }
}

if (-not $py) {
    Write-Host "[!] Python not found." -ForegroundColor Red
    Write-Host "    Install Python 3.11+ from https://python.org" -ForegroundColor Yellow
    Write-Host "    Or install Docker Desktop for easiest setup." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[*] Running installer..." -ForegroundColor Green
& $py "$root\snapescape.py" install

Write-Host ""
$start = Read-Host "Start SNAPESCAPE now? (Y/n)"
if ($start -ne "n" -and $start -ne "N") {
    & $py "$root\snapescape.py" start --open
}

Write-Host ""
Write-Host "  DONE! Three commands to remember:" -ForegroundColor Green
Write-Host "    snapescape.bat start          - Start platform" -ForegroundColor White
Write-Host "    snapescape.bat hunt target.com - Scan a target" -ForegroundColor White
Write-Host "    snapescape.bat dashboard      - Open UI" -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to close"
