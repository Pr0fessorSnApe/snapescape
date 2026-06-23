@echo off
title SNAPESCAPE - Hunt
cd /d "%~dp0"
if "%~1"=="" (
  echo.
  echo   Usage: HUNT.bat target.com
  echo   Example: HUNT.bat example.com
  echo.
  pause
  exit /b 1
)
python snapescape.py hunt %*
