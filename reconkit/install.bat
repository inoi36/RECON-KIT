@echo off
title ReconKit — First Time Setup
color 0A

echo.
echo  ============================================
echo   RECONKIT — FIRST TIME SETUP
echo  ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found!
    echo  Download Python: https://python.org/downloads
    echo  During install, make sure to tick "Add Python to PATH"
    pause
    exit /b 1
)

echo  [OK] Python detected!

:: Install pip packages
echo.
echo  [..] Installing required Python packages...
echo       (This may take a minute on first run)
echo.
cd /d "%~dp0backend"
pip install fastapi uvicorn requests dnspython python-whois shodan --quiet

echo.
echo  [OK] All packages installed successfully!
echo.
echo  ============================================
echo   SETUP COMPLETE! Run start.bat to launch.
echo  ============================================
echo.
pause
