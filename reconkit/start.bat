@echo off
title ReconKit
color 0A
cd /d "%~dp0backend"
start "ReconKit Backend" cmd /k "color 0A && title ReconKit Backend && echo. && echo  ReconKit backend running on http://localhost:8000 && echo  DO NOT close this window! && echo. && uvicorn main:app --host 0.0.0.0 --port 8000"
timeout /t 3 /nobreak >nul
start "" "%~dp0frontend\index.html"
