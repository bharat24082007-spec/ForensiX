@echo off
title ForensiX Digital Forensics Platform
echo ========================================================
echo Starting ForensiX Digital Forensics Platform...
echo ========================================================
cd /d "%~dp0"

echo [1/2] Starting ForensiX Server on http://127.0.0.1:5000 ...
start "ForensiX Server" cmd /k "python run.py"

timeout /t 2 /nobreak >nul

echo [2/2] Starting ngrok Public Tunnel...
start "ngrok Tunnel" cmd /k "ngrok http 5000"

timeout /t 3 /nobreak >nul

echo Opening browser...
start http://127.0.0.1:5000/login

echo ========================================================
echo ForensiX is active!
echo Local: http://127.0.0.1:5000/login
echo ngrok Web UI: http://127.0.0.1:4040
echo ========================================================
pause
