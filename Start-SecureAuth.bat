@echo off
setlocal
cd /d "%~dp0"

netstat -ano | findstr /R /C:":5000 .*LISTENING" >nul
if errorlevel 1 (
  start "SecureAuth Server" /min "%~dp0.venv\Scripts\python.exe" app.py
  timeout /t 2 /nobreak >nul
)
start "" http://127.0.0.1:5000/

endlocal
