@echo off
setlocal

REM ===================================================
REM   Rui Yang  -  standalone STOP
REM   Kills the upload-analyser window and releases
REM   port 8502. No admin needed (runs unelevated).
REM ===================================================

echo ===================================================
echo     Rui Yang  -  Stopping
echo ===================================================
echo.

REM ---- kill the named launcher window (and its child python) ----
echo [*] Stopping upload app window (RY Upload App)...
taskkill /FI "WINDOWTITLE eq RY Upload App" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq RY Upload App*" /T /F >nul 2>&1

REM ---- belt-and-suspenders: kill whatever still holds port 8502 ----
echo [*] Releasing port 8502...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8502" ^| findstr "LISTENING"') do (
    taskkill /PID %%p /T /F >nul 2>&1
)

echo.
echo [+] Rui Yang app stopped.
timeout /t 3 /nobreak >nul
exit /b 0
