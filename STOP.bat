@echo off
REM ===================================================
REM   Hybrid IDS  -  one-click STOP (project root)
REM   Kills the backend capture engine and the Streamlit
REM   dashboard spawned by START.bat / start_system.bat.
REM ===================================================
setlocal

REM ---- self-elevate (backend may run elevated, so killing it needs admin) ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges to stop services...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ===================================================
echo     Hybrid IDS  -  Stopping
echo ===================================================
echo.

REM ---- kill the named launcher windows (and their child python processes) ----
echo [*] Stopping backend window (IDS Backend)...
taskkill /FI "WINDOWTITLE eq IDS Backend" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq IDS Backend*" /T /F >nul 2>&1

echo [*] Stopping dashboard window (IDS Dashboard)...
taskkill /FI "WINDOWTITLE eq IDS Dashboard" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq IDS Dashboard*" /T /F >nul 2>&1

echo [*] Stopping Rui Yang upload app window (RY Upload App)...
taskkill /FI "WINDOWTITLE eq RY Upload App" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq RY Upload App*" /T /F >nul 2>&1

REM ---- belt-and-suspenders: kill whatever still holds the Streamlit ports 8501/8502 ----
echo [*] Releasing dashboard ports 8501/8502...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8501 :8502" ^| findstr "LISTENING"') do (
    taskkill /PID %%p /T /F >nul 2>&1
)

echo.
echo [+] Hybrid IDS stopped.
timeout /t 3 /nobreak >nul
exit /b 0
