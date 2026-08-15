@echo off
setlocal
cd /d "%~dp0"
title Rui Yang - PCAP Upload Analyser

REM ===================================================
REM   Rui Yang  -  standalone START
REM   Launches the PCAP-upload analyser (Streamlit) on
REM   port 8502. No live capture / no admin needed -
REM   the app is __file__-anchored with its own model+rules.
REM ===================================================

set "APP=%~dp0app\upload_app.py"

echo ===================================================
echo     Rui Yang  -  PCAP Upload Analyser
echo ===================================================
echo.

REM ---- preflight ----
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python not on PATH. Install Python 3.10+ and retry.
    pause
    exit /b 1
)

if not exist "%APP%" (
    echo [X] App not found at "%APP%".
    pause
    exit /b 1
)

REM ---- launch the upload analyser on 8502 ----
echo [*] Starting Rui Yang upload analyser (port 8502)...
start "RY Upload App" cmd /k python -m streamlit run "%APP%" --server.headless true --server.port 8502 --server.address 127.0.0.1

REM ---- wait for it to bind, then open the browser ----
echo [*] Waiting for the app to come online...
set "URL=http://localhost:8502"
set /a TRIES=0
:WAIT_LOOP
set /a TRIES+=1
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -TimeoutSec 1).StatusCode } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 goto READY
if %TRIES% geq 20 goto TIMEOUT
timeout /t 1 /nobreak >nul
goto WAIT_LOOP

:READY
echo [+] App ready at %URL%
start "" "%URL%"
goto DONE

:TIMEOUT
echo [!] App didn't respond in 20s. Open %URL% manually.

:DONE
echo.
echo [*] Running. Use STOP.bat (or close the terminal window) to stop.
timeout /t 3 /nobreak >nul
exit /b 0
