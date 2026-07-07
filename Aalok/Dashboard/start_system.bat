@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Hybrid IDS Launcher

REM ---- self-elevate to Administrator (tshark live capture + netsh need it) ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ===================================================
echo     Hybrid IDS  -  One-Click Launcher
echo ===================================================
echo.

REM ---- preflight checks ----
set "TSHARK=C:\Program Files\Wireshark\tshark.exe"
if not exist "%TSHARK%" (
    echo [X] tshark not found at "%TSHARK%".
    echo     Install Wireshark or update TSHARK_PATH in live_backend.py.
    pause
    exit /b 1
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python not on PATH. Install Python 3.10+ and retry.
    pause
    exit /b 1
)

if not exist "rf_model.pkl" (
    echo [X] rf_model.pkl missing. Run the training pipeline first:
    echo       python advanced_parser.py
    echo       python feature_engineer.py
    echo       python trainai_rf.py
    pause
    exit /b 1
)

REM ---- choose build: Aalok base, Aaron MITRE (share this DB/models), or Rui Yang upload app ----
set "AARON=%~dp0..\..\Aaron"
set "RUIYANG=%~dp0..\..\Rui Yang"
echo Select build to launch:
echo    [1] Aalok base build    -  Dashboard\live_backend.py + app.py
echo    [2] Aaron MITRE build   -  Aaron\live_backend.py + app.py (ATT^&CK + evidence)
echo    [3] Rui Yang upload app -  Rui Yang\app\upload_app.py (PCAP upload + rule engine, no live capture)
echo.
set "BUILD=1"
set /p "BUILD=Enter choice [1/2/3] (default 1): "
if "%BUILD%"=="3" (
    if exist "%RUIYANG%\app\upload_app.py" (
        echo [*] Launching Rui Yang upload app ^(standalone PCAP analyser, own model + rules^).
        set "BACKEND=NONE"
        set "APP=%RUIYANG%\app\upload_app.py"
    ) else (
        echo [!] Rui Yang build not found at "%RUIYANG%". Falling back to Aalok base.
        set "BACKEND=live_backend.py"
        set "APP=app.py"
    )
) else if "%BUILD%"=="2" (
    if exist "%AARON%\app.py" (
        echo [*] Launching Aaron MITRE build ^(shares this folder's DB + models^).
        set "BACKEND=%AARON%\live_backend.py"
        set "APP=%AARON%\app.py"
    ) else (
        echo [!] Aaron build not found at "%AARON%". Falling back to Aalok base.
        set "BACKEND=live_backend.py"
        set "APP=app.py"
    )
) else (
    echo [*] Launching Aalok base build.
    set "BACKEND=live_backend.py"
    set "APP=app.py"
)
echo.

REM ---- launch backend (skipped for builds with no live capture engine) ----
if /i "%BACKEND%"=="NONE" (
    echo [*] Selected build has no live backend ^(upload-only^); skipping capture engine.
) else (
    echo [*] Starting backend capture engine...
    start "IDS Backend" cmd /k "cd /d ""%~dp0"" && python ""%BACKEND%"""
)

REM ---- launch dashboard ----
echo [*] Starting Streamlit SOC dashboard...
start "IDS Dashboard" cmd /k "cd /d ""%~dp0"" && python -m streamlit run ""%APP%"" --server.headless true --server.port 8501"

REM ---- wait for Streamlit to bind, then open browser ----
echo [*] Waiting for dashboard to come online...
set "URL=http://localhost:8501"
set /a TRIES=0
:WAIT_LOOP
set /a TRIES+=1
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -TimeoutSec 1).StatusCode } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 goto READY
if %TRIES% geq 20 goto TIMEOUT
timeout /t 1 /nobreak >nul
goto WAIT_LOOP

:READY
echo [+] Dashboard ready at %URL%
start "" "%URL%"
goto DONE

:TIMEOUT
echo [!] Dashboard didn't respond in 20s. Open %URL% manually.

:DONE
echo.
echo [*] System running. Close the two terminal windows to stop.
timeout /t 3 /nobreak >nul
exit /b 0
