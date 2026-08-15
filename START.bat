@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Hybrid IDS - Full Launcher

REM ===================================================
REM   Hybrid IDS  -  one-click START (everything)
REM   Launches ONE unified dashboard on :8501. Aalok's app.py is the host and
REM   pulls every contributor's feature in as a tab (files stay in their own
REM   folders, imported in place - no second port / window):
REM     - Aalok base        Live SOC dashboard + Educational Simulator
REM     - Aaron  (MITRE)    ATT&CK Intelligence panel in the Live SOC tab
REM     - Rui Yang          PCAP Analysis + Threat Map tabs
REM     - Megan  (v2 ML)    Model Intelligence tab (SHAP / retrain / LSTM)
REM   Backend is Aalok's week 1-12 live_backend writing the shared
REM   Aalok\Dashboard\ids_logs.db; the dashboard backfills MITRE tags via
REM   Aaron's mapping. Aaron's auto-block (sidebar toggle -> firewall rule)
REM   is ported into this backend, so it is live here too; his full backend
REM   adds Severe-incident PCAP evidence capture and is still available via
REM   Aalok\Dashboard\start_system.bat option [2].
REM ===================================================

REM ---- self-elevate to Administrator (tshark live capture + netsh need it) ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "DASH=%~dp0Aalok\Dashboard"
set "AARON=%~dp0Aaron"
set "RUIYANG=%~dp0Rui Yang"

echo ===================================================
echo     Hybrid IDS  -  Full One-Click Launcher
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

if not exist "%DASH%\rf_model.pkl" (
    echo [X] rf_model.pkl missing in "%DASH%". Run the training pipeline first:
    echo       python advanced_parser.py
    echo       python feature_engineer.py
    echo       python trainai_rf.py
    pause
    exit /b 1
)

REM ---- unified host is Aalok's app.py; backend is Aalok's week 1-12 engine ----
REM ---- (dashboard backfills MITRE tags via Aaron's mapping, shared DB) ----
set "APP=%DASH%\app.py"
echo [*] Backend: Aalok ^(week 1-12^).
set "BACKEND=%DASH%\live_backend.py"
echo [*] Unified dashboard: Aalok app.py ^(+ Aaron / Rui Yang / Megan tabs^).
echo.

REM ---- launch live backend (sniffer -> shared ids_logs.db) ----
echo [*] Starting backend capture engine...
start "IDS Backend" /D "%DASH%" cmd /k python "%BACKEND%"

REM ---- launch the unified SOC dashboard on 8501 (Aalok host + all tabs) ----
echo [*] Starting unified Streamlit SOC dashboard (port 8501)...
start "IDS Dashboard" /D "%DASH%" cmd /k python -m streamlit run "%APP%" --server.headless true --server.port 8501 --server.address 127.0.0.1
echo.

REM ---- wait for the SOC dashboard to bind, then open it ----
echo [*] Waiting for SOC dashboard to come online...
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
echo [+] SOC dashboard ready at %URL%
start "" "%URL%"
goto DONE

:TIMEOUT
echo [!] SOC dashboard didn't respond in 20s. Open %URL% manually.

:DONE
echo.
echo [*] System running. Use STOP.bat (or close the terminal windows) to stop.
timeout /t 3 /nobreak >nul
exit /b 0
