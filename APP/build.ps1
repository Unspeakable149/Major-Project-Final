# Build the Hybrid IDS desktop app into a one-folder .exe.
#   Usage:  right-click > Run with PowerShell,  or:  powershell -File build.ps1
# Output:  APP\dist\HybridIDS\HybridIDS.exe
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "[*] Checking build dependency (pyinstaller)..."
python -m pip show pyinstaller *> $null
if (-not $?) {
    Write-Host "[*] Installing pyinstaller..."
    python -m pip install pyinstaller
}

Write-Host "[*] Cleaning previous build..."
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist")  { Remove-Item -Recurse -Force "dist" }

Write-Host "[*] Building (this takes a few minutes)..."
python -m PyInstaller HybridIDS.spec --noconfirm

if (Test-Path "dist\HybridIDS.exe") {
    Write-Host "[+] Done: dist\HybridIDS.exe  (single file - double-click to run)"
    Write-Host "    Run it as Administrator. Wireshark/tshark must be installed."
} else {
    Write-Host "[X] Build did not produce HybridIDS.exe - check the log above."
    exit 1
}
