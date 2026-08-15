#!/usr/bin/env bash
# Build Hybrid IDS natively on macOS or Linux.
#
#   chmod +x build_unix.sh
#   ./build_unix.sh
#
# Output:  dist/HybridIDS            (single executable)
#          dist/HybridIDS.app        (macOS only, double-clickable)
#
# PyInstaller cannot cross-compile, so this MUST run on the OS you want a
# binary for. Building on macOS gives a macOS binary, on Linux a Linux binary.
# A Linux build is also glibc-version-bound: build on the oldest distro you
# intend to support, or it will not start on older ones.
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
  echo "[X] This is the macOS/Linux build. On Windows run: powershell -File build.ps1"
  exit 1
fi

PY="${PYTHON:-python3}"
echo "[*] Using: $($PY --version)"

if ! $PY -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
  echo "[X] Python 3.10+ required. Set PYTHON=/path/to/python3.12 and retry."
  exit 1
fi

echo "[*] Installing dependencies..."
$PY -m pip install --upgrade pip >/dev/null
$PY -m pip install -r requirements.txt
$PY -m pip install pyinstaller

if ! command -v tshark >/dev/null 2>&1; then
  echo
  echo "[!] tshark not found. The app builds fine, but live capture needs it:"
  case "$(uname -s)" in
    Darwin) echo "      brew install --cask wireshark" ;;
    Linux)  echo "      sudo apt install tshark      # Debian/Ubuntu"
            echo "      sudo dnf install wireshark-cli  # Fedora" ;;
  esac
  echo
fi

echo "[*] Cleaning previous build..."
rm -rf build dist

echo "[*] Building (a few minutes)..."
$PY -m PyInstaller HybridIDS_unix.spec --noconfirm

if [[ -f dist/HybridIDS || -d dist/HybridIDS.app ]]; then
  echo
  echo "[+] Done."
  [[ -f dist/HybridIDS ]]     && echo "    dist/HybridIDS"
  [[ -d dist/HybridIDS.app ]] && echo "    dist/HybridIDS.app"
  echo
  echo "    Run with capture rights:   sudo ./dist/HybridIDS"
  echo "    Dashboard only:            ./dist/HybridIDS --no-capture"
else
  echo "[X] Build did not produce a binary — check the log above."
  exit 1
fi
