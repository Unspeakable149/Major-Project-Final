#!/usr/bin/env python3
"""Hybrid IDS — cross-platform launcher (Windows, macOS, Linux).

The packaged HybridIDS.exe is Windows-only: it is frozen by PyInstaller (which
cannot cross-compile) and its window is drawn by Edge WebView2. This script is
the portable equivalent — it runs the exact same dashboard and capture backend
from source and shows them in your normal web browser.

    python3 run_hybrid_ids.py               # capture + dashboard
    python3 run_hybrid_ids.py --no-capture  # dashboard only (read the saved DB)
    python3 run_hybrid_ids.py --port 8600

Packet capture needs elevated rights on every OS:
    Windows   run from an Administrator terminal (and install Wireshark/Npcap)
    macOS     sudo python3 run_hybrid_ids.py      (install Wireshark or `brew install wireshark`)
    Linux     sudo python3 run_hybrid_ids.py      (or grant tshark CAP_NET_RAW, see README)

Without those rights the dashboard still runs; only live capture is unavailable.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_dashboard() -> str:
    """Locate the Dashboard folder, tolerating either layout.

    The repository keeps it at ``Aalok/Dashboard`` (one folder per contributor,
    alongside Aaron/ Megan/ Rui Yang/); some packaged copies flatten it to a
    top-level ``Dashboard/``. Accept both so the launcher does not care which
    one it was dropped into.
    """
    for rel in (os.path.join("Aalok", "Dashboard"), "Dashboard"):
        candidate = os.path.join(HERE, rel)
        if os.path.isfile(os.path.join(candidate, "app.py")):
            return candidate
    return os.path.join(HERE, "Aalok", "Dashboard")   # best guess for the error message


DASH = _find_dashboard()
# Aaron/ Megan/ Rui Yang/ are resolved relative to this root by the dashboard.
ROOT = HERE


def _is_elevated() -> bool:
    """True if we can realistically open a capture device."""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _find_tshark() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    candidates = {
        "nt": [r"C:\Program Files\Wireshark\tshark.exe",
               r"C:\Program Files (x86)\Wireshark\tshark.exe"],
    }.get(os.name, [
        "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
    ])
    return next((p for p in candidates if os.path.exists(p)), None)


def _free_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _preflight(want_capture: bool) -> list[str]:
    """Return a list of human-readable warnings (empty means all good)."""
    warnings: list[str] = []

    if sys.version_info < (3, 10):
        warnings.append(
            f"Python {sys.version.split()[0]} detected — this project needs 3.10 or newer."
        )

    if not os.path.exists(os.path.join(DASH, "rf_model.pkl")):
        warnings.append(
            f"rf_model.pkl not found in {os.path.relpath(DASH, HERE)} — "
            "the bundle looks incomplete or the folder layout changed."
        )

    if want_capture:
        if _find_tshark() is None:
            warnings.append(
                "tshark was not found, so live capture is disabled.\n"
                "    macOS : brew install --cask wireshark   (or install Wireshark.app)\n"
                "    Debian: sudo apt install tshark\n"
                "    Fedora: sudo dnf install wireshark-cli\n"
                "    Windows: https://www.wireshark.org/download.html"
            )
        elif not _is_elevated():
            warnings.append(
                "Not running elevated — packet capture will likely fail.\n"
                "    macOS/Linux: re-run with sudo, or grant tshark capture rights:\n"
                "        sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)\n"
                "    Windows: run from an Administrator terminal."
            )

    if os.name != "nt":
        warnings.append(
            "Active response (firewall block buttons) is Windows-only — it uses "
            "`netsh advfirewall`. Detection, scoring, alerting and reports all work."
        )
    return warnings


def _ensure_database() -> None:
    """Create ids_logs.db and its schema if this is a fresh copy.

    The shared bundle ships without a database (it would otherwise carry
    captured traffic from whoever built it). Normally the capture backend
    creates the schema on start, but with --no-capture nothing would, and the
    dashboard would open on a table that does not exist and show a SQL error
    instead of an empty state. Creating it here makes a fresh copy open clean.
    """
    sys.path.insert(0, DASH)
    try:
        import live_backend

        live_backend.init_db()
    except Exception as exc:
        print(f"[!] Could not initialise ids_logs.db ({exc}).")


def _start_backend() -> None:
    """Run the capture loop in a daemon thread inside this process.

    Same-process (rather than a second python) so the backend and the dashboard
    share one working directory and therefore one ids_logs.db.
    """
    sys.path.insert(0, DASH)
    import live_backend

    threading.Thread(
        target=live_backend.run_live, kwargs={"interface": None},
        daemon=True, name="ids-backend",
    ).start()


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the Hybrid IDS dashboard.")
    ap.add_argument("--port", type=int, default=8501)
    ap.add_argument("--no-capture", action="store_true",
                    help="Dashboard only — do not start the live capture backend.")
    ap.add_argument("--no-browser", action="store_true",
                    help="Do not open a browser window automatically.")
    args = ap.parse_args()

    want_capture = not args.no_capture
    print("=" * 68)
    print(" Hybrid IDS — cross-platform launcher")
    print("=" * 68)

    for w in _preflight(want_capture):
        print(f"\n[!] {w}")

    os.environ["HYBRIDIDS_ROOT"] = ROOT
    os.chdir(DASH)
    _ensure_database()

    if want_capture and _find_tshark() is not None:
        try:
            _start_backend()
            print("\n[+] Capture backend started.")
        except Exception as exc:
            print(f"\n[!] Backend failed to start ({exc}); dashboard only.")

    port = _free_port(args.port)
    url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Dashboard: {url}")
    print("    Press Ctrl+C to stop.\n")

    if not args.no_browser:
        threading.Timer(3.0, lambda: webbrowser.open(url)).start()

    # Bind loopback only: the dashboard exposes live capture data and admin
    # controls with no authentication and must never be reachable off-host.
    sys.argv = [
        "streamlit", "run", os.path.join(DASH, "app.py"),
        "--server.headless=true",
        "--server.address=127.0.0.1",
        f"--server.port={port}",
        "--browser.gatherUsageStats=false",
    ]
    from streamlit.web.cli import main as st_main

    return int(st_main() or 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        sys.exit(0)
