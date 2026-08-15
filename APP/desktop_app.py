"""Hybrid IDS — native desktop launcher (single-file .exe friendly).

Opens the same Streamlit dashboard inside a real OS window (pywebview / WebView2)
and owns the whole lifecycle so there is one thing to double-click and one window
to close.

Process model
-------------
* Parent  : self-elevate to Admin, preflight, spawn ONE "server" child, show the
            native window, kill the child on close.
* Server  : a single child process that runs the capture backend in a daemon
            thread AND the Streamlit UI in its main thread. Keeping both in one
            process means they share one working directory (and therefore one
            ids_logs.db) — essential for a one-file build, where each process
            unpacks to its own private temp folder.

Works two ways from one file:
* Source run :  python desktop_app.py         (children are `python desktop_app.py …`)
* Frozen .exe:  built by HybridIDS.spec (onefile). No separate Python exists, so
                the launcher RE-ENTERS itself with `--hids-child server <port>`.
"""

from __future__ import annotations

import ctypes
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

FROZEN = bool(getattr(sys, "frozen", False))

# ── Paths ─────────────────────────────────────────────────────────────────────
# Frozen: everything is unpacked under sys._MEIPASS (onefile) or the dist folder
#         (onedir); either way _MEIPASS points at it. Source: this file's folder.
if FROZEN:
    HERE = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    ROOT = HERE                                  # Aaron/ Megan/ Rui Yang/ sit here
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
    ROOT = os.path.dirname(HERE)
DASH = os.path.join(HERE, "Dashboard")

# tshark ships with Wireshark; check the 64-bit and 32-bit install dirs.
TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]
TSHARK = next((p for p in TSHARK_CANDIDATES if os.path.exists(p)), TSHARK_CANDIDATES[0])
APP_TITLE = "Hybrid IDS — Threat Level Hunting"

CREATE_NO_WINDOW = 0x08000000


def _log_path() -> str:
    """A findable, persistent log location. Frozen onefile unpacks Dashboard/ to a
    temp dir that is wiped on exit, so a start-up failure there leaves nothing to
    read — write to %LOCALAPPDATA%\\HybridIDS instead so a user (or someone we gave
    the exe to) can actually find and share it. Source runs keep it beside the app."""
    if FROZEN:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "HybridIDS")
        try:
            os.makedirs(d, exist_ok=True)
            return os.path.join(d, "desktop_server.log")
        except Exception:
            pass
    return os.path.join(DASH, "desktop_server.log")


_SERVER_LOG = _log_path()


# ── Server child: backend thread + Streamlit main thread (one process) ────────
def _run_server_child(port: int) -> int:
    os.environ["HYBRIDIDS_ROOT"] = ROOT
    # In a frozen (PyInstaller) build Streamlit can't tell it is "installed" and
    # defaults global.developmentMode=true, which makes --server.port a fatal
    # conflict ("server.port does not work when global.developmentMode is true").
    # Force it off so the fixed port we picked is honored.
    os.environ["STREAMLIT_GLOBAL_DEVELOPMENT_MODE"] = "false"
    if DASH not in sys.path:
        sys.path.insert(0, DASH)

    # Capture engine in a daemon thread — dies with the process on window close.
    import live_backend
    threading.Thread(
        target=live_backend.run_live, kwargs={"interface": None},
        daemon=True, name="ids-backend",
    ).start()

    # Streamlit server in this (main) thread via its CLI entry point.
    os.chdir(DASH)
    sys.argv = [
        "streamlit", "run", os.path.join(DASH, "app.py"),
        "--server.headless=true",
        "--server.address=127.0.0.1",
        f"--server.port={port}",
        "--browser.gatherUsageStats=false",
        "--server.runOnSave=false",
    ]
    from streamlit.web.cli import main as st_main
    return int(st_main() or 0)


# ── Self-test child: prove the bundle can actually run every panel ────────────
def _run_selftest() -> int:
    """Exercise the contributor code paths inside the frozen bundle and report.

    A frozen build fails differently from a source run: a package can be missing
    from the archive, or present but unable to load its C extension, and the
    dashboard swallows both into a tidy "install deps" message that looks like a
    normal empty state. That is how a build shipped with `torch` excluded and
    nobody noticed the LSTM layer had stopped running. Importing is not enough to
    catch it either -- this actually computes a SHAP figure and tags a technique,
    because that is where a half-collected package (llvmlite's DLL, shap's _cext)
    gives out.

        HybridIDS_test.exe --hids-child selftest

    Prints PASS/FAIL per check; exit code is the number of failures.
    """
    os.environ["HYBRIDIDS_ROOT"] = ROOT
    # Reversed so Dashboard/ ends up ahead of the contributor folders after the
    # inserts: Aaron ships his own live_backend.py, and with his folder first on
    # sys.path `import live_backend` picks up his fork instead of the unified
    # engine. The server child gets this right by importing live_backend before
    # app.py touches sys.path at all; here the order has to be explicit.
    for p in reversed((DASH, os.path.join(ROOT, "Megan"), os.path.join(ROOT, "Aaron"))):
        if p not in sys.path:
            sys.path.insert(0, p)
    os.chdir(DASH)

    results: list[tuple[str, bool, str]] = []

    def check(name, fn):
        try:
            detail = fn() or "ok"
            results.append((name, True, str(detail)))
        except Exception as exc:
            results.append((name, False, f"{type(exc).__name__}: {exc}"))

    def _deps():
        import matplotlib
        import shap
        import torch
        return (f"torch {torch.__version__}, shap {shap.__version__}, "
                f"matplotlib {matplotlib.__version__}")

    def _rf_shap():
        import matplotlib
        import shap_explainer as se
        if not (se._SHAP_AVAILABLE and se._MPL_AVAILABLE):
            raise RuntimeError("shap/matplotlib flags are False inside the bundle")
        # Read the backend only after shap_explainer has been imported: it is the
        # module that pins Agg, and a GUI backend surviving that pin is exactly
        # what would leave the charts blank in the windowed exe.
        backend = matplotlib.get_backend()
        if backend.lower() != "agg":
            raise RuntimeError(f"expected the Agg backend, got {backend}")
        imp, labels = se.compute_global_importance()
        if imp is None:
            raise RuntimeError("compute_global_importance returned None")
        png = se._fig_to_bytes(se._global_importance_figure(imp, labels))
        return f"{len(imp)} features, {len(png)} byte PNG, backend {backend}"

    def _lstm_shap():
        import shap_explainer as se
        if not se._TORCH_AVAILABLE:
            raise RuntimeError("torch flag is False inside the bundle")
        feat, time_imp, labels = se.compute_lstm_global_importance()
        if feat is None:
            raise RuntimeError("compute_lstm_global_importance returned None")
        return f"{len(feat)} features x {len(time_imp)} timesteps"

    def _lstm_layer():
        import live_backend
        model, ok = live_backend._load_lstm_safe()
        if not ok or model is None:
            raise RuntimeError("live_backend could not load the LSTM (Layer 5 dead)")
        return "live_backend loaded lstm_model.pt"

    def _mitre():
        from mitre_mapping import tag_mitre
        tid, sub, name, tactic, tac_id = tag_mitre("High-Volume Flood Attack")
        if tid != "T1498":
            raise RuntimeError(f"unexpected technique for a flood: {tid}")
        return f"{tid} {name} / {tactic}"

    def _mitre_schema():
        """A fresh install must create the ATT&CK columns itself.

        No ids_logs.db ships (it would leak the builder's traffic), so the exe
        always starts on a database live_backend.init_db() has just created. If
        that misses the mitre_* columns the panel reports "not yet in database"
        and Aaron's whole view is dead on a new machine -- the migration used to
        live only in his own backend, so this is worth asserting, not assuming.
        """
        import sqlite3
        import tempfile

        import live_backend
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                live_backend.init_db()
                conn = sqlite3.connect(live_backend.DB_FILE)
                cols = {r[1] for r in conn.execute("PRAGMA table_info(live_threat_logs)")}
                conn.close()
            finally:
                os.chdir(cwd)
        wanted = {"mitre_technique_id", "mitre_sub_technique_id",
                  "mitre_technique_name", "mitre_tactic", "mitre_tactic_id"}
        missing = wanted - cols
        if missing:
            raise RuntimeError(f"fresh DB is missing {sorted(missing)}")
        return f"fresh DB has all {len(wanted)} ATT&CK columns"

    def _retrain():
        from retrain_pipeline import check_triggers, _load_state
        return f"triggers readable: {sorted(check_triggers(_load_state()))}"

    check("deps import (torch/shap/matplotlib)", _deps)
    check("Megan: RF SHAP chart", _rf_shap)
    check("Megan: LSTM SHAP chart", _lstm_shap)
    check("Megan: LSTM detection layer", _lstm_layer)
    check("Megan: retrain panel", _retrain)
    check("Aaron: MITRE tagging", _mitre)
    check("Aaron: MITRE schema on a fresh DB", _mitre_schema)

    failures = sum(1 for _, ok, _ in results if not ok)
    print(f"\nHybrid IDS frozen self-test  (frozen={FROZEN}, root={ROOT})\n")
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    print(f"\n{len(results) - failures}/{len(results)} passed\n")
    return failures


def _dispatch_child_if_requested() -> None:
    """If launched as `--hids-child <role>`, run that role and exit."""
    if "--hids-child" not in sys.argv:
        return
    i = sys.argv.index("--hids-child")
    role = sys.argv[i + 1]
    if role == "server":
        sys.exit(_run_server_child(int(sys.argv[i + 2])))
    if role == "selftest":
        sys.exit(_run_selftest())
    sys.exit(2)


# ── Small helpers ─────────────────────────────────────────────────────────────
def _message_box(text: str, title: str = APP_TITLE, style: int = 0x10) -> None:
    """Native Win32 message box (style 0x10 = MB_ICONERROR)."""
    ctypes.windll.user32.MessageBoxW(0, text, title, style)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """Re-run this program elevated, then exit the un-elevated instance."""
    if FROZEN:
        exe, params = sys.executable, ""
    else:
        exe = sys.executable
        params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, HERE, 1)


def free_port(preferred: int = 8501) -> int:
    """Return `preferred` if free, else an OS-assigned free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def preflight() -> str | None:
    """Return an error string if the environment can't run the IDS, else None."""
    if not os.path.exists(TSHARK):
        return (
            "Wireshark is required but was not found.\n\n"
            "Hybrid IDS captures live network traffic using tshark, which is part "
            "of Wireshark (it also installs the Npcap capture driver).\n\n"
            "Fix: install Wireshark, then run Hybrid IDS again.\n"
            "Download:  https://www.wireshark.org/download.html\n"
            "During setup, keep the default options (including Npcap).\n\n"
            f"Looked for tshark at:\n    {TSHARK}"
        )
    if not os.path.exists(os.path.join(DASH, "rf_model.pkl")):
        if FROZEN:
            # Models are bundled — if one is missing the download is incomplete/corrupt.
            return (
                "This copy of Hybrid IDS is incomplete (the detection model "
                "rf_model.pkl is missing).\n\nRe-download the HybridIDS.exe file and "
                "try again. If it keeps failing, the file may have been truncated or "
                "quarantined by antivirus."
            )
        return (
            "The trained model rf_model.pkl is missing from the Dashboard folder.\n\n"
            "Run the training pipeline first:\n"
            "    python Dashboard/advanced_parser.py\n"
            "    python Dashboard/feature_engineer.py\n"
            "    python Dashboard/trainai_rf.py"
        )
    return None


def webview2_available() -> bool:
    """True if the Edge WebView2 Runtime is registered on this machine.

    pywebview renders through WebView2, which ships with Windows 11 and is
    pushed to most Windows 10 installs — but it is NOT guaranteed on an older
    or freshly-imaged Windows 10 box. Without it `webview.start()` raises well
    after the server is already up, which in a windowed build surfaces as the
    app simply never appearing. Detect it first so we can fall back instead.

    Both registry views are checked: the runtime registers under WOW6432Node on
    64-bit Windows, but not on every servicing channel.
    """
    import winreg

    client = r"{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    for hive, path in (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{client}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{client}"),
        (winreg.HKEY_CURRENT_USER, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{client}"),
    ):
        try:
            with winreg.OpenKey(hive, path) as k:
                if winreg.QueryValueEx(k, "pv")[0] not in ("", "0.0.0.0"):
                    return True
        except OSError:
            continue
    return False


def _open_in_browser(url: str) -> None:
    """Fallback UI when no native window is possible.

    The dashboard is an ordinary local web app, so a browser tab is a complete
    substitute — the only thing lost is the native frame. Blocking on a message
    box keeps the parent (and therefore the capture backend) alive until the
    user is finished, matching how webview.start() blocks.
    """
    import webbrowser

    webbrowser.open(url)
    _message_box(
        "Hybrid IDS is running in your web browser.\n\n"
        f"    {url}\n\n"
        "The Microsoft Edge WebView2 Runtime was not found, so the app could "
        "not open its own window. Everything works the same in the browser.\n\n"
        "To get the native window, install the free WebView2 Runtime:\n"
        "    https://developer.microsoft.com/microsoft-edge/webview2/\n\n"
        "Keep this dialog open while you use Hybrid IDS.\n"
        "Click OK to shut the IDS down.",
        style=0x40,  # MB_ICONINFORMATION
    )


def wait_for_server(url: str, timeout: float = 90.0) -> bool:
    """Poll `url` until it answers 200 or `timeout` elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def _server_cmd(port: int) -> list[str]:
    """Command that runs the server child — the re-entrant exe when frozen."""
    if FROZEN:
        return [sys.executable, "--hids-child", "server", str(port)]
    return [sys.executable, os.path.abspath(__file__), "--hids-child", "server", str(port)]


def _kill_tree(proc: subprocess.Popen | None) -> None:
    """Terminate a child process and any grandchildren (tshark, streamlit helpers)."""
    if proc is None or proc.poll() is not None:
        return
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            creationflags=CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


# ── Main (parent) ─────────────────────────────────────────────────────────────
def main() -> int:
    if os.name != "nt":
        _message_box("This launcher is Windows-only.")
        return 1

    if not is_admin():
        relaunch_as_admin()
        return 0  # elevated instance takes over

    err = preflight()
    if err:
        _message_box(err)
        return 1

    port = free_port(8501)
    url = f"http://127.0.0.1:{port}"

    log = open(_SERVER_LOG, "w", encoding="utf-8", errors="replace")
    server = subprocess.Popen(
        _server_cmd(port), cwd=DASH, stdout=log, stderr=subprocess.STDOUT,
        creationflags=CREATE_NO_WINDOW,
    )

    try:
        if not wait_for_server(url, timeout=90):
            _message_box(
                "The dashboard did not start within 90 seconds.\n\n"
                f"See the log:\n    {_SERVER_LOG}"
            )
            return 1

        # Native window when WebView2 is present; otherwise degrade to the
        # user's browser rather than dying after the server is already up.
        if webview2_available():
            try:
                import webview  # imported late so a missing dep is diagnosable
                webview.create_window(
                    APP_TITLE, url, width=1400, height=900, min_size=(1000, 700)
                )
                webview.start()  # blocks until the window is closed
            except Exception as exc:
                # Runtime registered but unusable (corrupt install, locked-down
                # policy, unsupported build). The dashboard itself is fine.
                print(f"[!] native window failed ({exc}); falling back to browser")
                _open_in_browser(url)
        else:
            _open_in_browser(url)
    finally:
        _kill_tree(server)

    return 0


if __name__ == "__main__":
    _dispatch_child_if_requested()   # frozen/source server child returns/exits here
    sys.exit(main())
