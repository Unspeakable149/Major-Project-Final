# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — build Hybrid IDS natively on macOS or Linux.

PyInstaller CANNOT cross-compile: this spec must be run ON the target OS.

    macOS :  pyinstaller HybridIDS_unix.spec     ->  dist/HybridIDS      (+ .app)
    Linux :  pyinstaller HybridIDS_unix.spec     ->  dist/HybridIDS

The entry point is run_hybrid_ids.py (browser UI) rather than desktop_app.py,
because desktop_app.py is Windows-only — it self-elevates through the Win32 API
and renders via Edge WebView2, neither of which exists on macOS/Linux.

The bundle keeps the repository's one-folder-per-contributor layout, so the
dashboard's HYBRIDIDS_ROOT resolves the sibling imports exactly as in a source
checkout:
    <bundle>/Aalok/Dashboard/   Aaron/   Megan/   Rui Yang/

torch / shap / matplotlib stay excluded to keep the bundle small; the Model
Intelligence tab degrades gracefully. Wireshark/tshark is never bundled.
"""

import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_submodules, copy_metadata

if sys.platform.startswith("win"):
    raise SystemExit(
        "This spec is for macOS/Linux. On Windows use HybridIDS.spec instead."
    )

APP_DIR = SPECPATH
# This spec sits at the bundle root next to Aalok/ Aaron/ Megan/ Rui Yang/, so
# the contributor folders are siblings of the spec, not one level up.
ROOT_DIR = APP_DIR
DASH_REL = os.path.join("Aalok", "Dashboard")
DASH_DIR = os.path.join(APP_DIR, DASH_REL)
if not os.path.isfile(os.path.join(DASH_DIR, "app.py")):
    # Tolerate a flattened copy that put Dashboard/ at the top level.
    DASH_REL, DASH_DIR = "Dashboard", os.path.join(APP_DIR, "Dashboard")

# "tests" is Rui Yang's pytest suite (rules / scoring / offender_history /
# report). It is developer-facing only — nothing imports it at runtime — so it
# is left out of the frozen bundle rather than shipped dead inside the app.
_SKIP_DIRS = {"__pycache__", ".pytest_cache", ".streamlit_cache", "tests"}
# Packet captures are never shipped. The contributor folders hold test pcaps
# whose *payloads* contain real captured content (one carries /etc/passwd dumps
# and SSH sessions), so excluding by extension — not just the one temp file by
# name — is what keeps a distributable build free of raw traffic. Nothing at
# runtime reads them; the PCAP tab analyses files the user supplies.
_SKIP_EXT = {".pyc", ".pyo", ".log", ".pcap", ".pcapng", ".cap"}
_SKIP_NAMES = {
    "master_advanced_dataset.csv", "master_behavioral_dataset.csv",
    "temp_live.pcap", "temp_raw.csv",
    "desktop_backend.log", "desktop_streamlit.log", "desktop_server.log",
    # Alert databases hold real captured traffic (local IPs, ports, timings)
    # from whoever built the binary — never ship one. live_backend.init_db()
    # recreates the schema on first run.
    "ids_logs.db", "ids_logs.db.demo-backup", "offender_history.db",
    # retrain_state.json records absolute model-version paths, which embed the
    # builder's username and folder tree. retrain_pipeline._load_state() falls
    # back to sane defaults when it is absent, so simply omit it.
    "retrain_state.json",
    # ai_ready_advanced_flows.csv is engineered flow rows from a real capture
    # (public source IPs included) and is consumed only by the offline training
    # scripts (trainai_rf.py / trainai.py) — never at runtime.
    "ai_ready_advanced_flows.csv",
}


def tree_datas(src_dir, dest_prefix):
    out = []
    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if f in _SKIP_NAMES or os.path.splitext(f)[1].lower() in _SKIP_EXT:
                continue
            full = os.path.join(root, f)
            rel = os.path.relpath(root, src_dir)
            dest = dest_prefix if rel == "." else os.path.join(dest_prefix, rel)
            out.append((full, dest))
    return out


datas = tree_datas(DASH_DIR, DASH_REL)
for name in ("Aaron", "Megan", "Rui Yang"):
    sub = os.path.join(ROOT_DIR, name)
    if os.path.isdir(sub):
        datas += tree_datas(sub, name)

binaries = []
hiddenimports = []
# torch/shap/matplotlib carry Megan's Model Intelligence — the LSTM sequence
# layer live_backend runs every window (sig_lstm) as well as both SHAP charts.
# They used to be excluded to keep the binary small, but a frozen build has no
# pip, so the "install shap" fallback was unreachable advice. numba/llvmlite come
# with shap, not as extras: shap/utils/_clustering.py imports njit at module level.
for pkg in ("streamlit", "scapy", "sklearn", "plotly", "joblib", "altair",
            "docx", "requests", "psutil",
            "torch", "shap", "matplotlib", "numba", "llvmlite"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass

# torch ships its C++ SDK (headers, import libs, cmake) and test assets inside
# the wheel. Nothing at runtime reads them, so they are dropped rather than
# padding every download by tens of MB. See HybridIDS.spec for the same filter.
_TORCH_DEV_EXT = {".lib", ".a", ".h", ".hpp", ".cuh", ".cmake", ".pyi", ".in"}


def _is_torch_dev_file(src, dest):
    d = str(dest).replace("\\", "/")
    if not (d == "torch" or d.startswith("torch/")):
        return False
    if "/include/" in d + "/" or d.endswith("/include"):
        return True
    if "/test/" in d + "/" or d.endswith("/test"):
        return True
    return os.path.splitext(str(src))[1].lower() in _TORCH_DEV_EXT


datas = [e for e in datas if not _is_torch_dev_file(e[0], e[1])]
binaries = [e for e in binaries if not _is_torch_dev_file(e[0], e[1])]

# email.mime.* is imported lazily by notifier.py, so PyInstaller's static
# analysis misses it — same gap as the Windows build.
hiddenimports += collect_submodules("email.mime")
hiddenimports += ["streamlit.runtime.scriptrunner.magic_funcs"]
for meta in ("streamlit", "altair", "torch", "shap", "matplotlib", "numba",
             "llvmlite", "scipy", "cloudpickle", "slicer", "tqdm"):
    try:
        datas += copy_metadata(meta)
    except Exception:
        pass

# cv2 is only reachable from shap's image maskers (guarded by
# record_import_error), which this project never uses — ~90 MB for nothing.
_EXCLUDES = ["cv2", "tensorflow", "PyQt5", "PySide2", "webview"]

a = Analysis(
    [os.path.join(APP_DIR, "run_hybrid_ids.py")],
    pathex=[APP_DIR, DASH_DIR],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=_EXCLUDES,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="HybridIDS",
    console=True,          # capture needs sudo; a terminal is the honest UI here
    disable_windowed_traceback=False,
    runtime_tmpdir=None,
)

# macOS only: also emit a double-clickable .app wrapper.
if sys.platform == "darwin":
    app = BUNDLE(
        exe,
        name="HybridIDS.app",
        bundle_identifier="edu.hybridids.soc",
        info_plist={"NSHighResolutionCapable": True},
    )
