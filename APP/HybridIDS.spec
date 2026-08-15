# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — freeze the Hybrid IDS desktop app to a single .exe.

Build:   pyinstaller HybridIDS.spec         (run from the APP/ folder)
Output:  APP/dist/HybridIDS.exe             (one file — double-click to run)

Design notes
------------
* One entry point (desktop_app.py). A frozen build has no separate python.exe, so
  the launcher re-enters itself with `--hids-child <role>` to run the Streamlit
  UI + capture-backend as ONE child process (they share one working dir, hence
  one ids_logs.db — essential for a onefile build where each process unpacks to
  its own private temp folder). See desktop_app.py.
* The four contributor folders are shipped as DATA inside the exe so the
  dashboard's HYBRIDIDS_ROOT (= the onefile temp dir sys._MEIPASS when frozen)
  resolves the sibling Aaron/ Megan/ Rui Yang/ imports exactly as in a source run:
      <_MEIPASS>/Dashboard/   (patched app.py, live_backend.py, models, db)
      <_MEIPASS>/Aaron/  Megan/  Rui Yang/
* torch / shap / matplotlib ARE bundled. They were excluded once to keep the exe
  small, on the assumption that the Model-Intelligence tab's "pip install shap"
  message was a fair fallback — it is not: a frozen build has no pip and no
  site-packages the user can add to, so that message was a dead end. Worse, the
  omission was not cosmetic: live_backend._load_lstm_safe() needs torch, so the
  LSTM sequence layer (sig_lstm) silently never ran in the exe. Bundling them
  costs a few hundred MB and is what makes the packaged app the same detector as
  the source run. torch's compiler-only files are stripped below.
* Wireshark/tshark is NOT bundled (separate ~200 MB GPL install) — it stays a
  prerequisite, and the launcher's preflight points the user at it.
"""

import os
from PyInstaller.utils.hooks import collect_all, collect_submodules, copy_metadata

# ── Paths (SPECPATH is the APP/ folder PyInstaller runs from) ─────────────────
APP_DIR = SPECPATH
ROOT_DIR = os.path.dirname(APP_DIR)                 # holds Aaron/ Megan/ Rui Yang/
DASH_DIR = os.path.join(APP_DIR, "Dashboard")

# "tests" is Rui Yang's pytest suite (rules / scoring / offender_history /
# report). It is developer-facing only — nothing imports it at runtime — so it
# is left out of the frozen bundle rather than shipped dead inside the exe.
_SKIP_DIRS = {"__pycache__", ".pytest_cache", ".streamlit_cache", "tests"}
# Packet captures are never shipped. The contributor folders hold test pcaps
# whose *payloads* contain real captured content (one carries /etc/passwd dumps
# and SSH sessions), so excluding by extension — not just the one temp file by
# name — is what keeps a distributable build free of raw traffic. Nothing at
# runtime reads them; the PCAP tab analyses files the user supplies.
_SKIP_EXT = {".pyc", ".pyo", ".log", ".pcap", ".pcapng", ".cap"}
_SKIP_NAMES = {
    # big training artefacts + transient runtime files — not needed to run.
    "master_advanced_dataset.csv", "master_behavioral_dataset.csv",
    "temp_live.pcap", "temp_raw.csv",
    "desktop_backend.log", "desktop_streamlit.log",
    # Alert databases hold real captured traffic (local IPs, ports, timings) from
    # whoever built the exe. Shipping one leaks that to every recipient, so the
    # build starts empty: live_backend.init_db() creates the schema on first run.
    "ids_logs.db", "ids_logs.db.demo-backup", "offender_history.db",
    # retrain_state.json records absolute model-version paths, which embed the
    # builder's Windows username and folder tree. retrain_pipeline._load_state()
    # falls back to sane defaults when it is absent, so simply omit it.
    "retrain_state.json",
    # ai_ready_advanced_flows.csv is engineered flow rows from a real capture
    # (public source IPs included) and is consumed only by the offline training
    # scripts (trainai_rf.py / trainai.py) — never at runtime.
    "ai_ready_advanced_flows.csv",
}


def tree_datas(src_dir, dest_prefix):
    """Return [(file, dest_folder)] for every keepable file under src_dir."""
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


# ── App data: the four folders, shipped alongside the exe ─────────────────────
datas = []
datas += tree_datas(DASH_DIR, "Dashboard")
for name in ("Aaron", "Megan", "Rui Yang"):
    sub = os.path.join(ROOT_DIR, name)
    if os.path.isdir(sub):
        datas += tree_datas(sub, name)

# ── Third-party packages the frozen children need at runtime ──────────────────
binaries = []
hiddenimports = []
# docx = python-docx: powers Rui Yang's Word (.docx) report export.
# requests = geoip lookups in Rui Yang's pcap_engine (PCAP Analysis + Threat Map).
# psutil = live_backend interface auto-detect (optional but improves reliability).
# torch = Megan's LSTM: both the sequence layer live_backend runs every window
#   (sig_lstm) and the LSTM SHAP panel. shap + matplotlib = her two SHAP charts
#   (matplotlib because shap_explainer renders to PNG and hands the bytes to
#   st.image). numba/llvmlite are not optional extras — shap/utils/_clustering.py
#   does a module-level `from numba import njit`, so `import shap` needs them.
for pkg in ("streamlit", "scapy", "sklearn", "plotly", "joblib", "altair",
            "docx", "requests", "psutil",
            "torch", "shap", "matplotlib", "numba", "llvmlite"):
    try:
        d, b, h = collect_all(pkg)
    except Exception:
        continue
    datas += d
    binaries += b
    hiddenimports += h


# torch's wheel carries its C++ SDK — headers, import libraries and cmake files
# that only somebody *compiling* against libtorch needs — plus test assets. At
# runtime the app loads torch_cpu.dll and nothing from those trees, so shipping
# them would put tens of MB into every download for nothing.
_TORCH_DEV_EXT = {".lib", ".h", ".hpp", ".cuh", ".cmake", ".pyi", ".in"}


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

hiddenimports += collect_submodules("streamlit")
hiddenimports += ["lxml", "lxml.etree", "lxml._elementpath"]  # python-docx runtime deps
# notifier.py (email/Discord/Slack alerts) imports these indirectly; PyInstaller
# does not auto-collect the email.mime.* stdlib submodules, so name them here.
hiddenimports += collect_submodules("email")
hiddenimports += ["email.mime", "email.mime.multipart", "email.mime.text",
                  "email.mime.base", "email.mime.application", "smtplib"]
# Streamlit & friends look up their own dist metadata at runtime.
for pkg in ("streamlit", "pandas", "numpy", "scikit-learn", "plotly",
            "altair", "pyarrow", "joblib", "scapy", "python-docx",
            "requests", "urllib3", "certifi", "idna", "charset-normalizer",
            "psutil", "torch", "shap", "matplotlib", "numba", "llvmlite",
            "scipy", "cloudpickle", "slicer", "tqdm"):
    try:
        datas += copy_metadata(pkg)
    except Exception:
        pass

# cv2 (opencv, ~90 MB) is reachable from shap only through its *image* maskers,
# which this project never uses — shap/maskers/_image.py wraps the import in a
# record_import_error() guard, so leaving it out costs nothing. PyInstaller's
# analysis does not honour that guard, hence the explicit exclude.
# tensorflow / PyQt5 / PySide2 are not used at all; matplotlib runs headless
# (shap_explainer pins the Agg backend), so no GUI toolkit is needed either.
_EXCLUDES = ["cv2", "tensorflow", "PyQt5", "PySide2"]


a = Analysis(
    ["desktop_app.py"],
    pathex=[APP_DIR],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=_EXCLUDES,
    noarchive=False,
)

pyz = PYZ(a.pure)

# HIDS_TEST=1 builds a throwaway variant (console on, no forced elevation) so the
# frozen bundle can be smoke-tested from a normal shell. The real deliverable is
# the default: windowed + Administrator-manifested.
_TEST = os.environ.get("HIDS_TEST") == "1"

# One-file build: binaries + data are embedded in the single .exe and unpacked to
# a private temp dir (sys._MEIPASS) at launch. Double-click to run; nothing else
# to keep beside it. (Trade-off: a few seconds of self-extraction on start.)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="HybridIDS_test" if _TEST else "HybridIDS",
    console=_TEST,          # windowed app (no console) for the real build
    disable_windowed_traceback=False,
    icon=os.path.join(DASH_DIR, "favicon.ico") if os.path.exists(
        os.path.join(DASH_DIR, "favicon.ico")) else None,
    uac_admin=not _TEST,    # request Administrator (live capture + firewall)
    runtime_tmpdir=None,
)
