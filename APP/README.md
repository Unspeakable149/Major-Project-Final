# Hybrid IDS — Desktop App

A native-window, one-click build of the Hybrid IDS dashboard. Same detection
engine, models, and dashboard as the web version — but it opens in its **own
desktop window** (no browser, no `localhost` URL to visit) and ships as a single
double-clickable **`HybridIDS.exe`**.

This folder is self-contained. It is a **patched copy** of `Aalok/Dashboard`
(the canonical dashboard) plus the desktop launcher and build recipe. The
original contributor folders (`Aaron/`, `Megan/`, `Rui Yang/`) are **not
modified or copied** — they are pulled in from one level up at build time.

```
APP/
├── desktop_app.py      ← the launcher (native window + full lifecycle)
├── Dashboard/          ← patched copy of the dashboard
│   ├── app.py          ← single-view nav + trimmed FX (see "What changed")
│   ├── live_backend.py ← capture engine (run_live() entry for the launcher)
│   └── … models, ids_logs.db, favicon.ico, .streamlit/
├── requirements.txt
├── HybridIDS.spec      ← PyInstaller recipe (→ single .exe)
└── build.ps1           ← one-command build helper
```

## Requirements (Windows 11)
- **Windows 11** (WebView2 runtime ships with it — used for the native window).
- **Wireshark** installed, with `tshark.exe` at
  `C:\Program Files\Wireshark\tshark.exe` (live packet capture).
- To run from source or build: **Python 3.11+** and `pip install -r requirements.txt`.
- The `.exe` itself needs **neither Python nor pip** — everything is embedded.

## Run the shipped app
Double-click **`dist\HybridIDS.exe`**.

- It self-elevates to **Administrator** (a UAC prompt appears — required for live
  packet capture and firewall rules).
- First launch self-extracts the bundle to a temp folder, so it takes a few
  seconds to open the window.
- The capture backend and the dashboard run inside **one** child process, so they
  share **one** working directory and one `ids_logs.db`.
- **Close the window to stop everything** — no separate STOP step, no leftover
  `tshark`/Streamlit processes.

## Run from source (dev)
```
python desktop_app.py
```
Same behavior as the exe (self-elevates, native window), but uses your installed
Python instead of the frozen bundle.

## Build the .exe
```
powershell -File build.ps1
```
Produces a single **`dist\HybridIDS.exe`** — nothing else needs to sit beside it.

- `python-docx` **is** bundled, so Rui Yang's Word (`.docx`) report export works
  in the shipped app.
- `torch` / `shap` / `matplotlib` **are** bundled, so **Model Intelligence** shows
  real SHAP charts and the backend's **LSTM sequence layer (Layer 5)** runs — the
  packaged app is the same detector as a source run. They used to be excluded to
  keep the download small, on the theory that the tab's "install deps" message was
  an acceptable fallback. It was not: a frozen exe has no `pip` and no
  site-packages to install into, so that message was advice nobody could act on,
  and the missing `torch` silently cost a whole detection layer. That is what
  roughly doubles the file size; `shap` also drags in `numba`/`llvmlite`.
  `cv2` is excluded — shap reaches it only through image maskers this project
  never uses, and it guards that import itself.
- Wireshark/tshark is **never** bundled (separate GPL install); the launcher's
  preflight checks for it and tells the user if it's missing.

## What changed vs the web version (why it's faster)
This desktop copy carries the latest dashboard code plus two performance changes
that do **not** affect detection logic, accuracy, or any stored data:

- **Cursor/particle FX removed — the main lag fix.** The web app injected a
  continuous canvas particle field plus per-`mousemove` effects (a trailing ghost
  cursor, a screen-blend spotlight that repainted a large radial-gradient every
  frame, and "magnetic" buttons that measured every button on every mouse move).
  Those ran nonstop and caused the lag. This build keeps **only** the cheap
  one-shot hero title/subtitle reveal. A **"Reduce animations"** sidebar toggle
  can drop even that.
- **Single-view render.** The web app used `st.tabs`, which makes Streamlit
  rebuild **all six** views on every rerun (including each auto-refresh). This
  copy uses a **segmented nav** that renders **only the active view**, so the
  five heavy panels (simulator canvas, PCAP, threat map, SHAP/LSTM) no longer
  execute each cycle.
- **Native window** via pywebview (WebView2) instead of a browser tab.

The detection engine (`live_backend.py`), the trained models, the database
schema, and all thresholds/scoring are **unchanged** — only the UI shell and the
cosmetic effects were touched.

## Notes / limitations
- First launch shows a UAC prompt (Administrator is required for packet capture).
- Combined child-process logs (capture backend + Streamlit) are written to
  `Dashboard\desktop_server.log` if you need to diagnose a failed start.
- In a onefile build the bundle unpacks to a temp folder each launch, so runtime
  writes to `ids_logs.db` live in that temp copy and reset on the next launch —
  expected for a demo/portable app.
