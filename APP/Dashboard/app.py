import hashlib
import html as _html
import ipaddress
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import time
import io
import zipfile

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# ── Unified dashboard host ───────────────────────────────────────────────────
# This is Aalok's app and the single unified dashboard START.bat launches. It is
# the canonical runtime home (ids_logs.db, trained models, evidence/ all live in
# THIS folder), and it pulls the other contributors' features in from their own
# folders without copying anything: Aaron's MITRE tagging and Rui Yang's PCAP +
# threat map engine. repo root = Aalok/Dashboard ->
# Aalok -> repo root (three levels up). chdir into this folder so every relative
# path below resolves here regardless of how Streamlit was launched.
# Frozen (PyInstaller) build: desktop_app.py exports HYBRIDIDS_ROOT to the
# real bundle root; honor it. Source run: three levels up from this file.
_REPO_ROOT = os.environ.get("HYBRIDIDS_ROOT") or os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# This folder has to be on sys.path in its own right, not just as the working
# directory. `streamlit run app.py` happens to inject the script's directory,
# but nothing else does — not Streamlit's AppTest harness, and not a frozen
# PyInstaller build where the modules are unpacked beside the bundle. The
# sibling folders below are added explicitly for the same reason; this line
# extends that to same-folder imports (evaluate_benchmark, notifier), which
# previously worked only by inheriting Streamlit's behaviour.
_DASH_DIR = os.path.dirname(os.path.abspath(__file__))
if _DASH_DIR not in sys.path:
    sys.path.insert(0, _DASH_DIR)

# ── Aaron MITRE ATT&CK mapping ───────────────────────────────────────────────
# Pull Aaron's MITRE tagging from the sibling Aaron/ folder. Degrades gracefully
# if that folder is missing; nothing is moved or copied.
_AARON_DIR = os.path.join(_REPO_ROOT, "Aaron")
if _AARON_DIR not in sys.path:
    sys.path.insert(0, _AARON_DIR)
try:
    from mitre_mapping import tag_mitre, tactic_color, mitre_url, TACTIC_COLORS
    MITRE_OK = True
    MITRE_ERR = None
except Exception as _exc:  # missing folder — degrade gracefully
    MITRE_OK = False
    MITRE_ERR = str(_exc)

# ── Rui Yang PCAP/Threat-Map engine ──────────────────────────────────────────
# Resolve the sibling "Rui Yang/app" folder. The engine loads its own
# models/rules anchored to the Rui Yang folder; nothing is moved or copied.
_RY_APP_DIR = os.path.join(_REPO_ROOT, "Rui Yang", "app")
_RY_SCRIPTS_DIR = os.path.join(_REPO_ROOT, "Rui Yang", "scripts")
if _RY_APP_DIR not in sys.path:
    sys.path.insert(0, _RY_APP_DIR)
if _RY_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _RY_SCRIPTS_DIR)
try:
    import plotly.express as px
    from pcap_engine import analyse_pcap, get_ip_location
    PCAP_ENGINE_OK = True
    PCAP_ENGINE_ERR = None
except Exception as _exc:  # missing folder / deps — degrade gracefully
    PCAP_ENGINE_OK = False
    PCAP_ENGINE_ERR = str(_exc)

# Rui Yang's aggregated Threat Analysis Report helpers (Enhancement Idea 1).
# Kept optional so the dashboard still loads if the scripts folder is absent.
try:
    from report import (
        build_reasons as _ry_build_reasons,
        build_actions as _ry_build_actions,
        attack_breakdown as _ry_attack_breakdown,
        top_attackers as _ry_top_attackers,
        per_attack_cards as _ry_per_attack_cards,
        rank_by_threat_score as _ry_rank_by_threat_score,
    )
    RY_REPORT_OK = True
except Exception:
    RY_REPORT_OK = False

# Rui Yang's plain-English Management Report — same underlying detections as
# the Threat Analysis Report above, reworded for a non-technical reader.
try:
    from management_report import (
        build_overall_summary as _ry_build_overall_summary,
        build_incident_cards as _ry_build_incident_cards,
        attack_type_counts_plain as _ry_attack_type_counts_plain,
    )
    RY_MGMT_REPORT_OK = True
except Exception:
    RY_MGMT_REPORT_OK = False

# Rui Yang's Word (.docx) export for both report views. Optional: needs
# python-docx, which not every teammate's environment may have installed.
try:
    from docx_report import (
        build_technical_docx as _ry_build_technical_docx,
        build_management_docx as _ry_build_management_docx,
    )
    RY_DOCX_OK = True
except Exception:
    RY_DOCX_OK = False

# Detection Benchmark view — scores the Random Forest against a labelled
# benchmark CSV. evaluate_benchmark.py sits in this folder and is the single
# implementation of the metrics; the CLI (`python evaluate_benchmark.py x.csv`)
# calls the same evaluate_dataframe(), so the console and the on-screen gauges
# cannot disagree. Guarded like every other cross-module import here so a
# missing/renamed file degrades this one view instead of killing the app.
try:
    import evaluate_benchmark as _bench
    BENCHMARK_OK = True
except Exception:
    BENCHMARK_OK = False

# The packaged desktop app renders this dashboard inside a pywebview/WebView2
# window that has NO download handler. Streamlit's st.download_button hands that
# embedded browser a client-side blob, which WebView2 saves CORRUPTED — Word
# then reports "the file is corrupt and cannot be opened" even though the bytes
# python-docx produced are valid. Detect the desktop build (desktop_app.py is the
# only thing that exports HYBRIDIDS_ROOT) and, there, write the report straight
# to the user's Downloads folder server-side instead — the Streamlit server runs
# on the same machine, so the exact bytes land on disk intact. The source /
# real-browser build is unaffected and keeps the normal download button.
_IS_DESKTOP_APP = bool(os.environ.get("HYBRIDIDS_ROOT"))


def _save_to_downloads(data: bytes, file_name: str) -> str:
    """Write bytes to the user's Downloads folder, never clobbering an existing
    file, and return the path actually written."""
    dest_dir = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.isdir(dest_dir):
        dest_dir = os.path.expanduser("~")
    os.makedirs(dest_dir, exist_ok=True)
    stem, ext = os.path.splitext(file_name)
    out = os.path.join(dest_dir, file_name)
    n = 1
    while os.path.exists(out):
        out = os.path.join(dest_dir, f"{stem} ({n}){ext}")
        n += 1
    with open(out, "wb") as fh:
        fh.write(data)
    return out


def _offer_binary_download(build_fn, file_name, key, label, mime,
                           desktop_label=None, use_container_width=False):
    """Binary download that survives the desktop build.

    st.download_button hands the browser a client-side blob. The pywebview /
    WebView2 window has no download handler, and what it saves is corrupted —
    which is why the Word export already takes this route. Any binary payload has
    the same problem, PCAP evidence included, so in the desktop build the file is
    written server-side instead (the server is local, so the bytes land intact).

    build_fn is called only when the user actually clicks, so reading a PCAP off
    disk is not paid for on every rerun.
    """
    if _IS_DESKTOP_APP:
        if st.button(desktop_label or f"Save {label}", key=key,
                     use_container_width=use_container_width):
            try:
                st.success(f"Saved to:  {_save_to_downloads(build_fn(), file_name)}")
            except Exception as _e:
                st.caption(f"Save failed ({_e}).")
    else:
        try:
            st.download_button(
                label, data=build_fn(), file_name=file_name, mime=mime,
                key=key, use_container_width=use_container_width,
            )
        except Exception as _e:
            st.caption(f"Download unavailable ({_e}).")


def _offer_word_report(build_fn, file_name, key, label="Download as Word (.docx)"):
    """Word (.docx) export that works in BOTH the browser and desktop builds.

    build_fn is a zero-arg callable returning the .docx bytes. In the desktop
    build it is only invoked on click (and the file is saved to disk); in the
    browser build the bytes are handed to st.download_button as before.
    """
    if _IS_DESKTOP_APP:
        if st.button("Save as Word (.docx)", use_container_width=True, key=key):
            try:
                data = build_fn()
                dest_dir = os.path.join(os.path.expanduser("~"), "Downloads")
                if not os.path.isdir(dest_dir):
                    dest_dir = os.path.expanduser("~")
                os.makedirs(dest_dir, exist_ok=True)
                stem, ext = os.path.splitext(file_name)
                out = os.path.join(dest_dir, file_name)
                _n = 1
                while os.path.exists(out):     # never clobber an earlier export
                    out = os.path.join(dest_dir, f"{stem} ({_n}){ext}")
                    _n += 1
                with open(out, "wb") as _f:
                    _f.write(data)
                st.success(f"Word report saved to:  {out}")
            except Exception as _e:
                st.caption(f"Word export failed ({_e}).")
    else:
        try:
            st.download_button(
                label,
                data=build_fn(),
                file_name=file_name,
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                use_container_width=True,
                key=key,
            )
        except Exception as _e:
            st.caption(f"Word export unavailable ({_e}).")

# ── Megan Model Intelligence (SHAP / LSTM / retraining) ──────────────────────
# Pull Megan's v2 model-intelligence panels from the sibling Megan/ folder. Those
# modules anchor their own model/DB paths back to THIS shared Dashboard, so
# nothing is moved or copied. Degrade gracefully if the folder or its optional
# deps (shap, torch, matplotlib) are missing.
_MEGAN_DIR = os.path.join(_REPO_ROOT, "Megan")
if _MEGAN_DIR not in sys.path:
    sys.path.insert(0, _MEGAN_DIR)
try:
    from shap_explainer import render_shap_panel, render_lstm_shap_panel
    from retrain_pipeline import render_retrain_panel
    MODEL_INTEL_OK = True
    MODEL_INTEL_ERR = None
except Exception as _exc:  # missing folder / deps — degrade gracefully
    MODEL_INTEL_OK = False
    MODEL_INTEL_ERR = str(_exc)

st.set_page_config(
    page_title="Hybrid IDS — SOC Dashboard",
    page_icon="favicon.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    /* ══════════════════════════════════════════════════════════════════
       Design system — Anthropic dark: warm near-black, charcoal cards,
       cream serif display type, terracotta accent, cream pill CTAs.
       Tokens:  bg #141413 · card #1E1D1B · border #2B2A28 · cream #FAF9F5
                body #C9C7BE · muted #8E8C84 · accent #D97757
                severe #F0A48E/#3A201A · warn #E0B65C/#352B14 · ok #97C0A4/#1D2B20
       ══════════════════════════════════════════════════════════════════ */
    @import url('https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,400;8..60,600;8..60,700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif;
        color: #E8E6DE;
        -webkit-font-smoothing: antialiased;
    }

    /* Display type: cream serif headings, tight leading — claude.com style */
    h1, h2, h3, [data-testid="stMetricValue"] {
        font-family: 'Source Serif 4', Georgia, serif !important;
        letter-spacing: -0.01em;
        color: #FAF9F5 !important;
    }
    h1 { font-weight: 600 !important; font-size: 42px !important; line-height: 1.15 !important; }
    h2 { font-weight: 600 !important; }
    h3 { font-weight: 600 !important; }
    [data-testid="stCaptionContainer"] p { color: #8E8C84; font-size: 15px; }

    /* Sidebar: slightly deeper charcoal, hairline divide */
    [data-testid="stSidebar"] {
        background-color: #1A1918;
        border-right: 1px solid #2B2A28;
    }

    /* KPI metrics: charcoal cards on near-black, soft lift, serif numerals */
    [data-testid="stMetric"] {
        background-color: #1E1D1B;
        border: 1px solid #2B2A28;
        border-radius: 14px;
        padding: 18px 22px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
        transition: box-shadow .15s ease, border-color .15s ease, transform .15s ease;
    }
    [data-testid="stMetric"]:hover {
        border-color: #3A3733;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35);
        transform: translateY(-1px);
    }
    [data-testid="stMetricLabel"] {
        font-size: 12px; color: #8E8C84;
        text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600;
    }
    [data-testid="stMetricValue"] { font-size: 32px; font-weight: 600; }

    /* Tabs: quiet labels, accent underline carries the state */
    button[data-baseweb="tab"] {
        font-family: 'Inter', sans-serif;
        font-size: 14px; font-weight: 500;
        color: #8E8C84;
        padding: 10px 4px;
    }
    button[data-baseweb="tab"][aria-selected="true"] { color: #FAF9F5; font-weight: 600; }
    [data-baseweb="tab-list"] { gap: 22px; border-bottom: 1px solid #2B2A28; }

    .section-divider { border-top: 1px solid #2B2A28; margin: 22px 0; }
    hr { border-color: #2B2A28 !important; }
    .threat-header {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.09em;
        color: #8E8C84;
        margin-bottom: 8px;
    }

    /* Panels and annotation cards: charcoal surfaces, hairline borders */
    .block-panel {
        background-color: #1E1D1B;
        border: 1px solid #2B2A28;
        border-radius: 12px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .ip-label { font-family: 'JetBrains Mono', monospace; font-size: 15px; color: #F0A48E; font-weight: 600; }
    .blocked-label { font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #8E8C84; }
    .reasoning-card {
        background-color: #1E1D1B;
        border: 1px solid #2B2A28;
        border-left: 3px solid #D97757;
        border-radius: 8px;
        padding: 12px 16px;
        margin: 8px 0;
        font-size: 13px;
        color: #C9C7BE;
    }
    .reasoning-card code {
        font-family: 'JetBrains Mono', monospace;
        color: #E8B08C; background: #2A211B;
        padding: 1px 6px; border-radius: 4px;
    }
    code, [data-testid="stCode"] { font-family: 'JetBrains Mono', monospace; }

    .status-pill {
        display: inline-block;
        padding: 3px 12px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.05em;
    }
    .status-online { background: #1D2B20; color: #97C0A4; border: 1px solid #2E4434; }
    .status-paused { background: #352B14; color: #E0B65C; border: 1px solid #4A3D1E; }

    /* ── State 5: Interactive — hover / active / focus-visible / disabled ── */
    .block-panel { transition: border-color .15s ease, box-shadow .15s ease, transform .15s ease; }
    .block-panel:hover {
        border-color: #4A3A30;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.30);
        transform: translateY(-1px);
    }
    .reasoning-card { transition: border-left-color .15s ease, box-shadow .15s ease; }
    .reasoning-card:hover { border-left-color: #E8927C; box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25); }

    /* Buttons: pill silhouette. Primary = cream CTA with ink text, the
       claude.com "Try Claude" look. Secondary stays quiet charcoal. */
    .stButton > button, .stDownloadButton > button {
        border-radius: 999px !important;
        font-weight: 500;
        transition: transform .08s ease, box-shadow .15s ease, background .15s ease;
    }
    .stButton > button[kind="primary"], .stButton > button[data-testid="stBaseButton-primary"] {
        background: #FAF9F5 !important;
        color: #141413 !important;
        border: 1px solid #FAF9F5 !important;
        font-weight: 600;
    }
    .stButton > button[kind="primary"]:hover:not(:disabled),
    .stButton > button[data-testid="stBaseButton-primary"]:hover:not(:disabled) {
        background: #EDEBE3 !important;
    }
    .stButton > button[kind="secondary"], .stDownloadButton > button {
        background: transparent;
        border: 1px solid #3A3733 !important;
        color: #E8E6DE;
    }
    .stButton > button:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(0,0,0,.30); }
    .stButton > button:active:not(:disabled) { transform: translateY(1px); box-shadow: none; }
    .stButton > button:focus-visible,
    .stDownloadButton > button:focus-visible {
        outline: 3px solid #D97757;
        outline-offset: 2px;
    }
    .stButton > button:disabled { opacity: 0.45; cursor: not-allowed; }

    /* Dataframes: rounded charcoal shell so tables sit like cards */
    [data-testid="stDataFrame"] {
        border: 1px solid #2B2A28;
        border-radius: 12px;
        overflow: hidden;
        background: #1E1D1B;
    }

    /* ── State 2: Empty — centered card with icon + copy + CTA ── */
    .empty-state {
        text-align: center;
        padding: 48px 24px;
        background: #1A1918;
        border: 1px dashed #3A3733;
        border-radius: 14px;
        margin: 12px 0;
    }
    .empty-state .icon { font-size: 40px; line-height: 1; margin-bottom: 12px; }
    .empty-state .title {
        font-family: 'Source Serif 4', Georgia, serif;
        font-size: 19px; font-weight: 600; color: #FAF9F5; margin-bottom: 6px;
    }
    .empty-state .desc { font-size: 13px; color: #8E8C84; max-width: 420px; margin: 0 auto; }

    /* ── State 3: Loading — skeleton shimmer placeholders ── */
    .skeleton {
        height: 18px;
        border-radius: 6px;
        margin: 8px 0;
        background: linear-gradient(90deg, #1E1D1B 25%, #2A2927 37%, #1E1D1B 63%);
        background-size: 400% 100%;
        animation: shimmer 1.4s ease infinite;
    }
    .skeleton.tall { height: 120px; }
    @keyframes shimmer { 0% { background-position: 100% 0; } 100% { background-position: -100% 0; } }

    /* ── Ambient aurora: faint terracotta glow washing down from the top ── */
    [data-testid="stAppViewContainer"]::before {
        content: "";
        position: fixed;
        top: -340px; left: 50%;
        transform: translateX(-50%);
        width: 1300px; height: 580px;
        background: radial-gradient(ellipse at center,
            rgba(217, 119, 87, 0.14) 0%,
            rgba(217, 119, 87, 0.045) 42%,
            transparent 70%);
        pointer-events: none;
        z-index: 0;
    }

    /* Glassy app chrome: translucent near-black + blur, content slides under */
    [data-testid="stHeader"] {
        background: rgba(20, 20, 19, 0.65) !important;
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
    }
    .block-container { padding-top: 3rem; }

    /* ── Entrance: page fades up on first paint, KPI cards stagger in ── */
    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(10px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    .block-container { animation: fadeUp .45s ease both; }
    [data-testid="stMetric"] { animation: fadeUp .5s ease both; }
    [data-testid="stColumn"]:nth-of-type(1) [data-testid="stMetric"],
    [data-testid="column"]:nth-of-type(1) [data-testid="stMetric"] { animation-delay: .05s; }
    [data-testid="stColumn"]:nth-of-type(2) [data-testid="stMetric"],
    [data-testid="column"]:nth-of-type(2) [data-testid="stMetric"] { animation-delay: .12s; }
    [data-testid="stColumn"]:nth-of-type(3) [data-testid="stMetric"],
    [data-testid="column"]:nth-of-type(3) [data-testid="stMetric"] { animation-delay: .19s; }
    [data-testid="stColumn"]:nth-of-type(4) [data-testid="stMetric"],
    [data-testid="column"]:nth-of-type(4) [data-testid="stMetric"] { animation-delay: .26s; }

    /* ── Hero banner ── */
    .hero { padding: 4px 0 2px 0; }
    .hero .glyph {
        color: #D97757; font-size: 30px; line-height: 1;
        display: inline-block; margin-right: 14px;
        transform-origin: center;
        animation: spinIn 1.1s cubic-bezier(.2, .8, .2, 1) both;
    }
    @keyframes spinIn {
        from { transform: rotate(-120deg) scale(.5); opacity: 0; }
        to   { transform: rotate(0) scale(1); opacity: 1; }
    }
    .hero .title {
        font-family: 'Source Serif 4', Georgia, serif;
        font-size: 40px; font-weight: 600; color: #FAF9F5;
        letter-spacing: -0.01em; line-height: 1.15;
    }
    .hero .sub { color: #8E8C84; font-size: 15px; margin-top: 8px; max-width: 720px; }

    /* Live status: breathing dot inside the sidebar pill */
    .pulse-dot {
        width: 9px; height: 9px; border-radius: 50%;
        display: inline-block; margin-right: 7px; vertical-align: 0px;
    }
    .pulse-dot.on  { background: #97C0A4; animation: pulse 2s ease-out infinite; }
    .pulse-dot.off { background: #E0B65C; }
    @keyframes pulse {
        0%   { box-shadow: 0 0 0 0 rgba(151, 192, 164, .45); }
        70%  { box-shadow: 0 0 0 9px rgba(151, 192, 164, 0); }
        100% { box-shadow: 0 0 0 0 rgba(151, 192, 164, 0); }
    }

    /* Slim warm scrollbar */
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: #141413; }
    ::-webkit-scrollbar-thumb {
        background: #2E2D2A; border-radius: 999px; border: 2px solid #141413;
    }
    ::-webkit-scrollbar-thumb:hover { background: #4A453E; }

    /* Empty-state icon drifts gently */
    .empty-state .icon { animation: floaty 3.2s ease-in-out infinite; }
    @keyframes floaty { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-6px); } }

    /* Charts sit in rounded charcoal shells like every other card */
    [data-testid="stPlotlyChart"], [data-testid="stVegaLiteChart"] {
        border: 1px solid #2B2A28;
        border-radius: 12px;
        background: #1A1918;
        padding: 8px;
        overflow: hidden;
    }

    /* FX layer housekeeping: hide deploy btn, lift page content above the
       z0 particle canvas. (The 1px script iframe collapses itself from
       inside via frameElement — display:none here could block its load.) */
    [data-testid="stAppDeployButton"] { display: none; }
    .block-container { position: relative; z-index: 1; }

    /* Alerts (st.info / st.warning / st.error): charcoal card, accent rail */
    [data-testid="stAlert"] {
        background: #1E1D1B;
        border: 1px solid #2B2A28;
        border-left: 3px solid #6B87A8;
        border-radius: 10px;
        color: #C9C7BE;
    }
    [data-testid="stAlertContainer"] {
        background: transparent !important;
        color: #C9C7BE !important;
    }

    /* (prefers-reduced-motion gate removed on purpose: Windows "Animation
       effects = off" reports it and was silently disabling the entire demo.) */

    /* ── THREATCON banner: ambient indicator, reacts to live severity.
       Class-scoped — only elements carrying .threat-cond are touched. ── */
    .threat-cond {
        display: flex; align-items: center; gap: 12px;
        border: 1px solid #2B2A28; background: #1E1D1B;
        border-radius: 12px; padding: 12px 18px; margin: 4px 0 14px 0;
        font-family: 'JetBrains Mono', monospace; font-size: 13px;
    }
    .threat-cond .tc-light { width: 12px; height: 12px; border-radius: 50%; flex: none; }
    .threat-cond .tc-label { font-weight: 700; letter-spacing: 0.08em; }
    .threat-cond .tc-desc { color: #8E8C84; font-size: 12px; }
    @keyframes tcPulse {
        0%   { box-shadow: 0 0 0 0 var(--tc-glow); }
        70%  { box-shadow: 0 0 0 11px transparent; }
        100% { box-shadow: 0 0 0 0 transparent; }
    }
    .threat-cond.tc-sev { border-color: #5A2B20; background: linear-gradient(90deg, #2A1812, #1E1D1B 60%); }
    .threat-cond.tc-sev .tc-light { background: #F0795A; --tc-glow: rgba(240,121,90,.55); animation: tcPulse 1.1s ease-out infinite; }
    .threat-cond.tc-sev .tc-label { color: #F0A48E; }
    .threat-cond.tc-mod { border-color: #4A3D1E; background: linear-gradient(90deg, #241E10, #1E1D1B 60%); }
    .threat-cond.tc-mod .tc-light { background: #E0B65C; --tc-glow: rgba(224,182,92,.45); animation: tcPulse 1.7s ease-out infinite; }
    .threat-cond.tc-mod .tc-label { color: #E0B65C; }
    .threat-cond.tc-ok .tc-light { background: #97C0A4; --tc-glow: rgba(151,192,164,.40); animation: tcPulse 2.5s ease-out infinite; }
    .threat-cond.tc-ok .tc-label { color: #97C0A4; }

    /* ── Cyber kill chain strip (class-scoped) ── */
    .killchain { display: flex; align-items: stretch; margin: 8px 0 2px 0; }
    .kc-stage {
        flex: 1; background: #1E1D1B; border: 1px solid #2B2A28;
        border-radius: 10px; padding: 12px 12px 10px 12px; text-align: center;
        position: relative; transition: border-color .15s ease, opacity .2s ease;
    }
    .kc-arrow {
        display: flex; align-items: center; padding: 0 8px;
        color: #55534E; font-size: 18px; font-weight: 700;
    }
    .kc-name { font-size: 12.5px; font-weight: 600; color: #C9C7BE; }
    .kc-sub { font-size: 10.5px; color: #8E8C84; margin-top: 3px; font-family: 'JetBrains Mono', monospace; }
    .kc-stage.kc-on { border-color: #5A2B20; background: #2A1812; }
    .kc-stage.kc-on .kc-name { color: #F0A48E; }
    .kc-stage.kc-broken { border-color: #2E4434; background: #1D2B20; }
    .kc-stage.kc-broken .kc-name { color: #97C0A4; }
    .kc-stage.kc-dim { opacity: 0.35; }
    .kc-badge {
        position: absolute; top: -9px; left: 50%; transform: translateX(-50%);
        background: #1D2B20; border: 1px solid #2E4434; color: #97C0A4;
        font-size: 9px; font-weight: 700; letter-spacing: 0.06em;
        padding: 1px 8px; border-radius: 999px; white-space: nowrap;
    }

    /* ── Mobile-first: stack the 4 KPI metrics, no horizontal scroll ── */
    @media (max-width: 640px) {
        h1 { font-size: 30px !important; }
        [data-testid="stMetricValue"] { font-size: 24px; }
        .empty-state { padding: 32px 16px; }
    }
</style>
""", unsafe_allow_html=True)


# Active response shells out to `netsh advfirewall`, which exists only on
# Windows. Everything else (capture, detection, scoring, alerting, reports) is
# portable, so on macOS/Linux the block buttons report "unsupported" rather than
# silently doing nothing or raising FileNotFoundError.
FIREWALL_SUPPORTED = os.name == "nt"


def _safe_upload_name(name: str) -> str:
    """Reduce a browser-supplied upload filename to a harmless leaf name.

    `st.file_uploader` hands back the client's filename verbatim; joining that
    onto a directory lets a name like ``../../x.pcap`` escape the intended
    folder, and this app runs elevated, so an arbitrary-file-write there is
    worth closing off even though the uploader is only reachable from
    localhost. Keep a conservative character set and drop every path separator.
    """
    leaf = os.path.basename(str(name).replace("\\", "/"))
    leaf = re.sub(r"[^A-Za-z0-9._-]", "_", leaf).lstrip(".")
    return f"temp_{leaf or 'upload'}.pcap" if not leaf.lower().endswith(
        (".pcap", ".pcapng", ".cap")) else f"temp_{leaf}"


def _is_valid_ipv4(ip_address) -> bool:
    """True only for a well-formed IP literal.

    Guards the netsh calls below. They already pass arguments as a list (no
    shell), so this is not closing an injection hole — it stops a malformed
    value read back out of the alert DB from being handed to a
    firewall-modifying command at all.
    """
    try:
        ipaddress.ip_address(str(ip_address).strip())
        return True
    except ValueError:
        return False


# Block state is persisted in SQLite (blocked_ips table) rather than
# st.session_state so it survives reruns/reloads AND reflects auto-blocks written
# by Aaron's live_backend.py. See the DB helpers below.


def apply_firewall_block(ip_address):
    """Add a Windows Defender Firewall inbound block rule for the given IP.

    Uses ``netsh advfirewall`` to install a rule named ``IDS_BLOCK_<ip>``.
    Returns True on success, False if the IP is malformed or netsh exits
    non-zero (e.g. rule already exists or insufficient privileges).
    """
    if not _is_valid_ipv4(ip_address) or os.name != "nt":
        return False   # netsh is Windows-only; see FIREWALL_SUPPORTED
    rule_name = f"IDS_BLOCK_{ip_address.replace('.', '_').replace(':', '_')}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def remove_firewall_block(ip_address):
    if not _is_valid_ipv4(ip_address) or os.name != "nt":
        return False
    rule_name = f"IDS_BLOCK_{ip_address.replace('.', '_').replace(':', '_')}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        capture_output=True, text=True
    )
    return result.returncode == 0


# ── Auto-block DB helpers (Aaron) ─────────────────────────────────────────────
# blocked_ips persists manual + automatic blocks; autoblock_config is the shared
# key-value store the dashboard writes and live_backend.py reads each window to
# decide whether to auto-block a repeat-offender Severe source IP.

def _ensure_autoblock_tables(conn: sqlite3.Connection) -> None:
    """Idempotently create blocked_ips and autoblock_config tables.

    live_backend.py creates these at startup too; this guards against the
    dashboard opening before the backend has ever run.
    """
    conn.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            blocked_at  REAL    NOT NULL,
            ttl_seconds INTEGER NOT NULL DEFAULT 3600,
            reason      TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS autoblock_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    conn.executemany(
        "INSERT OR IGNORE INTO autoblock_config (key, value) VALUES (?, ?)",
        [("enabled", "0"), ("threshold", "3"), ("ttl_seconds", "3600")],
    )
    # capture_config holds the live BPF capture filter the backend reads each
    # window. Created here too so the dashboard can write it before the backend
    # has ever run.
    conn.execute('''
        CREATE TABLE IF NOT EXISTS capture_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    conn.executemany(
        "INSERT OR IGNORE INTO capture_config (key, value) VALUES (?, ?)",
        # 'interface' pins the tshark interface index the capture loop listens
        # on; empty means auto-detect. Seeded here as well as in
        # live_backend.init_db() because either side may create the DB first.
        [("bpf_filter", ""), ("interface", "")],
    )
    conn.commit()


@st.cache_resource
def _get_db_conn() -> sqlite3.Connection:
    """Single long-lived SQLite connection shared across Streamlit reruns.

    check_same_thread=False is safe because Streamlit's server is single-threaded
    per session; caching avoids re-opening ids_logs.db on every rerun.
    """
    conn = sqlite3.connect("ids_logs.db", check_same_thread=False, timeout=15)
    _ensure_autoblock_tables(conn)
    return conn


def _read_autoblock_config() -> dict:
    conn = _get_db_conn()
    rows = conn.execute("SELECT key, value FROM autoblock_config").fetchall()
    raw = dict(rows)
    return {
        "enabled":     bool(int(raw.get("enabled", "0"))),
        "threshold":   int(raw.get("threshold",   "3")),
        "ttl_seconds": int(raw.get("ttl_seconds", "3600")),
    }


def _write_autoblock_config(enabled: bool, threshold: int, ttl_seconds: int) -> None:
    conn = _get_db_conn()
    conn.executemany(
        "INSERT OR REPLACE INTO autoblock_config (key, value) VALUES (?, ?)",
        [
            ("enabled",     str(int(enabled))),
            ("threshold",   str(threshold)),
            ("ttl_seconds", str(ttl_seconds)),
        ],
    )
    conn.commit()


def _read_capture_filter() -> str:
    """Return the saved BPF capture filter (empty string = capture everything)."""
    conn = _get_db_conn()
    row = conn.execute(
        "SELECT value FROM capture_config WHERE key='bpf_filter'"
    ).fetchone()
    return (row[0] if row else "").strip()


def _write_capture_filter(bpf: str) -> None:
    conn = _get_db_conn()
    conn.execute(
        "INSERT OR REPLACE INTO capture_config (key, value) VALUES ('bpf_filter', ?)",
        (bpf.strip(),),
    )
    conn.commit()


def _read_capture_interface() -> str:
    """Return the pinned tshark interface index (empty string = auto-detect)."""
    conn = _get_db_conn()
    row = conn.execute(
        "SELECT value FROM capture_config WHERE key='interface'"
    ).fetchone()
    return (row[0] if row else "").strip()


def _write_capture_interface(index: str) -> None:
    conn = _get_db_conn()
    conn.execute(
        "INSERT OR REPLACE INTO capture_config (key, value) VALUES ('interface', ?)",
        (str(index).strip(),),
    )
    conn.commit()


def _dashboard_live_backend():
    """Import THIS folder's live_backend.py by file path, not by module name.

    A bare `import live_backend` does NOT get Aalok's engine: each sibling
    contributor folder is inserted at sys.path[0] *after* _DASH_DIR (see the
    _AARON_DIR / _RY_APP_DIR / _RY_SCRIPTS_DIR / _MEGAN_DIR blocks above), so
    Aaron's own live_backend.py outranks this folder's copy. His has no
    list_capture_interfaces(), the AttributeError gets swallowed by the caller's
    except, and the interface picker silently renders as "tshark could not list
    interfaces" on a machine where tshark is perfectly fine. Loading by location
    pins the import to the engine this dashboard actually drives — and in the
    frozen build the launcher has already imported the real one into the same
    process, so this must agree with it.

    Cached in sys.modules under a private name so it never collides with, or
    shadows, whatever `live_backend` resolves to for anyone else.
    """
    import importlib.util

    module = sys.modules.get("_dash_live_backend")
    if module is None:
        spec = importlib.util.spec_from_file_location(
            "_dash_live_backend", os.path.join(_DASH_DIR, "live_backend.py")
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["_dash_live_backend"] = module
        spec.loader.exec_module(module)
    return module


@st.cache_data(ttl=60, show_spinner=False)
def _list_capture_interfaces() -> list[tuple[str, str]]:
    """Interfaces tshark can capture on, as [(index, friendly name)].

    Cached for a minute: the dashboard reruns on every auto-refresh tick, and
    listing interfaces spawns a tshark process. A minute is short enough that an
    adapter connected mid-session still appears without a restart.
    """
    try:
        return _dashboard_live_backend().list_capture_interfaces()
    except Exception:
        return []


def _load_blocked_ips() -> pd.DataFrame:
    """Return the blocked_ips table with human-readable expiry columns."""
    conn = _get_db_conn()
    df = pd.read_sql(
        "SELECT ip, blocked_at, ttl_seconds, reason FROM blocked_ips ORDER BY blocked_at DESC",
        conn,
    )
    if df.empty:
        return df
    now = time.time()
    df["Expires At"] = pd.to_datetime(df["blocked_at"] + df["ttl_seconds"], unit="s")
    df["Remaining"]  = df.apply(
        lambda r: f"{max(0, int(r.ttl_seconds - (now - r.blocked_at))) // 60} min", axis=1
    )
    return df.rename(columns={"ip": "Source IP", "reason": "Reason"})[
        ["Source IP", "Expires At", "Remaining", "Reason"]
    ]


def _block_ip_to_db(ip: str, ttl_seconds: int, reason: str) -> bool:
    """Push the firewall rule, then record the block in blocked_ips."""
    success = apply_firewall_block(ip)
    if success:
        conn = _get_db_conn()
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, ttl_seconds, reason) "
            "VALUES (?, ?, ?, ?)",
            (ip, time.time(), ttl_seconds, reason),
        )
        conn.commit()
    return success


def _unblock_ip_from_db(ip: str) -> bool:
    """Delete the firewall rule, then drop the block from blocked_ips."""
    success = remove_firewall_block(ip)
    if success:
        conn = _get_db_conn()
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()
    return success


# ── Defense Config: threat-intel / baseline IP lists ──────────────────────────
# The backend (live_backend.py) loads threat_intel.txt / baseline.txt and now
# re-reads them every window, so edits made here apply live without a restart.
# Format is one IPv4 per line with a leading '#' comment header (preserved).

THREAT_INTEL_FILE = "threat_intel.txt"
BASELINE_FILE = "baseline.txt"

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

_DEFAULT_BASELINE_HEADER = (
    "# Hybrid IDS — Baseline Whitelist\n"
    "#\n"
    "# One IPv4 address per line. Lines starting with '#' are ignored.\n"
    "# Any captured source IP matching this list is forced to "
    '"Baseline (Safe)"\n'
    "# regardless of behavioral metrics. Threat-intel matches still win.\n"
)


def _is_valid_ipv4(value: str) -> bool:
    m = _IPV4_RE.match(value.strip())
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())


def _ip_sort_key(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def _read_ip_file(path: str) -> tuple[str, list]:
    """Return (comment_header, sorted_ip_list). Missing file -> ('', [])."""
    if not os.path.exists(path):
        return "", []
    header, ips = [], []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if stripped.startswith("#") or stripped == "":
                if not ips:  # only the leading block counts as the header
                    header.append(line)
            else:
                ips.append(stripped)
    return "\n".join(header), sorted(set(ips), key=_ip_sort_key)


def _write_ip_file(path: str, header: str, ips) -> None:
    """Write the comment header followed by the sorted, de-duplicated IPs."""
    lines = []
    if header.strip():
        lines.append(header.rstrip("\n"))
    lines.extend(sorted(set(ips), key=_ip_sort_key))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ── Defense Config: alert notifier ────────────────────────────────────────────
NOTIFIER_CONFIG_FILE = "notifier_config.json"
NOTIFIER_CONFIG_EXAMPLE = "notifier_config.json.example"


def _load_notifier_config() -> tuple[dict, str]:
    """Load notifier_config.json, falling back to the .example template.

    Returns (config_dict, source_label) so the UI can say whether it is editing
    the live config or seeding from the template.
    """
    for path, label in (
        (NOTIFIER_CONFIG_FILE, "notifier_config.json"),
        (NOTIFIER_CONFIG_EXAMPLE, "notifier_config.json.example (template)"),
    ):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f), label
            except (json.JSONDecodeError, OSError):
                continue
    return {}, "none"


def _save_notifier_config(cfg: dict) -> None:
    """Write notifier_config.json (gitignored — holds plaintext SMTP creds).

    The file is created owner-read/write only. SMTP passwords and webhook URLs
    are stored in clear text (SMTP AUTH needs the original secret, so hashing is
    not an option), and the default umask would otherwise leave them readable by
    every account on a shared machine. On Windows os.chmod only toggles the
    read-only attribute rather than applying an ACL, so the restriction is
    best-effort there — documented in SHARE-README.md.
    """
    with open(NOTIFIER_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(NOTIFIER_CONFIG_FILE, 0o600)
    except OSError:
        pass  # unsupported filesystem — the file is still written


def render_empty_state(icon: str, title: str, desc: str):
    """Render a centered empty-state card (icon + title + helper copy).

    The CTA button is rendered by the caller via st.button so it stays a real,
    keyboard-focusable Streamlit widget rather than dead HTML.
    """
    st.markdown(
        f'<div class="empty-state" role="status">'
        f'<div class="icon" aria-hidden="true">{icon}</div>'
        f'<div class="title">{title}</div>'
        f'<div class="desc">{desc}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_table_skeleton():
    """Skeleton placeholder shown while the first DB read is in flight.

    Reserves vertical space so the real table swapping in causes no layout shift.
    """
    bars = '<div class="skeleton"></div>' * 3 + '<div class="skeleton tall"></div>'
    st.markdown(f'<div aria-busy="true" aria-live="polite">{bars}</div>', unsafe_allow_html=True)


# ── SOC-grade UI components ───────────────────────────────────────────────────
# Every widget below is either plain class-scoped markdown or a fully
# self-contained component iframe. None of them reach into the parent
# Streamlit DOM, so page scrolling and pointer events stay untouched.

_MONO_IMPORT = (
    "@import url('https://fonts.googleapis.com/css2?"
    "family=JetBrains+Mono:wght@400;600;700&display=swap');"
)

_KC_STAGES = [
    ("Reconnaissance", "scan / probe"),
    ("Intrusion", "flood / brute-force"),
    ("Command & Control", "beacon / callback"),
    ("Exfiltration", "data transfer"),
]


def _kc_stage_of(profile) -> int | None:
    """Map a traffic profile string onto a kill-chain stage index (or None)."""
    p = str(profile).lower()
    if "exfil" in p or "transfer" in p:
        return 3
    if "c2" in p or "beacon" in p or "callback" in p:
        return 2
    if "flood" in p or "ddos" in p or "brute" in p or "sustained" in p:
        return 1
    if "scan" in p or "recon" in p or "probe" in p:
        return 0
    return None


def render_threat_condition(severe_n: int, moderate_n: int) -> None:
    """Ambient THREATCON banner — pulses with the worst severity on screen."""
    if severe_n:
        cls, label = "tc-sev", "THREATCON 1 — CRITICAL ACTIVITY"
        desc = f"{severe_n} severe alert(s) live · containment recommended"
    elif moderate_n:
        cls, label = "tc-mod", "THREATCON 2 — ELEVATED"
        desc = f"{moderate_n} suspicious flow(s) under watch"
    else:
        cls, label = "tc-ok", "THREATCON 3 — NOMINAL"
        desc = "all monitored flows within behavioral baseline"
    st.markdown(
        f'<div class="threat-cond {cls}" role="status">'
        f'<span class="tc-light"></span>'
        f'<span class="tc-label">{label}</span>'
        f'<span class="tc-desc">{desc}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


def render_kill_chain(logs_df: pd.DataFrame, blocked_ips: set) -> None:
    """Kill-chain strip: stages lit by observed profiles; the earliest stage
    whose source IP got blocked shows where the engine severed the chain, and
    everything downstream of the cut is dimmed."""
    stage_hits: dict[int, set] = {i: set() for i in range(4)}
    for _, r in logs_df.iterrows():
        s = _kc_stage_of(r.get("Traffic Profile", ""))
        if s is not None and "Baseline" not in str(r.get("Threat Level", "")):
            stage_hits[s].add(str(r.get("Source IP", "")))
    broken_at = None
    for i in range(4):
        if stage_hits[i] & blocked_ips:
            broken_at = i
            break
    cells = []
    for i, (name, sub) in enumerate(_KC_STAGES):
        cls, badge = "kc-stage", ""
        if broken_at is not None and i == broken_at:
            cls += " kc-broken"
            badge = '<div class="kc-badge">CHAIN BROKEN</div>'
        elif broken_at is not None and i > broken_at:
            cls += " kc-dim"
        elif stage_hits[i]:
            cls += " kc-on"
        cells.append(
            f'<div class="{cls}">{badge}'
            f'<div class="kc-name">{name}</div>'
            f'<div class="kc-sub">{sub} · {len(stage_hits[i])} src</div>'
            f'</div>'
        )
        if i < 3:
            cells.append('<div class="kc-arrow">›</div>')
    st.markdown(
        '<p class="threat-header" style="margin-top:14px;">Cyber Kill Chain</p>'
        f'<div class="killchain">{"".join(cells)}</div>',
        unsafe_allow_html=True,
    )


def render_soc_scoreboard(packets_dropped: int, threats_neutralized: int,
                          intel_tags: int, deflection_pct: int) -> None:
    """Gamified deflection scoreboard. Numbers count up on paint; the
    animation runs entirely inside this iframe."""
    cells = [
        ("PACKETS DROPPED", packets_dropped, "", "#F0795A", "deflected at the firewall"),
        ("THREATS NEUTRALIZED", threats_neutralized, "", "#97C0A4", "sources blocked + expiring"),
        ("INTEL TAGS APPLIED", intel_tags, "", "#E0B65C", "MITRE ATT&amp;CK mappings"),
        ("DEFLECTION RATE", deflection_pct, "%", "#97C0A4", "severe sources contained"),
    ]
    cell_html = "".join(
        f"<div class='cell'><div class='k'>{k}</div>"
        f"<div class='v' style='color:{color};' data-target='{v}' data-suffix='{suf}'>0{suf}</div>"
        f"<div class='s'>{s}</div></div>"
        for k, v, suf, color, s in cells
    )
    page = (
        "<!DOCTYPE html><html><head><style>" + _MONO_IMPORT + """
        * { box-sizing: border-box; }
        body { margin: 0; background: #141413; font-family: 'Inter', 'Segoe UI', sans-serif; }
        .board { display: flex; gap: 10px; }
        .cell {
            flex: 1; background: #1E1D1B; border: 1px solid #2B2A28;
            border-radius: 14px; padding: 14px 18px; min-width: 0;
        }
        .k { font-size: 10.5px; color: #8E8C84; font-weight: 600;
             letter-spacing: 0.09em; }
        .v { font-family: 'JetBrains Mono', monospace; font-size: 30px;
             font-weight: 700; margin-top: 4px; }
        .s { font-size: 10.5px; color: #6E6D66; margin-top: 2px; }
        </style></head><body>
        <div class='board'>""" + cell_html + """</div>
        <script>
        document.querySelectorAll('[data-target]').forEach(el => {
            const target = +el.dataset.target, suf = el.dataset.suffix || '';
            const t0 = performance.now(), dur = 1100;
            (function tick(t) {
                const p = Math.min((t - t0) / dur, 1);
                const ease = 1 - Math.pow(1 - p, 3);
                el.textContent = Math.round(target * ease).toLocaleString() + suf;
                if (p < 1) requestAnimationFrame(tick);
            })(t0);
        });
        </script></body></html>"""
    )
    components.html(page, height=110)


def _build_ticker_events(logs_df: pd.DataFrame, blocked_df: pd.DataFrame) -> list:
    """Assemble (css-class, text) ticker entries from blocks, alerts and
    MITRE tags. Severe first so the loudest events lead the crawl."""
    events = []
    if not blocked_df.empty:
        for ip in blocked_df["Source IP"].head(6):
            events.append(("sev", f"[BLOCKED] {ip}"))
    has_mitre = "ATT&CK ID" in logs_df.columns
    ok_quota = 4
    for _, r in logs_df.head(40).iterrows():
        lvl = str(r.get("Threat Level", ""))
        ip = r.get("Source IP", "?")
        prof = r.get("Traffic Profile", "flow")
        if "Severe" in lvl:
            events.append(("sev", f"[ALERT] {prof} :: {ip}"))
        elif "Moderate" in lvl:
            events.append(("warn", f"[FLAG] {prof} :: {ip}"))
        elif ok_quota > 0:
            events.append(("ok", f"[OK] baseline :: {ip}"))
            ok_quota -= 1
        tid = r.get("ATT&CK ID") if has_mitre else None
        if tid is not None and pd.notna(tid) and str(tid) not in ("", "N/A"):
            name = str(r.get("ATT&CK Technique", ""))[:28]
            events.append(("warn", f"[TAGGED] MITRE {tid} {name}"))
    if not events:
        events.append(("ok", "[IDLE] no events logged yet — engine listening"))
    return events[:26]


def render_event_ticker(events: list) -> None:
    """Terminal-style live event ticker. The marquee animation is strictly
    scoped to this iframe — the parent page is never touched."""
    crawl = " <span class='sep'>//</span> ".join(
        f"<span class='{cls}'>{_html.escape(txt)}</span>" for cls, txt in events
    ) + " <span class='sep'>//</span> "
    dur = max(22, len(events) * 3)
    page = (
        "<!DOCTYPE html><html><head><style>" + _MONO_IMPORT + """
        body { margin: 0; background: #141413; }
        .wrap {
            display: flex; align-items: center; height: 44px;
            background: #1A1918; border: 1px solid #2B2A28; border-radius: 10px;
            overflow: hidden; font-family: 'JetBrains Mono', monospace;
        }
        .live {
            flex: none; display: flex; align-items: center; gap: 7px;
            padding: 0 14px; height: 100%; border-right: 1px solid #2B2A28;
            color: #F0795A; font-size: 11px; font-weight: 700; letter-spacing: 0.12em;
        }
        .live .dot { width: 7px; height: 7px; border-radius: 50%;
                     background: #F0795A; animation: blink 1s steps(2) infinite; }
        @keyframes blink { 50% { opacity: 0.25; } }
        .belt { flex: 1; overflow: hidden; white-space: nowrap; }
        .track { display: inline-block; white-space: nowrap; font-size: 12.5px;
                 animation: crawl __DUR__s linear infinite; }
        @keyframes crawl { from { transform: translateX(0); }
                           to   { transform: translateX(-50%); } }
        .ok   { color: #97C0A4; }
        .warn { color: #E0B65C; }
        .sev  { color: #F0795A; font-weight: 600; }
        .sep  { color: #55534E; }
        </style></head><body>
        <div class='wrap'>
            <div class='live'><span class='dot'></span>LIVE</div>
            <div class='belt'><div class='track'>
                <span>__CRAWL__</span><span>__CRAWL__</span>
            </div></div>
        </div></body></html>"""
    ).replace("__DUR__", str(dur)).replace("__CRAWL__", crawl)
    components.html(page, height=52)


def _pseudo_payload(profile: str, rng: random.Random) -> bytes:
    """Synthetic payload bytes themed to the detected profile so the hex dump
    reads like the attack it represents."""
    p = str(profile).lower()
    if "brute" in p or "force" in p or "sustained" in p:
        txt = (b"USER admin\r\nPASS p@ssw0rd!\r\n530 Login incorrect.\r\n"
               b"USER root\r\nPASS toor123\r\n530 Login incorrect.\r\n")
    elif "scan" in p or "recon" in p or "probe" in p:
        txt = bytes(rng.choice((0, 0, 0, 2, 16, 0)) for _ in range(72))
    elif "c2" in p or "beacon" in p:
        alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        txt = (b"POST /sync HTTP/1.1\r\nX-Session: "
               + bytes(rng.choice(alpha) for _ in range(40)) + b"\r\n\r\n")
    elif "flood" in p or "ddos" in p:
        txt = b"\x02\x04\x05\xb4\x01\x01\x04\x02" * 12   # bare SYN options, no data
    else:
        txt = (b"GET /index.html HTTP/1.1\r\nHost: intranet.local\r\n"
               b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
    pad = bytes(rng.randrange(256) for _ in range(max(0, 96 - len(txt))))
    return (txt + pad)[:160]


def _pseudo_packet_bytes(src_ip, dst_ip, port, profile, seed: str):
    """Deterministic Wireshark-style frame: the real header fields (IPs, port)
    are woven into synthetic bytes, so the same alert always renders the same
    dump. Returns (bytes, header_length)."""
    rng = random.Random(hashlib.md5(seed.encode()).hexdigest())

    def ip4(ip):
        parts = str(ip).split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return [int(p) & 0xFF for p in parts]
        return list(hashlib.md5(str(ip).encode()).digest()[:4])   # v6 / hostname

    try:
        dport = int(float(port))
    except (TypeError, ValueError):
        dport = 443
    hdr = [rng.randrange(256) for _ in range(12)] + [0x08, 0x00]            # eth
    hdr += [0x45, 0x00, 0x00, 0xA8, rng.randrange(256), rng.randrange(256),
            0x40, 0x00, 0x40, 0x06, rng.randrange(256), rng.randrange(256)]  # ipv4
    hdr += ip4(src_ip) + ip4(dst_ip)
    sport = rng.randrange(49152, 65535)
    hdr += [sport >> 8, sport & 0xFF, (dport >> 8) & 0xFF, dport & 0xFF]     # tcp
    hdr += [rng.randrange(256) for _ in range(16)]                           # seq/ack/flags
    return bytes(hdr) + _pseudo_payload(profile, rng), len(hdr)


def render_hex_inspector(seed: str, src_ip, dst_ip, port, profile, verdict,
                         meta: dict, mitre: dict | None, attrib: list) -> None:
    """Wireshark-style triage view: hex dump on the left; flow metadata, the
    MITRE ATT&CK mapping and SHAP-style feature attribution on the right.
    Fully self-contained iframe — no parent-DOM access."""
    data, hdr_len = _pseudo_packet_bytes(src_ip, dst_ip, port, profile, seed)
    v = str(verdict)
    pl_color = "#F0795A" if "Severe" in v else ("#E0B65C" if "Moderate" in v else "#97C0A4")

    rows = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexes = " ".join(
            f"<span class='{'hd' if off + j < hdr_len else 'pl'}'>{b:02x}</span>"
            for j, b in enumerate(chunk)
        )
        ascii_col = "".join(
            _html.escape(chr(b)) if 32 <= b < 127 else "<i>·</i>" for b in chunk
        )
        rows.append(
            f"<div class='row'><span class='off'>{off:04x}</span>"
            f"<span class='hex'>{hexes}</span>"
            f"<span class='asc'>{ascii_col}</span></div>"
        )

    meta_html = "".join(
        f"<div class='mrow'><span class='mk'>{_html.escape(str(k))}</span>"
        f"<span class='mv'>{_html.escape(str(val))}</span></div>"
        for k, val in meta.items()
    )

    if mitre:
        link = (f"<a href='{mitre['url']}' target='_blank'>{mitre['id']}</a>"
                if mitre.get("url") else mitre["id"])
        mitre_html = (
            "<div class='card' style='border-left:3px solid " + mitre["color"] + ";'>"
            "<div class='ct'>MITRE ATT&amp;CK — Aaron</div>"
            f"<div class='mid' style='color:{mitre['color']};'>{link}"
            f" <span class='msub'>{_html.escape(str(mitre['sub']))}</span></div>"
            f"<div class='mname'>{_html.escape(str(mitre['name']))}</div>"
            f"<div class='mtac'>Tactic: {_html.escape(str(mitre['tactic']))}</div>"
            "</div>"
        )
    else:
        mitre_html = ("<div class='card'><div class='ct'>MITRE ATT&amp;CK — Aaron</div>"
                      "<div class='mname'>No technique mapped for this flow.</div></div>")

    bars = []
    for label, val in attrib:
        w = min(100, abs(val) * 100)
        color = "#F0795A" if val >= 0 else "#97C0A4"
        sign = "↑ threat" if val >= 0 else "↓ benign"
        bars.append(
            f"<div class='arow'><span class='al'>{_html.escape(str(label))}</span>"
            f"<span class='abar'><span style='width:{w:.0f}%;background:{color};'></span></span>"
            f"<span class='av' style='color:{color};'>{sign}</span></div>"
        )
    attrib_html = (
        "<div class='card'><div class='ct'>Feature Attribution — SHAP-style (Megan)</div>"
        + "".join(bars)
        + "<div class='note'>Full SHAP waterfall lives in the Model Intelligence tab.</div></div>"
    )

    page = (
        "<!DOCTYPE html><html><head><style>" + _MONO_IMPORT + """
        * { box-sizing: border-box; }
        body { margin: 0; background: #141413; color: #C9C7BE;
               font-family: 'Inter', 'Segoe UI', sans-serif; }
        .grid { display: grid; grid-template-columns: 1.3fr 1fr; gap: 12px; }
        .dump {
            background: #1A1918; border: 1px solid #2B2A28; border-radius: 12px;
            padding: 12px 14px; font-family: 'JetBrains Mono', monospace;
            font-size: 12px; line-height: 1.75; overflow-x: auto;
        }
        .dump .row { white-space: nowrap; }
        .off { color: #6E6D66; margin-right: 14px; }
        .hex .hd { color: #C9C7BE; }
        .hex .pl { color: __PL__; }
        .asc { color: #8E8C84; margin-left: 16px; letter-spacing: 0.08em; }
        .asc i { color: #44423E; font-style: normal; }
        .card {
            background: #1E1D1B; border: 1px solid #2B2A28; border-radius: 12px;
            padding: 10px 14px; margin-bottom: 10px;
        }
        .ct { font-size: 10px; color: #8E8C84; font-weight: 700;
              letter-spacing: 0.09em; margin-bottom: 7px; }
        .mrow { display: flex; justify-content: space-between; gap: 10px;
                font-size: 12px; padding: 2.5px 0; }
        .mk { color: #8E8C84; }
        .mv { color: #E8E6DE; font-family: 'JetBrains Mono', monospace;
              text-align: right; word-break: break-all; }
        .mid { font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 14px; }
        .mid a { color: inherit; text-decoration: none; border-bottom: 1px dotted; }
        .msub { color: #8E8C84; font-weight: 400; font-size: 11px; }
        .mname { font-size: 12.5px; color: #E8E6DE; margin-top: 3px; }
        .mtac { font-size: 11px; color: #8E8C84; margin-top: 2px; }
        .arow { display: flex; align-items: center; gap: 8px; padding: 3px 0; font-size: 11.5px; }
        .al { width: 128px; color: #C9C7BE; font-family: 'JetBrains Mono', monospace; flex: none; }
        .abar { flex: 1; height: 8px; background: #141413; border-radius: 999px;
                overflow: hidden; border: 1px solid #2B2A28; }
        .abar span { display: block; height: 100%; border-radius: 999px; }
        .av { width: 64px; text-align: right; font-size: 10.5px; flex: none; }
        .note { font-size: 10.5px; color: #6E6D66; margin-top: 7px; }
        ::-webkit-scrollbar { height: 8px; width: 8px; }
        ::-webkit-scrollbar-thumb { background: #2E2D2A; border-radius: 999px; }
        </style></head><body>
        <div class='grid'>
            <div class='dump'>__ROWS__</div>
            <div>
                <div class='card'><div class='ct'>Flow Metadata</div>__META__</div>
                __MITRE__
                __ATTRIB__
            </div>
        </div></body></html>"""
    ).replace("__PL__", pl_color).replace("__ROWS__", "".join(rows)) \
     .replace("__META__", meta_html).replace("__MITRE__", mitre_html) \
     .replace("__ATTRIB__", attrib_html)
    components.html(page, height=470, scrolling=True)


def _rf_attrib_from_row(row) -> list:
    """Lightweight SHAP-style attribution: each engineered feature scored
    against the live_backend thresholds, signed toward threat (+) or benign (−)."""
    def num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    clamp = lambda x: max(-1.0, min(1.0, x))
    pps = num(row.get("Packets/Sec"))
    sar = num(row.get("SYN/ACK Ratio"))
    avgw = num(row.get("Avg Window"))
    tb = num(row.get("Total Bytes"))
    return [
        ("packets_per_sec", clamp(pps / 500.0)),
        ("syn_ack_ratio", clamp((sar - 1.0) / 4.0)),
        ("avg_window_size", clamp(-(avgw / 1500.0))),
        ("total_bytes", clamp(tb / 2_000_000.0)),
    ]


_SEV_RANK = {"Baseline": 0, "Moderate": 1, "Severe": 2}


def _sev_bucket(verdict: str) -> str:
    """Collapse a full threat label to its severity bucket name."""
    v = str(verdict)
    if "Severe" in v:
        return "Severe"
    if "Moderate" in v:
        return "Moderate"
    if "Baseline" in v:
        return "Baseline"
    return ""


def _sev_palette(verdict: str) -> tuple[str, str]:
    """(background, foreground) for a verdict — matches highlight_threat_row."""
    bucket = _sev_bucket(verdict)
    return {
        "Severe":   ("#3A201A", "#F0A48E"),
        "Moderate": ("#352B14", "#E0B65C"),
        "Baseline": ("#1D2B20", "#97C0A4"),
    }.get(bucket, ("#1E1D1B", "#BCB9AE"))


def render_detection_rationale(row) -> None:
    """Explain *why* a flow got its severity by showing each detection layer's
    verdict and marking the one(s) that decided the fused result.

    Reads the per-layer signals persisted by live_backend.write_alerts
    (sig_heuristic / sig_rf / sig_slow / sig_dns / sig_lstm / sig_intel /
    sig_baseline). Caller gates on their presence; nothing here assumes a fresh
    schema beyond that — sig_lstm in particular is absent from DBs written by a
    pre-LSTM backend, so its row is only added when the column came through.
    """
    def _val(key, default="—"):
        v = row.get(key)
        if v is None or (isinstance(v, float) and pd.isna(v)):
            return default
        return v

    def _flag(key):
        try:
            return int(float(_val(key, 0)))
        except (TypeError, ValueError):
            return 0

    final = str(row.get("Threat Level", "—"))
    final_bucket = _sev_bucket(final)
    intel_hit = _flag("Sig Intel") == 1
    baseline_hit = _flag("Sig Baseline") == 1

    # Layers in evaluation order. (label, verdict-text, is-an-override-flag)
    layers = [
        ("Signature heuristics", str(_val("Sig Heuristic")), False),
        ("Random Forest (ML)",   str(_val("Sig RF")),        False),
        ("Rolling-window (slow attack)", str(_val("Sig Slow")), False),
        ("DNS-tunnel detector",  str(_val("Sig DNS")),       False),
    ]
    # The LSTM's raw verdict is logged uncapped; live_backend caps what it may
    # contribute to the fused level (apply_lstm_cap), so a Severe here can
    # legitimately not be the deciding layer.
    if "Sig LSTM" in row.index:
        layers.append(("LSTM sequence model", str(_val("Sig LSTM")), False))
    layers += [
        ("Threat-intel feed",
         "Match — forces Severe" if intel_hit else "No match", intel_hit),
        ("Baseline whitelist",
         "Match — forces Baseline" if baseline_hit else "No match", baseline_hit),
    ]

    rows_html = []
    for label, verdict, is_override in layers:
        # Decide which layer(s) drove the final verdict. Overrides win outright;
        # otherwise a behavioral layer "decides" when its bucket equals the fused
        # final bucket (and intel/baseline did not override).
        if intel_hit:
            decided = (label == "Threat-intel feed")
        elif baseline_hit:
            decided = (label == "Baseline whitelist")
        else:
            decided = (not is_override) and _sev_bucket(verdict) == final_bucket \
                and final_bucket != ""
        bg, fg = _sev_palette(verdict if not is_override else final) if (
            is_override and (intel_hit or baseline_hit)
        ) else _sev_palette(verdict)
        mark = ("<span style='color:#D97757;font-weight:700'>&#9656; decided</span>"
                if decided else "")
        rows_html.append(
            f"<tr>"
            f"<td style='padding:6px 12px;color:#BCB9AE'>{_html.escape(label)}</td>"
            f"<td style='padding:6px 12px;background:{bg};color:{fg};"
            f"border-radius:4px;font-weight:600'>{_html.escape(verdict)}</td>"
            f"<td style='padding:6px 12px'>{mark}</td>"
            f"</tr>"
        )

    st.markdown('<p class="threat-header">Detection rationale — why this verdict</p>',
                unsafe_allow_html=True)
    st.markdown(
        "<table style='border-collapse:separate;border-spacing:0 4px;width:100%'>"
        "<tr><th style='text-align:left;padding:4px 12px;color:#7C7A70'>Layer</th>"
        "<th style='text-align:left;padding:4px 12px;color:#7C7A70'>Verdict</th>"
        "<th></th></tr>"
        + "".join(rows_html) + "</table>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Final threat level **{final}** = highest-severity layer "
        "(threat-intel and whitelist override the fused result)."
    )


def render_threat_report(row) -> None:
    """Threat Analysis Report — the FYP "Threat Level Hunting" enhancement.

    Turns the bare verdict into the report the brief asks for: a 0-100 Threat
    Score, its risk band, the *reasons* that produced it, and the *suggested
    actions*, plus the component breakdown behind the number. Reads only the
    columns the backend persists (Threat Score / Risk Band / Score Reasons /
    Score Actions / Score Breakdown); caller gates on their presence.
    """
    raw_score = row.get("Threat Score")
    if raw_score is None or (isinstance(raw_score, float) and pd.isna(raw_score)):
        return
    score = int(float(raw_score))
    band = str(row.get("Risk Band", "—"))
    reasons = [r for r in str(row.get("Score Reasons", "") or "").split(" | ") if r]
    actions = [a for a in str(row.get("Score Actions", "") or "").split(" | ") if a]
    try:
        breakdown = json.loads(row.get("Score Breakdown") or "{}")
    except (TypeError, ValueError):
        breakdown = {}

    band_color = {
        "Normal": "#97C0A4", "Low": "#9FC08A", "Medium": "#E0B65C",
        "High": "#F0A063", "Critical": "#F0795A",
    }.get(band, "#C9C7BE")

    st.markdown('<p class="threat-header">Threat Analysis Report</p>',
                unsafe_allow_html=True)
    pct = max(0, min(100, score))
    st.markdown(
        "<div style='display:flex;align-items:baseline;gap:12px;margin-bottom:6px'>"
        f"<span style='font-size:40px;font-weight:800;color:{band_color};"
        f"font-family:JetBrains Mono,monospace;line-height:1'>{score}</span>"
        "<span style='color:#7C7A70'>/ 100</span>"
        f"<span style='font-size:14px;font-weight:700;color:{band_color};"
        f"letter-spacing:.06em'>{band.upper()}</span></div>"
        "<div style='height:10px;border-radius:6px;background:#2B2A28;overflow:hidden'>"
        f"<div style='width:{pct}%;height:100%;background:{band_color}'></div></div>",
        unsafe_allow_html=True,
    )

    rc1, rc2 = st.columns(2)
    with rc1:
        st.markdown("**Possible reasons**")
        st.markdown("\n".join(f"- {r}" for r in reasons) if reasons else "- —")
    with rc2:
        st.markdown("**Suggested actions**")
        st.markdown("\n".join(f"- {a}" for a in actions) if actions else "- —")

    if breakdown:
        bdf = pd.DataFrame(list(breakdown.items()), columns=["Component", "Points"])
        st.caption("Score composition (severity + frequency + behaviour + "
                   "historical + confidence − false-positive reduction)")
        st.dataframe(bdf, hide_index=True, width="stretch", height=250)


def render_flow_detail(row) -> None:
    """Full drill-down for one selected flow row.

    The main table stays lean (a few columns); clicking a row expands the
    complete record here: every captured field, the full destination-port list,
    the per-protocol packet breakdown for that source IP, the MITRE technique
    card, and the raw hex inspector. Reuses render_hex_inspector and the
    protocol_breakdown table that already back the rest of the dashboard.
    """
    src_ip = str(row.get("Source IP", "—"))
    profile = str(row.get("Traffic Profile", "—"))
    verdict = str(row.get("Threat Level", "—"))

    st.markdown(
        f'<p class="threat-header">Flow Detail — {src_ip}</p>',
        unsafe_allow_html=True,
    )

    # Threat Analysis Report (0-100 score + reasons + actions) leads the panel
    # when the backend persisted a score; the field dump and rationale follow.
    if "Threat Score" in row.index:
        render_threat_report(row)
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Full field dump (everything we loaded for this row, minus internal keys
    # and the per-layer signals, which get their own rationale panel below).
    _skip = {"id", "Evidence Path", "Sig Heuristic", "Sig RF", "Sig Slow",
             "Sig DNS", "Sig LSTM", "Sig Intel", "Sig Baseline",
             "Threat Score", "Risk Band", "Score Reasons", "Score Actions",
             "Score Breakdown"}
    detail_items = [
        (str(k), "—" if pd.isna(v) else str(v))
        for k, v in row.items() if k not in _skip
    ]
    detail_tbl = pd.DataFrame(detail_items, columns=["Field", "Value"])
    dc1, dc2 = st.columns([1, 1])
    with dc1:
        st.dataframe(detail_tbl, hide_index=True, width="stretch", height=320)
    with dc2:
        # Per-(protocol) packet/byte breakdown for this source IP, summed across
        # all logged windows — same table the Per-Protocol Inspector reads.
        try:
            pb = pd.read_sql_query(
                "SELECT protocol AS Protocol, SUM(packets) AS Packets, "
                "SUM(bytes) AS Bytes FROM protocol_breakdown WHERE source_ip = ? "
                "GROUP BY protocol ORDER BY Packets DESC",
                _get_db_conn(), params=(src_ip,),
            )
        except Exception:
            pb = pd.DataFrame()
        st.caption("Protocol breakdown (all windows)")
        if pb.empty:
            st.info("No per-protocol counters logged for this source yet.")
        else:
            st.dataframe(pb, hide_index=True, width="stretch", height=200)
        _src_ports = str(row.get("Src Ports", "") or "").strip()
        if _src_ports:
            st.caption(f"Source ports seen: {_src_ports}")
        _ports = str(row.get("Ports", "") or "").strip()
        if _ports:
            st.caption(f"Destination ports seen: {_ports}")

    # Per-layer detection rationale (only when the backend persisted signals).
    if "Sig RF" in row.index:
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        render_detection_rationale(row)

    # Hex inspector — same synthetic-but-themed view used in alert triage.
    _meta = {
        "Timestamp": row.get("Time"),
        "Source IP": src_ip,
        "Source Port": row.get("Source Port", "—"),
        "Transport": row.get("Transport", "—"),
        "Dest Port": row.get("Dest Port", "—"),
        "Packets/Sec": row.get("Packets/Sec"),
        "SYN/ACK Ratio": row.get("SYN/ACK Ratio"),
        "Avg Window": row.get("Avg Window"),
        "Total Bytes": row.get("Total Bytes"),
        "Profile": profile,
        "Verdict": verdict,
    }
    if "Confidence (%)" in row.index and pd.notna(row.get("Confidence (%)")):
        _meta["Model Confidence"] = f"{row['Confidence (%)']}%"

    _mitre = None
    _tid = row.get("ATT&CK ID") if "ATT&CK ID" in row.index else None
    if _tid is not None and pd.notna(_tid) and str(_tid) not in ("", "N/A"):
        _tact = row.get("ATT&CK Tactic") or ""
        _sub = row.get("Sub-Technique")
        _mitre = {
            "id": _tid,
            "sub": _sub if (_sub and pd.notna(_sub)) else "—",
            "name": row.get("ATT&CK Technique") or "",
            "tactic": _tact,
            "color": tactic_color(_tact) if MITRE_OK and _tact else "#D97757",
            "url": mitre_url(_tid, _sub) if MITRE_OK else "",
        }

    try:
        _port = int(float(row.get("Dest Port") or 0)) or 443
    except (TypeError, ValueError):
        _port = 443
    with st.expander("Raw hex inspector", expanded=True):
        render_hex_inspector(
            seed=f"{src_ip}|{row.get('Time')}",
            src_ip=src_ip, dst_ip="10.0.0.21", port=_port,
            profile=profile, verdict=verdict,
            meta=_meta, mitre=_mitre, attrib=_rf_attrib_from_row(row),
        )
        st.caption(
            "Payload bytes are a deterministic synthetic reconstruction themed "
            "to the detected profile — header fields carry the real source IP, "
            "transport, port and verdict."
        )


def _theme_plotly(fig):
    """Warm-dark Anthropic styling for plotly figures (charcoal/cream).

    Setting title_font alone (without title.text) left the title's text
    unset; the Plotly.js rendering path then coerced that missing value to
    the literal string "undefined" and displayed it as the chart's title.
    Explicitly carrying the existing text (or "" if there wasn't one)
    through title= avoids ever leaving text unset.
    """
    fig.update_layout(
        paper_bgcolor="#1A1918", plot_bgcolor="#1A1918",
        font=dict(family="Inter, sans-serif", color="#C9C7BE"),
        title=dict(
            text=fig.layout.title.text or "",
            font=dict(family="Source Serif 4, Georgia, serif", color="#FAF9F5"),
        ),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor="#2B2A28", zerolinecolor="#2B2A28")
    fig.update_yaxes(gridcolor="#2B2A28", zerolinecolor="#2B2A28")
    return fig


def _backfill_mitre(conn: sqlite3.Connection) -> None:
    """Back-fill MITRE columns on rows written before this upgrade.

    Tags at most 500 untagged rows per call so a large legacy DB doesn't stall
    the first dashboard paint. Safe to re-run; only touches rows where
    mitre_technique_id IS NULL.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT id, traffic_profile FROM live_threat_logs "
        "WHERE mitre_technique_id IS NULL LIMIT 500"
    )
    rows = cur.fetchall()
    if not rows:
        return
    updates = []
    for row_id, profile in rows:
        tid, sub, name, tactic, tac_id = tag_mitre(profile or "")
        updates.append((tid, sub, name, tactic, tac_id, row_id))
    cur.executemany(
        "UPDATE live_threat_logs SET mitre_technique_id=?, mitre_sub_technique_id=?, "
        "mitre_technique_name=?, mitre_tactic=?, mitre_tactic_id=? WHERE id=?",
        updates,
    )
    conn.commit()


def load_threat_logs():
    """Read recent threat logs.

    Returns a ``(DataFrame, error)`` tuple. ``error`` is ``None`` on success and
    a human-readable string on failure, so the UI can tell a genuine DB/connection
    fault apart from a healthy-but-empty database (the two must look different).

    The selected columns adapt to the live schema: confidence, evidence_path,
    and the MITRE ATT&CK columns are included only when the backend has migrated
    them in, so an older database (or one written by a pre-MITRE backend) still
    loads cleanly. ``id`` is always selected as an internal key and hidden from
    the visible table by the caller.
    """
    try:
        conn = sqlite3.connect('ids_logs.db', timeout=15)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(live_threat_logs)")
        existing_cols = [row[1] for row in cursor.fetchall()]

        has_confidence = 'confidence' in existing_cols
        has_evidence = 'evidence_path' in existing_cols
        has_mitre = 'mitre_technique_id' in existing_cols
        has_ports = 'dominant_transport' in existing_cols
        has_src_ports = 'top_source_port' in existing_cols
        has_signals = 'sig_rf' in existing_cols
        # sig_lstm arrived after the other five, so a DB written by an older
        # backend has the signals block but not this column — gate it separately.
        has_lstm_sig = 'sig_lstm' in existing_cols
        has_score = 'threat_score' in existing_cols

        conf_col = 'ROUND(confidence * 100, 1) AS "Confidence (%)",' if has_confidence else ""
        evid_col = 'evidence_path AS "Evidence Path",' if has_evidence else ""
        ports_cols = (
            'dominant_transport AS "Transport",'
            'top_dest_port      AS "Dest Port",'
            'dest_ports         AS "Ports",'
        ) if has_ports else ""
        # Source port mirrors dest: modal port + the unique-port list. Gated on
        # its own column so a pre-source-port DB still loads cleanly.
        src_port_cols = (
            'top_source_port AS "Source Port",'
            'source_ports    AS "Src Ports",'
        ) if has_src_ports else ""
        mitre_cols = (
            'mitre_technique_id     AS "ATT&CK ID",'
            'mitre_sub_technique_id AS "Sub-Technique",'
            'mitre_technique_name   AS "ATT&CK Technique",'
            'mitre_tactic           AS "ATT&CK Tactic",'
            'mitre_tactic_id        AS "Tactic ID",'
        ) if has_mitre else ""
        # Per-layer detection signals power the "why was this flagged" rationale
        # in the flow drill-down. Gated so a pre-signals DB still loads.
        sig_cols = (
            'sig_heuristic AS "Sig Heuristic",'
            'sig_rf        AS "Sig RF",'
            'sig_slow      AS "Sig Slow",'
            'sig_dns       AS "Sig DNS",'
            + ('sig_lstm AS "Sig LSTM",' if has_lstm_sig else "") +
            'sig_intel     AS "Sig Intel",'
            'sig_baseline  AS "Sig Baseline",'
        ) if has_signals else ""
        # Threat Scoring enhancement columns power the Threat Analysis Report in
        # the flow drill-down. Gated so a pre-scoring DB still loads cleanly.
        score_cols = (
            'threat_score     AS "Threat Score",'
            'score_band       AS "Risk Band",'
            'threat_reasons   AS "Score Reasons",'
            'threat_actions   AS "Score Actions",'
            'threat_breakdown AS "Score Breakdown",'
        ) if has_score else ""

        # Back-fill older rows that pre-date MITRE tagging so the panel isn't blank.
        if has_mitre and MITRE_OK:
            _backfill_mitre(conn)

        query = f"""
            SELECT timestamp        AS "Time",
                   source_ip        AS "Source IP",
                   {src_port_cols}
                   packets_per_sec  AS "Packets/Sec",
                   avg_window_size  AS "Avg Window",
                   syn_ack_ratio    AS "SYN/ACK Ratio",
                   total_bytes      AS "Total Bytes",
                   traffic_profile  AS "Traffic Profile",
                   threat_level     AS "Threat Level",
                   {ports_cols}
                   {conf_col}
                   {evid_col}
                   {mitre_cols}
                   {sig_cols}
                   {score_cols}
                   id
            FROM live_threat_logs
            ORDER BY id DESC
            LIMIT 500
        """

        df = pd.read_sql_query(query, conn)
        conn.close()
        return df, None
    except Exception as exc:
        return pd.DataFrame(), str(exc)


def detection_engine_status():
    if os.path.exists("rf_model.pkl"):
        return "Hybrid (Behavioral ML + Signature Rules)"
    if os.path.exists("advanced_kmeans_model.pkl"):
        return "Hybrid (Anomaly Clustering + Signature Rules)"
    return "Signature Rules Only"


def highlight_threat_row(row):
    threat = str(row.get("Threat Level", ""))
    base = [""] * len(row)
    idx = row.index.tolist().index("Threat Level") if "Threat Level" in row.index else -1
    if idx == -1:
        return base
    if "Severe" in threat:
        base[idx] = "background-color: #3A201A; color: #F0A48E; font-weight: bold"
    elif "Moderate" in threat:
        base[idx] = "background-color: #352B14; color: #E0B65C; font-weight: bold"
    elif "Baseline" in threat:
        base[idx] = "background-color: #1D2B20; color: #97C0A4"
    return base


st.markdown(
    """
    <div class="hero">
        <div style="display:flex;align-items:baseline;">
            <span class="title">Hybrid Intrusion Detection System</span>
        </div>
        <div class="sub">Real-time network behavioral analysis &mdash; hybrid signature
        and machine-learning detection across IPv4 and IPv6.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Interactive FX layer (lightweight) ───────────────────────────────────────
# st.markdown strips <script>, so the effects bundle rides in a zero-height
# component iframe (same-origin srcdoc) and decorates the PARENT page. Trimmed
# for the desktop app: only the one-shot decode-glitch hero title + terminal-
# typed subtitle remain. The particle field, cursor-tracking effects (ghost
# cursor, spotlight, magnetic buttons) and scroll parallax were removed because
# their per-mousemove / continuous rAF work caused noticeable UI lag. Runs once
# per page load (flag on window.parent).
_FX_JS = """
<script>
(function () {
  /* Collapse this script-carrier iframe's slot out of the page flow first
     (runs on every reload, before the run-once guard). */
  try {
    const fe = window.frameElement;
    if (fe) {
      const slot = fe.closest('[data-testid="stElementContainer"]') || fe.parentElement;
      slot.style.cssText += ';position:absolute;opacity:0;width:1px;height:1px;' +
                            'overflow:hidden;pointer-events:none;margin:0;padding:0;';
    }
  } catch (err) {}

  const P = window.parent, D = P.document;
  if (P.__idsFx) return;
  P.__idsFx = true;

  /* Lightweight one-shot hero reveal only. The particle field, cursor-
     tracking effects (ghost cursor, spotlight, magnetic buttons) and all
     continuous animation loops were removed — they caused UI lag. */
  /* ── Hero: decode-glitch title + terminal-typed subtitle ── */
  const GLYPHS = '!<>-_\\\\/[]{}=+*^?#01';
  function decode(el, text) {
    if (!el || el.__busy) return;
    el.__busy = true;
    const total = 26;
    let frame = 0;
    const timer = P.setInterval(() => {
      frame++;
      const reveal = Math.floor((frame / total) * text.length);
      let out = text.slice(0, reveal);
      for (let i = reveal; i < text.length; i++) {
        out += text[i] === ' ' ? ' ' : GLYPHS[(Math.random() * GLYPHS.length) | 0];
      }
      el.textContent = out;
      if (frame >= total) {
        el.textContent = text;
        el.__busy = false;
        P.clearInterval(timer);
      }
    }, 26);
  }
  function typeIn(el, text) {
    if (!el) return;
    el.textContent = '';
    const caret = D.createElement('span');
    caret.textContent = '\\u258c';
    caret.style.color = '#D97757';
    caret.style.animation = 'idsBlink 1s steps(1) infinite';
    el.append(caret);
    let i = 0;
    const timer = P.setInterval(() => {
      caret.before(D.createTextNode(text[i]));
      i++;
      if (i >= text.length) {
        P.clearInterval(timer);
        P.setTimeout(() => caret.remove(), 2600);
      }
    }, 11);
  }
  const styleEl = D.createElement('style');
  styleEl.textContent = '@keyframes idsBlink { 50% { opacity: 0; } }';
  D.head.append(styleEl);

  let boundTitle = null;
  function bindHero(animate) {
    const t = D.querySelector('.hero .title');
    if (!t || t === boundTitle) return;
    boundTitle = t;
    const txt = t.textContent;
    t.addEventListener('mouseenter', () => decode(t, txt));
    if (animate) {
      decode(t, txt);
      const s = D.querySelector('.hero .sub');
      if (s) typeIn(s, s.textContent.replace(/\\s+/g, ' ').trim());
    }
  }
  P.setTimeout(() => bindHero(true), 350);
  /* Streamlit reruns rebuild the hero DOM — rebind hover (no replay) */
  new P.MutationObserver(() => bindHero(false)).observe(D.body, { childList: true, subtree: true });
})();
</script>
"""
# The heavy cursor/particle FX are already gone from this desktop build; only the
# one-shot hero text reveal remains. This toggle lets a user drop even that on
# very slow hardware. Declared here so the gate runs before the FX iframe injects.
_lite_mode = st.sidebar.checkbox(
    "Reduce animations",
    value=False,
    key="lite_mode",
    help="Turns off the one-shot hero title/subtitle animation. The heavy "
         "particle field and cursor effects have already been removed for speed.",
)
if not _lite_mode:
    components.html(_FX_JS, height=1)

# ── Re-openable welcome / help overlay ───────────────────────────────────────
# A modal the operator can pop open any time from the "How to use" button (not a
# one-time thing): forget what a section does, click it again. Plain Streamlit so
# it renders the same everywhere.
@st.dialog("Welcome — Hybrid IDS Dashboard", width="large")
def show_welcome_overlay():
    st.markdown(
        "A live **Intrusion Detection System**. The backend sniffs your network in "
        "2-second windows, scores every source IP with rules + a Random Forest, and "
        "logs a **threat level** you see here. *Live monitoring just re-reads that log "
        "every few seconds — the actual capture runs in `live_backend.py`.*"
    )
    g1, g2, g3, g4 = st.tabs(
        ["Severity", "Alert labels", "Investigate a hit", "The tabs"]
    )
    with g1:
        st.markdown(
            "- **Severe** — loud / high-impact (flood, aggressive scan, threat-intel IP).\n"
            "- **Moderate** — suspicious not critical (slow scan, sustained probe, bandwidth spike).\n"
            "- **Baseline** — normal traffic.\n\n"
            "**Important:** severity is mostly driven by **packets/sec**, so ordinary "
            "high-speed traffic — a **download, video stream, Windows Update, or CDN** "
            "(Google / AWS / your ISP) — can show as a **Severe “High-Volume Flood”** even "
            "though it's harmless. Always check *who* the source IP is before trusting a Severe."
        )
    with g2:
        st.markdown(
            "- **High-Volume Flood / DDoS SYN Flood** — very high pps. Real from an "
            "attacker; usually just a **big download/stream** from a CDN.\n"
            "- **Aggressive / Port Scan** — one source touching many ports.\n"
            "- **Slow Port Scan / Sustained SYN** — low rate, caught over ~30s. From "
            "`fe80::…` it's often your **own LAN device**.\n"
            "- **Bandwidth Spike / Speed Test** — large transfer, soft-flagged.\n"
            "- **Known Malicious IP (Threat Intel)** — an IP *you* added to the list in "
            "the **Defense Config** tab."
        )
    with g3:
        st.markdown(
            "1. In **Live SOC Dashboard**, click the alert's row in the telemetry table.\n"
            "2. The **Detection rationale** panel shows each layer's verdict and marks the "
            "one that decided the severity — so you see *why* it fired.\n"
            "3. Check the **Source IP**: `192.168.*`, `10.*`, `fe80::*` = your own network; "
            "a public IP resolving to Google / AWS / your ISP = almost certainly benign.\n"
            "4. If it's a real threat, use **Block IP** lower on the page."
        )
    with g4:
        st.markdown(
            "- **Live SOC Dashboard** — real-time alerts, telemetry, blocking.\n"
            "- **Educational Simulator** — safe sandbox to watch each attack type.\n"
            "- **PCAP Analysis** — upload a `.pcap` for offline forensics.\n"
            "- **Threat Map** — geolocate attacker IPs.\n"
            "- **Model Intelligence** — SHAP / LSTM / retraining.\n"
            "- **Defense Config** — manage the threat-intel & whitelist IPs and the notifier."
        )
    if st.button("Got it", type="primary", use_container_width=True):
        st.rerun()


_wc_spacer, _wc_btn = st.columns([5, 1])
with _wc_btn:
    if st.button("How to use", use_container_width=True, key="welcome_overlay_btn"):
        show_welcome_overlay()

# ── View navigation (lazy single-view render) ────────────────────────────────
# st.tabs builds EVERY tab body on every rerun (browser only hides the inactive
# ones), so all six heavy views rebuilt on each interaction / auto-refresh — the
# main source of UI lag. A segmented nav renders only the selected view.
_VIEWS = ["Live SOC Dashboard", "Educational Simulator", "PCAP Analysis",
          "Threat Map", "Model Intelligence", "Defense Config",
          "Detection Benchmark"]
_active = st.segmented_control(
    "View", _VIEWS, default=_VIEWS[0], key="_main_nav",
    label_visibility="collapsed",
)
if not _active:
    _active = _VIEWS[0]

# ── Monitoring Controls sidebar — rendered unconditionally on every view ─────
# (mirrors the old st.tabs behavior where tab1 ran every rerun). Defines
# enable_live / refresh_rate / severity_filter used by the Live view below.
st.sidebar.header("Monitoring Controls")
enable_live = st.sidebar.checkbox(
    "Enable Live Monitoring", value=True, key="enable_live_monitoring"
)
refresh_rate = st.sidebar.selectbox("Refresh Interval (seconds)", [2, 5, 10, 30], index=1)
severity_filter = st.sidebar.multiselect(
    "Show severity levels",
    options=["Severe", "Moderate", "Baseline"],
    default=["Severe", "Moderate", "Baseline"],
    key="sev_filter",
)
st.sidebar.markdown("---")
status_class = "status-online" if enable_live else "status-paused"
status_text = "MONITORING" if enable_live else "PAUSED"
dot_class = "on" if enable_live else "off"
st.sidebar.markdown(
    f'<span class="status-pill {status_class}">'
    f'<span class="pulse-dot {dot_class}"></span>{status_text}</span>',
    unsafe_allow_html=True,
)
st.sidebar.caption(f"Detection Engine: {detection_engine_status()}")

# ── Capture interface ─────────────────────────────────────────────────────
# Which adapter the engine listens on. Saved to capture_config in ids_logs.db;
# live_backend re-reads it each window, so a change applies without restarting
# the capture loop.
#
# This exists because auto-detect resolves the DEFAULT-ROUTE adapter, and test
# traffic frequently is not on it: attacking from a VM puts packets on a VMnet
# adapter, attacking localhost puts them on the Npcap loopback adapter, and an
# active VPN moves the default route off the real NIC. The engine then captures
# a quiet interface and logs "no packets in window" while the attack is running
# — which reads exactly like a broken detector. It matters most here: the frozen
# launcher calls run_live(interface=None) and has no command line to override.
st.sidebar.markdown("---")
st.sidebar.markdown("**Capture Interface**")
_ifaces = _list_capture_interfaces()
_cur_iface = _read_capture_interface()
_AUTO_LABEL = "Auto-detect (default route)"

if not _ifaces:
    st.sidebar.caption(
        "tshark could not list interfaces — check the Wireshark install. "
        "The engine falls back to auto-detect."
    )
else:
    _labels = [_AUTO_LABEL] + [f"#{i} — {n}" for i, n in _ifaces]
    _iface_by_label = {f"#{i} — {n}": i for i, n in _ifaces}
    # A pinned index whose adapter has since disappeared (VM shut down, VPN
    # dropped) must still appear, or the box would silently read "Auto" while
    # the engine is still pinned to a missing interface.
    if _cur_iface and _cur_iface not in [i for i, _ in _ifaces]:
        _gone = f"#{_cur_iface} — (adapter not present)"
        _labels.append(_gone)
        _iface_by_label[_gone] = _cur_iface
    _sel = 0
    if _cur_iface:
        for _pos, _lab in enumerate(_labels):
            if _iface_by_label.get(_lab) == _cur_iface:
                _sel = _pos
                break
    _iface_choice = st.sidebar.selectbox(
        "Listen on", _labels, index=_sel, key="iface_select",
        help=(
            "The network adapter packets are captured from. Auto-detect picks "
            "whichever adapter carries the default route — correct for internet "
            "traffic, wrong for a VM, a second NIC, or a localhost test. Pick "
            "the loopback adapter to detect attacks against 127.0.0.1. Applies "
            "to the NEXT capture window."
        ),
    )
    if st.sidebar.button("Apply interface", key="iface_save",
                         use_container_width=True):
        _cur_iface = _iface_by_label.get(_iface_choice, "")
        _write_capture_interface(_cur_iface)
        st.sidebar.success("Capture interface saved — next window.")

if _cur_iface:
    _pinned_name = dict(_ifaces).get(_cur_iface, "adapter not present")
    st.sidebar.caption(f"Pinned: #{_cur_iface} — {_pinned_name}")
else:
    st.sidebar.caption("Auto-detecting the default-route adapter.")

# ── Capture filter (BPF) ──────────────────────────────────────────────────
# Wireshark-style CAPTURE filter: a libpcap/BPF expression saved to
# capture_config in ids_logs.db. live_backend.py re-reads it each window and
# passes it to `tshark -f`, so it changes WHAT gets captured (not just what's
# shown). Takes effect on the next capture window — it is not retroactive.
st.sidebar.markdown("---")
st.sidebar.markdown("**Capture Filter (BPF)**")
_cur_bpf = _read_capture_filter()
_bpf_in = st.sidebar.text_input(
    "BPF expression",
    value=_cur_bpf,
    placeholder="e.g. tcp port 80 or udp",
    key="bpf_input",
    help=(
        "libpcap capture filter applied at the interface, before detection. "
        "Examples: 'tcp', 'udp port 53', 'host 10.0.0.5', 'tcp port 80 or 443'. "
        "Leave blank to capture everything. Applies to the NEXT window."
    ),
)
def _clear_capture_filter():
    # A widget's own session_state key may only be written BEFORE that widget
    # is instantiated. As an on_click callback this runs ahead of the rerun, so
    # blanking bpf_input here is legal — doing it inline after the text_input
    # above raised StreamlitAPIException ("`st.session_state.bpf_input` cannot
    # be modified after the widget with key `bpf_input` is instantiated") and
    # crashed the whole page.
    _write_capture_filter("")
    st.session_state["bpf_input"] = ""


_bc1, _bc2 = st.sidebar.columns(2)
if _bc1.button("Save", key="bpf_save", use_container_width=True):
    _write_capture_filter(_bpf_in)
    st.sidebar.success("Capture filter saved.")
# No st.rerun() — a button with on_click already reruns the script, and by then
# _read_capture_filter() above returns the cleared value, so the "Active:"
# caption below is correct on the very same pass.
_bc2.button(
    "Clear", key="bpf_clear", use_container_width=True,
    on_click=_clear_capture_filter,
)
if _cur_bpf:
    st.sidebar.caption(f"Active: `{_cur_bpf}` — next window")
else:
    st.sidebar.caption("No capture filter — capturing all traffic.")

# ── Auto-block settings (Aaron) ───────────────────────────────────────────
# Writes autoblock_config in ids_logs.db; live_backend.py reads it each window
# and auto-blocks any source IP that accumulates >= threshold Severe alerts.
st.sidebar.markdown("---")
st.sidebar.markdown("**Auto-Block Settings**")

ab_cfg = _read_autoblock_config()
auto_block_on = st.sidebar.toggle(
    "Auto-block Severe ≥ N hits",
    value=ab_cfg["enabled"],
    help=(
        "When enabled, any source IP that accumulates N or more Severe alerts "
        "is automatically blocked via a Windows Firewall inbound rule. The "
        "block is removed after the TTL expires — no manual action required."
    ),
)
hit_threshold = st.sidebar.number_input(
    "Severe-hit threshold (N)", min_value=1, max_value=50,
    value=ab_cfg["threshold"], step=1,
)
ttl_hours = st.sidebar.slider(
    "Block expiry (hours)", min_value=1, max_value=24,
    value=ab_cfg["ttl_seconds"] // 3600,
)
new_ttl_seconds = ttl_hours * 3600
if (
    auto_block_on != ab_cfg["enabled"]
    or hit_threshold != ab_cfg["threshold"]
    or new_ttl_seconds != ab_cfg["ttl_seconds"]
):
    _write_autoblock_config(auto_block_on, hit_threshold, new_ttl_seconds)
    st.sidebar.success("Auto-block settings saved.")

st.sidebar.markdown("**Currently Blocked IPs**")
_sidebar_blocked = _load_blocked_ips()
if _sidebar_blocked.empty:
    st.sidebar.caption("No IPs are currently blocked.")
else:
    st.sidebar.dataframe(_sidebar_blocked, hide_index=True, use_container_width=True)


if _active == "Live SOC Dashboard":
    @st.fragment(run_every=(refresh_rate if enable_live else None))
    def _live_soc_panel():
        if enable_live:
            # State 3 (loading): skeleton + spinner on the FIRST paint only, so the
            # first load never flashes blank. On the periodic auto-refresh we read
            # silently — re-showing the skeleton every cycle made the whole page dim
            # and "flash" each refresh.
            if not st.session_state.get("_soc_loaded_once", False):
                skeleton_slot = st.empty()
                with skeleton_slot.container():
                    render_table_skeleton()
                with st.spinner("Querying alert database…"):
                    logs_df, db_error = load_threat_logs()
                skeleton_slot.empty()
                st.session_state["_soc_loaded_once"] = True
            else:
                logs_df, db_error = load_threat_logs()

            if db_error is not None:
                # State 4 (error): a genuine DB / connection fault — surfaced loudly,
                # not silently swallowed as "no data". Includes a retry path.
                st.error(
                    "Unable to read the alert database. The detection backend may not "
                    "be running, or the database file is locked."
                )
                with st.expander("Error details"):
                    st.code(db_error)
                if st.button("Try Again", key="retry_db", type="primary"):
                    st.rerun()
                st.stop()

            if logs_df.empty:
                # State 2 (empty): connected fine, just no telemetry logged yet.
                render_empty_state(
                    "",
                    "Waiting for network telemetry",
                    "Connected to the alert database, but no flows have been logged yet. "
                    "Start a capture or generate traffic to populate the dashboard.",
                )
            else:
                def severity_of(value: str) -> str:
                    if "Severe" in str(value):
                        return "Severe"
                    if "Moderate" in str(value):
                        return "Moderate"
                    return "Baseline"

                logs_df["__sev__"] = logs_df["Threat Level"].map(severity_of)
                filtered_df = logs_df[logs_df["__sev__"].isin(severity_filter)].drop(columns="__sev__")
                logs_df = logs_df.drop(columns="__sev__")

                severe_mask = logs_df["Threat Level"] == "Severe (Critical Anomaly)"
                severe_df = logs_df[severe_mask]
                moderate_count = int(
                    logs_df["Threat Level"].astype(str).str.contains("Moderate").sum()
                )
                unique_sources = logs_df["Source IP"].nunique()
                # Count from DB so the metric reflects auto-blocks written by the backend.
                _blocked_now = _load_blocked_ips()
                blocked_count = len(_blocked_now)
                _blocked_ip_set = (
                    set(_blocked_now["Source IP"]) if not _blocked_now.empty else set()
                )

                # Ambient THREATCON banner — reacts to the worst live severity.
                render_threat_condition(len(severe_df), moderate_count)

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Flows Logged", len(logs_df))
                m2.metric("Critical Threats", len(severe_df))
                m3.metric("Unique Source IPs", unique_sources)
                m4.metric("Blocked IPs", blocked_count)

                # Deflection scoreboard: packets attributed to blocked severe
                # sources count as dropped (2-second capture windows), neutralized
                # = active blocks, intel tags = MITRE-mapped rows.
                _dropped_rows = severe_df[severe_df["Source IP"].isin(_blocked_ip_set)]
                packets_dropped = int(
                    (pd.to_numeric(_dropped_rows["Packets/Sec"], errors="coerce")
                     .fillna(0) * 2).sum()
                )
                _severe_srcs = set(severe_df["Source IP"])
                deflection_pct = (
                    int(round(100 * len(_severe_srcs & _blocked_ip_set) / len(_severe_srcs)))
                    if _severe_srcs else 100
                )
                intel_tags = (
                    int(logs_df["ATT&CK ID"].notna().sum())
                    if "ATT&CK ID" in logs_df.columns else 0
                )
                render_soc_scoreboard(packets_dropped, blocked_count, intel_tags, deflection_pct)
                render_kill_chain(logs_df, _blocked_ip_set)

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

                table_col, chart_col = st.columns([3, 1])

                with table_col:
                    st.markdown('<p class="threat-header">Live Network Telemetry</p>', unsafe_allow_html=True)

                    # ── Display filter (structured) ───────────────────────────────
                    # Wireshark-style DISPLAY filter: narrows the already-captured
                    # rows (severity is applied above; the BPF capture filter lives
                    # in the sidebar). These widgets only re-slice the loaded frame —
                    # nothing is re-captured.
                    _has_transport = "Transport" in filtered_df.columns
                    _fc1, _fc2, _fc3 = st.columns([1.2, 1, 1.4])
                    with _fc1:
                        transport_filter = st.multiselect(
                            "Transport", ["TCP", "UDP", "OTHER"],
                            default=["TCP", "UDP", "OTHER"], key="transport_filter",
                            disabled=not _has_transport,
                            help=None if _has_transport else
                            "No transport data in this DB yet — capture a window first.",
                        )
                    with _fc2:
                        port_filter = st.number_input(
                            "Port (0 = any)", min_value=0, max_value=65535,
                            value=0, step=1, key="port_filter",
                            help="Matches the flow on either side — source or "
                            "destination port (top port or the full per-window list).",
                        )
                    with _fc3:
                        ip_query = st.text_input(
                            "Source IP contains", value="",
                            placeholder="e.g. 10.0.0", key="ip_filter",
                        )

                    view_df = filtered_df
                    if _has_transport:
                        view_df = view_df[view_df["Transport"].isin(transport_filter)]
                    if port_filter and int(port_filter) > 0:
                        _pf = int(port_filter)
                        _mask = pd.Series(False, index=view_df.index)
                        # Match the port on either side of the flow: the modal
                        # source/dest port or anywhere in the per-window port lists.
                        for _num_col in ("Dest Port", "Source Port"):
                            if _num_col in view_df.columns:
                                _mask = _mask | (
                                    pd.to_numeric(view_df[_num_col], errors="coerce") == _pf
                                )
                        for _list_col in ("Ports", "Src Ports"):
                            if _list_col in view_df.columns:
                                _mask = _mask | view_df[_list_col].fillna("").astype(str).apply(
                                    lambda s: str(_pf) in re.split(r"[,\s]+", s)
                                )
                        view_df = view_df[_mask]
                    if ip_query.strip():
                        view_df = view_df[
                            view_df["Source IP"].astype(str).str.contains(
                                ip_query.strip(), case=False, na=False
                            )
                        ]

                    def _reset_all_filters():
                        st.session_state.update(
                            sev_filter=["Severe", "Moderate", "Baseline"],
                            transport_filter=["TCP", "UDP", "OTHER"],
                            port_filter=0, ip_filter="",
                        )

                    if view_df.empty:
                        # State 2 (empty via filter): data exists but the active
                        # filters hide all of it. Offer a one-click reset.
                        render_empty_state(
                            "",
                            "No flows match the current filter",
                            "Your severity / transport / port / IP filters hide every "
                            "logged flow. Reset them or widen the selection to see telemetry.",
                        )
                        st.button(
                            "Reset filters", key="reset_filters", type="primary",
                            on_click=_reset_all_filters,
                        )
                    else:
                        # Simple main table: a few key columns only. The full record
                        # lives in view100 and is surfaced on row click below.
                        view100 = view_df.head(100).reset_index(drop=True)

                        # ── Sticky row selection ──────────────────────────────
                        # This panel is an st.fragment that re-queries the DB
                        # every refresh_rate seconds, so fresh flows land at the
                        # top and every existing row shifts down. Streamlit
                        # stores a dataframe selection by ROW POSITION, not by
                        # row identity, so a shifting table silently re-points
                        # the tick box — and the drill-down below it — at
                        # whichever flow slid into that slot.
                        #
                        # Fix: while a row is selected, FREEZE the rendered
                        # snapshot. The positions the widget remembers keep
                        # meaning the same flow, so the selection stays on the
                        # row the analyst actually clicked. The rest of the page
                        # (metrics, charts, kill chain) keeps updating live and
                        # the table resumes the moment the selection is cleared.
                        _sel_epoch = st.session_state.get("_telemetry_sel_epoch", 0)
                        _sel_key = f"telemetry_select_{_sel_epoch}"

                        def _clear_telemetry_selection():
                            # A dataframe selection cannot be cleared through
                            # session_state, so retire the widget key instead:
                            # a new key is a new widget, with no selection.
                            st.session_state["_telemetry_sel_epoch"] = (
                                st.session_state.get("_telemetry_sel_epoch", 0) + 1
                            )
                            st.session_state.pop("_telemetry_frozen", None)
                            st.session_state.pop("_telemetry_shown", None)
                            try:
                                # The retired key is never rendered again — drop
                                # its state so long sessions do not accumulate a
                                # dead selection dict per pin/unpin cycle.
                                del st.session_state[_sel_key]
                            except Exception:
                                pass

                        # What the widget reported on the previous run. Read it
                        # before rendering: the freeze decision has to be made
                        # while this run's table is still being built.
                        _prev_rows = []
                        _prev_state = st.session_state.get(_sel_key)
                        if _prev_state is not None:
                            try:
                                _prev_rows = list(_prev_state["selection"]["rows"])
                            except Exception:
                                try:
                                    _prev_rows = list(_prev_state.selection.rows)
                                except Exception:
                                    _prev_rows = []

                        # A filter change means the analyst asked for a different
                        # slice of traffic — honour that and drop any freeze.
                        _filter_sig = (
                            tuple(sorted(severity_filter)),
                            tuple(sorted(transport_filter)),
                            int(port_filter or 0),
                            ip_query.strip().lower(),
                        )
                        if st.session_state.get("_telemetry_filter_sig") != _filter_sig:
                            st.session_state["_telemetry_filter_sig"] = _filter_sig
                            st.session_state.pop("_telemetry_frozen", None)
                            st.session_state.pop("_telemetry_shown", None)
                            _prev_rows = []

                        _frozen = st.session_state.get("_telemetry_frozen")
                        if not _prev_rows:
                            # Nothing selected — the table runs live again.
                            _frozen = None
                            st.session_state.pop("_telemetry_frozen", None)
                        elif _frozen is None:
                            # A selection appeared this run. It was made against
                            # the snapshot that was last on screen, so that is
                            # the frame to freeze — not the fresher one just
                            # pulled from the DB, in which the rows have already
                            # moved.
                            _frozen = st.session_state.get("_telemetry_shown")
                            if _frozen is not None:
                                st.session_state["_telemetry_frozen"] = _frozen

                        table_df = view100 if _frozen is None else _frozen
                        st.session_state["_telemetry_shown"] = table_df

                        # Ordered as a readable flow tuple: who (Source IP:Source Port)
                        # → over what (Transport) → to where (Dest Port), then the
                        # rate and the verdict. Ports only appear when the backend has
                        # logged them, so an older DB still renders.
                        _key_cols = [
                            c for c in ("Time", "Source IP", "Source Port", "Transport",
                                        "Dest Port", "Packets/Sec", "Threat Score",
                                        "Threat Level")
                            if c in table_df.columns
                        ]
                        simple_df = table_df[_key_cols]
                        # Ports are identifiers, not magnitudes: render them as bare
                        # integers (no 59,272 thousands-grouping) with hover help.
                        _port_help = {
                            "Source Port": "Ephemeral/client port the source opened "
                            "this window (most frequent). Full set in the row detail.",
                            "Dest Port": "Service/destination port contacted most "
                            "this window. Full set in the row detail.",
                        }
                        _col_config = {
                            c: st.column_config.NumberColumn(c, format="%d", help=h)
                            for c, h in _port_help.items() if c in simple_df.columns
                        }
                        try:
                            _styled = simple_df.style.apply(highlight_threat_row, axis=1)
                            _sel = st.dataframe(
                                _styled, width="stretch", height=420,
                                on_select="rerun", selection_mode="single-row",
                                hide_index=True, key=_sel_key,
                                column_config=_col_config,
                            )
                        except Exception:
                            _sel = st.dataframe(
                                simple_df, width="stretch", height=420,
                                on_select="rerun", selection_mode="single-row",
                                hide_index=True, key=_sel_key,
                                column_config=_col_config,
                            )

                        if _frozen is not None:
                            _fz_txt, _fz_btn = st.columns([3, 1])
                            with _fz_txt:
                                st.caption(
                                    "Selection pinned — this table is paused so the "
                                    "selected flow cannot slide out from under you. "
                                    "Capture and every other panel keep running live."
                                )
                            with _fz_btn:
                                st.button(
                                    "Resume live table", key="telemetry_resume",
                                    on_click=_clear_telemetry_selection,
                                    use_container_width=True,
                                )

                        csv_bytes = view_df.drop(
                            columns=[c for c in ("id",) if c in view_df.columns]
                        ).to_csv(index=False).encode("utf-8")

                        # Always offer the current live capture if present. This reads
                        # the snapshot file `temp_live.pcap` from the Dashboard folder
                        # and serves it to the browser. If the backend isn't writing
                        # a live file, the button is hidden and we fall back to CSV.
                        live_pcap = "temp_live.pcap"
                        if os.path.exists(live_pcap):
                            try:
                                with open(live_pcap, "rb") as fh:
                                    live_bytes = fh.read()
                                st.download_button(
                                    label="Download current capture (PCAP)",
                                    data=live_bytes,
                                    file_name=f"temp_live_{int(time.time())}.pcap",
                                    mime="application/vnd.tcpdump.pcap",
                                    key="live_pcap_dl",
                                )
                            except Exception:
                                st.caption("Live PCAP currently unavailable")

                        # If the filtered view references captured PCAP evidence files,
                        # offer them as direct downloads (single PCAP) or a ZIP archive
                        # of multiple PCAPs. Otherwise fall back to the CSV export.
                        pcap_paths = []
                        if "Evidence Path" in view_df.columns:
                            pcap_paths = [p for p in view_df["Evidence Path"].dropna().unique()]
                        existing_pcaps = [p for p in pcap_paths if os.path.exists(p)]

                        if len(existing_pcaps) == 1:
                            p = existing_pcaps[0]
                            _offer_binary_download(
                                lambda _p=p: open(_p, "rb").read(),
                                file_name=os.path.basename(p),
                                key=f"evdl_single_{p}",
                                label="Download PCAP",
                                desktop_label="Save PCAP",
                                mime="application/vnd.tcpdump.pcap",
                            )
                        elif len(existing_pcaps) > 1:
                            buf = io.BytesIO()
                            with zipfile.ZipFile(buf, "w") as zf:
                                for p in existing_pcaps:
                                    try:
                                        zf.write(p, arcname=os.path.basename(p))
                                    except Exception:
                                        # skip unreadable files
                                        pass
                            buf.seek(0)
                            _offer_binary_download(
                                buf.getvalue,
                                file_name=f"ids_evidence_pcaps_{int(time.time())}.zip",
                                key="evdl_zip",
                                label=f"Download {len(existing_pcaps)} PCAPs (zip)",
                                desktop_label=f"Save {len(existing_pcaps)} PCAPs (zip)",
                                mime="application/zip",
                            )
                        else:
                            st.download_button(
                                label="Export Filtered Logs (CSV)",
                                data=csv_bytes,
                                file_name=f"ids_threat_logs_{int(time.time())}.csv",
                                mime="text/csv",
                            )

                        # ── Click-row drill-down ──────────────────────────────────
                        _rows = []
                        try:
                            _rows = list(_sel.selection.rows)
                        except Exception:
                            _rows = []
                        if _rows and _rows[0] < len(table_df):
                            st.markdown(
                                '<div class="section-divider"></div>',
                                unsafe_allow_html=True,
                            )
                            # table_df, not view100: while pinned the detail has
                            # to describe the frozen row, not whatever now sits
                            # at that position in the live query.
                            render_flow_detail(table_df.iloc[_rows[0]])
                        else:
                            st.caption(
                                "Click a row to inspect the full flow — ports, protocol "
                                "breakdown, MITRE mapping, and the raw hex view."
                            )

                    # ── PCAP Evidence Downloads ───────────────────────────────────
                    # Severe incidents capture the source PCAP window (live_backend).
                    # Surface those files here as direct downloads, keyed off the
                    # unfiltered logs so evidence stays reachable regardless of the
                    # active severity filter.
                    if "Evidence Path" in logs_df.columns:
                        evidence_rows = logs_df[
                            logs_df["Evidence Path"].notna() &
                            (logs_df["Threat Level"] == "Severe (Critical Anomaly)")
                        ][["Time", "Source IP", "Evidence Path"]].drop_duplicates(
                            subset=["Evidence Path"]
                        ).head(20)

                        if not evidence_rows.empty:
                            st.markdown(
                                '<p class="threat-header" style="margin-top:14px;">PCAP Evidence Files</p>',
                                unsafe_allow_html=True,
                            )
                            for _, ev_row in evidence_rows.iterrows():
                                ev_path = ev_row["Evidence Path"]
                                ev_ip = ev_row["Source IP"]
                                ev_time = ev_row["Time"]
                                ev_col_info, ev_col_btn = st.columns([4, 1])
                                with ev_col_info:
                                    st.markdown(
                                        f'<div class="reasoning-card">'
                                        f'<b>{ev_ip}</b> &nbsp;·&nbsp; {ev_time} &nbsp;·&nbsp; '
                                        f'<code>{os.path.basename(ev_path)}</code>'
                                        f'</div>',
                                        unsafe_allow_html=True,
                                    )
                                with ev_col_btn:
                                    if os.path.exists(ev_path):
                                        _offer_binary_download(
                                            lambda _p=ev_path: open(_p, "rb").read(),
                                            file_name=os.path.basename(ev_path),
                                            key=f"evdl_{ev_path}",
                                            label="PCAP",
                                            desktop_label="Save",
                                            mime="application/vnd.tcpdump.pcap",
                                        )
                                    else:
                                        st.caption("file missing")

                with chart_col:
                    st.markdown('<p class="threat-header">Threat Distribution</p>', unsafe_allow_html=True)
                    threat_counts = logs_df["Threat Level"].value_counts().reset_index()
                    threat_counts.columns = ["Threat Level", "Count"]
                    st.bar_chart(threat_counts.set_index("Threat Level"))

                    st.markdown('<p class="threat-header">Top Talkers</p>', unsafe_allow_html=True)
                    top_ips = logs_df["Source IP"].value_counts().head(5).reset_index()
                    top_ips.columns = ["Source IP", "Flows"]
                    st.dataframe(top_ips, width="stretch", hide_index=True)

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">Per-Protocol Breakdown</p>', unsafe_allow_html=True)
                selected_ip = st.selectbox(
                    "Inspect Source IP",
                    logs_df["Source IP"].unique(),
                    key="per_proto_ip",
                )
                try:
                    proto_conn = sqlite3.connect('ids_logs.db', timeout=15)
                    proto_df = pd.read_sql_query(
                        "SELECT protocol, SUM(packets) AS pkts FROM protocol_breakdown "
                        "WHERE source_ip = ? GROUP BY protocol",
                        proto_conn, params=[selected_ip],
                    )
                    proto_conn.close()
                except Exception:
                    proto_df = pd.DataFrame()
                if not proto_df.empty:
                    st.bar_chart(proto_df.set_index("protocol"))
                else:
                    st.info("No per-protocol data yet for this IP.")

                # ── Fleet-wide protocol mix + DNS-tunnel watch ──────────────────
                # Aggregates the protocol_breakdown table the backend already writes
                # every window, so the analyst sees the whole network's protocol
                # profile (not just one source) without any backend change.
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">Protocol Mix — All Sources</p>', unsafe_allow_html=True)
                try:
                    fleet_proto = pd.read_sql_query(
                        "SELECT protocol AS Protocol, SUM(packets) AS Packets, "
                        "SUM(bytes) AS Bytes, COUNT(DISTINCT source_ip) AS Sources "
                        "FROM protocol_breakdown GROUP BY protocol ORDER BY Packets DESC",
                        _get_db_conn(),
                    )
                except Exception:
                    fleet_proto = pd.DataFrame()
                if fleet_proto.empty:
                    st.info("No protocol breakdown logged yet — start live capture to populate this view.")
                else:
                    pc1, pc2 = st.columns([2, 1])
                    with pc1:
                        st.bar_chart(fleet_proto.set_index("Protocol")["Packets"])
                    with pc2:
                        st.dataframe(fleet_proto, hide_index=True, width="stretch", height=260)

                    # DNS-heavy callout — mirrors live_backend.dns_tunnel_check, which
                    # flags a source pushing DNS over port 53 as a tunnel / C2 channel.
                    # Here the signal is cumulative DNS volume across all windows.
                    try:
                        dns_talkers = pd.read_sql_query(
                            'SELECT source_ip AS "Source IP", SUM(packets) AS "DNS Packets" '
                            "FROM protocol_breakdown WHERE protocol = 'DNS' "
                            'GROUP BY source_ip HAVING SUM(packets) > 30 '
                            'ORDER BY "DNS Packets" DESC LIMIT 10',
                            _get_db_conn(),
                        )
                    except Exception:
                        dns_talkers = pd.DataFrame()
                    if not dns_talkers.empty:
                        st.warning(
                            f"{len(dns_talkers)} source(s) show elevated cumulative DNS "
                            "volume (>30 packets) — possible DNS tunnelling / C2 channel."
                        )
                        st.dataframe(dns_talkers, hide_index=True, width="stretch")

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">Threat Activity Timeline</p>', unsafe_allow_html=True)

                timeline_df = logs_df.copy()
                timeline_df["Severity"] = timeline_df["Threat Level"].map(
                    lambda v: "Severe" if "Severe" in str(v) else ("Moderate" if "Moderate" in str(v) else "Baseline")
                )
                timeline_pivot = (
                    timeline_df.groupby(["Time", "Severity"]).size().unstack(fill_value=0).sort_index()
                )
                for sev in ["Severe", "Moderate", "Baseline"]:
                    if sev not in timeline_pivot.columns:
                        timeline_pivot[sev] = 0
                st.line_chart(timeline_pivot[["Severe", "Moderate", "Baseline"]])

                # ═══════════════════════════════════════════════════════════
                # MITRE ATT&CK INTELLIGENCE PANEL
                # ═══════════════════════════════════════════════════════════
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">MITRE ATT&CK® Intelligence</p>', unsafe_allow_html=True)

                mitre_cols_present = "ATT&CK ID" in logs_df.columns

                if mitre_cols_present and MITRE_OK and logs_df["ATT&CK ID"].notna().any():
                    mitre_df = logs_df[logs_df["ATT&CK ID"].notna() & (logs_df["ATT&CK ID"] != "N/A")].copy()

                    if not mitre_df.empty:
                        # ── Summary metrics row ──────────────────────────────────
                        unique_techniques = mitre_df["ATT&CK ID"].nunique()
                        unique_tactics = mitre_df["ATT&CK Tactic"].nunique()
                        top_technique = mitre_df["ATT&CK ID"].value_counts().idxmax()
                        top_tactic = mitre_df["ATT&CK Tactic"].value_counts().idxmax()

                        mm1, mm2, mm3, mm4 = st.columns(4)
                        mm1.metric("Unique Techniques", unique_techniques)
                        mm2.metric("Unique Tactics", unique_tactics)
                        mm3.metric("Top Technique", top_technique)
                        mm4.metric("Top Tactic", top_tactic)

                        # ── Tactic filter ────────────────────────────────────────
                        all_tactics = sorted(mitre_df["ATT&CK Tactic"].dropna().unique().tolist())
                        selected_tactics = st.multiselect(
                            "Filter by Tactic", options=all_tactics, default=all_tactics,
                            key="mitre_tactic_filter",
                        )
                        filtered_mitre = mitre_df[mitre_df["ATT&CK Tactic"].isin(selected_tactics)]

                        # ── Badge grid ───────────────────────────────────────────
                        st.markdown("**Observed Techniques**")
                        technique_counts = (
                            filtered_mitre.groupby(["ATT&CK ID", "Sub-Technique", "ATT&CK Technique", "ATT&CK Tactic", "Tactic ID"])
                            .size().reset_index(name="hits")
                            .sort_values("hits", ascending=False)
                        )

                        badge_html = "<div style='display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;'>"
                        for _, trow in technique_counts.iterrows():
                            tid = trow["ATT&CK ID"]
                            sub = trow.get("Sub-Technique", "") or ""
                            name = trow["ATT&CK Technique"]
                            tact = trow["ATT&CK Tactic"]
                            hits = trow["hits"]
                            color = tactic_color(tact)
                            display_id = sub if sub else tid
                            url = mitre_url(tid, sub)
                            badge_html += (
                                f"<a href='{url}' target='_blank' style='text-decoration:none;'>"
                                f"<div style='background:{color}22;border:1px solid {color}88;"
                                f"border-radius:8px;padding:6px 12px;font-size:12px;color:#C9C7BE;"
                                f"min-width:120px;'>"
                                f"<div style='font-family:monospace;font-weight:700;color:{color};'>{display_id}</div>"
                                f"<div style='font-size:11px;color:#9C9A92;margin-top:2px;'>{name[:32]}</div>"
                                f"<div style='font-size:10px;color:#8E8C84;margin-top:1px;'>{tact} · {hits} hit(s)</div>"
                                f"</div></a>"
                            )
                        badge_html += "</div>"
                        st.markdown(badge_html, unsafe_allow_html=True)

                        # ── Tactic distribution bar chart ────────────────────────
                        tact_chart_col, tech_table_col = st.columns([1, 2])

                        with tact_chart_col:
                            st.markdown("**Tactic Distribution**")
                            tactic_dist = filtered_mitre["ATT&CK Tactic"].value_counts().reset_index()
                            tactic_dist.columns = ["Tactic", "Count"]
                            st.bar_chart(tactic_dist.set_index("Tactic"))

                        with tech_table_col:
                            st.markdown("**Technique Drill-Down**")
                            drill = technique_counts.rename(columns={
                                "ATT&CK ID": "Technique ID",
                                "Sub-Technique": "Sub-Technique",
                                "ATT&CK Technique": "Name",
                                "ATT&CK Tactic": "Tactic",
                                "hits": "Hits",
                            })[["Technique ID", "Sub-Technique", "Name", "Tactic", "Hits"]]
                            st.dataframe(drill, width="stretch", hide_index=True)

                        # ── Per-IP ATT&CK fingerprint ────────────────────────────
                        st.markdown("**Source IP ATT&CK Fingerprint**")
                        selected_mitre_ip = st.selectbox(
                            "Select IP to fingerprint",
                            filtered_mitre["Source IP"].unique(),
                            key="mitre_ip_select",
                        )
                        ip_techniques = (
                            filtered_mitre[filtered_mitre["Source IP"] == selected_mitre_ip]
                            [["ATT&CK ID", "Sub-Technique", "ATT&CK Technique", "ATT&CK Tactic", "Traffic Profile"]]
                            .drop_duplicates()
                        )
                        st.dataframe(ip_techniques, width="stretch", hide_index=True)

                    else:
                        st.info("No non-benign MITRE-tagged events in the current filtered view.")
                else:
                    st.info(
                        "MITRE ATT&CK columns not yet in database. "
                        "Run live_backend.py once to auto-migrate, or run `python mitre_backfill.py`."
                    )

                # Alert triage now lives inline in the telemetry table above: click
                # any row to open the full hex inspector + MITRE + protocol detail
                # for that flow (render_flow_detail). The standalone selectbox-driven
                # triage panel was retired so there is a single drill-down entry point.

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">One-Click Threat Mitigation</p>', unsafe_allow_html=True)

                # Block state lives in the DB now (survives reruns + reflects auto-blocks).
                _blocked_df = _load_blocked_ips()
                _current_blocked_ips = (
                    set(_blocked_df["Source IP"].tolist()) if not _blocked_df.empty else set()
                )
                severe_ips = severe_df["Source IP"].unique().tolist()
                unmitigated = [ip for ip in severe_ips if ip not in _current_blocked_ips]

                # ── Auto-block enforcement (Aaron) ───────────────────────────
                # Second enforcement point, deliberately. live_backend applies the
                # same policy per capture window, which is what makes auto-block
                # work headlessly (START.bat, the .exe, dashboard closed). This one
                # acts on what is actually on screen: it blocks the moment the view
                # shows an IP over threshold, instead of on the backend's next
                # window, and it covers rows that arrived from a replay or an
                # imported database rather than from live capture.
                # The two cannot fight: both go through blocked_ips, _maybe_auto_block
                # skips IPs already in that table, and this loop only considers IPs
                # not already blocked.
                _ab_cfg = _read_autoblock_config()
                if _ab_cfg["enabled"] and unmitigated:
                    _hit_counts = severe_df["Source IP"].value_counts()
                    _auto_blocked_now = []
                    for ip in unmitigated:
                        if int(_hit_counts.get(ip, 0)) >= _ab_cfg["threshold"]:
                            if _block_ip_to_db(
                                ip, _ab_cfg["ttl_seconds"],
                                f"Auto-block: {int(_hit_counts[ip])} Severe hits "
                                f"(threshold {_ab_cfg['threshold']})"
                            ):
                                _auto_blocked_now.append(ip)
                    if _auto_blocked_now:
                        # Refresh block state so the panel below reflects the
                        # auto-blocks immediately instead of on the next rerun.
                        _current_blocked_ips |= set(_auto_blocked_now)
                        unmitigated = [ip for ip in unmitigated if ip not in _current_blocked_ips]
                        st.info(
                            f"Auto-block engaged for {len(_auto_blocked_now)} source(s): "
                            f"{', '.join(_auto_blocked_now)}."
                        )

                if unmitigated:
                    st.warning(f"{len(unmitigated)} critical threat source(s) detected and awaiting mitigation.")

                    _block_ttl = _ab_cfg["ttl_seconds"]  # already read just above

                    for ip in unmitigated:
                        ip_flows = len(severe_df[severe_df["Source IP"] == ip])
                        col_info, col_btn = st.columns([5, 1])
                        with col_info:
                            st.markdown(
                                f'<div class="block-panel">'
                                f'<span class="ip-label">{ip}</span>'
                                f'&nbsp;&nbsp;&nbsp;Severe (Critical Anomaly)'
                                f'&nbsp;&nbsp;|&nbsp;&nbsp;{ip_flows} alert(s) logged'
                                f'</div>',
                                unsafe_allow_html=True
                            )
                        with col_btn:
                            if st.button("Block IP", key=f"block_{ip}", type="primary"):
                                # State 3 (loading): the netsh call is slow + side-effecting.
                                # The spinner blocks the rerun so the button can't be
                                # double-fired into a duplicate firewall rule.
                                with st.spinner(f"Applying firewall rule for {ip}…"):
                                    success = _block_ip_to_db(ip, _block_ttl, "Manual block via SOC dashboard")
                                if success:
                                    ttl_label = (
                                        f"{_block_ttl // 3600}h" if _block_ttl >= 3600
                                        else f"{_block_ttl // 60}m"
                                    )
                                    st.success(f"Firewall rule applied for {ip}. Expires in {ttl_label}.")
                                else:
                                    st.error(
                                        f"Unable to apply firewall rule for {ip}. "
                                        f"Administrator privileges required."
                                    )
                elif severe_ips:
                    st.success("All detected critical threat sources have been mitigated.")
                else:
                    st.info("No critical threats detected in the current dataset.")

                _registry_df = _load_blocked_ips()
                if not _registry_df.empty:
                    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                    st.markdown('<p class="threat-header">Blocked IP Registry</p>', unsafe_allow_html=True)

                    registry_col, action_col = st.columns([3, 2])

                    with registry_col:
                        st.dataframe(_registry_df, width="stretch", hide_index=True)

                    with action_col:
                        st.caption("Remove a firewall rule to restore access for a previously blocked IP.")
                        ip_to_unblock = st.selectbox(
                            "Select IP to unblock",
                            _registry_df["Source IP"].tolist(),
                            label_visibility="collapsed"
                        )
                        if st.button("Remove Block", key="unblock_btn"):
                            with st.spinner(f"Removing firewall rule for {ip_to_unblock}…"):
                                success = _unblock_ip_from_db(ip_to_unblock)
                            if success:
                                st.success(f"Firewall rule removed. {ip_to_unblock} is now unblocked.")
                                st.rerun()
                            else:
                                st.error(
                                    f"Could not remove the rule for {ip_to_unblock}. "
                                    f"Administrator privileges required."
                                )

                # ── Live event ticker (scoped iframe) ─────────────────────────────
                # Terminal crawl of the freshest blocks, alerts and MITRE tags.
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                render_event_ticker(_build_ticker_events(logs_df, _blocked_now))

        else:
            st.info("Live monitoring is paused. Enable it from the sidebar to begin real-time analysis.")
            st.markdown("---")
            st.markdown("**System Overview**")
            col_a, col_b, col_c = st.columns(3)
            col_a.markdown("**Capture Layer**\n\nLive packet capture across the active network interface in 2-second windows.")
            col_b.markdown("**Detection Layer**\n\n" + detection_engine_status() + " with multi-window correlation.")
            col_c.markdown("**Response Layer**\n\nOne-click firewall isolation and persistent alert logging.")
    _live_soc_panel()


elif _active == "Educational Simulator":
    st.subheader("Network Traffic and Attack Simulator")
    st.markdown("Visualize how different network behaviors trigger the detection engine.")

    scenario = st.radio(
        "Select Scenario:",
        ("Normal Web Browsing", "Reconnaissance (Port Scan)", "DDoS Flood",
         "Brute-Force Login", "C2 Beacon (Stealth)"),
        horizontal=True
    )

    if scenario == "Normal Web Browsing":
        sim_mode = "normal"
        st.success("Classification: BASELINE — Standard web traffic pattern. No anomaly detected.")
        reasoning = [
            ("packets/sec", "low", "well below the 300 pps moderate threshold"),
            ("syn_ack_ratio", "~1.0", "balanced — every SYN is acknowledged"),
            ("unique_dest_ports", "1–3", "far below the 20-port scan threshold"),
            ("traffic_profile", "Standard Web Traffic", "no rule matched"),
        ]
    elif scenario == "Reconnaissance (Port Scan)":
        sim_mode = "scan"
        st.warning("Classification: MODERATE — Sequential port probing across many destination ports.")
        reasoning = [
            ("unique_dest_ports", "> 20", "triggers `ports > 20` Port Scan rule"),
            ("packets/sec", "moderate", "sustained probing, not flood-level"),
            ("syn_ack_ratio", "elevated", "many SYNs sent, few ACKs returned (closed ports)"),
            ("traffic_profile", "Port Scan / Reconnaissance", "Moderate severity"),
        ]
    elif scenario == "DDoS Flood":
        sim_mode = "ddos"
        st.error("Classification: SEVERE — Extreme SYN packet rate with anomalous SYN/ACK ratio.")
        reasoning = [
            ("packets/sec", "> 500", "triggers high-volume flood rule"),
            ("syn_ack_ratio", "> 5", "overwhelming SYNs vs returning ACKs"),
            ("total_syn_flags", "very high", "SYN flood signature"),
            ("traffic_profile", "DDoS SYN Flood", "Severe — fusion engine picks max severity"),
        ]
    elif scenario == "Brute-Force Login":
        sim_mode = "brute"
        st.warning("Classification: MODERATE — Sustained authentication attempts across many windows.")
        reasoning = [
            ("rolling_syn (30s)", "> 150", "multi-window slow-attack detector trips"),
            ("packets/sec (single window)", "low", "below the 500 pps single-window flood threshold"),
            ("unique_dest_ports", "1", "all targeting one auth port (e.g. 22 / 3389)"),
            ("traffic_profile", "Sustained SYN / Brute-Force Probe", "caught by rolling-state layer"),
        ]
    else:
        sim_mode = "c2"
        st.warning("Classification: MODERATE — Low-and-slow periodic beacon, likely command-and-control.")
        reasoning = [
            ("packets/sec", "very low", "stealth — single-window heuristic alone misses this"),
            ("iat_std", "near 0", "highly regular beacon interval (telemetry-like rhythm)"),
            ("unique_dest_ips", "1", "single hard-coded callback host"),
            ("detection path", "ML + rolling state", "ML flags rhythmic IAT pattern as suspicious"),
        ]

    reasoning_html = "".join(
        f'<div class="reasoning-card"><b>{label}</b>: <code>{value}</code> — {note}</div>'
        for label, value, note in reasoning
    )
    st.markdown("**Detection Reasoning**", help="Which feature values trigger which rule path.")
    st.markdown(reasoning_html, unsafe_allow_html=True)

    # Interactive attack lab. Self-contained iframe: scenario pills, intensity,
    # IDS defense toggle, live per-window telemetry (same thresholds as
    # live_backend.classify_profile), 3-strike auto-block, event log, and a
    # Mystery mode where the analyst must identify the attack from the meters.
    _SIM_LAB = """
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0; padding: 2px;
            background: #141413; color: #E8E6DE;
            font-family: 'Inter', 'Segoe UI', sans-serif;
            overflow: hidden; user-select: none;
        }
        .bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
        .pill {
            border: 1px solid #3A3733; background: transparent; color: #C9C7BE;
            border-radius: 999px; padding: 6px 14px; font-size: 12.5px; font-weight: 600;
            cursor: pointer; transition: all .15s ease; font-family: inherit;
        }
        .pill:hover { border-color: #D97757; color: #FAF9F5; transform: translateY(-1px); }
        .pill.on { background: #FAF9F5; color: #141413; border-color: #FAF9F5; }
        .pill.mys.on { background: #B49FE8; border-color: #B49FE8; }
        .spacer { flex: 1; }
        .ctl { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: #8E8C84; }
        input[type=range] { width: 110px; accent-color: #D97757; }
        .toggle {
            width: 38px; height: 20px; border-radius: 999px; border: 1px solid #3A3733;
            background: #1E1D1B; position: relative; cursor: pointer; transition: background .2s;
        }
        .toggle.on { background: #2E4434; border-color: #5E8A68; }
        .toggle::after {
            content: ""; position: absolute; top: 2px; left: 2px; width: 14px; height: 14px;
            border-radius: 50%; background: #8E8C84; transition: left .2s, background .2s;
        }
        .toggle.on::after { left: 20px; background: #97C0A4; }
        canvas { display: block; margin: 0 auto; max-width: 100%; background: #1A1918; border-radius: 12px; border: 1px solid #2B2A28; }
        .cards { display: flex; gap: 8px; margin-top: 8px; }
        .card {
            flex: 1; background: #1E1D1B; border: 1px solid #2B2A28; border-radius: 10px;
            padding: 8px 12px; min-width: 0;
        }
        .card .k { font-size: 10px; color: #8E8C84; text-transform: uppercase; letter-spacing: .07em; font-weight: 600; }
        .card .v { font-size: 20px; font-weight: 700; color: #FAF9F5; font-family: 'JetBrains Mono', monospace; margin-top: 2px; }
        .card.verdict .v { font-size: 14px; line-height: 1.25; font-family: 'Inter', sans-serif; }
        .v.sev0 { color: #97C0A4; } .v.sev1 { color: #E0B65C; } .v.sev2 { color: #F0795A; }
        #rule { font-size: 11.5px; color: #8E8C84; margin-top: 6px; font-family: 'JetBrains Mono', monospace; min-height: 15px; }
        #guessRow { display: none; gap: 6px; margin-top: 8px; align-items: center; flex-wrap: wrap; }
        #guessRow span { font-size: 12px; color: #B49FE8; font-weight: 600; }
        .lab-grid { display: flex; gap: 8px; margin-top: 8px; }
        #log {
            flex: 1; background: #1A1918; border: 1px solid #2B2A28; border-radius: 10px;
            height: 132px; overflow-y: auto; padding: 8px 10px;
            font-family: 'JetBrains Mono', monospace; font-size: 11px; line-height: 1.7;
        }
        #log .t { color: #6E6D66; }
        #log .ok { color: #97C0A4; } #log .warn { color: #E0B65C; }
        #log .sev { color: #F0795A; } #log .info { color: #8E8C84; } #log .mys { color: #B49FE8; }
        ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #2E2D2A; border-radius: 999px; }
    </style>
    </head>
    <body>
    <div class="bar" id="pills">
        <button class="pill" data-m="normal">Normal</button>
        <button class="pill" data-m="scan">Port Scan</button>
        <button class="pill" data-m="ddos">DDoS Flood</button>
        <button class="pill" data-m="brute">Brute-Force</button>
        <button class="pill" data-m="c2">C2 Beacon</button>
        <button class="pill mys" data-m="mystery">&#127922; Mystery</button>
        <div class="spacer"></div>
        <div class="ctl">Intensity <input type="range" id="inten" min="0.5" max="3" step="0.25" value="1">
            <b id="intenV" style="color:#D97757;">&times;1.0</b></div>
        <div class="ctl">IDS Defense <div class="toggle on" id="defT"></div></div>
        <button class="pill" id="pauseB">Pause</button>
        <button class="pill" id="resetB">Reset</button>
    </div>
    <canvas id="cv" width="880" height="290"></canvas>
    <div class="cards">
        <div class="card"><div class="k">Packets / sec</div><div class="v" id="mPps">0</div></div>
        <div class="card"><div class="k">SYN : ACK</div><div class="v" id="mSar">0.0</div></div>
        <div class="card"><div class="k">Unique ports</div><div class="v" id="mPorts">0</div></div>
        <div class="card"><div class="k">Avg frame (B)</div><div class="v" id="mAvg">0</div></div>
        <div class="card verdict" style="flex:1.6;"><div class="k">Engine verdict</div>
            <div class="v sev0" id="mVer">Standard Web Traffic</div></div>
    </div>
    <div id="rule">window closing&hellip;</div>
    <div id="guessRow">
        <span>Identify the attack from the telemetry:</span>
        <button class="pill" data-g="normal">Normal</button>
        <button class="pill" data-g="scan">Port Scan</button>
        <button class="pill" data-g="ddos">DDoS</button>
        <button class="pill" data-g="brute">Brute-Force</button>
        <button class="pill" data-g="c2">C2 Beacon</button>
    </div>
    <div class="lab-grid"><div id="log"></div></div>
    <script>
        const cv = document.getElementById('cv'), ctx = cv.getContext('2d');
        const $ = id => document.getElementById(id);
        let mode = '__INIT_MODE__', intensity = 1, defense = true, paused = false;
        let mystery = false, hiddenMode = null;
        let blocked = false, sevStreak = 0;
        let packets = [], flashes = [], scanPort = 1, frame = 0;
        const WIN = 120, SCALE = 6;
        let win = { syn: 0, ack: 0, bytes: 0, n: 0, ports: new Set() };
        let synHist = [], beaconGaps = [], lastBeacon = 0, beaconLock = false;

        const N = {
            atk: { x: 95,  y: 95,  w: 78, label: 'Attacker', sub: '203.0.113.66' },
            cli: { x: 95,  y: 210, w: 78, label: 'Workstation', sub: '10.0.0.21' },
            fw:  { x: 440, y: 150, w: 92, label: 'Firewall / IDS', sub: 'hybrid engine' },
            srv: { x: 790, y: 150, w: 78, label: 'Server', sub: '10.0.0.5' }
        };

        /* Iframes swallow mouse events, which would freeze the parent page's
           ghost cursor / spotlight while the pointer is over this lab. Forward
           mousemove to the parent document with translated coordinates
           (same-origin srcdoc, so the parent realm is reachable). */
        document.addEventListener('mousemove', e => {
            try {
                const fe = window.frameElement;
                if (!fe) return;
                const r = fe.getBoundingClientRect();
                window.parent.document.dispatchEvent(new window.parent.MouseEvent('mousemove', {
                    clientX: r.left + e.clientX, clientY: r.top + e.clientY, bubbles: true
                }));
            } catch (err) {}
        }, { passive: true });

        function effMode() { return mystery ? hiddenMode : mode; }

        function log(msg, cls) {
            const el = document.createElement('div');
            const t = new Date().toTimeString().slice(0, 8);
            el.innerHTML = '<span class="t">[' + t + ']</span> <span class="' + (cls || 'info') + '">' + msg + '</span>';
            const box = $('log');
            box.prepend(el);
            while (box.children.length > 60) box.lastChild.remove();
        }

        class Pkt {
            constructor(benign, ret) {
                const m = effMode();
                this.benign = benign; this.ret = !!ret;
                const from = ret ? N.srv : (benign ? N.cli : N.atk);
                this.x = from.x; this.y = from.y + (Math.random() - 0.5) * 18;
                this.stage = 1;
                this.tx = N.fw.x; this.ty = N.fw.y;
                this.speed = ret ? 5 : (m === 'ddos' && !benign ? 9 : 4.2);
                if (benign) {
                    this.port = Math.random() > 0.5 ? 443 : 80;
                    this.size = 350 + Math.random() * 700;
                    this.color = '#7FBF8E'; this.r = 3.5; this.syn = !ret;
                } else if (m === 'scan') {
                    this.port = scanPort++; if (scanPort > 1024) scanPort = 1;
                    this.size = 60; this.color = '#E0B65C'; this.r = 3; this.syn = true;
                } else if (m === 'ddos') {
                    this.port = 80; this.size = 60; this.color = '#F0795A'; this.r = 4.5; this.syn = true;
                } else if (m === 'brute') {
                    this.port = Math.random() > 0.5 ? 22 : 3389;
                    this.size = 130; this.color = '#E0B65C'; this.r = 3.5; this.syn = true;
                } else if (m === 'c2') {
                    this.port = 443; this.size = 95; this.color = '#B49FE8'; this.r = 3.5; this.syn = true;
                } else {
                    this.port = Math.random() > 0.5 ? 443 : 80;
                    this.size = 350 + Math.random() * 700;
                    this.color = '#7FBF8E'; this.r = 3.5; this.syn = true;
                }
                win.n++; win.bytes += this.size; win.ports.add(this.port);
                if (this.syn && !ret) win.syn++; else win.ack++;
                this.trail = [];
                this._setLeg(this.x, this.y, this.tx, this.ty);
            }
            /* Each hop is a quadratic bezier arc: control point offset
               perpendicular to the wire so packets sweep in glowing curves
               instead of sliding along straight lines. */
            _setLeg(x0, y0, x1, y1) {
                const mx = (x0 + x1) / 2, my = (y0 + y1) / 2;
                const dx = x1 - x0, dy = y1 - y0;
                const len = Math.max(Math.hypot(dx, dy), 1);
                const amp = (Math.random() - 0.5) * Math.min(64, len * 0.35);
                this.p0 = { x: x0, y: y0 };
                this.p1 = { x: mx - dy / len * amp, y: my + dx / len * amp };
                this.p2 = { x: x1, y: y1 };
                this.t = 0; this.dt = this.speed / len;
            }
            step() {
                this.trail.push({ x: this.x, y: this.y });
                if (this.trail.length > 7) this.trail.shift();
                this.t += this.dt;
                if (this.t < 1) {
                    const u = 1 - this.t, t = this.t;
                    this.x = u * u * this.p0.x + 2 * u * t * this.p1.x + t * t * this.p2.x;
                    this.y = u * u * this.p0.y + 2 * u * t * this.p1.y + t * t * this.p2.y;
                    return;
                }
                this.x = this.p2.x; this.y = this.p2.y;
                if (this.stage === 1) {
                    if (!this.benign && blocked) {           /* firewall eats it */
                        flashes.push({ x: N.fw.x - 50, y: this.y, t: 14 });
                        this.stage = 3; return;
                    }
                    this.stage = 2;
                    const dest = this.ret ? (this.benign ? N.cli : N.atk) : N.srv;
                    this.tx = dest.x; this.ty = dest.y;
                    this._setLeg(this.x, this.y, dest.x, dest.y);
                } else this.stage = 3;
            }
            draw() {
                /* fading luminous trail behind the packet */
                for (let i = 1; i < this.trail.length; i++) {
                    ctx.beginPath();
                    ctx.moveTo(this.trail[i - 1].x, this.trail[i - 1].y);
                    ctx.lineTo(this.trail[i].x, this.trail[i].y);
                    ctx.strokeStyle = this.color;
                    ctx.globalAlpha = 0.05 + (i / this.trail.length) * 0.22;
                    ctx.lineWidth = 1.6;
                    ctx.stroke();
                }
                ctx.globalAlpha = 1;
                ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, 6.283);
                ctx.shadowColor = this.color; ctx.shadowBlur = 9;
                ctx.fillStyle = this.color; ctx.globalAlpha = 0.92; ctx.fill();
                ctx.shadowBlur = 0; ctx.globalAlpha = 1;
                if (!this.ret) {
                    ctx.fillStyle = 'rgba(250,249,245,0.5)'; ctx.font = '9px monospace';
                    ctx.textAlign = 'left'; ctx.fillText(':' + this.port, this.x + 6, this.y - 4);
                }
            }
        }

        function node(n, fill, edge, dead) {
            ctx.shadowColor = dead ? '#000' : edge; ctx.shadowBlur = dead ? 0 : 12;
            ctx.fillStyle = dead ? '#22211F' : fill;
            ctx.beginPath(); ctx.roundRect(n.x - n.w / 2, n.y - 26, n.w, 52, 8); ctx.fill();
            ctx.shadowBlur = 0;
            ctx.strokeStyle = dead ? '#3A3733' : edge; ctx.lineWidth = 1.5; ctx.stroke();
            ctx.textAlign = 'center';
            ctx.fillStyle = dead ? '#6E6D66' : 'rgba(250,249,245,0.9)';
            ctx.font = '600 11px Inter, sans-serif'; ctx.fillText(n.label, n.x, n.y - 2);
            ctx.fillStyle = dead ? '#55534E' : 'rgba(142,140,132,0.95)';
            ctx.font = '9px monospace'; ctx.fillText(n.sub, n.x, n.y + 12);
            if (dead) {
                ctx.fillStyle = '#F0795A'; ctx.font = '700 10px Inter, sans-serif';
                ctx.fillText('BLOCKED', n.x, n.y + 40);
            }
        }

        function wire(a, b) {
            ctx.beginPath(); ctx.moveTo(a.x + a.w / 2, a.y); ctx.lineTo(b.x - b.w / 2, b.y);
            ctx.strokeStyle = '#2B2A28'; ctx.lineWidth = 2; ctx.stroke();
        }

        function classify(pps, sar, ports, avg, rollSyn, beacon) {
            if (pps > 500 && sar > 5) return ['DDoS SYN Flood', 2, 'pps ' + pps + ' > 500  AND  syn:ack ' + sar + ' > 5'];
            if (pps > 1000) return ['High-Volume Flood', 2, 'pps ' + pps + ' > 1000'];
            if (ports > 20) return ['Port Scan / Reconnaissance', 1, 'unique ports ' + ports + ' > 20'];
            if (rollSyn > 150 && pps < 300) return ['Sustained SYN / Brute-Force', 1, 'rolling 30s SYN ' + rollSyn + ' > 150'];
            if (beacon) return ['C2 Beacon (rhythmic IAT)', 1, 'beacon interval std &asymp; 0 &mdash; rhythm layer (single window saw nothing)'];
            if (pps <= 5 && avg < 150) return ['Idle / Background', 0, 'pps ' + pps + ' &le; 5, small frames'];
            return ['Standard Web Traffic', 0, 'no rule matched &mdash; balanced syn:ack ' + sar];
        }

        function closeWindow() {
            const pps = Math.round(win.n * SCALE / 2);
            const sar = +(win.syn / Math.max(win.ack, 1)).toFixed(1);
            const ports = win.ports.size;
            const avg = Math.round(win.bytes / Math.max(win.n, 1));
            synHist.push(win.syn * SCALE); if (synHist.length > 15) synHist.shift();
            const rollSyn = synHist.reduce((a, b) => a + b, 0);
            const beacon = beaconLock && effMode() === 'c2' && !blocked;
            const [name, sev, why] = blocked
                ? ['Standard Web Traffic', 0, 'attacker neutralized &mdash; only benign flows remain']
                : classify(pps, sar, ports, avg, rollSyn, beacon);

            $('mPps').textContent = pps; $('mSar').textContent = sar;
            $('mPorts').textContent = ports; $('mAvg').textContent = avg;
            const v = $('mVer');
            if (mystery && !blocked) { v.textContent = '? ? ?'; v.className = 'v'; $('rule').innerHTML = 'verdict hidden &mdash; read the meters and make the call'; }
            else { v.textContent = name; v.className = 'v sev' + sev; $('rule').innerHTML = 'rule: ' + why; }

            const shown = (mystery && !blocked) ? '[redacted]' : name;
            if (sev === 2) {
                sevStreak++;
                log('SEVERE window &mdash; ' + shown + ' (' + sevStreak + '/3 strikes)', 'sev');
                if (defense && sevStreak >= 3 && !blocked) {
                    blocked = true;
                    log('AUTO-BLOCK engaged &mdash; firewall dropped 203.0.113.66 (mirrors blocked_ips table)', 'sev');
                }
            } else {
                if (sev === 1) log(mystery ? 'MODERATE window &mdash; [redacted]'
                                           : name + ' &mdash; ' + why.replace(/&[a-z]+;/g, ''), 'warn');
                sevStreak = 0;
            }
            win = { syn: 0, ack: 0, bytes: 0, n: 0, ports: new Set() };
        }

        function spawn() {
            const m = effMode();
            if (Math.random() < 0.03) { packets.push(new Pkt(true)); }           /* benign hum */
            if (Math.random() < 0.022) { packets.push(new Pkt(true, true)); }    /* server replies */
            if (m === 'c2') {
                const gap = Math.round(90 / intensity);
                if (frame % gap === 0) {
                    packets.push(new Pkt(false));
                    if (lastBeacon) {
                        beaconGaps.push(frame - lastBeacon);
                        if (beaconGaps.length > 4) beaconGaps.shift();
                        if (beaconGaps.length >= 3 &&
                            Math.max(...beaconGaps) - Math.min(...beaconGaps) <= 4) {
                            if (!beaconLock) log('rhythm detector: fixed-interval callbacks &mdash; flagging C2', 'mys');
                            beaconLock = true;
                        }
                    }
                    lastBeacon = frame;
                }
                return;
            }
            const rate = { normal: 0.02, scan: 0.30, ddos: 0.90, brute: 0.14 }[m] * intensity;
            const burst = m === 'ddos' ? 4 : 1;
            if (Math.random() < rate) for (let i = 0; i < burst; i++) packets.push(new Pkt(m === 'normal'));
        }

        function loop() {
            requestAnimationFrame(loop);
            if (paused) return;
            frame++;
            ctx.clearRect(0, 0, cv.width, cv.height);
            wire(N.atk, N.fw); wire(N.cli, N.fw); wire(N.fw, N.srv);

            const hot = sevStreak > 0 && !blocked;
            node(N.atk, '#33211C', blocked ? '#3A3733' : '#C4664A', blocked);
            node(N.cli, '#20262E', '#6B87A8');
            node(N.fw, '#1D2B20', hot ? '#F0795A' : '#5E8A68');
            node(N.srv, '#23202C', '#8E79C9');

            spawn();
            for (let i = packets.length - 1; i >= 0; i--) {
                packets[i].step(); packets[i].draw();
                if (packets[i].stage === 3) packets.splice(i, 1);
            }
            if (packets.length > 400) packets.splice(0, packets.length - 400);

            for (let i = flashes.length - 1; i >= 0; i--) {
                const f = flashes[i];
                ctx.beginPath(); ctx.arc(f.x, f.y, (14 - f.t) * 1.6, 0, 6.283);
                ctx.strokeStyle = 'rgba(240,121,90,' + (f.t / 14).toFixed(2) + ')';
                ctx.lineWidth = 2; ctx.stroke();
                if (--f.t <= 0) flashes.splice(i, 1);
            }

            /* 2-second aggregation window sweep */
            const p = (frame % WIN) / WIN;
            ctx.fillStyle = 'rgba(217,119,87,0.55)';
            ctx.fillRect(0, cv.height - 3, cv.width * p, 3);
            ctx.fillStyle = 'rgba(142,140,132,0.8)';
            ctx.font = '9px monospace'; ctx.textAlign = 'right';
            ctx.fillText('2s aggregation window', cv.width - 8, cv.height - 8);

            if (frame % WIN === 0) closeWindow();
        }

        function setMode(m) {
            mystery = m === 'mystery';
            if (mystery) {
                const opts = ['scan', 'ddos', 'brute', 'c2'];
                hiddenMode = opts[(Math.random() * opts.length) | 0];
                log('MYSTERY scenario armed &mdash; identify it from the telemetry', 'mys');
                $('guessRow').style.display = 'flex';
            } else {
                mode = m;
                $('guessRow').style.display = 'none';
                log('scenario &rarr; ' + m, 'info');
            }
            document.querySelectorAll('#pills .pill[data-m]').forEach(b =>
                b.classList.toggle('on', b.dataset.m === m));
            reset(true);
        }

        function reset(keepMode) {
            packets = []; flashes = []; blocked = false; sevStreak = 0;
            synHist = []; beaconGaps = []; lastBeacon = 0; beaconLock = false;
            win = { syn: 0, ack: 0, bytes: 0, n: 0, ports: new Set() };
            if (!keepMode) log('lab reset', 'info');
        }

        document.querySelectorAll('#pills .pill[data-m]').forEach(b =>
            b.addEventListener('click', () => setMode(b.dataset.m)));
        document.querySelectorAll('#guessRow .pill').forEach(b =>
            b.addEventListener('click', () => {
                if (!mystery) return;
                const right = b.dataset.g === hiddenMode;
                log(right ? 'CORRECT &mdash; it was ' + hiddenMode + '. Analyst instincts confirmed.'
                          : 'Not quite &mdash; it was ' + hiddenMode + '. Check the rule that fired.',
                    right ? 'ok' : 'warn');
                mystery = false;
                mode = hiddenMode;
                document.querySelectorAll('#pills .pill[data-m]').forEach(x =>
                    x.classList.toggle('on', x.dataset.m === mode));
                $('guessRow').style.display = 'none';
            }));
        $('inten').addEventListener('input', e => {
            intensity = +e.target.value;
            $('intenV').innerHTML = '&times;' + intensity.toFixed(2).replace(/0+$/, '').replace(/\\.$/, '.0');
        });
        $('defT').addEventListener('click', () => {
            defense = !defense;
            $('defT').classList.toggle('on', defense);
            log('IDS auto-block defense ' + (defense ? 'ENABLED' : 'DISABLED'), defense ? 'ok' : 'warn');
            if (!defense && blocked) { blocked = false; sevStreak = 0; log('attacker unblocked', 'warn'); }
        });
        $('pauseB').addEventListener('click', () => {
            paused = !paused;
            $('pauseB').textContent = paused ? 'Resume' : 'Pause';
        });
        $('resetB').addEventListener('click', () => reset(false));

        log('lab online &mdash; thresholds mirror live_backend.classify_profile()', 'ok');
        setMode('__INIT_MODE__');
        loop();
    </script>
    </body>
    </html>
    """
    components.html(_SIM_LAB.replace("__INIT_MODE__", sim_mode), height=660)
    st.caption(
        "All verdict thresholds are the real ones from `live_backend.py` — "
        "500 pps / SYN:ACK 5 for floods, 20 unique ports for scans, 150 rolling "
        "SYNs for brute-force, rhythmic beacon intervals for C2. Three Severe "
        "windows trigger the same auto-block the live engine writes to "
        "`blocked_ips`."
    )

    st.markdown("---")
    st.markdown("**Behavioral Signatures by Scenario**")
    sig_data = {
        "Scenario": [
            "Normal Web Browsing", "Reconnaissance (Port Scan)", "DDoS SYN Flood",
            "Brute-Force Login", "C2 Beacon (Stealth)"
        ],
        "Typical Packets/Sec": ["< 5", "10 — 50", "> 500", "low (sustained)", "very low (periodic)"],
        "Unique Dest Ports": ["1 — 3", "> 20", "1", "1 (22 / 3389)", "1 (443)"],
        "SYN/ACK Ratio": ["~1.0", "~1.2", "> 5.0", "elevated", "~1.0"],
        "Detection Path": [
            "Rules", "Rules", "Rules + ML",
            "Rolling multi-window state",
            "ML pattern + rolling state"
        ],
        "Threat Classification": [
            "Baseline (Safe)", "Moderate (Suspicious)", "Severe (Critical Anomaly)",
            "Moderate (Suspicious)", "Moderate (Suspicious)"
        ]
    }
    st.dataframe(pd.DataFrame(sig_data), width="stretch", hide_index=True)


elif _active == "PCAP Analysis":
    st.subheader("Offline PCAP Forensic Analysis")
    st.markdown(
        "Upload a capture file to score every flow with the hybrid rule + ML engine. "
        "Complements the live SOC view with after-the-fact investigation."
    )

    if not PCAP_ENGINE_OK:
        st.error(
            "The PCAP analysis engine could not be loaded. Make sure the "
            "'Rui Yang' folder sits alongside the 'Aalok' folder and its "
            "dependencies (scapy, plotly) are installed."
        )
        with st.expander("Error details"):
            st.code(PCAP_ENGINE_ERR)
    else:
        st.info("Supports .pcap, .pcapng and .cap formats")
        uploaded = st.file_uploader(
            "Choose a PCAP file",
            type=["pcap", "pcapng", "cap"],
            key="pcap_upload",
        )

        if uploaded:
            # Streamlit reruns this whole script on ANY widget interaction
            # anywhere on the page (e.g. the report-view toggle below, or a
            # filter on another tab), not just on a new upload. Without this
            # cache, every such rerun would re-run analyse_pcap() on the same
            # file, and since it calls offender_history.record() for every
            # alert flow, repeat reruns silently re-recorded the same flows as
            # new offences, inflating "Prior Hits" in the persistent DB. Only
            # (re-)analyse when the uploaded file itself has actually changed.
            _upload_key = (uploaded.name, uploaded.size)
            if st.session_state.get("pcap_upload_key") != _upload_key:
                tmp_path = os.path.join(_RY_APP_DIR, _safe_upload_name(uploaded.name))
                with open(tmp_path, "wb") as f:
                    f.write(uploaded.read())
                try:
                    with st.spinner("Analysing PCAP file…"):
                        df_results = analyse_pcap(tmp_path)
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                st.session_state["pcap_upload_key"] = _upload_key
                st.session_state["pcap_df_results"] = df_results
            else:
                df_results = st.session_state["pcap_df_results"]

            # The PCAP engine prefixes Severity with a status emoji (e.g. a red
            # circle before "Severe"). Strip any leading non-word chars to a plain
            # label so the dashboard renders text only — done here on our own copy,
            # leaving the engine untouched.
            if not df_results.empty and "Severity" in df_results.columns:
                df_results["Severity"] = (
                    df_results["Severity"].astype(str)
                    .str.replace(r"^[^\w]+", "", regex=True).str.strip()
                )

            if df_results.empty:
                st.warning("No flows found in this PCAP file.")
            else:
                severe   = len(df_results[df_results["Severity"] == "Severe"])
                moderate = len(df_results[df_results["Severity"].str.contains("Moderate")])
                safe     = len(df_results[df_results["Severity"] == "Safe"])
                total    = len(df_results)

                st.markdown('<p class="threat-header">Analysis Summary</p>', unsafe_allow_html=True)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Flows", total)
                c2.metric("Severe", severe)
                c3.metric("Moderate", moderate)
                c4.metric("Safe", safe)

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                chart_col, src_col = st.columns(2)

                with chart_col:
                    st.markdown('<p class="threat-header">Severity Distribution</p>', unsafe_allow_html=True)
                    severity_counts = df_results["Severity"].value_counts().reset_index()
                    severity_counts.columns = ["Severity", "Count"]
                    fig = px.bar(
                        severity_counts, x="Severity", y="Count", color="Severity",
                        color_discrete_map={
                            "Severe": "#F0795A", "Moderate": "#E0B65C",
                            "Safe": "#97C0A4",
                        },
                    )
                    st.plotly_chart(_theme_plotly(fig), use_container_width=True)

                with src_col:
                    st.markdown('<p class="threat-header">Detection Source</p>', unsafe_allow_html=True)
                    source_counts = df_results[
                        df_results["Severity"] != "Safe"
                    ]["Source"].value_counts().reset_index()
                    source_counts.columns = ["Source", "Count"]
                    if not source_counts.empty:
                        fig2 = px.pie(
                            source_counts, values="Count", names="Source",
                            title="What caught the attacks?",
                            color_discrete_sequence=["#D97757", "#97C0A4", "#E0B65C", "#6B87A8"],
                        )
                        # Default right-side legend placement gets clipped by
                        # the container edge in this half-width column,
                        # truncating longer labels (e.g. "Rule + ML" -> "Rule
                        # + N"). A horizontal legend below the chart has the
                        # full column width to lay out in instead.
                        fig2.update_layout(legend=dict(
                            orientation="h", yanchor="bottom", y=-0.3,
                            xanchor="center", x=0.5,
                        ))
                        st.plotly_chart(_theme_plotly(fig2), use_container_width=True)
                    else:
                        st.info("No attacks detected to attribute.")

                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">Alert Details</p>', unsafe_allow_html=True)
                alerts = df_results[df_results["Severity"] != "Safe"]
                if not alerts.empty:
                    st.dataframe(alerts, width="stretch")

                    # ── Threat Analysis Report (Rui Yang · Enhancement Idea 1) ─
                    # Aggregated, always-visible report directly under the alert
                    # table — no row-click needed. Reuses Rui Yang's report.py
                    # helpers; degrades silently if that module isn't importable.
                    if RY_REPORT_OK:
                        st.markdown('<div class="section-divider"></div>',
                                    unsafe_allow_html=True)
                        st.markdown(
                            '<p class="threat-header">Incident Report</p>',
                            unsafe_allow_html=True,
                        )

                        # ── Technical / Management view toggle ────────────
                        if "pcap_report_view" not in st.session_state:
                            st.session_state["pcap_report_view"] = "technical"
                        _tcol, _mcol = st.columns(2)
                        if _tcol.button(
                            "Technical Report", use_container_width=True, key="pcap_view_tech",
                            type="primary" if st.session_state["pcap_report_view"] == "technical" else "secondary",
                        ):
                            st.session_state["pcap_report_view"] = "technical"
                            st.rerun()
                        if _mcol.button(
                            "Management Report", use_container_width=True, key="pcap_view_mgmt",
                            type="primary" if st.session_state["pcap_report_view"] == "management" else "secondary",
                        ):
                            st.session_state["pcap_report_view"] = "management"
                            st.rerun()

                        if "Threat Score" in alerts.columns:
                            _ov = int(pd.to_numeric(
                                alerts["Threat Score"], errors="coerce"
                            ).max())
                        else:
                            _ov = 0
                        _band, _bcol = (
                            ("Normal", "#97C0A4") if _ov <= 20 else
                            ("Low", "#9FC08A")     if _ov <= 40 else
                            ("Medium", "#E0B65C")  if _ov <= 60 else
                            ("High", "#F0A063")    if _ov <= 80 else
                            ("Critical", "#F0795A")
                        )

                        if st.session_state["pcap_report_view"] == "technical":
                            st.markdown(
                                "<div style='display:flex;align-items:baseline;gap:12px;"
                                "margin-bottom:6px'>"
                                f"<span style='font-size:40px;font-weight:800;color:{_bcol};"
                                "font-family:JetBrains Mono,monospace;line-height:1'>"
                                f"{_ov}</span><span style='color:#7C7A70'>/ 100</span>"
                                f"<span style='font-size:14px;font-weight:700;color:{_bcol};"
                                f"letter-spacing:.06em'>{_band.upper()}</span></div>"
                                "<div style='height:10px;border-radius:6px;background:#2B2A28;"
                                "overflow:hidden'>"
                                f"<div style='width:{max(0,min(100,_ov))}%;height:100%;"
                                f"background:{_bcol}'></div></div>",
                                unsafe_allow_html=True,
                            )

                            st.markdown("**Detected**")
                            for _atk, _cnt in _ry_attack_breakdown(alerts).most_common():
                                st.markdown(f"- {_atk} — {_cnt} flow(s)")

                            _rc1, _rc2 = st.columns(2)
                            with _rc1:
                                st.markdown("**Possible reasons**")
                                for _r in _ry_build_reasons(alerts):
                                    st.markdown(f"- {_r}")
                            with _rc2:
                                st.markdown("**Suggested actions**")
                                for _a in _ry_build_actions(alerts):
                                    st.markdown(f"- {_a}")

                            st.markdown("**Top attacking sources**")
                            _att = _ry_top_attackers(alerts, get_ip_location, limit=5)
                            st.dataframe(pd.DataFrame(_att), width="stretch",
                                         hide_index=True)

                            # ── Per-attack detail cards (only when few attacks) ──
                            # 5 or fewer alerts -> give each its own focused card;
                            # beyond that the aggregate above plus the flow table is
                            # clearer than a long stack of cards. Wrapped defensively
                            # so an older Streamlit (no border= / width=) or a bad
                            # row can't blank out the whole report.
                            _PER_ATTACK_LIMIT = 5
                            try:
                                _n_alerts = len(alerts)
                                # Always show the first N (matching the Management
                                # view below) instead of an all-or-nothing cutoff -
                                # that previously meant 6+ alerts showed ZERO
                                # per-attack detail on screen here. "First N" is
                                # now highest Threat Score, not just whichever
                                # happened to appear earliest.
                                st.markdown(
                                    '<p class="threat-header" '
                                    'style="margin-top:14px;">Per-Attack '
                                    'Breakdown</p>',
                                    unsafe_allow_html=True,
                                )
                                _ranked_alerts = _ry_rank_by_threat_score(alerts)
                                for _card in _ry_per_attack_cards(
                                        _ranked_alerts.head(_PER_ATTACK_LIMIT), get_ip_location):
                                    st.markdown(
                                        f"**{_card['reason_name']}** "
                                        f"— Score {_card['score']} "
                                        f"({_card['level']})"
                                    )
                                    st.markdown(
                                        f"`{_card['src']}` → `{_card['dst']}` "
                                        f": port {_card['port']}"
                                    )
                                    st.markdown(f"**Why:** {_card['why']}")
                                    st.markdown(f"**Action:** {_card['action']}")
                                    st.caption(f"Origin: {_card['origin']}")
                                    st.markdown(
                                        '<div class="section-divider"></div>',
                                        unsafe_allow_html=True,
                                    )
                                if _n_alerts > _PER_ATTACK_LIMIT:
                                    st.info(
                                        f"{_n_alerts - _PER_ATTACK_LIMIT} additional attack(s) "
                                        "not shown here; per-flow detail is in the flow table, "
                                        "or download the Word report below for full detail."
                                    )
                            except Exception as _card_err:
                                st.caption(
                                    "Per-attack breakdown unavailable "
                                    f"({_card_err})."
                                )

                            if RY_DOCX_OK:
                                _offer_word_report(
                                    lambda: _ry_build_technical_docx(
                                        alerts, _ov, f"{_band}", get_ip_location
                                    ),
                                    "threat_analysis_report.docx",
                                    "pcap_docx_tech",
                                )

                        elif not RY_MGMT_REPORT_OK:
                            st.warning(
                                "Management report module could not be loaded "
                                "(management_report.py missing from Rui Yang/scripts)."
                            )
                        else:
                            # ── Management Report (plain English) ─────────
                            try:
                                st.info(_ry_build_overall_summary(alerts, _ov, f"{_band}"))

                                st.markdown("**What was detected**")
                                for _label, _cnt in _ry_attack_type_counts_plain(alerts).most_common():
                                    _cnt_word = "event" if _cnt == 1 else "events"
                                    st.markdown(f"- {_label} — {_cnt} {_cnt_word}")

                                st.markdown(
                                    '<p class="threat-header" '
                                    'style="margin-top:14px;">Incident Details</p>',
                                    unsafe_allow_html=True,
                                )
                                _MGMT_CARD_LIMIT = 5
                                _mgmt_cards = _ry_build_incident_cards(
                                    _ry_rank_by_threat_score(alerts), get_ip_location)
                                for _card in _mgmt_cards[:_MGMT_CARD_LIMIT]:
                                    st.markdown(
                                        f"**Source:** {_card['origin']}  \n"
                                        f"**When:** {_card['start']} to {_card['end']}  \n"
                                        f"**Rating:** {_card['level']}"
                                    )
                                    st.markdown(f"**What happened:** {_card['what']}")
                                    st.markdown(f"**Data exposure:** {_card['exposure']}")
                                    st.markdown(f"**Severity:** {_card['severity_sentence']}")
                                    st.markdown(
                                        f"**Recommended next step / lesson learnt:** {_card['takeaway']}"
                                    )
                                    if _card["prior"]:
                                        _prior_word = "prior incident" if _card['prior'] == 1 else "prior incidents"
                                        st.caption(
                                            f"This source has {_card['prior']} {_prior_word} on record."
                                        )
                                    st.markdown(
                                        '<div class="section-divider"></div>',
                                        unsafe_allow_html=True,
                                    )
                                if len(_mgmt_cards) > _MGMT_CARD_LIMIT:
                                    _extra_n = len(_mgmt_cards) - _MGMT_CARD_LIMIT
                                    _extra_word = "additional lower-priority event" if _extra_n == 1 else "additional lower-priority events"
                                    st.info(
                                        f"{_extra_n} {_extra_word} not shown here — see the "
                                        "Technical Report for the full list."
                                    )

                                if RY_DOCX_OK:
                                    _offer_word_report(
                                        lambda: _ry_build_management_docx(
                                            alerts, _ov, f"{_band}", get_ip_location
                                        ),
                                        "management_incident_report.docx",
                                        "pcap_docx_mgmt",
                                    )
                            except Exception as _mgmt_err:
                                st.caption(f"Management report unavailable ({_mgmt_err}).")

                    # ── Flow Triage — Raw Hex Inspector ───────────────────────
                    # Same scoped inspector as the Live SOC tab, fed by Rui
                    # Yang's flow records; MITRE mapping derived from the rule
                    # that fired (Aaron), attribution from the flow features.
                    st.markdown(
                        '<p class="threat-header" style="margin-top:14px;">Flow Triage — Raw Hex Inspector</p>',
                        unsafe_allow_html=True,
                    )
                    _pcap_triage = alerts.head(25).reset_index(drop=True)
                    _pcap_labels = [
                        f"{r['Src IP']} → {r['Dst IP']} :{r['Port']} · {r['Severity']} · {r['Reason']}"
                        for _, r in _pcap_triage.iterrows()
                    ]
                    _ppick = st.selectbox(
                        "Select flow to inspect",
                        range(len(_pcap_labels)),
                        format_func=lambda i: _pcap_labels[i],
                        key="pcap_triage_pick",
                    )
                    with st.expander("Raw hex inspector", expanded=True):
                        prow = _pcap_triage.iloc[_ppick]
                        try:
                            _pconf = float(str(prow.get("Confidence", "0")).rstrip("%"))
                        except ValueError:
                            _pconf = 0.0
                        try:
                            _ppkts = float(prow.get("Packets", 0) or 0)
                        except (TypeError, ValueError):
                            _ppkts = 0.0
                        _p_port = prow.get("Port", 443)
                        _p_meta = {
                            "Flow": prow.get("Flow", "—"),
                            "Source IP": prow["Src IP"],
                            "Destination IP": prow["Dst IP"],
                            "Destination Port": _p_port,
                            "Packets in Flow": prow.get("Packets", "—"),
                            "Verdict": f"{prow['Severity']} · {prow['Reason']}",
                            "Detection Source": prow.get("Source", "—"),
                            "Engine Confidence": prow.get("Confidence", "—"),
                        }
                        _p_mitre = None
                        if MITRE_OK:
                            _ptid, _psub, _pname, _ptac, _ = tag_mitre(str(prow.get("Reason", "")))
                            if _ptid and str(_ptid) != "N/A":
                                _p_mitre = {
                                    "id": _ptid, "sub": _psub or "—", "name": _pname,
                                    "tactic": _ptac, "color": tactic_color(_ptac),
                                    "url": mitre_url(_ptid, _psub),
                                }
                        try:
                            _p_known_port = int(float(_p_port)) in (80, 443, 53)
                        except (TypeError, ValueError):
                            _p_known_port = True
                        _p_attrib = [
                            ("engine_confidence", min(1.0, _pconf / 100.0)),
                            ("flow_volume", min(1.0, _ppkts / 200.0)),
                            ("dst_port_profile", -0.6 if _p_known_port else 0.6),
                        ]
                        render_hex_inspector(
                            seed=f"{prow['Src IP']}|{prow['Dst IP']}|{_p_port}",
                            src_ip=prow["Src IP"], dst_ip=prow["Dst IP"], port=_p_port,
                            profile=prow.get("Reason", ""), verdict=prow["Severity"],
                            meta=_p_meta, mitre=_p_mitre, attrib=_p_attrib,
                        )
                        st.caption(
                            "Payload bytes are a deterministic synthetic reconstruction "
                            "themed to the detection reason — header fields carry the "
                            "real flow endpoints and port."
                        )
                else:
                    st.success("No threats detected in this PCAP file.")

                with st.expander("View All Flows"):
                    st.dataframe(df_results, width="stretch")

                # Hand off to the Threat Map tab
                st.session_state["pcap_results"] = df_results


elif _active == "Threat Map":
    # Animated Leaflet flow map — attacker/normal points animate along
    # a line toward a fixed anchor ("My Computer"). Plotly's geo traces can't do
    # smooth moving markers inside Streamlit without full-script reruns, so this
    # renders as a self-contained iframe via components.html(), same pattern the
    # dashboard already uses elsewhere (e.g. the attack-simulation canvas above).
    _THREAT_FLOW_MAP_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
  html, body { margin: 0; padding: 0; background: #141413; }
  #map { width: 100%; height: 540px; background: #141413; }
  .leaflet-container { background: #141413; font-family: 'Inter', 'Segoe UI', sans-serif; }
  .leaflet-popup-content-wrapper {
    background: #1E1D1B; color: #FAF9F5; border: 1px solid #2B2A28; border-radius: 8px;
  }
  .leaflet-popup-content { font-size: 12.5px; line-height: 1.5; margin: 8px 10px; }
  .leaflet-popup-content b { color: #F0795A; }
  .leaflet-popup-tip { background: #1E1D1B; }
  .flow-legend {
    position: absolute; bottom: 10px; left: 10px; z-index: 1000;
    background: rgba(26,25,24,0.85); border: 1px solid #2B2A28; border-radius: 8px;
    padding: 8px 12px; font-family: 'Inter', sans-serif; font-size: 11.5px; color: #C9C7BE;
  }
  .flow-legend .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
  .flow-legend div { margin: 2px 0; }
  .flow-label {
    background: rgba(20,20,19,0.82); border: none; box-shadow: none;
    color: #FAF9F5; font-family: 'JetBrains Mono', monospace; font-size: 10.5px;
    padding: 1px 5px; border-radius: 4px; pointer-events: none;
  }
  .flow-label.attack-label { color: #F0795A; }
  .flow-label.normal-label { color: #C9C7BE; opacity: 0.8; }
  .flow-label::before { display: none; }
</style>
</head>
<body>
<div id="map"></div>
<div class="flow-legend">
  <div><span class="dot" style="background:#F0795A;"></span>Malicious traffic &rarr; My Computer</div>
  <div><span class="dot" style="background:#FAFAFA;"></span>Normal traffic &rarr; My Computer</div>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
(function () {
  var ANCHOR = [__ANCHOR_LAT__, __ANCHOR_LON__];
  var ATTACK_POINTS = __ATTACK_POINTS__;
  var NORMAL_POINTS = __NORMAL_POINTS__;

  var map = L.map('map', { zoomControl: true }).setView(ANCHOR, 2);

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; <a href="https://carto.com/attributions">CARTO</a> &copy; OpenStreetMap contributors',
    subdomains: 'abcd',
    maxZoom: 19,
  }).addTo(map);

  L.marker(ANCHOR, {
    icon: L.divIcon({
      className: '',
      html: '<div style="width:16px;height:16px;border-radius:50%;background:#97C0A4;' +
            'border:2px solid #FAF9F5;box-shadow:0 0 12px 4px rgba(151,192,164,0.6);"></div>',
      iconSize: [16, 16], iconAnchor: [8, 8],
    }),
  }).addTo(map)
    .bindPopup('<b>My Computer</b><br>Monitored network')
    .bindTooltip('My Computer', {
      permanent: true, direction: 'top', offset: [0, -10], className: 'flow-label',
    });

  // Interpolating raw lat/lon puts the dot off the line: Leaflet draws the
  // polyline straight in *projected* pixel space (Web Mercator), which is a
  // different curve than a straight line in lat/lon space, especially over
  // long distances. Projecting both endpoints and interpolating in pixel
  // space keeps the dot exactly on the line Leaflet actually renders.
  function lerpOnMap(from, to, t) {
    var zoom = map.getZoom();
    var p1 = map.project(from, zoom);
    var p2 = map.project(to, zoom);
    var px = p1.add(p2.subtract(p1).multiplyBy(t));
    return map.unproject(px, zoom);
  }

  // Mirrors the engine's own packet-rate normalization (Flow Packets/s / 500,
  // capped at 5 — see pkt_score in pcap_engine.py) so "fast" on the map means
  // the same thing as "fast" to the scoring model: a DDoS flood races in,
  // a slow scan crawls.
  function speedFor(pps, maxMs, minMs) {
    var intensity = Math.min((pps || 0) / 500, 5);
    return maxMs - (intensity / 5) * (maxMs - minMs);
  }

  function addFlow(point, opts) {
    var from = L.latLng(point.lat, point.lon);
    var to = L.latLng(ANCHOR[0], ANCHOR[1]);
    var popupHtml = '<b>' + point.ip + '</b><br>' +
      (point.city ? point.city + ', ' : '') + point.country + '<br>' +
      (point.reason ? point.reason + '<br>' : '') +
      opts.label + ': ' + point.weight +
      (point.pps ? ' &middot; ' + Math.round(point.pps) + ' pkt/s' : '');

    var line = L.polyline([from, to], {
      color: opts.color, weight: opts.lineWeight, opacity: opts.lineOpacity,
    }).addTo(map);
    line.bindPopup(popupHtml);
    line.on('mouseover', function () { line.setStyle({ opacity: Math.min(opts.lineOpacity * 2.5, 0.9) }); });
    line.on('mouseout', function () { line.setStyle({ opacity: opts.lineOpacity }); });

    // Fixed marker at the true source location, separate from the animated
    // dot below — the moving dot alone gives the line no readable origin,
    // so this pins a permanent location label right where the flow
    // originates. City is more compact than a full IP; the IP itself is
    // still in the popup on hover/click.
    if (opts.showLabel) {
      var labelText = point.city || point.country || point.ip;
      L.circleMarker(from, {
        radius: 4, color: opts.color, fillColor: opts.color,
        fillOpacity: 0.55, weight: 1.5, opacity: 0.9,
      }).addTo(map)
        .bindPopup(popupHtml)
        .bindTooltip(labelText, {
          permanent: true, direction: 'right', offset: [6, 0],
          className: 'flow-label ' + opts.labelClass,
        });
    }

    var marker = L.circleMarker(from, {
      radius: opts.dotRadius, color: opts.color, fillColor: opts.color,
      fillOpacity: 1, weight: 0,
    }).addTo(map);
    marker.bindPopup(popupHtml);
    marker.on('mouseover', function () { marker.openPopup(); });

    var durationMs = speedFor(point.pps, opts.maxMs, opts.minMs);
    var startOffset = Math.random() * durationMs;

    function animate(ts) {
      var t = ((ts + startOffset) % durationMs) / durationMs;
      marker.setLatLng(lerpOnMap(from, to, t));
      requestAnimationFrame(animate);
    }
    requestAnimationFrame(animate);
  }

  ATTACK_POINTS.forEach(function (p) {
    addFlow(p, {
      color: '#F0795A', lineWeight: 1.5, lineOpacity: 0.35,
      dotRadius: 5, maxMs: 3200, minMs: 700, label: 'Attacks',
      showLabel: true, labelClass: 'attack-label',
    });
  });

  NORMAL_POINTS.forEach(function (p) {
    addFlow(p, {
      color: '#FAFAFA', lineWeight: 1, lineOpacity: 0.15,
      dotRadius: 3, maxMs: 4200, minMs: 1800, label: 'Packets',
      showLabel: true, labelClass: 'normal-label',
    });
  });
})();
</script>
</body>
</html>
"""

    st.subheader("Global Threat Origin Map")

    if not PCAP_ENGINE_OK:
        st.error("The threat-map engine could not be loaded (see the PCAP Analysis tab).")
    elif "pcap_results" not in st.session_state:
        st.info("Upload and analyse a PCAP file in the PCAP Analysis tab first to populate the map.")
    else:
        df_results = st.session_state["pcap_results"]
        attacks = df_results[df_results["Severity"] != "Safe"]
        normal  = df_results[df_results["Severity"] == "Safe"]

        if attacks.empty and normal.empty:
            st.info("No flows to map yet.")
        else:
            st.info("Resolving IP locations… (private IPs are skipped)")

            # Normal-traffic IPs are capped so a mixed-traffic capture can't
            # burn through the free ip-api.com lookup's rate limit — attacker
            # IPs matter more for this feature and are never capped.
            _NORMAL_IP_CAP = 15
            attack_counts = attacks["Src IP"].value_counts()
            normal_counts = normal["Src IP"].value_counts().head(_NORMAL_IP_CAP)

            jobs = [(ip, "attack") for ip in attack_counts.index] + \
                   [(ip, "normal") for ip in normal_counts.index]

            attack_points, normal_points = [], []
            progress = st.progress(0)
            for i, (ip, kind) in enumerate(jobs):
                loc = get_ip_location(ip)
                if loc:
                    src_df = attacks if kind == "attack" else normal
                    ip_rows = src_df[src_df["Src IP"] == ip]
                    counts = attack_counts if kind == "attack" else normal_counts
                    # Peak packet rate drives the flow's animation speed below —
                    # a DDoS flood should visibly race in faster than a slow scan.
                    point = {
                        "ip": ip, "lat": loc["lat"], "lon": loc["lon"],
                        "country": loc.get("country") or "Unknown",
                        "city": loc.get("city") or "",
                        "weight": int(counts[ip]),
                        "pps": float(ip_rows["Pkts/s"].max()) if "Pkts/s" in ip_rows else 0.0,
                    }
                    if kind == "attack" and "Reason" in ip_rows:
                        point["reason"] = str(ip_rows["Reason"].mode().iloc[0])
                    (attack_points if kind == "attack" else normal_points).append(point)
                progress.progress((i + 1) / max(len(jobs), 1))
            progress.empty()

            if attack_points or normal_points:
                # Fixed illustrative anchor every flow animates toward — not
                # real self-geolocation, matches the point Aalok's dashboard
                # already converged arcs on (previously labelled "SOC").
                _ANCHOR_LAT, _ANCHOR_LON = 1.3521, 103.8198

                _map_html = (
                    _THREAT_FLOW_MAP_TEMPLATE
                    .replace("__ANCHOR_LAT__", str(_ANCHOR_LAT))
                    .replace("__ANCHOR_LON__", str(_ANCHOR_LON))
                    .replace("__ATTACK_POINTS__", json.dumps(attack_points))
                    .replace("__NORMAL_POINTS__", json.dumps(normal_points))
                )
                components.html(_map_html, height=560)

                st.markdown('<p class="threat-header">Attacker Details</p>', unsafe_allow_html=True)
                if attack_points:
                    st.dataframe(
                        pd.DataFrame(attack_points)[["ip", "country", "city", "weight"]]
                          .rename(columns={"weight": "attacks"}),
                        width="stretch",
                    )
                else:
                    st.caption("No attacker IPs resolved to a public location for this capture.")
            else:
                st.warning("All source IPs are private/local — no locations to map.")
                st.info("Try a PCAP with public source IPs for the map to populate.")


elif _active == "Model Intelligence":
    st.subheader("Model Intelligence")
    st.markdown(
        "Explainability, sequence modelling, and automated retraining for the "
        "detection models — Megan's v2 feature set."
    )

    if not MODEL_INTEL_OK:
        st.error(
            "The Model Intelligence modules could not be loaded. Make sure the "
            "'Megan' folder sits alongside the 'Aalok' folder and its dependencies "
            "(shap, torch, matplotlib) are installed."
        )
        with st.expander("Error details"):
            st.code(MODEL_INTEL_ERR)
    else:
        # ── SHAP explainability ───────────────────────────────────────────────
        st.markdown('<p class="threat-header">SHAP Explainability</p>', unsafe_allow_html=True)
        render_shap_panel()

        # ── LSTM sequence model status ────────────────────────────────────────
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown('<p class="threat-header">LSTM Sequence Model</p>', unsafe_allow_html=True)
        st.caption(
            "Captures temporal attack patterns across consecutive capture windows "
            "that the per-window Random Forest cannot see (e.g. a slow port scan)."
        )
        try:
            from lstm_model import load_lstm, MODEL_PATH as _LSTM_PATH
            _lstm = load_lstm()
            if _lstm is not None:
                st.success(f"LSTM model loaded: `{_LSTM_PATH.name}`")
            elif not _LSTM_PATH.exists():
                st.info("LSTM model not trained yet. Train with: "
                        "`python Megan/lstm_model.py --train`")
            else:
                st.warning("PyTorch is not installed — LSTM inference unavailable. "
                           "`pip install torch`")
        except Exception as _lstm_exc:
            st.caption(f"LSTM unavailable: {_lstm_exc}")

        # ── LSTM explainability ───────────────────────────────────────────────
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown('<p class="threat-header">LSTM SHAP Explainability</p>', unsafe_allow_html=True)
        render_lstm_shap_panel()

        # ── Automated retraining ──────────────────────────────────────────────
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown('<p class="threat-header">Automated Retraining</p>', unsafe_allow_html=True)
        if _IS_DESKTOP_APP:
            # The one-file build unpacks Dashboard/ to a private temp folder that
            # Windows deletes when the window closes, and a retrain writes the new
            # rf_model.pkl straight back into it. So it genuinely retrains and the
            # panel genuinely reports success — the model is just gone next launch.
            # Say so up front rather than let someone retrain, restart, and wonder
            # why the version history is empty.
            st.info(
                "Retraining works here, but the retrained model lasts only until "
                "this window is closed — the packaged app runs from a temporary "
                "folder. Run the dashboard from source to keep a retrained model."
            )
        render_retrain_panel()

elif _active == "Defense Config":
    st.subheader("Defense Config")
    st.markdown(
        "Operational controls for the detection engine and alerting — managed "
        "from the dashboard instead of hand-editing files. Changes to the "
        "detection lists are picked up by the live backend on its next capture "
        "window; notifier changes apply on the next Severe alert."
    )

    # ═══════════════════════════════════════════════════════════════════════
    # DETECTION LISTS — threat-intel (malicious) and baseline (whitelist)
    # ═══════════════════════════════════════════════════════════════════════
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    st.markdown('<p class="threat-header">Detection Lists</p>', unsafe_allow_html=True)
    st.caption(
        "Threat-intel IPs are forced to **Severe**; baseline IPs are forced to "
        "**Baseline (Safe)**. Precedence: threat-intel beats baseline."
    )

    _list_specs = [
        (THREAT_INTEL_FILE, "Threat-Intel (malicious)", "", "intel"),
        (BASELINE_FILE, "Baseline (whitelist)", _DEFAULT_BASELINE_HEADER, "baseline"),
    ]
    _list_cols = st.columns(2)
    for _col, (_path, _title, _default_header, _kind) in zip(_list_cols, _list_specs):
        with _col:
            _header, _ips = _read_ip_file(_path)
            st.metric(_title, f"{len(_ips)} IP(s)")
            _edited = st.text_area(
                "One IPv4 per line",
                value="\n".join(_ips),
                key=f"ips_text_{_kind}",
                height=220,
            )
            if st.button(f"Save {_title}", key=f"ips_save_{_kind}"):
                _cands = [ln.strip() for ln in _edited.splitlines() if ln.strip()]
                _bad = [c for c in _cands if not _is_valid_ipv4(c)]
                if _bad:
                    st.error(f"Invalid IPv4 address(es): {', '.join(_bad[:5])}")
                else:
                    _write_ip_file(_path, _header or _default_header, _cands)
                    st.success(
                        f"Saved {len(set(_cands))} IP(s) to {_path}. "
                        "Live backend applies it next window."
                    )

    # ═══════════════════════════════════════════════════════════════════════
    # ALERT NOTIFIER — email / Discord / Slack config + test send
    # ═══════════════════════════════════════════════════════════════════════
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    st.markdown('<p class="threat-header">Alert Notifier</p>', unsafe_allow_html=True)

    _ncfg, _nsrc = _load_notifier_config()
    # NOT named `_active`: in this build that name holds the segmented-control
    # nav selection driving the if/elif view chain this block sits inside.
    # Reusing it here shadowed the nav variable — harmless only because an
    # elif chain stops at the first match, which is far too subtle to leave
    # standing next to a chain that gains new branches over time.
    _active_channels = [c for c in ("email", "discord", "slack")
                        if _ncfg.get(c, {}).get("enabled")]
    st.caption(
        f"Editing **{_nsrc}** — file is gitignored (holds plaintext SMTP creds). "
        f"Active channels: **{', '.join(_active_channels) if _active_channels else 'none'}**. "
        "Severe alerts are throttled to one per source IP per channel per hour "
        "by the backend process."
    )

    _em = _ncfg.get("email", {})
    _dc = _ncfg.get("discord", {})
    _sl = _ncfg.get("slack", {})

    with st.form("notifier_config_form"):
        st.markdown("**Email (SMTP)**")
        _em_enabled = st.checkbox("Enable email", value=bool(_em.get("enabled")))
        _ec1, _ec2 = st.columns(2)
        with _ec1:
            _smtp_host = st.text_input("SMTP host", value=_em.get("smtp_host", ""))
            _username = st.text_input("Username", value=_em.get("username", ""))
            _from_addr = st.text_input("From address", value=_em.get("from_addr", ""))
        with _ec2:
            _smtp_port = st.number_input(
                "SMTP port", value=int(_em.get("smtp_port", 587)), step=1, min_value=1
            )
            _password = st.text_input(
                "Password", value="", type="password",
                help="Leave blank to keep the existing password.",
            )
            _to_addrs = st.text_input(
                "To (comma-separated)", value=", ".join(_em.get("to_addrs", []))
            )
        _tls_col, _ssl_col = st.columns(2)
        with _tls_col:
            _use_tls = st.checkbox("Use STARTTLS", value=bool(_em.get("use_tls", True)))
        with _ssl_col:
            _use_ssl = st.checkbox("Use SSL", value=bool(_em.get("use_ssl", False)))

        st.markdown("**Discord**")
        _dc_enabled = st.checkbox("Enable Discord", value=bool(_dc.get("enabled")))
        _dc_url = st.text_input(
            "Discord webhook URL", value="", type="password",
            help="Leave blank to keep the existing webhook URL.",
        )

        st.markdown("**Slack**")
        _sl_enabled = st.checkbox("Enable Slack", value=bool(_sl.get("enabled")))
        _sl_url = st.text_input(
            "Slack webhook URL", value="", type="password",
            help="Leave blank to keep the existing webhook URL.",
        )

        _saved = st.form_submit_button("Save notifier config")

    if _saved:
        _new_cfg = {
            "email": {
                "enabled": _em_enabled,
                "smtp_host": _smtp_host,
                "smtp_port": int(_smtp_port),
                "use_tls": _use_tls,
                "use_ssl": _use_ssl,
                "username": _username,
                "password": _password or _em.get("password", ""),
                "from_addr": _from_addr,
                "to_addrs": [a.strip() for a in _to_addrs.split(",") if a.strip()],
            },
            "discord": {
                "enabled": _dc_enabled,
                "webhook_url": _dc_url or _dc.get("webhook_url", ""),
            },
            "slack": {
                "enabled": _sl_enabled,
                "webhook_url": _sl_url or _sl.get("webhook_url", ""),
            },
        }
        _save_notifier_config(_new_cfg)
        st.success("Saved notifier_config.json.")

    st.markdown("**Test the notifier**")
    st.caption(
        "Sends a synthetic Severe alert from the dashboard process to all enabled "
        "channels. (The backend keeps its own throttle state, separate from this.)"
    )
    if st.button("Send test alert", key="notifier_test_btn"):
        _cfg_now, _ = _load_notifier_config()
        _active_now = [c for c in ("email", "discord", "slack")
                       if _cfg_now.get(c, {}).get("enabled")]
        if not _active_now:
            st.info("No channels enabled — enable a channel and Save first.")
        else:
            try:
                import importlib
                import notifier as _notifier
                importlib.reload(_notifier)  # pick up the freshly-saved config
                _notifier.notify_severe({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source_ip": "203.0.113.1",  # RFC 5737 test address
                    "profile": "Test Alert (Dashboard)",
                    "threat": "Severe (Critical Anomaly)",
                    "pps": 999.0,
                    "sar": 9.9,
                    "total_bytes": 123456,
                    "confidence": 1.0,
                })
                st.success(
                    f"Test alert dispatched to: {', '.join(_active_now)}. "
                    "Check the channel(s) / console for delivery."
                )
            except Exception as _test_exc:
                st.error(f"Test send failed: {_test_exc}")


# ═══════════════════════════════════════════════════════════════════════════
# DETECTION BENCHMARK VIEW
# ═══════════════════════════════════════════════════════════════════════════
# "How often is the model right?", answered against labelled ground truth.
#
# Deliberately separate from the Model Intelligence view: that tab explains why
# a single decision was made (SHAP, LSTM sequence view) and covers the LSTM.
# This one measures how often the RANDOM FOREST is right across a whole
# labelled dataset — a different model and a different question, so it gets
# its own view rather than crowding that one.
#
# The evaluation itself lives in evaluate_benchmark.py (same folder, also
# runnable as a CLI). Nothing here recomputes a metric.
elif _active == "Detection Benchmark":
    st.subheader("Detection Benchmark")
    st.markdown(
        "Scores the Random Forest classifier against a **labelled** benchmark "
        "dataset — CIC-IDS-2017 / 2018 style, or any CSV with flow features "
        "plus a ground-truth `Label` column — and checks the result against "
        "this project's stated performance targets."
    )

    if not BENCHMARK_OK:
        st.warning(
            "The benchmark module could not be loaded "
            "(evaluate_benchmark.py missing from the Dashboard folder)."
        )
    else:
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown(
            '<p class="threat-header">Performance Targets</p>',
            unsafe_allow_html=True,
        )
        st.caption(
            "These are the targets the project is measured against. A run has "
            "to clear every one of them to count as a pass."
        )
        _target_rows = []
        for _k, (_label, _target, _lower, _unit) in _bench.SPEC_TARGETS.items():
            _shown = f"{_target*100:.0f}%" if _unit == "%" else f"{_target:.0f} ms"
            _target_rows.append({
                "Metric": _label,
                "Target": f"{'below' if _lower else 'at least'} {_shown}",
            })
        st.dataframe(pd.DataFrame(_target_rows), width="stretch", hide_index=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown(
            '<p class="threat-header">Run a Benchmark</p>',
            unsafe_allow_html=True,
        )
        st.caption(
            "The CSV needs a `Label` column (`BENIGN` for normal traffic, the "
            "attack name otherwise). Standard CIC-IDS column names are mapped "
            "automatically; any feature the file does not carry is treated as "
            "zero, so a partial column set still runs — it just measures the "
            "model on less information."
        )

        _bench_file = st.file_uploader(
            "Labelled benchmark CSV", type=["csv"], key="benchmark_csv"
        )

        if _bench_file is not None:
            _res = None
            try:
                with st.spinner("Scoring the model against ground truth..."):
                    _bench_df = pd.read_csv(_bench_file, low_memory=False)
                    _res = _bench.evaluate_dataframe(_bench_df)
            except _bench.BenchmarkError as _bexc:
                st.error(f"Could not evaluate this file: {_bexc}")
            except Exception as _bexc:
                st.error(f"Unexpected error while evaluating: {_bexc}")

            if _res:
                st.success(
                    f"Scored {_res['rows']:,} flows — "
                    f"{_res['attack_rows']:,} attack, "
                    f"{_res['benign_rows']:,} benign."
                )

                # ── Headline: one gauge per spec target ───────────────────
                st.markdown(
                    '<p class="threat-header" style="margin-top:14px;">Results '
                    'vs Targets</p>',
                    unsafe_allow_html=True,
                )
                _metric_keys = ["detection_rate", "false_positive",
                                "precision", "f1", "latency_ms"]
                _cols = st.columns(len(_metric_keys))
                for _col, _key in zip(_cols, _metric_keys):
                    _label, _target, _lower, _unit = _bench.SPEC_TARGETS[_key]
                    _val = _res[_key]
                    _ok = _bench.passes(_key, _val)
                    if _unit == "%":
                        _shown = f"{_val*100:.2f}%"
                        _target_txt = f"{'<' if _lower else '>'} {_target*100:.0f}%"
                    else:
                        _shown = f"{_val:.3f} ms"
                        _target_txt = f"< {_target:.0f} ms"
                    _col.metric(
                        _label, _shown,
                        f"{'PASS' if _ok else 'FAIL'} · target {_target_txt}",
                        delta_color="normal" if _ok else "inverse",
                    )

                _all_pass = all(_bench.passes(_k, _res[_k]) for _k in _metric_keys)
                if _all_pass:
                    st.success("All performance targets met on this dataset.")
                else:
                    _failed = [_bench.SPEC_TARGETS[_k][0] for _k in _metric_keys
                               if not _bench.passes(_k, _res[_k])]
                    st.warning(
                        "Below target on: " + ", ".join(_failed) + ". "
                        "The per-attack table below shows which attack types "
                        "are responsible."
                    )

                # ── Confusion matrix ──────────────────────────────────────
                st.markdown(
                    '<p class="threat-header" style="margin-top:14px;">'
                    'Confusion Matrix</p>',
                    unsafe_allow_html=True,
                )
                _cm = pd.DataFrame(
                    [[_res['tp'], _res['fn']], [_res['fp'], _res['tn']]],
                    index=["Actually Attack", "Actually Benign"],
                    columns=["Flagged Attack", "Flagged Benign"],
                )
                _cm_col, _cm_note = st.columns([2, 3])
                _cm_col.dataframe(_cm, width="stretch")
                _cm_note.markdown(
                    f"- **{_res['tp']:,} caught** — attacks correctly flagged.\n"
                    f"- **{_res['fn']:,} missed** — attacks that slipped through. "
                    f"This is the number that matters most; a miss is an "
                    f"intrusion nobody sees.\n"
                    f"- **{_res['fp']:,} false alarms** — benign traffic flagged. "
                    f"Costly in a different way: they train analysts to ignore "
                    f"the dashboard.\n"
                    f"- **{_res['tn']:,} correctly ignored.**"
                )

                # ── Per-attack detection rate ─────────────────────────────
                _per_attack = _res.get('per_attack')
                if _per_attack is not None and len(_per_attack):
                    st.markdown(
                        '<p class="threat-header" style="margin-top:14px;">'
                        'Detection Rate by Attack Type</p>',
                        unsafe_allow_html=True,
                    )
                    st.caption(
                        "Worst first. The headline Detection Rate averages every "
                        "attack type together, which can hide a class the model "
                        "misses outright — this splits it back out."
                    )
                    _pa_display = _per_attack.copy()
                    _pa_display["Detection Rate"] = (
                        _pa_display["Detection Rate"] * 100
                    ).map(lambda v: f"{v:.2f}%")
                    st.dataframe(_pa_display, width="stretch", hide_index=True)

                    _blind = _per_attack[_per_attack["Detection Rate"] == 0]
                    if len(_blind):
                        st.error(
                            "Missed entirely: "
                            + ", ".join(_blind["Attack Type"].tolist())
                            + ". The model has no detection capability for "
                            "these on this dataset."
                        )

                # ── Export ────────────────────────────────────────────────
                st.markdown(
                    '<p class="threat-header" style="margin-top:14px;">Export</p>',
                    unsafe_allow_html=True,
                )
                _summary_rows = [{
                    "Metric": _bench.SPEC_TARGETS[_k][0],
                    "Value": (f"{_res[_k]*100:.4f}"
                              if _bench.SPEC_TARGETS[_k][3] == "%"
                              else f"{_res[_k]:.4f}"),
                    "Unit": _bench.SPEC_TARGETS[_k][3],
                    "Target": _bench.SPEC_TARGETS[_k][1],
                    "Result": "PASS" if _bench.passes(_k, _res[_k]) else "FAIL",
                } for _k in _metric_keys]
                _summary_rows += [
                    {"Metric": "True Positives", "Value": _res['tp'],
                     "Unit": "flows", "Target": "", "Result": ""},
                    {"Metric": "False Negatives", "Value": _res['fn'],
                     "Unit": "flows", "Target": "", "Result": ""},
                    {"Metric": "False Positives", "Value": _res['fp'],
                     "Unit": "flows", "Target": "", "Result": ""},
                    {"Metric": "True Negatives", "Value": _res['tn'],
                     "Unit": "flows", "Target": "", "Result": ""},
                ]
                _bench_csv = pd.DataFrame(_summary_rows).to_csv(
                    index=False).encode("utf-8")
                st.download_button(
                    "Download results (.csv)",
                    _bench_csv,
                    file_name="detection_benchmark_results.csv",
                    mime="text/csv",
                    key="benchmark_export",
                )

                with st.expander("Full classification report"):
                    st.code(_res['classification_report'], language="text")
        else:
            st.info(
                "Upload a labelled CSV to score the model. The same evaluation "
                "runs from a terminal with "
                "`python evaluate_benchmark.py <file.csv>`."
            )
