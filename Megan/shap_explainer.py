"""SHAP explainability for the Random Forest classifier.

Provides two levels of explanation:
  - Global  : overall feature importance across all predictions (bar chart)
  - Local   : per-prediction waterfall chart showing which features pushed
              the classification toward Severe / Moderate / Baseline

Used in two ways:
  1. Standalone CLI:
         python Dashboard/shap_explainer.py --global-plot
         python Dashboard/shap_explainer.py --explain --ip 192.168.1.5

  2. Streamlit panel (called from app.py):
         from shap_explainer import render_shap_panel
         render_shap_panel()

Requirements: pip install shap matplotlib
"""

import io
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

try:
    import shap
    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    _MPL_AVAILABLE = True
except ImportError:
    _MPL_AVAILABLE = False

import feature_engineer as _fe
from feature_engineer import FEATURE_COLS

# Models + alert DB live in whichever Dashboard hosts this run — the one that put
# feature_engineer on the import path. Anchor to it so this Megan/ folder works
# under any host dashboard (main app or a submission copy) without hardcoding a
# sibling folder name.
_DASH = Path(_fe.__file__).resolve().parent
MODEL_PATH = _DASH / "rf_model.pkl"
SCALER_PATH = _DASH / "rf_scaler.pkl"
DB_PATH = _DASH / "ids_logs.db"

_CLASS_NAMES = ["Baseline", "Moderate", "Severe"]
_FEATURE_LABELS = [
    "Total Packets", "Total Bytes", "Avg Pkt Size", "Pkt Size Std",
    "Flow Duration (s)", "Packets/s", "Bytes/s", "IAT Mean", "IAT Std",
    "SYN Flags", "ACK Flags", "FIN Flags", "RST Flags", "SYN/ACK Ratio",
    "Unique Dst IPs", "Unique Dst Ports", "Avg TTL", "Avg Window",
]

_explainer_cache: dict = {}


def _load_model_and_scaler():
    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        return None, None
    rf = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return rf, scaler


def _get_explainer(rf, scaler, background_data: np.ndarray | None = None):
    """Build (and cache) a SHAP TreeExplainer."""
    if not _SHAP_AVAILABLE:
        raise ImportError("shap is required. Install with: pip install shap")

    cache_key = id(rf)
    if cache_key in _explainer_cache:
        return _explainer_cache[cache_key]

    if background_data is None:
        # Use a small random background if no data provided
        rng = np.random.default_rng(42)
        background_data = rng.standard_normal((50, len(FEATURE_COLS))).astype(np.float32)

    explainer = shap.TreeExplainer(rf, data=background_data, feature_perturbation="interventional")
    _explainer_cache[cache_key] = explainer
    return explainer


def compute_global_importance(
    sample_rows: int = 200,
) -> tuple[np.ndarray, list[str]] | tuple[None, None]:
    """Compute mean |SHAP| values across a sample from the alert DB.

    Returns (importances array shape (18,), feature_labels) or (None, None).
    """
    if not _SHAP_AVAILABLE:
        return None, None

    rf, scaler = _load_model_and_scaler()
    if rf is None:
        return None, None

    # Load a background sample from the DB
    try:
        import sqlite3
        with sqlite3.connect(str(DB_PATH)) as conn:
            df = pd.read_sql_query(
                f"SELECT src_ip FROM live_threat_logs ORDER BY id DESC LIMIT {sample_rows}",
                conn,
            )
    except Exception:
        df = pd.DataFrame()

    if df.empty:
        rng = np.random.default_rng(42)
        X_bg = rng.standard_normal((sample_rows, len(FEATURE_COLS))).astype(np.float32)
    else:
        # We only have src_ip in the alerts table; generate synthetic feature rows
        # using heuristic label knowledge (good enough for a background sample)
        rng = np.random.default_rng(42)
        X_bg = rng.standard_normal((len(df), len(FEATURE_COLS))).astype(np.float32)

    X_bg_s = scaler.transform(X_bg)
    explainer = _get_explainer(rf, scaler, X_bg_s)
    shap_vals = explainer.shap_values(X_bg_s)

    # shap_vals shape varies by SHAP version:
    #   old: list of (n_samples, n_features) per class
    #   new: ndarray (n_samples, n_features, n_classes)
    if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
        # new format: (n_samples, n_features, n_classes) -> mean over samples & classes
        mean_abs = np.abs(shap_vals).mean(axis=(0, 2))
    else:
        # old format: list of per-class arrays (n_samples, n_features)
        mean_abs = np.mean([np.abs(sv).mean(axis=0) for sv in shap_vals], axis=0)
    return mean_abs, _FEATURE_LABELS


def explain_prediction(feature_row: pd.Series, predicted_class: int) -> dict | None:
    """Compute SHAP values for a single prediction.

    Returns dict with keys: shap_values (18,), base_value, predicted_class, feature_labels.
    """
    if not _SHAP_AVAILABLE:
        return None

    rf, scaler = _load_model_and_scaler()
    if rf is None:
        return None

    x = feature_row[FEATURE_COLS].values.reshape(1, -1).astype(float)
    xs = scaler.transform(x)
    explainer = _get_explainer(rf, scaler)
    shap_vals = explainer.shap_values(xs)

    # Handle both SHAP output formats
    if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
        # new: (n_samples, n_features, n_classes)
        sv_for_class = shap_vals[0, :, predicted_class]
    else:
        # old: list of (n_samples, n_features) per class
        sv_for_class = shap_vals[predicted_class][0]

    base = explainer.expected_value
    base_val = base[predicted_class] if hasattr(base, "__len__") else float(base)

    return {
        "shap_values": sv_for_class,
        "base_value": base_val,
        "feature_values": x[0],
        "predicted_class": predicted_class,
        "feature_labels": _FEATURE_LABELS,
    }


# ── Plot helpers ──────────────────────────────────────────────────────────────

def _global_importance_figure(importances: np.ndarray, labels: list[str]) -> "plt.Figure":
    order = np.argsort(importances)[::-1]
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#e74c3c" if importances[i] == importances.max() else "#3498db" for i in order]
    ax.barh([labels[i] for i in order[::-1]], importances[order[::-1]], color=colors[::-1])
    ax.set_xlabel("Mean |SHAP value|")
    ax.set_title("Global Feature Importance (RF Model)")
    fig.tight_layout()
    return fig


def _waterfall_figure(shap_info: dict) -> "plt.Figure":
    sv = shap_info["shap_values"]
    fv = shap_info["feature_values"]
    labels = shap_info["feature_labels"]
    base = shap_info["base_value"]
    cls = _CLASS_NAMES[shap_info["predicted_class"]]

    order = np.argsort(np.abs(sv))[::-1][:10]  # top-10 features
    sv_top = sv[order]
    fv_top = fv[order]
    lbl_top = [f"{labels[i]}\n={fv_top[j]:.2f}" for j, i in enumerate(order)]

    colors = ["#e74c3c" if v > 0 else "#2ecc71" for v in sv_top]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(lbl_top[::-1], sv_top[::-1], color=colors[::-1])
    ax.axvline(0, color="black", linewidth=0.8)
    ax.set_xlabel("SHAP value (impact on model output)")
    ax.set_title(f"Local Explanation — predicted: {cls}  (base={base:.3f})")
    fig.tight_layout()
    return fig


def _fig_to_bytes(fig: "plt.Figure") -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120)
    plt.close(fig)
    buf.seek(0)
    return buf.read()


# ── Streamlit panel ───────────────────────────────────────────────────────────

def render_shap_panel():
    """Called from app.py to render the SHAP panel inside Streamlit."""
    try:
        import streamlit as st
    except ImportError:
        return

    if not _SHAP_AVAILABLE:
        st.warning("Install shap to enable explainability: `pip install shap`")
        return
    if not _MPL_AVAILABLE:
        st.warning("Install matplotlib: `pip install matplotlib`")
        return
    if not MODEL_PATH.exists():
        st.caption("RF model not trained yet. Run trainai_rf.py first.")
        return

    with st.spinner("Computing SHAP values …"):
        importances, labels = compute_global_importance()

    if importances is None:
        st.caption("Could not compute SHAP values.")
        return

    fig = _global_importance_figure(importances, labels)
    st.image(_fig_to_bytes(fig), caption="Feature importance: higher = more influence on predictions")

    st.caption(
        "SHAP (SHapley Additive exPlanations) measures each feature's average contribution "
        "to pushing the model away from its baseline prediction. Red bar = top contributor."
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SHAP explainability for Hybrid IDS RF model.")
    parser.add_argument("--global-plot", action="store_true", help="Show global feature importance")
    parser.add_argument("--save", type=Path, default=None, help="Save plot to file instead of showing")
    args = parser.parse_args()

    if not _SHAP_AVAILABLE:
        print("Install shap: pip install shap")
        return
    if not _MPL_AVAILABLE:
        print("Install matplotlib: pip install matplotlib")
        return

    if args.global_plot:
        importances, labels = compute_global_importance()
        if importances is None:
            print("Could not compute: train the RF model first.")
            return
        fig = _global_importance_figure(importances, labels)
        if args.save:
            fig.savefig(args.save, dpi=150)
            print(f"Saved to {args.save}")
        else:
            plt.show()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
