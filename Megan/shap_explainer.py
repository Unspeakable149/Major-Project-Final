"""SHAP explainability for the Random Forest classifier and the LSTM sequence model.

Provides two levels of explanation, for both models:
  - Global  : overall feature importance across all predictions (bar chart)
  - Local   : per-prediction chart showing which features pushed
              the classification toward Severe / Moderate / Baseline

The RF model is explained with shap.TreeExplainer (exact, fast).
The LSTM model is a PyTorch sequence model, so it is explained with
shap.GradientExplainer instead, which yields SHAP values shaped
(SEQUENCE_LEN, 18) — i.e. per-feature *and* per-timestep attribution.

Used in two ways:
  1. Standalone CLI:
         python Dashboard/shap_explainer.py --global-plot
         python Dashboard/shap_explainer.py --lstm-global-plot
         python Dashboard/shap_explainer.py --explain --ip 192.168.1.5

  2. Streamlit panel (called from app.py):
         from shap_explainer import render_shap_panel
         render_shap_panel()

Requirements: pip install shap matplotlib torch
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
    # Every figure here is rendered straight to PNG bytes for st.image — nothing
    # is ever shown in a window. Pin the headless Agg backend before pyplot is
    # imported so matplotlib does not go looking for a GUI toolkit: the packaged
    # desktop build is a windowed .exe with no tkinter, where that search ends in
    # an import error instead of a chart.
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    _MPL_AVAILABLE = True
except ImportError:
    _MPL_AVAILABLE = False

try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False

import feature_engineer as _fe
from feature_engineer import FEATURE_COLS

# lstm_model defines its nn.Module subclass at import time, so it raises when
# torch is absent — which is the normal case in the packaged desktop build
# (torch/shap/matplotlib are excluded from the .exe to keep it small). Importing
# it unguarded would take the *whole* Model Intelligence panel down with it,
# including the RF SHAP path that doesn't need torch at all. Degrade to
# LSTM-unavailable instead, mirroring the _SHAP_AVAILABLE/_MPL_AVAILABLE flags.
try:
    from lstm_model import load_lstm, SEQUENCE_LEN, INPUT_SIZE, MODEL_PATH as _LSTM_MODEL_PATH
    _LSTM_AVAILABLE = True
except Exception:
    _LSTM_AVAILABLE = False
    SEQUENCE_LEN = 15                      # matches lstm_model.SEQUENCE_LEN
    INPUT_SIZE = len(FEATURE_COLS)
    _LSTM_MODEL_PATH = Path(_fe.__file__).resolve().parent / "lstm_model.pt"

    def load_lstm(*_a, **_kw):             # noqa: D103 — stub for the guarded path
        return None

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

_TIMESTEP_LABELS = [f"t-{SEQUENCE_LEN - 1 - i}" for i in range(SEQUENCE_LEN)]  # oldest -> newest

# live_threat_logs stores these 4 of the 18 FEATURE_COLS as real per-alert values
# (see live_backend.py's CREATE TABLE) — map engineered-feature name -> DB column.
_REAL_BG_COLS = {
    "packets_per_second": "packets_per_sec",
    "avg_window_size": "avg_window_size",
    "syn_ack_ratio": "syn_ack_ratio",
    "total_bytes": "total_bytes",
}

_explainer_cache: dict = {}
_lstm_explainer_cache: dict = {}

# ── Theme (mirrors app.py's dark palette tokens) ───────────────────────────────
# Card/border/ink tokens are copied verbatim from app.py's CSS so the plots read
# as part of the same UI rather than a plain-matplotlib white rectangle dropped
# into a dark page. Mark colors (accent/blue) are chosen separately from the
# app's own status pastels (severe/ok), which validate poorly as a two-color
# CVD-safe pair — red/green-family pairs fail colorblind separation regardless
# of exact shade. Accent (brand orange) + blue is the validated warm/cool
# diverging pair instead (run: dataviz skill's validate_palette.js).
_THEME_CARD = "#1E1D1B"
_THEME_BORDER = "#2B2A28"
_THEME_CREAM = "#FAF9F5"
_THEME_BODY = "#C9C7BE"
_THEME_MUTED = "#8E8C84"
_THEME_ACCENT = "#D97757"   # positive / highlighted / "toward Severe"
_THEME_BLUE = "#3987E5"     # negative / secondary / "toward Baseline"

if _MPL_AVAILABLE:
    _DIVERGING_CMAP = LinearSegmentedColormap.from_list(
        "ids_diverging", [_THEME_BLUE, _THEME_BORDER, _THEME_ACCENT]
    )


def _style_dark_axes(fig: "plt.Figure", *axes: "plt.Axes") -> None:
    """Apply the app's dark card theme to a matplotlib figure in place."""
    fig.patch.set_facecolor(_THEME_CARD)
    for ax in axes:
        ax.set_facecolor(_THEME_CARD)
        ax.tick_params(colors=_THEME_BODY, labelsize=9)
        ax.xaxis.label.set_color(_THEME_MUTED)
        ax.yaxis.label.set_color(_THEME_MUTED)
        ax.title.set_color(_THEME_CREAM)
        for spine in ax.spines.values():
            spine.set_color(_THEME_BORDER)
        ax.grid(color=_THEME_BORDER, linewidth=0.6, alpha=0.7)
        ax.set_axisbelow(True)


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

    # live_threat_logs persists 4 of the 18 engineered features directly
    # (the rest were never stored raw) — pull those in as real background
    # values and only fabricate the remaining 14.
    try:
        import sqlite3
        with sqlite3.connect(str(DB_PATH)) as conn:
            df = pd.read_sql_query(
                f"SELECT {', '.join(_REAL_BG_COLS.values())} "
                f"FROM live_threat_logs ORDER BY id DESC LIMIT {sample_rows}",
                conn,
            )
    except Exception:
        df = pd.DataFrame()

    rng = np.random.default_rng(42)
    n_rows = len(df) if not df.empty else sample_rows
    X_bg = rng.standard_normal((n_rows, len(FEATURE_COLS))).astype(np.float32)

    if not df.empty:
        for feature_name, db_col in _REAL_BG_COLS.items():
            col_idx = FEATURE_COLS.index(feature_name)
            X_bg[:, col_idx] = pd.to_numeric(df[db_col], errors="coerce").fillna(0).values

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


# ── LSTM explainability ────────────────────────────────────────────────────────

def _get_lstm_explainer(model, background_seqs: np.ndarray):
    """Build (and cache) a SHAP GradientExplainer for the LSTM model.

    TreeExplainer only works on tree ensembles, so the LSTM (a PyTorch RNN)
    needs GradientExplainer instead — it approximates Shapley values from
    the model's gradients w.r.t. a background sample.
    """
    if not _SHAP_AVAILABLE:
        raise ImportError("shap is required. Install with: pip install shap")
    if not _TORCH_AVAILABLE:
        raise ImportError("PyTorch is required. Install with: pip install torch")

    cache_key = id(model)
    if cache_key in _lstm_explainer_cache:
        return _lstm_explainer_cache[cache_key]

    bg = torch.from_numpy(background_seqs.astype(np.float32))
    explainer = shap.GradientExplainer(model, bg)
    _lstm_explainer_cache[cache_key] = explainer
    return explainer


def _lstm_background(sample_rows: int = 50) -> np.ndarray | None:
    """Synthetic scaled background sequences for the LSTM explainer.

    Like the RF path in compute_global_importance, the alert DB only stores
    src_ip (not full feature rows), so there is no real historical sequence
    to sample from — a scaled random background stands in, same limitation
    as the RF explainer.
    """
    _, scaler = _load_model_and_scaler()
    if scaler is None:
        return None
    rng = np.random.default_rng(42)
    X_bg = rng.standard_normal((sample_rows, SEQUENCE_LEN, INPUT_SIZE)).astype(np.float32)
    flat_s = scaler.transform(X_bg.reshape(-1, INPUT_SIZE))
    return flat_s.reshape(sample_rows, SEQUENCE_LEN, INPUT_SIZE).astype(np.float32)


def _lstm_shap_to_array(shap_vals) -> np.ndarray:
    """Normalise GradientExplainer output to shape (n_samples, seq_len, n_features, n_classes)."""
    if isinstance(shap_vals, list):
        # old format: list of (n_samples, seq_len, n_features), one per class
        return np.stack(shap_vals, axis=-1)
    return shap_vals  # new format already (n_samples, seq_len, n_features, n_classes)


def compute_lstm_global_importance(
    sample_rows: int = 30,
    nsamples: int = 50,
) -> tuple[np.ndarray, np.ndarray, list[str]] | tuple[None, None, None]:
    """Compute mean |SHAP| values for the LSTM model, both per-feature and per-timestep.

    GradientExplainer cost scales as sample_rows * nsamples (each sample takes
    `nsamples` gradient evaluations), so keep both modest — this runs synchronously
    in the Streamlit panel. Defaults here (30 * 50 = 1,500 evaluations) run in a
    few seconds; the RF equivalent (TreeExplainer) is exact and doesn't have this
    cost, hence its much larger default sample_rows=200.

    Returns (feature_importance (18,), timestep_importance (SEQUENCE_LEN,), feature_labels)
    or (None, None, None) if SHAP/torch/the model are unavailable.
    """
    if not _SHAP_AVAILABLE or not _TORCH_AVAILABLE:
        return None, None, None

    model = load_lstm()
    if model is None:
        return None, None, None

    X_bg = _lstm_background(sample_rows)
    if X_bg is None:
        return None, None, None

    explainer = _get_lstm_explainer(model, X_bg)
    shap_vals = explainer.shap_values(torch.from_numpy(X_bg), nsamples=nsamples)
    arr = _lstm_shap_to_array(shap_vals)  # (n, seq_len, n_features, n_classes)

    mean_abs = np.abs(arr).mean(axis=(0, 3))       # (seq_len, n_features)
    feature_importance = mean_abs.mean(axis=0)     # (n_features,)
    timestep_importance = mean_abs.mean(axis=1)    # (seq_len,)
    return feature_importance, timestep_importance, _FEATURE_LABELS


def explain_lstm_prediction(sequence: np.ndarray, predicted_class: int) -> dict | None:
    """Compute SHAP values for a single LSTM prediction.

    Args:
        sequence: scaled feature sequence, shape (SEQUENCE_LEN, 18) — e.g. from
            SequenceBuffer.get_sequence(src_ip) in lstm_model.py.
        predicted_class: the LSTM's predicted class index (0/1/2).

    Returns dict with keys: shap_values (SEQUENCE_LEN, 18), feature_values,
    predicted_class, feature_labels, timestep_labels.
    """
    if not _SHAP_AVAILABLE or not _TORCH_AVAILABLE:
        return None

    model = load_lstm()
    if model is None:
        return None

    X_bg = _lstm_background()
    if X_bg is None:
        return None

    explainer = _get_lstm_explainer(model, X_bg)
    x = sequence.reshape(1, SEQUENCE_LEN, INPUT_SIZE).astype(np.float32)
    shap_vals = explainer.shap_values(torch.from_numpy(x))
    arr = _lstm_shap_to_array(shap_vals)  # (1, seq_len, n_features, n_classes)

    return {
        "shap_values": arr[0, :, :, predicted_class],   # (SEQUENCE_LEN, 18)
        "feature_values": x[0],                          # (SEQUENCE_LEN, 18)
        "predicted_class": predicted_class,
        "feature_labels": _FEATURE_LABELS,
        "timestep_labels": _TIMESTEP_LABELS,
    }


# ── Plot helpers ──────────────────────────────────────────────────────────────

def _global_importance_figure(importances: np.ndarray, labels: list[str]) -> "plt.Figure":
    order = np.argsort(importances)[::-1]
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = [_THEME_ACCENT if importances[i] == importances.max() else _THEME_BLUE for i in order]
    ax.barh([labels[i] for i in order[::-1]], importances[order[::-1]], color=colors[::-1])
    ax.set_xlabel("Mean |SHAP value|")
    ax.set_title("Global Feature Importance (RF Model)")
    _style_dark_axes(fig, ax)
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

    colors = [_THEME_ACCENT if v > 0 else _THEME_BLUE for v in sv_top]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(lbl_top[::-1], sv_top[::-1], color=colors[::-1])
    ax.axvline(0, color=_THEME_MUTED, linewidth=0.8)
    ax.set_xlabel("SHAP value (impact on model output)")
    ax.set_title(f"Local Explanation — predicted: {cls}  (base={base:.3f})")
    _style_dark_axes(fig, ax)
    fig.tight_layout()
    return fig


def _lstm_global_importance_figure(
    feature_importance: np.ndarray, timestep_importance: np.ndarray, labels: list[str]
) -> "plt.Figure":
    fig, (ax_feat, ax_time) = plt.subplots(1, 2, figsize=(14, 5))

    order = np.argsort(feature_importance)[::-1]
    colors = [_THEME_ACCENT if feature_importance[i] == feature_importance.max() else _THEME_BLUE for i in order]
    ax_feat.barh([labels[i] for i in order[::-1]], feature_importance[order[::-1]], color=colors[::-1])
    ax_feat.set_xlabel("Mean |SHAP value|")
    ax_feat.set_title("LSTM: Feature Importance")

    ax_time.bar(_TIMESTEP_LABELS, timestep_importance, color=_THEME_BLUE)
    ax_time.set_xlabel("Timestep (t-0 = most recent window)")
    ax_time.set_ylabel("Mean |SHAP value|")
    ax_time.set_title("LSTM: Timestep Importance")
    ax_time.tick_params(axis="x", rotation=45)

    _style_dark_axes(fig, ax_feat, ax_time)
    fig.tight_layout()
    return fig


def _lstm_local_figure(shap_info: dict) -> "plt.Figure":
    """Heatmap of SHAP values over (timestep x feature) for one LSTM prediction,
    plus a bar chart of the top contributing features summed across time.
    """
    sv = shap_info["shap_values"]          # (SEQUENCE_LEN, 18)
    labels = shap_info["feature_labels"]
    cls = _CLASS_NAMES[shap_info["predicted_class"]]

    fig, (ax_heat, ax_bar) = plt.subplots(1, 2, figsize=(14, 5))

    vmax = np.abs(sv).max() or 1.0
    im = ax_heat.imshow(sv.T, aspect="auto", cmap=_DIVERGING_CMAP, vmin=-vmax, vmax=vmax)
    ax_heat.set_yticks(range(len(labels)))
    ax_heat.set_yticklabels(labels, fontsize=8)
    ax_heat.set_xticks(range(SEQUENCE_LEN))
    ax_heat.set_xticklabels(_TIMESTEP_LABELS, rotation=45, fontsize=8)
    ax_heat.set_title(f"LSTM: SHAP over time — predicted {cls}")
    cbar = fig.colorbar(im, ax=ax_heat, label="SHAP value")
    cbar.ax.yaxis.label.set_color(_THEME_MUTED)
    cbar.ax.tick_params(colors=_THEME_BODY, labelsize=8)
    cbar.outline.set_edgecolor(_THEME_BORDER)

    total_by_feature = sv.sum(axis=0)  # signed contribution summed across timesteps
    order = np.argsort(np.abs(total_by_feature))[::-1][:10]
    colors = [_THEME_ACCENT if v > 0 else _THEME_BLUE for v in total_by_feature[order]]
    ax_bar.barh([labels[i] for i in order][::-1], total_by_feature[order][::-1], color=colors[::-1])
    ax_bar.axvline(0, color=_THEME_MUTED, linewidth=0.8)
    ax_bar.set_xlabel("Summed SHAP value (across all timesteps)")
    ax_bar.set_title("Top contributing features")

    _style_dark_axes(fig, ax_heat, ax_bar)
    fig.tight_layout()
    return fig


def _fig_to_bytes(fig: "plt.Figure") -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, facecolor=fig.get_facecolor())
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

    _cached = st.cache_data(ttl=300, show_spinner=False)(compute_global_importance)
    with st.spinner("Computing SHAP values …"):
        importances, labels = _cached()

    if importances is None:
        st.caption("Could not compute SHAP values.")
        return

    fig = _global_importance_figure(importances, labels)
    st.image(_fig_to_bytes(fig), caption="Feature importance: higher = more influence on predictions")

    st.caption(
        "SHAP (SHapley Additive exPlanations) measures each feature's average contribution "
        "to pushing the model away from its baseline prediction. Highlighted bar = top contributor."
    )


def render_lstm_shap_panel():
    """Called from app.py to render the LSTM SHAP panel inside Streamlit."""
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
    if not _TORCH_AVAILABLE:
        st.warning("Install torch to enable LSTM explainability: `pip install torch`")
        return
    if not _LSTM_MODEL_PATH.exists():
        st.caption("LSTM model not trained yet. Run: `python Megan/lstm_model.py --train`")
        return

    # Cache across reruns — GradientExplainer is far slower than the RF's exact
    # TreeExplainer, and Streamlit reruns this on every widget interaction anywhere
    # in the app, not just when this tab is opened.
    _cached = st.cache_data(ttl=300, show_spinner=False)(compute_lstm_global_importance)
    with st.spinner("Computing LSTM SHAP values … (first run takes a few seconds)"):
        feat_imp, time_imp, labels = _cached()

    if feat_imp is None:
        st.caption("Could not compute LSTM SHAP values.")
        return

    fig = _lstm_global_importance_figure(feat_imp, time_imp, labels)
    st.image(
        _fig_to_bytes(fig),
        caption="LSTM feature & timestep importance: higher = more influence on sequence predictions",
    )

    st.caption(
        "The LSTM looks at the last 15 capture windows per source IP. Timestep "
        "importance shows whether recent or older windows drive its verdicts; "
        "feature importance shows which flow metrics matter most across that history."
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SHAP explainability for Hybrid IDS RF model.")
    parser.add_argument("--global-plot", action="store_true", help="Show global RF feature importance")
    parser.add_argument("--lstm-global-plot", action="store_true", help="Show global LSTM feature/timestep importance")
    parser.add_argument("--save", type=Path, default=None, help="Save plot to file instead of showing")
    args = parser.parse_args()

    if not _SHAP_AVAILABLE:
        print("Install shap: pip install shap")
        return
    if not _MPL_AVAILABLE:
        print("Install matplotlib: pip install matplotlib")
        return

    if args.lstm_global_plot:
        if not _TORCH_AVAILABLE:
            print("Install torch: pip install torch")
            return
        feat_imp, time_imp, labels = compute_lstm_global_importance()
        if feat_imp is None:
            print("Could not compute: train the LSTM model first (lstm_model.py --train).")
            return
        fig = _lstm_global_importance_figure(feat_imp, time_imp, labels)
        if args.save:
            fig.savefig(args.save, dpi=150)
            print(f"Saved to {args.save}")
        else:
            plt.show()
    elif args.global_plot:
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
