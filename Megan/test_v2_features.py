"""Smoke tests for the v2 model-intelligence features: SHAP, LSTM, retraining.

Validates the REAL integrated artifacts in the host Dashboard (the one that
ships feature_engineer + the trained models) rather than synthetic throwaway
data, so a green run here means the Model Intelligence tab will work.

The host Dashboard is auto-discovered (the submission's Dashboard folder), so
this file works no matter the CWD. Every check is read-only except the LSTM
train test, which writes into a pytest tmp sandbox — the real lstm_model.pt is
never overwritten.

Run:
    python -m pytest Megan/test_v2_features.py -q
"""

import sys
from pathlib import Path

import pandas as pd
import pytest

# ── Locate the host Dashboard (sibling submission folder) and put it on path ───
_REPO = Path(__file__).resolve().parent.parent
_cands = sorted(_REPO.glob("*/Dashboard/feature_engineer.py"))
_dash = None
for _c in _cands:                      # prefer a submission Dashboard if present
    if "submission" in _c.parts[-3].lower():
        _dash = _c.parent
        break
if _dash is None and _cands:
    _dash = _cands[0].parent
if _dash is not None and str(_dash) not in sys.path:
    sys.path.insert(0, str(_dash))

pytestmark = pytest.mark.skipif(_dash is None, reason="host Dashboard not found")


def _dataset() -> Path:
    csv = _dash / "master_advanced_dataset.csv"
    if not csv.exists():
        pytest.skip("master_advanced_dataset.csv not present")
    return csv


# ── Feature pipeline ──────────────────────────────────────────────────────────

def test_feature_pipeline():
    """engineer_flows turns the shipped dataset into the 18-feature flow table."""
    from feature_engineer import engineer_flows, FEATURE_COLS
    flows = engineer_flows(pd.read_csv(_dataset(), low_memory=False))
    assert not flows.empty
    assert all(c in flows.columns for c in FEATURE_COLS)


# ── SHAP explainability ─────────────────────────────────────────────────────--

def test_shap_global_importance():
    pytest.importorskip("shap")
    from shap_explainer import compute_global_importance
    importances, labels = compute_global_importance(sample_rows=50)
    if importances is None:
        pytest.skip("rf_model.pkl missing or shap unavailable")
    assert len(importances) == 18
    assert len(labels) == 18


def test_lstm_shap_global_importance():
    """GradientExplainer path for the LSTM: per-feature + per-timestep importance."""
    pytest.importorskip("shap")
    pytest.importorskip("torch")
    from shap_explainer import compute_lstm_global_importance
    from lstm_model import SEQUENCE_LEN
    feat_imp, time_imp, labels = compute_lstm_global_importance(sample_rows=20)
    if feat_imp is None:
        pytest.skip("lstm_model.pt / rf_scaler.pkl missing or shap/torch unavailable")
    assert feat_imp.shape == (18,)
    assert time_imp.shape == (SEQUENCE_LEN,)
    assert len(labels) == 18


def test_lstm_shap_explain_prediction():
    """Per-prediction SHAP values for one LSTM sequence, shape (SEQUENCE_LEN, 18)."""
    pytest.importorskip("shap")
    pytest.importorskip("torch")
    import numpy as np
    from shap_explainer import explain_lstm_prediction
    from lstm_model import SEQUENCE_LEN, INPUT_SIZE, load_lstm

    if load_lstm() is None:
        pytest.skip("lstm_model.pt missing")

    seq = np.random.default_rng(0).standard_normal((SEQUENCE_LEN, INPUT_SIZE)).astype(np.float32)
    info = explain_lstm_prediction(seq, predicted_class=2)
    if info is None:
        pytest.skip("rf_scaler.pkl missing or shap/torch unavailable")
    assert info["shap_values"].shape == (SEQUENCE_LEN, 18)
    assert len(info["timestep_labels"]) == SEQUENCE_LEN


# ── LSTM sequence model ─────────────────────────────────────────────────────--

def test_lstm_load():
    """A trained lstm_model.pt loads; if absent, load_lstm() returns None cleanly."""
    pytest.importorskip("torch")
    from lstm_model import load_lstm, MODEL_PATH
    model = load_lstm()
    assert (model is not None) or (not MODEL_PATH.exists())


def test_lstm_train_sandbox(tmp_path):
    """Exercise the train path end-to-end, writing into a sandbox (never the
    real model file)."""
    pytest.importorskip("torch")
    import lstm_model
    orig = lstm_model.MODEL_PATH
    lstm_model.MODEL_PATH = tmp_path / "lstm_sandbox.pt"
    try:
        lstm_model.train_lstm(_dataset(), epochs=2)
        assert lstm_model.MODEL_PATH.exists()
    finally:
        lstm_model.MODEL_PATH = orig


# ── LSTM fusion cap (write_alerts' Layer 5) ─────────────────────────────────--

def test_lstm_cap_no_verdict():
    """No LSTM verdict yet (None) contributes nothing to fusion."""
    from live_backend import apply_lstm_cap
    threats, effective = apply_lstm_cap(
        ["Baseline (Safe)", "Baseline (Safe)", "Baseline (Safe)", "Baseline (Safe)"],
        lstm_threat=None, lstm_full_history=False,
    )
    assert effective is None
    assert threats == ["Baseline (Safe)"] * 4


def test_lstm_cap_moderate_passes_through_unconditionally():
    """The LSTM can push Baseline -> Moderate on its own, regardless of history —
    this is the slow-scan detection case it exists for."""
    from live_backend import apply_lstm_cap, fuse
    threats, effective = apply_lstm_cap(
        ["Baseline (Safe)"] * 4, lstm_threat="Moderate (Suspicious)", lstm_full_history=False,
    )
    assert effective == "Moderate (Suspicious)"
    assert fuse(*threats) == "Moderate (Suspicious)"


def test_lstm_cap_severe_downgraded_without_full_history():
    """A Severe LSTM read on a partial (padded) sequence, with no other signal
    agreeing, is capped down to Moderate rather than trusted outright."""
    from live_backend import apply_lstm_cap, fuse
    threats, effective = apply_lstm_cap(
        ["Baseline (Safe)"] * 4, lstm_threat="Severe (Critical Anomaly)", lstm_full_history=False,
    )
    assert effective == "Moderate (Suspicious)"
    assert fuse(*threats) == "Moderate (Suspicious)"


def test_lstm_cap_severe_downgraded_without_agreement():
    """A Severe LSTM read WITH full history but with every other signal still
    at Baseline is still capped — no corroborating signal, no Severe."""
    from live_backend import apply_lstm_cap, fuse
    threats, effective = apply_lstm_cap(
        ["Baseline (Safe)"] * 4, lstm_threat="Severe (Critical Anomaly)", lstm_full_history=True,
    )
    assert effective == "Moderate (Suspicious)"
    assert fuse(*threats) == "Moderate (Suspicious)"


def test_lstm_cap_severe_allowed_with_full_history_and_agreement():
    """Full history AND another signal already at Moderate+ -> Severe passes through."""
    from live_backend import apply_lstm_cap, fuse
    threats, effective = apply_lstm_cap(
        ["Baseline (Safe)", "Moderate (Suspicious)", "Baseline (Safe)", "Baseline (Safe)"],
        lstm_threat="Severe (Critical Anomaly)", lstm_full_history=True,
    )
    assert effective == "Severe (Critical Anomaly)"
    assert fuse(*threats) == "Severe (Critical Anomaly)"


# ── Retraining pipeline ─────────────────────────────────────────────────────--

def test_retrain_triggers():
    """check_triggers reports status without side effects."""
    from retrain_pipeline import check_triggers, _load_state
    triggers = check_triggers(_load_state())
    assert "should_retrain" in triggers
    assert "new_samples" in triggers
    assert "hours_since_last" in triggers


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
