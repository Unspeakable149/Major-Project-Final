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
