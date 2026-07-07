"""Model retraining pipeline — periodic re-training of the RF (and optionally LSTM)
classifier using data that has accumulated in ids_logs.db.

Trigger conditions (all must hold):
  1. At least MIN_SAMPLES new alerts since last retrain.
  2. At least MIN_HOURS_BETWEEN_RETRAINS hours have elapsed.
  3. (Optional) The model's estimated accuracy has drifted below DRIFT_THRESHOLD.

Versioning:
  - Every retrain saves rf_model_v<ISO-timestamp>.pkl alongside rf_model.pkl.
  - The last MAX_VERSIONS are kept; older ones are deleted.
  - Rollback: python Dashboard/retrain_pipeline.py --rollback

Usage:
  python Dashboard/retrain_pipeline.py            (check + retrain if due)
  python Dashboard/retrain_pipeline.py --force    (retrain regardless of triggers)
  python Dashboard/retrain_pipeline.py --status   (print trigger status)
  python Dashboard/retrain_pipeline.py --rollback (restore previous version)
  python Dashboard/retrain_pipeline.py --rollback --version rf_model_v2024-01-15T12-00-00.pkl
"""

import argparse
import json
import shutil
import sqlite3
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

import feature_engineer as _fe
from feature_engineer import FEATURE_COLS
from trainai_rf import assign_behavioral_label as heuristic_label

# Models, DB, and version history live in whichever Dashboard hosts this run —
# the one that put feature_engineer on the import path — so this Megan/ folder
# works under any host dashboard without hardcoding a sibling folder name.
_DASH = Path(_fe.__file__).resolve().parent
MODEL_PATH = _DASH / "rf_model.pkl"
SCALER_PATH = _DASH / "rf_scaler.pkl"
DB_PATH = _DASH / "ids_logs.db"
STATE_PATH = _DASH / "retrain_state.json"
VERSIONS_DIR = _DASH / "model_versions"

MIN_SAMPLES = 500
MIN_HOURS_BETWEEN_RETRAINS = 6
DRIFT_THRESHOLD = 0.85
MAX_VERSIONS = 5


# ── State management ──────────────────────────────────────────────────────────

def _load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            pass
    return {"last_retrain_ts": 0.0, "last_sample_count": 0, "version_history": []}


def _save_state(state: dict):
    STATE_PATH.write_text(json.dumps(state, indent=2))


# ── Data loading from DB ───────────────────────────────────────────────────────

def _load_alerts_from_db(since_id: int = 0) -> pd.DataFrame:
    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            df = pd.read_sql_query(
                "SELECT id, src_ip, severity FROM live_threat_logs WHERE id > ?",
                conn, params=(since_id,),
            )
    except Exception:
        df = pd.DataFrame(columns=["id", "src_ip", "severity"])
    return df


def _synthesise_features_from_alerts(alerts: pd.DataFrame) -> pd.DataFrame:
    """Generate synthetic feature rows from alert records for re-labelling.

    Since the alerts DB only stores (src_ip, severity) — not raw features —
    we synthesise plausible feature vectors per severity class using statistical
    ranges derived from the heuristic rule boundaries. This keeps the retrain
    loop self-contained without requiring raw PCAP re-parsing.
    """
    rng = np.random.default_rng(42)
    rows = []
    for _, alert in alerts.iterrows():
        sev = int(alert["severity"])
        # Generate a feature vector consistent with the labelled severity
        if sev == 2:  # Severe
            pps = rng.uniform(600, 2000)
            syn_ack = rng.uniform(5, 20)
        elif sev == 1:  # Moderate
            pps = rng.uniform(21, 500)
            syn_ack = rng.uniform(0.5, 5)
        else:  # Baseline
            pps = rng.uniform(0.1, 20)
            syn_ack = rng.uniform(0.1, 2)

        avg_size = rng.uniform(40, 1500)
        total_packets = int(pps * 2)
        total_bytes = int(total_packets * avg_size)
        duration = 2.0

        row = {
            "src_ip": alert["src_ip"],
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_size,
            "packet_size_std": rng.uniform(0, avg_size * 0.5),
            "flow_duration_sec": duration,
            "packets_per_second": pps,
            "bytes_per_second": total_bytes / duration,
            "iat_mean": rng.uniform(0.0001, 0.5),
            "iat_std": rng.uniform(0, 0.3),
            "total_syn_flags": int(total_packets * rng.uniform(0, 0.8)),
            "total_ack_flags": max(1, int(total_packets * rng.uniform(0.1, 0.9))),
            "total_fin_flags": int(total_packets * rng.uniform(0, 0.2)),
            "total_rst_flags": int(total_packets * rng.uniform(0, 0.1)),
            "syn_ack_ratio": syn_ack,
            "unique_target_ips": int(rng.uniform(1, 5)),
            "unique_target_ports": int(pps / 20) if sev == 1 else int(rng.uniform(1, 5)),
            "avg_ttl": rng.uniform(32, 128),
            "avg_window_size": rng.uniform(1024, 65535),
            "label": sev,
        }
        rows.append(row)
    return pd.DataFrame(rows)


# ── Trigger evaluation ────────────────────────────────────────────────────────

def check_triggers(state: dict) -> dict[str, bool | int]:
    alerts = _load_alerts_from_db(state["last_sample_count"])
    new_samples = len(alerts)
    hours_since = (time.time() - state["last_retrain_ts"]) / 3600

    sample_trigger = new_samples >= MIN_SAMPLES
    time_trigger = hours_since >= MIN_HOURS_BETWEEN_RETRAINS
    drift_trigger = _estimate_drift(state)

    return {
        "new_samples": new_samples,
        "hours_since_last": round(hours_since, 2),
        "sample_trigger": sample_trigger,
        "time_trigger": time_trigger,
        "drift_trigger": drift_trigger,
        "should_retrain": sample_trigger and time_trigger,
    }


def _estimate_drift(state: dict) -> bool:
    """Check if the model's self-reported accuracy on recent DB samples is below threshold."""
    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        return False
    try:
        rf = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        alerts = _load_alerts_from_db(0)
        if len(alerts) < 50:
            return False
        sample = alerts.sample(min(200, len(alerts)), random_state=42)
        flows = _synthesise_features_from_alerts(sample)
        X = flows[FEATURE_COLS].fillna(0).values
        y = flows["label"].values
        Xs = scaler.transform(X)
        y_pred = rf.predict(Xs)
        score = f1_score(y, y_pred, average="macro", zero_division=0)
        return bool(score < DRIFT_THRESHOLD)
    except Exception:
        return False


# ── Retraining ────────────────────────────────────────────────────────────────

def retrain(force: bool = False, retrain_lstm: bool = False) -> bool:
    """Perform retraining. Returns True if retrain happened."""
    state = _load_state()

    if not force:
        triggers = check_triggers(state)
        if not triggers["should_retrain"]:
            print(f"[INFO] Retrain not due yet.")
            print(f"       New samples: {triggers['new_samples']}/{MIN_SAMPLES}")
            print(f"       Hours since last: {triggers['hours_since_last']:.1f}/{MIN_HOURS_BETWEEN_RETRAINS}")
            return False

    print("[INFO] Retraining RF model ...")
    alerts = _load_alerts_from_db(0)

    if len(alerts) < 100:
        # Fall back to the existing training CSV when DB is sparse (e.g. force retrain
        # during initial setup before live traffic has accumulated).
        csv_fallback = _DASH / "master_advanced_dataset.csv"
        if csv_fallback.exists():
            print(f"[INFO] DB has only {len(alerts)} alerts; using CSV fallback: {csv_fallback.name}")
            from feature_engineer import engineer_flows
            raw = pd.read_csv(csv_fallback, low_memory=False)
            flows_raw = engineer_flows(raw)
            if flows_raw.empty:
                print("[WARN] CSV fallback produced no flows — cannot retrain.")
                return False
            # Use label column if present, otherwise heuristic
            if "label" in raw.columns:
                label_map = raw.groupby("Source")["label"].first().to_dict()
                flows_raw["label"] = flows_raw["src_ip"].map(label_map).fillna(0).astype(int)
            else:
                flows_raw["label"] = flows_raw.apply(heuristic_label, axis=1)
            flows = flows_raw
        else:
            print(f"[WARN] Only {len(alerts)} alerts in DB and no CSV fallback found.")
            return False
    else:
        flows = _synthesise_features_from_alerts(alerts)

    X = flows[FEATURE_COLS].fillna(0).values
    y = flows["label"].values

    if len(np.unique(y)) < 2:
        print("[WARN] Only one class in training data — skipping retrain.")
        return False

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_leaf=2,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    rf.fit(X_train_s, y_train)

    y_pred = rf.predict(X_test_s)
    f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    print(f"  New model F1 (macro): {f1:.3f}")

    # Version the existing model before overwriting
    _version_model(state)

    joblib.dump(rf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"  Model saved: {MODEL_PATH}")

    # Retrain LSTM if requested
    if retrain_lstm:
        try:
            from lstm_model import train_lstm
            csv = _DASH / "master_advanced_dataset.csv"
            if csv.exists():
                print("[INFO] Retraining LSTM …")
                train_lstm(csv)
        except Exception as e:
            print(f"[WARN] LSTM retrain failed: {e}")

    # Update state
    new_max_id = int(alerts["id"].max()) if not alerts.empty else state["last_sample_count"]
    state["last_retrain_ts"] = time.time()
    state["last_sample_count"] = new_max_id
    _save_state(state)

    print(f"[INFO] Retrain complete at {datetime.now().isoformat(timespec='seconds')}.")
    return True


def _version_model(state: dict):
    """Copy current rf_model.pkl into model_versions/ with a timestamp suffix."""
    if not MODEL_PATH.exists():
        return

    VERSIONS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    dest = VERSIONS_DIR / f"rf_model_v{ts}.pkl"
    shutil.copy2(MODEL_PATH, dest)
    shutil.copy2(SCALER_PATH, VERSIONS_DIR / f"rf_scaler_v{ts}.pkl") if SCALER_PATH.exists() else None

    history: list = state.setdefault("version_history", [])
    history.append(str(dest))

    # Prune oldest versions beyond MAX_VERSIONS
    while len(history) > MAX_VERSIONS:
        old = Path(history.pop(0))
        old.unlink(missing_ok=True)
        # Remove matching scaler
        old_scaler = old.parent / old.name.replace("rf_model", "rf_scaler")
        old_scaler.unlink(missing_ok=True)

    print(f"  Versioned: {dest.name}")


# ── Rollback ──────────────────────────────────────────────────────────────────

def rollback(version: str | None = None):
    state = _load_state()
    history = state.get("version_history", [])

    if not history:
        print("[ERROR] No version history found. Nothing to rollback.")
        return

    if version:
        target = Path(version)
    else:
        target = Path(history[-1])

    if not target.exists():
        print(f"[ERROR] Version file not found: {target}")
        return

    shutil.copy2(target, MODEL_PATH)
    scaler_ver = target.parent / target.name.replace("rf_model", "rf_scaler")
    if scaler_ver.exists():
        shutil.copy2(scaler_ver, SCALER_PATH)

    print(f"[INFO] Rolled back to: {target.name}")


# ── Streamlit panel ───────────────────────────────────────────────────────────

def render_retrain_panel():
    """Called from app.py to render the retraining panel inside Streamlit."""
    try:
        import streamlit as st
    except ImportError:
        return

    state = _load_state()
    triggers = check_triggers(state)

    col1, col2, col3 = st.columns(3)
    col1.metric("New alerts since last retrain", triggers["new_samples"])
    col2.metric("Hours since last retrain", f"{triggers['hours_since_last']:.1f}")
    col3.metric("Drift detected", "Yes" if triggers["drift_trigger"] else "No")

    if triggers["should_retrain"]:
        st.warning("Retraining is due based on trigger conditions.")
    else:
        st.success(f"No retrain needed. Next check: when {MIN_SAMPLES} new alerts accumulate.")

    col_a, col_b = st.columns(2)
    if col_a.button("🔄 Retrain now (force)"):
        with st.spinner("Retraining …"):
            retrain(force=True)
        st.success("Retrain complete. Reload the dashboard.")

    state2 = _load_state()
    history = state2.get("version_history", [])
    if history and col_b.button("⏪ Rollback to previous version"):
        rollback()
        st.success(f"Rolled back to {Path(history[-1]).name}")

    if history:
        st.caption("Saved model versions: " + ", ".join(Path(p).name for p in history))


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Model retraining pipeline for Hybrid IDS.")
    parser.add_argument("--force", action="store_true", help="Retrain regardless of triggers")
    parser.add_argument("--status", action="store_true", help="Show trigger status only")
    parser.add_argument("--rollback", action="store_true", help="Rollback to previous model version")
    parser.add_argument("--version", default=None, help="Specific version file to rollback to")
    parser.add_argument("--lstm", action="store_true", help="Also retrain the LSTM model")
    args = parser.parse_args()

    if args.rollback:
        rollback(args.version)
        return

    state = _load_state()
    triggers = check_triggers(state)

    if args.status:
        print("── Retrain Status ───────────────────────────────")
        print(f"  New samples    : {triggers['new_samples']:,}  (threshold: {MIN_SAMPLES})")
        print(f"  Hours elapsed  : {triggers['hours_since_last']:.1f}  (threshold: {MIN_HOURS_BETWEEN_RETRAINS})")
        print(f"  Drift detected : {'Yes' if triggers['drift_trigger'] else 'No'}  (threshold: F1 < {DRIFT_THRESHOLD})")
        print(f"  Should retrain : {'Yes' if triggers['should_retrain'] else 'No'}")
        return

    retrain(force=args.force, retrain_lstm=args.lstm)


if __name__ == "__main__":
    main()
