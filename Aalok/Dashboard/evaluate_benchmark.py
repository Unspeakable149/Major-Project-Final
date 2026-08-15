"""Evaluate the trained RF classifier against a labeled benchmark dataset.

Designed for CIC-IDS-2017 / CIC-IDS-2018 style CSVs where each row already
holds engineered flow features plus a ground-truth Label column
(BENIGN / DoS Hulk / PortScan / ...).

Usage:
    python evaluate_benchmark.py path/to/cicids_flows.csv

The script renames the benchmark's columns to this project's feature names
where possible, scales them with the saved rf_scaler, predicts with rf_model,
collapses the multi-class output to attack vs benign, and reports the
spec target metrics (DR > 95%, FPR < 5%, Precision > 90%, F1 > 92%,
latency < 10 ms per decision).

Structure
---------
The numbers are computed by `evaluate_dataframe()`, which RETURNS a result
dict and prints nothing. `main()` (the CLI) and the dashboard's Detection
Benchmark tab both call it, so the console output and the on-screen gauges
can never disagree about what the model scored — there is one implementation
of the metrics, not two.
"""

import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report

# Model files sit next to this script. Anchoring to __file__ rather than the
# process working directory matters because the dashboard imports this module
# from a Streamlit process whose cwd is not necessarily Aalok/Dashboard.
BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

FEATURE_COLS = [
    'total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports',
    'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags',
    'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second',
    'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio',
    'packet_size_std', 'iat_mean', 'iat_std',
]

# Common CIC-IDS column aliases. Add more as needed for your specific CSV.
CIC_ALIASES = {
    'Total Fwd Packets': 'total_packets',
    'Total Length of Fwd Packets': 'total_bytes',
    'Flow Duration': 'flow_duration_sec',
    'Flow Packets/s': 'packets_per_second',
    'Flow Bytes/s': 'bytes_per_second',
    'Average Packet Size': 'avg_packet_size',
    'Packet Length Std': 'packet_size_std',
    'Flow IAT Mean': 'iat_mean',
    'Flow IAT Std': 'iat_std',
    'SYN Flag Count': 'total_syn_flags',
    'ACK Flag Count': 'total_ack_flags',
    'FIN Flag Count': 'total_fin_flags',
    'RST Flag Count': 'total_rst_flags',
}

# The spec targets this project is measured against. Held in one place so the
# CLI and the dashboard gauges cannot drift apart.
#   key: (label, target, lower_is_better, unit)
SPEC_TARGETS = {
    'detection_rate':  ("Detection Rate",  0.95, False, "%"),
    'false_positive':  ("False Positive",  0.05, True,  "%"),
    'precision':       ("Precision",       0.90, False, "%"),
    'f1':              ("F1-Score",        0.92, False, "%"),
    'latency_ms':      ("Latency",         10.0, True,  "ms"),
}


class BenchmarkError(Exception):
    """A benchmark CSV that cannot be evaluated (bad columns, no label, ...).

    Raised instead of calling sys.exit() so the dashboard can show the problem
    in the UI. main() catches it and exits, preserving the CLI contract.
    """


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={k: v for k, v in CIC_ALIASES.items() if k in df.columns})
    df.columns = [c.strip() for c in df.columns]
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0
    if 'Label' not in df.columns:
        raise BenchmarkError(
            "Expected a 'Label' column with BENIGN / attack-name values.")
    return df


def load_model_and_scaler():
    """Load rf_model.pkl + rf_scaler.pkl from beside this script."""
    model_path = BASE_DIR / "rf_model.pkl"
    scaler_path = BASE_DIR / "rf_scaler.pkl"
    for p in (model_path, scaler_path):
        if not p.exists():
            raise BenchmarkError(f"Model file not found: {p.name} (expected in {BASE_DIR})")
    return joblib.load(model_path), joblib.load(scaler_path)


def compute_metrics(y_true_bin, y_pred_bin, latency_ms: float) -> dict:
    """Confusion counts + the five spec metrics. Pure arithmetic, no I/O."""
    tp = int(((y_true_bin == 1) & (y_pred_bin == 1)).sum())
    fn = int(((y_true_bin == 1) & (y_pred_bin == 0)).sum())
    fp = int(((y_true_bin == 0) & (y_pred_bin == 1)).sum())
    tn = int(((y_true_bin == 0) & (y_pred_bin == 0)).sum())

    dr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * dr / (precision + dr)) if (precision + dr) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

    return {
        'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn,
        'detection_rate': dr,
        'false_positive': fpr,
        'precision': precision,
        'f1': f1,
        'accuracy': accuracy,
        'latency_ms': latency_ms,
    }


def passes(metric_key: str, value: float) -> bool:
    """Does this metric value meet its spec target?"""
    _, target, lower_is_better, _ = SPEC_TARGETS[metric_key]
    return value <= target if lower_is_better else value >= target


def per_attack_detection(labels, y_true_bin, y_pred_bin) -> pd.DataFrame:
    """Detection rate broken down by the CSV's own attack-name labels.

    The headline Detection Rate averages every attack type together, which
    hides the useful part: a model can score 96% overall while missing one
    whole attack class outright. This splits it back out, benign rows
    excluded (they have no "detection rate" to speak of — their errors are
    the false-positive figure instead).
    """
    labels = pd.Series(labels).astype(str)
    rows = []
    for name in sorted(labels[y_true_bin == 1].unique()):
        mask = (labels == name).to_numpy() & (y_true_bin == 1)
        total = int(mask.sum())
        if not total:
            continue
        caught = int((y_pred_bin[mask] == 1).sum())
        rows.append({
            'Attack Type': name,
            'Flows': total,
            'Detected': caught,
            'Missed': total - caught,
            'Detection Rate': caught / total,
        })
    out = pd.DataFrame(rows)
    return out.sort_values('Detection Rate') if len(out) else out


def evaluate_dataframe(df: pd.DataFrame) -> dict:
    """Run the full benchmark over an already-loaded CSV. Returns a dict.

    This is the single source of truth for the numbers — both the CLI and the
    dashboard call it. Raises BenchmarkError on unusable input.
    """
    df = normalize_columns(df)
    features = df[FEATURE_COLS].replace([np.inf, -np.inf], 0).fillna(0)
    labels = df['Label'].astype(str)
    y_true_bin = (labels.str.upper() != 'BENIGN').astype(int).to_numpy()

    model, scaler = load_model_and_scaler()

    scaled = scaler.transform(features)
    t0 = time.perf_counter()
    y_pred = model.predict(scaled)
    elapsed = time.perf_counter() - t0
    latency_ms = (elapsed / max(len(scaled), 1)) * 1000.0
    y_pred_bin = (np.asarray(y_pred) > 0).astype(int)

    result = compute_metrics(y_true_bin, y_pred_bin, latency_ms)
    result['rows'] = int(len(df))
    result['benign_rows'] = int((y_true_bin == 0).sum())
    result['attack_rows'] = int((y_true_bin == 1).sum())
    result['per_attack'] = per_attack_detection(labels, y_true_bin, y_pred_bin)
    result['classification_report'] = classification_report(
        y_true_bin, y_pred_bin, target_names=['Benign', 'Attack'],
        zero_division=0)
    return result


def evaluate_csv(path) -> dict:
    """Load a benchmark CSV from disk and evaluate it."""
    path = Path(path)
    if not path.exists():
        raise BenchmarkError(f"file not found: {path}")
    return evaluate_dataframe(pd.read_csv(path, low_memory=False))


def report(y_true_bin, y_pred_bin, latency_ms: float) -> None:
    """Print the spec-target table. Kept for backwards compatibility."""
    _print_report(compute_metrics(y_true_bin, y_pred_bin, latency_ms))


def _print_report(m: dict) -> None:
    print("\nBenchmark evaluation (attack vs benign):")
    for key in ('detection_rate', 'false_positive', 'precision', 'f1'):
        label, target, lower, _ = SPEC_TARGETS[key]
        arrow = "<" if lower else ">"
        verdict = "PASS" if passes(key, m[key]) else "FAIL"
        print(f"  {label:<15}: {m[key]*100:6.2f}%   target {arrow} {target*100:.0f}%   [{verdict}]")
    lat_verdict = "PASS" if passes('latency_ms', m['latency_ms']) else "FAIL"
    print(f"  {'Latency':<15}: {m['latency_ms']:6.3f} ms target < 10 ms [{lat_verdict}]")
    print(f"\n  Confusion: tp={m['tp']}  fn={m['fn']}  fp={m['fp']}  tn={m['tn']}")

    per_attack = m.get('per_attack')
    if per_attack is not None and len(per_attack):
        print("\n  Detection rate by attack type (worst first):")
        for _, r in per_attack.iterrows():
            print(f"    {r['Attack Type'][:34]:<34} "
                  f"{r['Detection Rate']*100:6.2f}%  "
                  f"({r['Detected']}/{r['Flows']})")


def main():
    if len(sys.argv) < 2:
        print("usage: python evaluate_benchmark.py <benchmark_csv>")
        sys.exit(1)

    path = Path(sys.argv[1])
    print(f"[1/4] Loading {path.name}...")
    try:
        df = pd.read_csv(path, low_memory=False) if path.exists() else None
        if df is None:
            sys.exit(f"file not found: {path}")
        print(f"      rows: {len(df):,}")

        print("[2/4] Normalizing columns and aligning with model feature set...")
        print("[3/4] Loading rf_model.pkl + rf_scaler.pkl...")
        print("[4/4] Predicting...")
        result = evaluate_dataframe(df)
    except BenchmarkError as exc:
        sys.exit(str(exc))

    print("\nMulti-class breakdown vs ground truth:")
    print(result['classification_report'])

    _print_report(result)


if __name__ == "__main__":
    main()
