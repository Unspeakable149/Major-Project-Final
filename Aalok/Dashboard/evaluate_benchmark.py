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
"""

import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report

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


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns={k: v for k, v in CIC_ALIASES.items() if k in df.columns})
    df.columns = [c.strip() for c in df.columns]
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0
    if 'Label' not in df.columns:
        raise SystemExit("Expected a 'Label' column with BENIGN / attack-name values.")
    return df


def report(y_true_bin, y_pred_bin, latency_ms: float) -> None:
    tp = int(((y_true_bin == 1) & (y_pred_bin == 1)).sum())
    fn = int(((y_true_bin == 1) & (y_pred_bin == 0)).sum())
    fp = int(((y_true_bin == 0) & (y_pred_bin == 1)).sum())
    tn = int(((y_true_bin == 0) & (y_pred_bin == 0)).sum())

    dr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * dr / (precision + dr)) if (precision + dr) else 0.0

    def verdict(value, target, lower_is_better=False):
        ok = value <= target if lower_is_better else value >= target
        return "PASS" if ok else "FAIL"

    print("\nBenchmark evaluation (attack vs benign):")
    print(f"  Detection Rate : {dr*100:6.2f}%   target > 95%   [{verdict(dr, 0.95)}]")
    print(f"  False Positive : {fpr*100:6.2f}%   target <  5%   [{verdict(fpr, 0.05, lower_is_better=True)}]")
    print(f"  Precision      : {precision*100:6.2f}%   target > 90%   [{verdict(precision, 0.90)}]")
    print(f"  F1-Score       : {f1*100:6.2f}%   target > 92%   [{verdict(f1, 0.92)}]")
    print(f"  Latency        : {latency_ms:6.3f} ms target < 10 ms [{verdict(latency_ms, 10.0, lower_is_better=True)}]")
    print(f"\n  Confusion: tp={tp}  fn={fn}  fp={fp}  tn={tn}")


def main():
    if len(sys.argv) < 2:
        print("usage: python evaluate_benchmark.py <benchmark_csv>")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        sys.exit(f"file not found: {path}")

    print(f"[1/4] Loading {path.name}...")
    df = pd.read_csv(path, low_memory=False)
    print(f"      rows: {len(df):,}")

    print("[2/4] Normalizing columns and aligning with model feature set...")
    df = normalize_columns(df)
    features = df[FEATURE_COLS].replace([np.inf, -np.inf], 0).fillna(0)
    y_true_bin = (df['Label'].astype(str).str.upper() != 'BENIGN').astype(int).to_numpy()

    print("[3/4] Loading rf_model.pkl + rf_scaler.pkl...")
    model = joblib.load("rf_model.pkl")
    scaler = joblib.load("rf_scaler.pkl")

    print("[4/4] Predicting...")
    scaled = scaler.transform(features)
    t0 = time.perf_counter()
    y_pred = model.predict(scaled)
    elapsed = time.perf_counter() - t0
    latency_ms = (elapsed / max(len(scaled), 1)) * 1000.0
    y_pred_bin = (y_pred > 0).astype(int)

    print("\nMulti-class breakdown vs ground truth:")
    print(classification_report(y_true_bin, y_pred_bin, target_names=['Benign', 'Attack'], zero_division=0))

    report(y_true_bin, y_pred_bin, latency_ms)


if __name__ == "__main__":
    main()
