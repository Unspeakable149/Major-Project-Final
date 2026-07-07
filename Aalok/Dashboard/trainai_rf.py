"""Train the Random Forest classifier.

Labels come from velocity + flag features (weak supervision) since raw
PCAPs have no ground-truth labels. For real benchmark validation, use
evaluate_benchmark.py with CIC-IDS-2017.

Spec targets: DR > 95%, FPR < 5%, Precision > 90%, F1 > 92%, latency < 10ms.
"""

import time
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

LABEL_NAMES = {0: "Baseline (Safe)", 1: "Moderate (Suspicious)", 2: "Severe (Critical Anomaly)"}

FEATURE_COLS = [
    'total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports',
    'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags',
    'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second',
    'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio',
    'packet_size_std', 'iat_mean', 'iat_std',
]


def assign_behavioral_label(row) -> int:
    pps = row.get('packets_per_second', 0)
    sar = row.get('syn_ack_ratio', 0)
    ports = row.get('unique_target_ports', 0)
    avg_size = row.get('avg_packet_size', 0)

    if pps > 500 and sar > 5:
        return 2
    if pps > 1000:
        return 2
    if ports > 20:
        return 1
    if pps > 300 and avg_size > 800:
        return 1
    return 0


def report_target_metrics(y_true, y_pred, latency_ms: float):
    """Detection Rate, FPR, Precision, F1 vs spec targets.

    Treats class 0 as 'benign' and classes 1/2 collectively as 'attack' so
    the binary detection metrics line up with the project's success criteria.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    attack_true = y_true > 0
    attack_pred = y_pred > 0

    tp = int(((attack_true) & (attack_pred)).sum())
    fn = int(((attack_true) & (~attack_pred)).sum())
    fp = int(((~attack_true) & (attack_pred)).sum())
    tn = int(((~attack_true) & (~attack_pred)).sum())

    dr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = dr
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    def mark(value, target, lower_is_better=False):
        ok = value <= target if lower_is_better else value >= target
        return "PASS" if ok else "FAIL"

    print("\n   Spec target metrics (attack vs benign, binary view):")
    print(f"      Detection Rate   : {dr*100:6.2f}%   target > 95%      [{mark(dr, 0.95)}]")
    print(f"      False Positive   : {fpr*100:6.2f}%   target <  5%      [{mark(fpr, 0.05, lower_is_better=True)}]")
    print(f"      Precision        : {precision*100:6.2f}%   target > 90%      [{mark(precision, 0.90)}]")
    print(f"      F1-Score         : {f1*100:6.2f}%   target > 92%      [{mark(f1, 0.92)}]")
    print(f"      Latency          : {latency_ms:6.3f} ms target < 10 ms    [{mark(latency_ms, 10.0, lower_is_better=True)}]")


def main():
    print("[1/9] Loading flow dataset...")
    df = pd.read_csv("ai_ready_advanced_flows.csv")
    print(f"      flow records: {len(df):,}")

    print("[2/9] Selecting feature matrix...")
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise SystemExit(
            f"Missing columns in input CSV: {missing}\n"
            f"Rerun feature_engineer.py to regenerate the dataset with the current feature set."
        )
    features = df[FEATURE_COLS].replace([np.inf, -np.inf], 0).fillna(0)

    print("[3/9] Deriving heuristic (weak-supervision) labels...")
    labels = df.apply(assign_behavioral_label, axis=1)
    for label_id, count in sorted(labels.value_counts().to_dict().items()):
        print(f"      class {label_id} ({LABEL_NAMES[label_id]}): {count}")

    print("[4/9] Scaling features (StandardScaler)...")
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)

    print("[5/9] Splitting train/test (80/20, stratified where possible)...")
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            scaled, labels, test_size=0.2, random_state=42, stratify=labels
        )
    except ValueError:
        X_train, X_test, y_train, y_test = train_test_split(
            scaled, labels, test_size=0.2, random_state=42
        )
    print(f"      train: {len(X_train)}  test: {len(X_test)}")

    print("[6/9] Training RandomForestClassifier (100 trees, balanced weights)...")
    model = RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced'
    )
    model.fit(X_train, y_train)

    print("[7/9] Evaluating on held-out test set...")
    # Latency: average per-decision predict time on the test split.
    t0 = time.perf_counter()
    y_pred = model.predict(X_test)
    elapsed = time.perf_counter() - t0
    per_decision_ms = (elapsed / max(len(X_test), 1)) * 1000.0

    acc = accuracy_score(y_test, y_pred)
    present = sorted(labels.unique())
    print(f"\n   Accuracy: {acc*100:.2f}%")
    print("\n   Per-class classification report:")
    print(classification_report(
        y_test, y_pred, labels=present, target_names=[LABEL_NAMES[i] for i in present], zero_division=0
    ))
    print("   Confusion matrix:")
    print(f"   labels={[LABEL_NAMES[i] for i in present]}")
    print(f"   {confusion_matrix(y_test, y_pred, labels=present)}")

    report_target_metrics(y_test, y_pred, per_decision_ms)

    print("\n[8/9] Feature importance ranking:")
    importance = pd.DataFrame({
        'feature': FEATURE_COLS,
        'importance': model.feature_importances_,
    }).sort_values('importance', ascending=False)
    for _, r in importance.iterrows():
        bar = '#' * int(r['importance'] * 60)
        print(f"      {r['feature']:22s} {r['importance']:.4f}  {bar}")

    print("\n[9/9] Saving artifacts...")
    joblib.dump(model, "rf_model.pkl")
    joblib.dump(scaler, "rf_scaler.pkl")
    print("      wrote rf_model.pkl, rf_scaler.pkl")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"  accuracy : {acc*100:.2f}%")
    print(f"  latency  : {per_decision_ms:.3f} ms / decision")
    print(f"  features : {len(FEATURE_COLS)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
