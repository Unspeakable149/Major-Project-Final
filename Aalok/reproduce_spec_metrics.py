"""Reproduce the five spec-target metrics reported in the presentation.

Run from Aalok/Dashboard so live_backend and the model artifacts resolve:

    cd Aalok/Dashboard
    python ../reproduce_spec_metrics.py

Scores the shipped Random Forest against the heuristic rule engine over the
261-flow capture in ai_ready_advanced_flows.csv, and times batched inference.

These four rate metrics are AGREEMENT scores, not independent detection scores --
the model is trained with weak supervision from classify_profile(). See
SPEC_METRICS.md for the full caveat. The latency figure is unaffected by it.
"""

import platform
import sys
import time
from pathlib import Path

import joblib
import pandas as pd

DATASET = "ai_ready_advanced_flows.csv"
TIMING_RUNS = 5


def _load():
    """Import live_backend and the model artifacts, failing with a clear reason."""
    # Python puts the *script's* directory on sys.path, not the working directory,
    # so `python ../reproduce_spec_metrics.py` from Dashboard/ would miss it.
    if str(Path.cwd()) not in sys.path:
        sys.path.insert(0, str(Path.cwd()))
    try:
        import live_backend as lb
    except ImportError as exc:
        sys.exit(f"error: cannot import live_backend ({exc}).\n"
                 f"       run this from the Aalok/Dashboard directory.")

    missing = [f for f in (DATASET, "rf_model.pkl", "rf_scaler.pkl")
               if not Path(f).is_file()]
    if missing:
        sys.exit(f"error: missing in {Path.cwd()}: {', '.join(missing)}")

    try:
        model = joblib.load("rf_model.pkl")
        scaler = joblib.load("rf_scaler.pkl")
    except Exception as exc:                      # noqa: BLE001 - report and stop
        sys.exit(f"error: could not load model artifacts: {exc}")

    return lb, model, scaler


def main() -> int:
    lb, model, scaler = _load()
    df = pd.read_csv(DATASET)

    absent = [c for c in lb.FEATURE_COLS if c not in df.columns]
    if absent:
        sys.exit(f"error: {DATASET} is missing feature column(s): {', '.join(absent)}")

    # Index with FEATURE_COLS, never with the CSV's own column order. Neither
    # artifact carries feature_names_in_, so a wrong order scores silently wrong.
    scaled = scaler.transform(df[lb.FEATURE_COLS])

    model.predict(scaled[:5])                     # warm joblib's thread pool
    timings = []
    for _ in range(TIMING_RUNS):
        start = time.perf_counter()
        preds = model.predict(scaled).astype(int)
        timings.append((time.perf_counter() - start) / len(scaled) * 1000)

    rf = [lb.THREAT_LABEL_MAP.get(int(p), "Baseline (Safe)") for p in preds]
    rule = [lb.classify_profile(r.packets_per_second, r.syn_ack_ratio,
                                int(r.unique_target_ports), r.avg_packet_size)[1]
            for r in df.itertuples()]

    def attack(verdict):
        return not verdict.startswith("Baseline")

    tp = sum(1 for a, b in zip(rf, rule) if attack(a) and attack(b))
    fn = sum(1 for a, b in zip(rf, rule) if not attack(a) and attack(b))
    fp = sum(1 for a, b in zip(rf, rule) if attack(a) and not attack(b))
    tn = sum(1 for a, b in zip(rf, rule) if not attack(a) and not attack(b))

    if tp + fn == 0:
        sys.exit("error: no attack flows in the dataset - nothing to score.")

    dr = tp / (tp + fn)
    precision = tp / (tp + fp) if tp + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * dr / (precision + dr) if precision + dr else 0.0
    latency = min(timings)

    def verdict(ok):
        return "PASS" if ok else "FAIL"

    print(f"flows            : {len(df)}")
    print(f"attack flows     : {tp + fn}")
    print(f"features         : {len(lb.FEATURE_COLS)} (live_backend.FEATURE_COLS order)")
    print(f"confusion        : tp={tp} fn={fn} fp={fp} tn={tn}")
    print(f"Detection Rate   : {dr * 100:.1f} %   target > 95 %   {verdict(dr > .95)}")
    print(f"False Positive   : {fpr * 100:.1f} %   target < 5 %    {verdict(fpr < .05)}")
    print(f"Precision        : {precision * 100:.1f} %   target > 90 %   {verdict(precision > .90)}")
    print(f"F1-Score         : {f1 * 100:.1f} %   target > 92 %   {verdict(f1 > .92)}")
    print(f"Latency/decision : {latency:.3f} ms (best of {TIMING_RUNS}, batched)"
          f"   target < 10 ms   {verdict(latency < 10)}")
    print(f"python {sys.version.split()[0]} / {platform.platform()}")

    all_pass = (dr > .95 and fpr < .05 and precision > .90
                and f1 > .92 and latency < 10)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
