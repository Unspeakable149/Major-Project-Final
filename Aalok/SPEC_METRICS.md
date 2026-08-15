# Spec Target Metrics — Reproduction

Backing evidence for the "Metrics against the spec targets" slide. `TEST_RESULTS.md`
covers the six live Kali attacks; this file covers the five numeric spec targets,
which were previously only reported on the slide with no artifact in the repo.

## Reproduce

```bash
cd Aalok/Dashboard
python ../reproduce_spec_metrics.py
```

Needs `rf_model.pkl`, `rf_scaler.pkl` and `ai_ready_advanced_flows.csv`, all of
which are already in `Aalok/Dashboard/`. No tshark, no live NIC, no admin rights.

## Result

```
flows            : 261
attack flows     : 15
features         : 18 (live_backend.FEATURE_COLS order)
confusion        : tp=15 fn=0 fp=0 tn=246
Detection Rate   : 100.0 %   target > 95 %   PASS
False Positive   : 0.0 %   target < 5 %    PASS
Precision        : 100.0 %   target > 90 %   PASS
F1-Score         : 100.0 %   target > 92 %   PASS
Latency/decision : 0.149 ms (best of 5, batched)   target < 10 ms   PASS
python 3.14.5 / Windows-11-10.0.26200-SP0
```

Latency is machine-dependent — the figure quoted on the slide (0.33 ms) came from
an earlier run on the demo laptop. Both are roughly 30-60x inside the 10 ms budget.
The batching is what buys this: `write_alerts()` makes **one** `predict()` call per
capture window over the whole feature matrix, not one call per flow.

## What these four 100 % figures actually mean

They are agreement scores, not independent detection scores, and the deck says so.

Raw PCAPs carry no ground-truth labels, so the Random Forest is trained with weak
supervision — the labels come from `classify_profile()`, our own heuristic rules.
Scoring the model against those same rules measures how faithfully it reproduces the
boundary it was taught. On 261 flows containing 15 rule-flagged attacks, 100 %
agreement is the expected outcome, not a triumph.

Two things are worth stating plainly:

- The **latency** number is a genuine engineering result. It is not affected by the
  weak-supervision caveat at all.
- The real detection evidence is `TEST_RESULTS.md` — 6 of 6 live attacks from a Kali
  VM, where the labels came from us launching the attacks rather than from our rules.

For genuinely independent numbers, `Dashboard/evaluate_benchmark.py` maps the same 18
features onto labelled CIC-IDS-2017/2018 columns and re-scores against third-party
ground truth.

## Gotcha

`ai_ready_advanced_flows.csv` stores its columns in a different order to
`live_backend.FEATURE_COLS`, and neither `rf_model.pkl` nor `rf_scaler.pkl` carries
`feature_names_in_` (both were fitted on bare numpy arrays). Feeding the CSV in its
own column order therefore does **not** raise — it silently scores garbage
(detection rate drops to ~13 %). Always index with `FEATURE_COLS` before scaling.
