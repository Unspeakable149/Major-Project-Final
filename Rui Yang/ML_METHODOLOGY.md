# Machine Learning Model — Methodology & Justification

**Where it lives:** `Rui Yang/scripts/train2.py` (training), consumed by `analyse_pcap()` in
`Rui Yang/app/pcap_engine.py` (inference). Saved artifacts: `Rui Yang/models/ids_model_live.pkl`
(the trained classifier), `scaler_live.pkl` (feature scaler), `live_features.pkl` (the exact
feature list, in order, the model expects).

This document covers the **statistical detection layer** — the Random Forest classifier that
runs alongside the 15-rule signature engine documented in `SCORING_METHODOLOGY.md`. That
document explains how a rule match and this model's output get combined into one threat score;
this one explains how the model itself was built, why, and how well it actually performs.

---

## 1. Why a statistical layer, not just rules

Every rule in `rules.py` checks for a *known* pattern — a specific port, packet-size range, or
flag combination. That catches attacks that look like something already seen and coded for, but
misses anything that doesn't match a named signature. A statistical model trained on real traffic
can flag a flow as anomalous purely from its packet-level shape, without needing a human to have
written a rule for that exact pattern first — the two approaches catch genuinely different things,
which is the whole premise of "hybrid" in this project's name.

## 2. Dataset

**CICIDS2017** (Sharafaldin, Lashkari & Ghorbani, 2018) — the same dataset `derive_thresholds.py`
uses for the rule engine's thresholds, so both halves of the hybrid system are grounded in the
same ground truth. `C:\HybridIDPS\data\cleaned\cleaned_full_dataset.csv`: 2,520,590 labeled flows
— 2,094,896 Normal Traffic, 425,694 attack traffic across 6 categories (Port Scanning, DDoS, DoS,
Brute Force, Web Attacks, Bots).

**Real class imbalance, handled explicitly, not ignored:** attack traffic is ~17% of the dataset.
Left alone, a classifier optimizing raw accuracy could score 83% just by predicting "Normal" every
time. Two things address this:
- `class_weight='balanced'` — the model penalizes misclassifying the minority (attack) class more
  heavily during training, instead of treating both classes as equally common.
- `stratify=y_binary` on the train/test split — guarantees the 80/20 split preserves the same
  attack/normal ratio in both halves, so evaluation isn't accidentally easier or harder than the
  real distribution.

## 3. Feature selection — the constraint that shapes everything else

CICFlowMeter (the tool that produced CICIDS2017's features) computes dozens of flow statistics
offline, after a capture is complete. The **live-capture** half of this project's Hybrid IDS has
to compute flow features in real time, packet by packet, as traffic arrives — it cannot use any
CICFlowMeter feature that isn't actually derivable from raw packets on the fly.

This model is trained on exactly the same 22-feature subset the live engine can compute —
`LIVE_FEATURES` in `train2.py` (packet counts, byte counts, packet-length statistics, inter-arrival
timing, flag counts, destination port, initial window size). This is a deliberate constraint, not
an oversight: training on the full CICFlowMeter feature set would produce a model that looks
better in isolated evaluation but silently fails (or has to skip features) the moment it's asked
to score a flow from raw captured traffic. The PCAP-upload engine (this component) computes these
same 22 features itself in `pcap_engine.py`'s `extract_features()` — no CICFlowMeter dependency at
inference time either.

## 4. Model and hyperparameters

`RandomForestClassifier` (scikit-learn):

| Parameter | Value | Why |
|---|---|---|
| `n_estimators` | 200 | Enough trees to stabilize predictions without excessive training time on 2M+ rows |
| `max_depth` | 30 | Deep enough to capture non-linear interactions between packet-shape features without unconstrained overfitting |
| `class_weight` | `balanced` | Counteracts the ~83/17 normal/attack imbalance (§2) |
| `min_samples_split` | 5 | Requires at least 5 samples before splitting a node — a light regularizer against overfitting to noise |
| `min_samples_leaf` | 2 | Same purpose, applied to leaf size |
| `random_state` | 42 | Fixed seed — this training run is reproducible; rerunning `train2.py` against the same dataset produces the same model, not a different one each time |

An ensemble of trees was chosen over a single model (e.g. logistic regression) because the
features here interact non-linearly — a high packet count only means something different combined
with a small average packet size (a flood) versus a large one (bulk transfer) — and Random Forest
captures that without hand-engineering interaction terms. `StandardScaler` normalizes feature
magnitudes before training (features span very different ranges — a destination port number vs.
a byte count in the millions), applied consistently at both training and inference time via the
saved `scaler_live.pkl`.

## 5. Evaluation methodology and results

Standard 80/20 stratified holdout (§2) — the model is evaluated on 20% of the data it never saw
during training. These are the actual results of the currently deployed model, reproduced by
rerunning `train2.py` against the same dataset with the same fixed seed (not estimated or
carried over from an old run):

| Metric | Value |
|---|---|
| Accuracy | 99.85% |
| Precision | 99.30% |
| Recall | 99.84% |
| F1 Score | 99.57% |
| Attack detection | 85,003 / 85,139 (99.8%) |
| False positives | 596 / 418,979 normal flows (0.14%) |

**Per-attack-type detection rate — reported honestly, including the weaker categories:**

| Attack type | Detection rate |
|---|---|
| Port Scanning | 100.0% (17,981 / 17,986) |
| DDoS | 99.9% (25,669 / 25,683) |
| DoS | 99.9% (38,674 / 38,722) |
| Brute Force | 99.7% (1,889 / 1,895) |
| Bots | 92.8% (349 / 376) |
| Web Attacks | 92.5% (441 / 477) |

Four of six categories detect above 99%. Bots and Web Attacks sit visibly lower, around 92-93% —
named here rather than folded into the headline accuracy number. Two plausible, non-exclusive
reasons: these categories have far fewer training examples (376 and 477 rows respectively, vs.
tens of thousands for the flood-type attacks), and their traffic shape is closer to legitimate
web traffic than a flood's is, giving the model less of a clear statistical signal to key off.

## 6. Feature importance

```
Max Packet Length              0.1434
Average Packet Size            0.1303
Destination Port               0.1142
Total Length of Fwd Packets    0.0706
Fwd Packet Length Max          0.0571
Fwd Packet Length Min          0.0559
Total Fwd Packets              0.0506
Init_Win_bytes_forward         0.0491
Fwd Packet Length Mean         0.0463
Flow IAT Max                   0.0416
```

The model leans heavily on packet-size features (the top 2 alone account for ~28% of total
importance) and destination port. This is a useful interpretability check, not just a curiosity:
it explains *why* the rule engine's packet-size-based rules (port scan, DDoS, ICMP flood) and this
model tend to agree on the same flows — they're often keying off similar underlying signal, just
via different mechanisms (a hard threshold vs. a learned split). It also flags a real limitation:
an attack that doesn't move packet size or destination port off their normal baseline — a slow,
low-and-slow C2 beacon, for instance — has less for this particular feature set to key off, which
is exactly the gap JA3 TLS fingerprinting (evaluated this project, not built — see the Final
Reflection Report) was intended to help close, since it looks at *which tool* is talking rather
than traffic volume at all.

## 7. Honest limitations

- **Binary only.** The model answers "attack or not," not "which attack." Naming the specific
  attack type is the rule engine's job (`rules.py`'s 15 named rules) — this is why the system
  fuses both rather than relying on either alone; the ML layer's own output has no attack-type
  label to offer even when it fires correctly.
- **Benchmark dataset, not live production traffic.** CICIDS2017 is a widely-used, realistic
  academic benchmark, but it is still a captured, curated dataset, not this specific project's own
  live network. Performance on real live traffic could differ from these holdout numbers, though
  the live and PCAP-upload paths use the same live-extractable feature constraint (§3) specifically
  to keep that gap as small as possible.
- **Bots and Web Attacks detect meaningfully worse than the other four categories** (§5) — stated
  plainly here rather than only in the headline 99.85% accuracy figure, which is true but would
  overstate performance on those two categories specifically if it were the only number reported.

---

## References

- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion
  Detection Dataset and Intrusion Traffic Characterization.* ICISSP 2018 — the CICIDS2017 dataset
  this model is trained and evaluated on.
- Breiman, L. (2001). *Random Forests.* Machine Learning, 45(1), 5-32 — the ensemble method this
  classifier is built on.
