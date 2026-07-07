# Threat Scoring Model — Methodology & Justification

**Enhancement:** *Threat Level Hunting* (CSCI / FYP enhancement brief).
**Where it lives:** `compute_threat_score()` in `Dashboard/live_backend.py`
(computation) and `render_threat_report()` in `Dashboard/app.py` (the report).
**Tests:** `tests/test_threat_score.py` (41 cases pinning every bucket + the
end-to-end behaviour).

---

## 1. Why this enhancement

The v1.0 engine ends at a **categorical** verdict — `Baseline (Safe)`,
`Moderate (Suspicious)`, or `Severe (Critical Anomaly)`. That answers *is this a
threat?* but not *how bad, why, and what do I do about it?* Two `Severe` flows —
a single spoofed SYN from a known-bad host and a 3,000-pps flood from a repeat
offender — look identical in a categorical view.

This model turns the verdict into a **0-100 Threat Score**, a **risk band**, and
an **analyst report** (reasons + suggested actions), so a business or consumer
gets an at-a-glance picture of the threat and an analyst gets an actionable one.
It implements all eight ideas in the enhancement brief:

| Brief idea | Implemented as |
|---|---|
| 1 — Threat Analysis Report | `render_threat_report()` → score, band, reasons, actions |
| 2 — Overall Threat Score (additive) | `compute_threat_score()` sum of components − FP reduction |
| 3 — Severity by attack type | `ATTACK_SEVERITY` table |
| 4 — Attack frequency | `_frequency_score()` (pps buckets) |
| 5 — Behavioural indicators | `_behaviour_score()` (port fan-out, failed handshakes, spray) |
| 6 — Historical information | `_historical_score()` + `INCIDENT_HISTORY` |
| 7 — Detection confidence | `_confidence_score()` (RF `predict_proba` buckets) |
| 8 — Final score → level | `_band_for()` (0-20-40-60-80-100) |

---

## 2. The formula

```
score = Severity            (0–40)   attack type, Idea 3
      + Frequency           (0–20)   connection rate, Idea 4
      + Behaviour           (0–15)   abnormal indicators, Idea 5
      + Historical          (0–10)   repeat-offender memory, Idea 6
      + Confidence          (5–15)   detection certainty, Idea 7
      − False-Positive Reduction     Idea 2 (see §4)
score = clamp(score, 0, 100)
band  = Normal | Low | Medium | High | Critical   (Idea 8)
```

The theoretical span before clamping is 5–100. The design intent is that a
component only contributes when its signal is genuinely present, and the fused
verdict decides whether the additive model runs at all (§4).

---

## 3. Component weights and their justification

The **exact numbers are calibrated examples** — the brief explicitly invites the
student to justify their own. They are anchored to three widely-used security
frameworks so the *relative* weighting is defensible, not arbitrary:

- **CVSS v3.1** (FIRST) — the idea of a 0-100/0-10 composite built from bounded
  sub-scores, and severity *bands* mapped from ranges, comes straight from CVSS.
- **MITRE ATT&CK** — the per-attack-type ordering (recon < volumetric <
  C2/exfil) follows the tactic each profile maps to in the dashboard
  (`TA0043 Reconnaissance` → `TA0011 Command & Control` / `TA0010 Exfiltration`).
- **NIST SP 800-61r2** (Incident Handling) — its *functional impact* +
  *recoverability* prioritisation motivates weighting **repeat offenders** and
  **detection confidence** into the total, not just raw volume.

### 3.1 Severity — attack type (0–40, Idea 3)

`ATTACK_SEVERITY` in `live_backend.py`:

| Profile | Score | Rationale |
|---|---|---|
| Standard Web / Ping / Whitelisted | 0 | benign baseline |
| Speed Test / Large Data Transfer | 8 | high volume, low intent |
| Port Scan / Reconnaissance | 15 | recon, pre-attack (ATT&CK TA0043) |
| Slow Port Scan (multi-window) | 18 | recon + evasion effort |
| DDoS SYN Flood | 30 | active availability attack (TA0040) |
| Sustained SYN / Brute-Force | 30 | active credential/DoS attack |
| High-Volume Flood | 35 | higher-impact availability attack |
| DNS Tunnel / C2 Channel | 35 | C2 / exfil (TA0011 / TA0010) — post-compromise |
| Known Malicious IP (intel) | 40 | confirmed-bad source, highest base |

A **floor keyed on the fused verdict** (`SEVERITY_FLOOR`: Severe→30, Moderate→15)
guarantees the number can never contradict the category. Rationale mirrors the
brief's example ordering (Malware 40 > DNS Tunnel 35 > SYN Flood 30 > Port Scan
15).

### 3.2 Frequency — connection rate (0–20, Idea 4)

`_frequency_score(pps)` — buckets taken directly from the brief:

| Packets/sec | Score |
|---|---|
| < 20 | 0 |
| 20–100 | 5 |
| 100–300 | 10 |
| 300–700 | 15 |
| > 700 | 20 |

Intensity is a magnitude, not a yes/no — buckets keep it monotonic and bounded.

### 3.3 Behaviour — abnormal indicators (0–15, Idea 5)

`_behaviour_score()` counts independent indicators, then maps the count onto the
brief's Normal / Slightly / Moderately / Highly bands (0 / 5 / 10 / 15):

- **Port fan-out** — `unique_target_ports > 20` (horizontal scan).
- **Failed / reset connections** — `RST > 20` or `RST > ACK` (incomplete or
  refused handshakes — brute-force, scan).
- **SYN/ACK imbalance** — `syn_ack_ratio > 3` (half-open handshakes — SYN flood).
- **Host spray** — `unique_target_ips > 10` (fan-out across targets).

Counting distinct behaviours (rather than summing raw magnitudes) prevents a
single loud metric from dominating and keeps the term bounded at 15.

### 3.4 Historical — repeat offender (0–10, Idea 6)

`_historical_score(prior_incidents)` — `INCIDENT_HISTORY` counts prior
non-baseline windows per source IP this session:

| Prior incidents | Score |
|---|---|
| 0 | 0 |
| 1–5 | 3 |
| 6–10 | 6 |
| > 10 | 10 |

Prioritising repeat offenders is the NIST 800-61 *recurrence* principle. Session
memory resets on backend restart; the SQLite alert log is the durable record.

### 3.5 Confidence — detection certainty (5–15, Idea 7)

`_confidence_score()` — the Random Forest's `predict_proba` max:

| Model confidence | Score |
|---|---|
| < 60 % | 5 |
| 60–80 % | 10 |
| > 80 % | 15 |

When the K-Means fallback model is active (no calibrated probability) the term is
the low bucket (5). Weighting confidence communicates *how sure the system is*,
so a low-confidence anomaly is not over-stated.

### 3.6 Final band (Idea 8)

`_band_for()`:

| Score | Band |
|---|---|
| 0–20 | Normal |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

---

## 4. False-positive reduction (Idea 2) — the key design decision

Rather than a fixed subtraction, FP reduction is realised by **gating the
additive model on the fused verdict**:

- If the fusion engine rules a flow **`Baseline (Safe)`** and it is **not** on the
  intel feed → **score 0 / Normal**. High-rate but benign traffic (a speed test
  at 900 pps) therefore never accumulates a misleading score.
- A **baseline-whitelisted** source is likewise forced to 0.
- Conversely, a **confirmed threat-intel match** is floored into the **High**
  band (≥ 75) regardless of current traffic volume — a known-malicious host is
  dangerous even when quiet.

This keeps the numeric score and the categorical verdict consistent by
construction, which is what makes the score trustworthy in a demo.

Worked examples (from `tests/test_threat_score.py`, verified):

| Scenario | Verdict | Score | Band |
|---|---|---|---|
| Normal web browsing | Baseline | 0 | Normal |
| Speed test @ 900 pps | Baseline | 0 | Normal (FP suppressed) |
| Port scan, 45 ports, 2 priors | Moderate | 53 | Medium |
| SYN flood @ 1500 pps, 12 priors | Severe | 85 | Critical |
| Known-bad IP, low traffic | Severe | 75 | High (intel floor) |
| Whitelisted host flooding | Severe | 0 | Normal (whitelist) |

---

## 5. "Why use my dashboard over a teammate's?"

The scoring model is the concrete differentiator:

1. **Explains, not just detects.** Every alert carries the reasons behind its
   score and recommended actions — the report an analyst can act on, not a bare
   "Attack Detected".
2. **Resolves ties.** Two `Severe` flows get different scores (85 vs 75), so the
   SOC knows what to triage first — a binary flag cannot.
3. **Consistent by construction.** Fusion gates the additive score, so the number
   and the category never disagree, and benign heavy traffic is suppressed.
4. **Justified and tunable.** Weights are anchored to CVSS / ATT&CK / NIST and
   pinned by 41 unit tests, so threshold changes are deliberate and fail loud.

---

## 6. References

- FIRST — *Common Vulnerability Scoring System (CVSS) v3.1 Specification*.
- MITRE — *ATT&CK Enterprise Matrix* (tactics TA0043, TA0040, TA0011, TA0010).
- NIST — *SP 800-61 Rev. 2, Computer Security Incident Handling Guide*
  (functional impact, recoverability, incident prioritisation).
- Threat-intel severity ordering informed by AbuseIPDB / Spamhaus DROP / FireHOL
  blocklist confidence models.
