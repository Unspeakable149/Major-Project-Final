# Threat Scoring Model — Methodology & Justification

**Enhancement:** *Threat Analysis Report* (Enhancement Ideas 1–8, from the
project's shared enhancement brief).
**Where it lives:** `compute_threat_score()` in `Rui Yang/scripts/scoring.py`
(computation), `Rui Yang/scripts/report.py` (the report layer that reads it).
**Tests:** `Rui Yang/tests/test_scoring.py` (54 cases pinning every bucket +
the end-to-end behaviour), `Rui Yang/tests/test_rules.py` (36 cases pinning
every detection rule that feeds this model's `reason` input).

---

## 1. Why this enhancement

The rule + ML engine alone produces a categorical verdict — Safe, Moderate,
or Severe. That answers *is this a threat?* but not *how bad, why, and what
should an analyst do about it?* Two Severe flows — a single confirmed
malware-port hit and a sustained flood from a source with twelve prior
incidents — look identical in a bare categorical view.

This model turns the verdict into a 0–100 Threat Score, a five-tier level,
and (via `report.py`) a per-flow narrative of *why* and *what to do*, so a
non-technical reader and an analyst both get something actionable instead of
a bare label.

| Brief idea | Implemented as |
|---|---|
| 1 — Threat Analysis Report | `report.py` / `management_report.py` — score, level, reasons, actions |
| 2 — Overall Threat Score (additive) + FP reduction | `compute_threat_score()` |
| 3 — Severity by attack type | `SEVERITY_BY_RULE` |
| 4 — Attack frequency | `frequency_score()` (pps buckets) |
| 5 — Behavioural indicators | `behaviour_score()` |
| 6 — Historical information | `historical_score()` + `offender_history.py` |
| 7 — Detection confidence | `confidence_score()` |
| 8 — Final score → level | `threat_level()` (0-20-40-60-80-100) |

---

## 2. The formula

```
score = Severity        (12–40)  attack type, Idea 3
      + Frequency        (0–20)  packet rate, Idea 4
      + Behaviour        (0–15)  abnormal indicators, Idea 5
      + Confidence       (5–15)  detection certainty, Idea 7
      + Historical       (0–10)  repeat-offender memory, Idea 6
      + Critical Port    (0–10)  target-service sensitivity — see §3.7
      − False-Positive Reduction               Idea 2 (see §4)
score = clamp(score, 0, 100)
level = Normal | Low | Medium | High | Critical  (Idea 8)
```

Each component is bounded and additive so no single factor can dominate the
total, and the final clamp keeps the score meaningful even when several
components max out at once. This engine scores completed offline flows from
an uploaded PCAP — 14 named signature rules plus an RF model's probability —
so every component below is shaped around what's actually knowable from a
finished flow, not a live per-window packet stream.

---

## 3. Component weights and their justification

The exact numbers are calibrated examples rather than a formally derived
model, anchored to three widely-used frameworks so the *relative* weighting
is defensible, not arbitrary:

- **CVSS v3.1** (FIRST) — a bounded 0–100 composite built from bounded
  sub-scores, with severity *bands* mapped from ranges.
- **MITRE ATT&CK** — attack-type severity ordering follows the tactic each
  rule's finding maps to (reconnaissance < credential access/exploitation <
  impact/C2/exfiltration).
- **NIST SP 800-61r2** — repeat-offender and detection-confidence weighting
  follows its *recurrence* and *reliability* prioritisation principles.

### 3.1 Severity — attack type (12–40, Idea 3)

`SEVERITY_BY_RULE` in `scoring.py`, ordered by the MITRE ATT&CK tactic each
rule's finding corresponds to:

| Rule | Score | ATT&CK tactic | Rationale |
|---|---|---|---|
| Telnet Usage Detected | 12 | — (hygiene) | Unencrypted protocol exposure, not an active attack in progress |
| Port Scan Detected | 15 | TA0043 Reconnaissance | Pre-attack probing |
| NULL/Xmas Scan Detected | 18 | TA0043 Reconnaissance | Stealth-scan variant — evasion intent raises it slightly above a plain scan |
| Oversized Packet Detected | 20 | — (anomaly) | Generic size anomaly, low confidence in specific intent |
| ML Anomaly Detected | 20 | — (unclassified) | No named rule matched; ML-only findings carry the same low base as an unspecified anomaly |
| High Bandwidth Anomaly | 22 | — (anomaly) | Volume anomaly without a specific attack signature |
| Web Attack Detected | 25 | TA0001/TA0002 Initial Access / Execution | Exploitation attempt against a web-facing service |
| Brute Force Detected | 28 | TA0006 Credential Access | Active credential-guessing |
| ICMP Flood Detected | 28 | TA0040 Impact | Availability attack |
| Bot Activity Detected | 30 | TA0011 Command & Control | Traffic to a beacon-style control port — implies established compromise |
| DoS Attack Detected | 30 | TA0040 Impact | Single-flow availability attack |
| DDoS Attack Detected | 38 | TA0040 Impact | Larger-scale volumetric flood — see honest caveat below |
| DNS Tunneling Detected | 35 | TA0011/TA0010 C2 / Exfiltration | Post-compromise data exfiltration channel |
| Suspicious Port Detected | 40 | — (confirmed indicator) | Traffic to a *known* malware port is closer to ground-truth confirmation than any behavioural inference — highest base score |

**Honest caveat, not glossed over:** `check_ddos` and `check_dos` are both
single-flow volumetric rules — neither actually confirms traffic is
*distributed* across multiple attacking sources. The "DDoS" name reflects
the packet-size/volume signature CICIDS2017 labels that way, not a verified
multi-source origin. The severity gap (38 vs 30) is justified by the larger
sustained-volume floor `check_ddos` requires (§ rules.py `ddos_min_fwd_packets`),
not by confirmed distribution.

### 3.2 Frequency — packet rate (0–20, Idea 4)

`frequency_score()` bands the flow's packets/sec into five tiers, since raw
rate is a magnitude rather than a yes/no signal and needs bucketing to stay
bounded and monotonic:

| Packets/sec | Score |
|---|---|
| < 20 | 0 |
| 20–100 | 5 |
| 100–300 | 10 |
| 300–700 | 15 |
| ≥ 700 | 20 |

### 3.3 Behaviour — abnormal indicators (0–15, Idea 5)

`behaviour_score()` counts independent indicators present in the flow, then
bands the count onto Normal/Slightly/Moderately/Highly abnormal (0/5/10/15):

- **Unusual destination port** — malware/C2 ports (4444, 1337, 31337, 6666–6668) or 8080.
- **Bandwidth spike** — `Flow Bytes/s > 1,000,000`.
- **High packet rate** — `Flow Packets/s > 1000` (recon/flood behaviour).
- **Flagless / stealth packets** — no FIN, PSH, or ACK set (possible scan).
- **Oversized DNS** — port 53 with `Fwd Packet Length Mean > 200` (tunnelling indicator).

Counting distinct indicators rather than summing raw magnitudes keeps the
term bounded at 15 and stops one loud metric from dominating.

### 3.4 Historical — repeat offender (0–10, Idea 6)

`historical_score()` bands how many times this source IP has previously
been flagged an attacker:

| Prior incidents | Score |
|---|---|
| 0 | 0 |
| 1–5 | 3 |
| 6–10 | 6 |
| > 10 | 10 |

Backed by `offender_history.py` — a persistent SQLite store, so this memory
survives across separate PCAP uploads, not just within one file (NIST 800-61's
*recurrence* principle).

### 3.5 Confidence — detection certainty (5–15, Idea 7)

`confidence_score()` bands the stronger of the rule's own confidence or the
RF model's attack probability:

| max(rule confidence %, ML probability %) | Score |
|---|---|
| < 60 | 5 |
| 60–80 | 10 |
| > 80 | 15 |

Taking the *stronger* of the two signals means a high-certainty detection
from either source is rewarded, rather than requiring both to agree.

### 3.6 Final level (Idea 8)

`threat_level()` maps the final clamped score onto five bands:

| Score | Level |
|---|---|
| 0–20 | Normal |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

### 3.7 Critical Port bonus (0–10)

`critical_port_score()` is a CVSS-style context modifier: the *same* attack
is more dangerous against a high-value service than an arbitrary port, so
this adds points when the flow's destination is a sensitive service:

| Destination port | Bonus | Service |
|---|---|---|
| 22, 23, 3389 | 10 | Remote shell / desktop — worst case if compromised |
| 3306, 5432, 1433, 445 | 8 | Database / file share |
| 53, 389, 88 | 6 | Name resolution / directory / auth infrastructure |
| anything else | 0 | — |

This exists because the underlying detection rules are port-agnostic by
design (the same `check_dos`/`check_ddos` logic fires regardless of target),
so without this modifier, a flood against an arbitrary port and a flood
against an exposed database would score identically — which understates the
real-world impact difference.

---

## 4. False-positive reduction (Idea 2)

The clearest case is handled by an explicit gate, not a penalty: a flow with
`reason == "Normal Traffic"` and no rule fired is short-circuited to score 0
before any component is even computed. This exists because of a real bug —
`severity_score()`'s default of 15 for any unlisted reason used to leak a
nonzero score onto flows the report itself was labelling "Safe," since
"Normal Traffic" was never in `SEVERITY_BY_RULE`. The gate is pinned by
`test_normal_traffic_scores_zero_even_with_unlisted_reason` so it can't
silently regress.

For borderline cases — a rule that fired but with weak corroborating
evidence — `false_positive_reduction()` subtracts specific, evidence-based
penalties instead of an all-or-nothing gate:

- **−5** if a rule fired but the ML model is strongly confident it's benign
  (`attack_prob < 0.05`) — the two detectors disagree, and ML's dissent is
  treated as real signal, not noise.
- **−3** if the flow has fewer than 5 forward packets — too little evidence
  for a confident verdict either way.

Penalties stack, so a flow hitting both conditions is discounted by 8
points total rather than whichever penalty happens to apply first.

---

## 5. Why these numbers are trustworthy

1. **Thresholds are data-derived, not hand-picked.** Every fire/no-fire
   *threshold* the rules in §3.1 depend on (`rules.py`'s `THRESHOLDS`, e.g.
   the DDoS byte-mean floor, the DoS pps floor) is computed by
   `derive_thresholds.py` from real CICIDS2017 traffic — each floor anchored
   below a validated synthetic attack sample's percentile rank, and checked
   safe against known-normal samples in the *other* direction too, rather
   than picked by trial-and-error.
2. **A genuine methodology mistake is part of the record, not hidden.** The
   first attempt at data-derived thresholds actually broke a working
   detection (the DDoS byte-mean floor came out low enough that ordinary
   HTTPS traffic cleared it) — caught by regression-testing in both
   directions, not just checking the attack side. `derive_thresholds.py`'s
   own `safe_floor()` now enforces that dual-direction check automatically.
3. **Real historical bugs are pinned by name, not just covered generically.**
   `Rui Yang/tests/` (117 tests total across `test_rules.py`, `test_scoring.py`,
   `test_offender_history.py`, `test_report.py`) includes named regression
   tests tied to specific real incidents — the port-443 gap, the DoS
   false-positive on browsing traffic, the DDoS false-positive on a
   legitimate Google IP, the most-severe-wins rule resolution, this model's
   own Normal-Traffic zero-score gate, and the DNS-tunnelling port-agnostic
   fix — so a regression on any of them fails loud instead of silently
   shipping.

---

## 6. References

- FIRST — *Common Vulnerability Scoring System (CVSS) v3.1 Specification*.
- MITRE — *ATT&CK Enterprise Matrix* (tactics TA0043, TA0040, TA0006, TA0011, TA0010, TA0001/TA0002).
- NIST — *SP 800-61 Rev. 2, Computer Security Incident Handling Guide* (recurrence, detection reliability, incident prioritisation).
- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP 2018 — the CICIDS2017 dataset this engine's thresholds and ML model are both derived from.
