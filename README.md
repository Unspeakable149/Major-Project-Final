# Hybrid IDS

**Real-time intrusion detection that runs on an ordinary laptop, and explains every alert in plain English.**

A network intrusion detection system that watches live traffic, decides whether
what it sees is an attack, and tells you *why* — with a 0–100 threat score, the
behaviour that triggered it, the suggested response, and a one-click firewall
block. No subscription, no cloud, no security analyst required.

Built as the CMP3602 Major Project, Diploma in Cybersecurity & Digital Forensics,
Temasek Polytechnic.

| | |
|---|---|
| **New here / non-technical?** | Start with **[docs/OVERVIEW.md](docs/OVERVIEW.md)** — what it does and why, no jargon |
| **Want to run it?** | **[docs/INSTALL.md](docs/INSTALL.md)** → **[docs/USAGE.md](docs/USAGE.md)** |
| **Reviewing the engineering?** | **[Aalok/how_it_works.md](Aalok/how_it_works.md)** and **[Test evidence](#test-evidence)** below |
| **Just want the app?** | [**Releases**](https://github.com/Unspeakable149/Major-Project-Final/releases) — prebuilt Windows `.exe`, no Python needed |

---

## What problem this solves

Signature antivirus works from a list of threats somebody already reported, so it
reacts *after* the damage. The quiet attacks — a slow port scan, an overnight
brute-force, malware tunnelling data out over DNS — walk straight past it. The
tools that do catch those need a security operations centre and a trained analyst
to read them.

This project puts that class of detection on a normal computer, and makes the
output readable by someone who is not a security analyst.

---

## What it detects

| Attack | Caught by | Evidence |
|---|---|---|
| Fast port scan (`nmap`, 1000 ports) | Heuristic rules | [TEST_RESULTS.md](Aalok/TEST_RESULTS.md) test 1 |
| SYN flood (`hping3`) | Heuristic + Random Forest | test 2 |
| Slow / stealth port scan (`nmap -T2`) | Multi-window rolling state | test 3 |
| Sustained low-rate SYN | Multi-window rolling state | test 4 |
| Traffic to a known-malicious IP | Threat intel feed | test 5 |
| UDP flood | Heuristic rules | test 6 |
| DNS-tunnel command-and-control | Per-protocol DNS rate check | [how_it_works.md §4.4](Aalok/how_it_works.md) |

**6 of 6 live attacks detected**, launched from a Kali Linux VM against the
monitored host, every alert on screen in under four seconds.

---

## How it works

Two independent detection brains judge the same traffic, and the more serious
verdict wins.

```
        [ tshark live capture — 2-second windows ]
                          |
                          v
      [ flow engineering — 18 behavioural features per source IP ]
                          |
        +-----------------+-----------------+
        |                                   |
        v                                   v
[ Random Forest ]                  [ heuristic rule engine ]
[ LSTM sequence model ]            [ rolling multi-window state ]
        |                          [ DNS-tunnel check ]
        |                          [ threat intel feed ]
        |                          [ baseline whitelist ]
        +-----------------+-----------------+
                          |
                          v
              [ fusion — max severity wins ]
                          |
                          v
       [ 0-100 threat score + plain-English reasoning ]
                          |
                          v
   [ SQLite alert log ] --> [ Streamlit dashboard ] --> [ one-click firewall block ]
```

Why two brains: rules are exact but blind to anything new; the model generalises
but can be noisy. Running both and taking the worse verdict gives coverage
without giving up precision.

Full detail — every layer, the 18 features, verdict precedence, the SQLite schema
— is in **[Aalok/how_it_works.md](Aalok/how_it_works.md)**.

---

## Quick start

**Prerequisite on every platform: Wireshark/tshark.** It is the capture engine and
it is not pip-installable. [Install instructions per OS →](docs/INSTALL.md)

### Option 1 — Windows, no Python

Download `HybridIDS.exe` from [**Releases**](https://github.com/Unspeakable149/Major-Project-Final/releases)
and double-click it. It self-elevates to Administrator (needed for packet capture)
and opens in its own window.

### Option 2 — from source, any OS

```bash
git clone https://github.com/Unspeakable149/Major-Project-Final.git
cd Major-Project-Final
python -m pip install -r requirements.txt
python run_hybrid_ids.py
```

Opens on `http://127.0.0.1:8501`.

- **Windows** — run from an Administrator terminal, or double-click `START.bat`
  (self-elevates and starts backend + dashboard together).
- **macOS / Linux** — `sudo python3 run_hybrid_ids.py`.
- `--no-capture` runs the dashboard with no network access and no admin rights.
- `--port 8600` moves it off the default port.

**The dashboard starts empty, and that is expected.** No alert database ships
with the repo — it would contain real captured traffic. The app creates an empty
one on first run; let a capture run for a minute and alerts appear.

---

## Repository layout

The dashboard resolves its sibling folders by path and imports them **in place** —
nothing is vendored — so the one-folder-per-contributor layout is load-bearing.
Keep it.

```
Aalok/          detection engine, dashboard, models, threat scoring
  Dashboard/
    app.py              the whole UI; hosts every contributor's tab
    live_backend.py     capture -> clean -> engineer -> classify -> score -> alert
    feature_engineer.py flow feature extraction
    advanced_parser.py  tshark -> dataframe
    notifier.py         email / Discord / Slack dispatch
    trainai_rf.py       Random Forest training
    evaluate_benchmark.py  scores the model against labelled CIC-IDS data
  tests/                pytest suite pinning the detection thresholds
Aaron/          MITRE ATT&CK technique mapping -> Live SOC tab
Megan/          LSTM sequence model, SHAP explainability, retraining pipeline
Rui Yang/       offline PCAP analysis engine, scoring, reporting -> PCAP + Threat Map tabs
APP/            desktop build: native-window launcher + PyInstaller recipe
docs/           overview, install, usage
```

Dashboard tabs: `Live SOC Dashboard`, `Educational Simulator`, `PCAP Analysis`,
`Threat Map`, `Model Intelligence`, `Defense Config`.

Every cross-folder import is wrapped in try/except with a graceful fallback, so a
missing dependency degrades one panel instead of killing the app. **Keep that
pattern if you add anything.**

---

## Test evidence

| Document | What it covers |
|---|---|
| [Aalok/TEST_RESULTS.md](Aalok/TEST_RESULTS.md) | Six live attacks from a Kali VM, per-attack detection layer and verdict |
| [Aalok/SPEC_METRICS.md](Aalok/SPEC_METRICS.md) | The five numeric spec targets, and how to reproduce them |
| [FEATURE-TEST-REPORT.md](FEATURE-TEST-REPORT.md) | Every feature by contributor, marked WORKS / PARTIAL / BROKEN / NOT TESTED |
| [Aalok/THREAT_SCORING.md](Aalok/THREAT_SCORING.md) | The 0-100 threat score: components and weight justification |
| [Rui Yang/ML_METHODOLOGY.md](Rui%20Yang/ML_METHODOLOGY.md) | PCAP-side model: training data, features, validation |
| [Rui Yang/SCORING_METHODOLOGY.md](Rui%20Yang/SCORING_METHODOLOGY.md) | PCAP-side offender scoring and threshold derivation |

### Reproducing the spec metrics

```bash
cd Aalok/Dashboard
python ../reproduce_spec_metrics.py
```

Needs no tshark, no network interface and no admin rights — everything it reads is
already in the repo.

```
flows            : 261
attack flows     : 15
confusion        : tp=15 fn=0 fp=0 tn=246
Detection Rate   : 100.0 %   target > 95 %   PASS
False Positive   : 0.0 %     target < 5 %    PASS
Precision        : 100.0 %   target > 90 %   PASS
F1-Score         : 100.0 %   target > 92 %   PASS
Latency/decision : 0.19 ms   target < 10 ms  PASS
```

**Read those four 100 % figures honestly.** Raw PCAPs carry no ground-truth
labels, so the Random Forest is trained with weak supervision — its labels come
from our own heuristic rules. Scoring the model against those same rules measures
how faithfully it reproduces the boundary it was taught, so 100 % agreement is the
expected outcome, not a triumph. The **latency** figure is unaffected by that
caveat and is a genuine engineering result. The real detection evidence is
`TEST_RESULTS.md`, where the labels came from us launching the attacks. For
independent numbers, `Dashboard/evaluate_benchmark.py` re-scores the same 18
features against labelled CIC-IDS-2017/2018 ground truth.

That caveat is stated here for the same reason it is stated in the report and on
the slides: a metric you cannot explain the weakness of is not evidence.

---

## Running the tests

```bash
cd Aalok      && python -m pytest        # detection thresholds, feature engineering
cd "Rui Yang" && python -m pytest        # PCAP rules, scoring, reporting
```

---

## Security notice

**Only run this on a network you are authorised to monitor.** It captures and
inspects live packet traffic. Doing that on a network you do not own or have
permission to test may be illegal where you live.

It runs elevated, it has no authentication, and its firewall buttons really do
change your firewall. Read **[SECURITY.md](SECURITY.md)** before you run it on
anything that matters.

---

## What is deliberately not in this repository

Alert databases and `.pcap` captures (real traffic from a real home network),
training datasets, model version snapshots, filled-in `notifier_config.json` /
`baseline.txt` (real credentials and host whitelists — copy the `.example` files
and fill them in locally), PyInstaller build output, and the coursework documents.

`Aalok/Dashboard/ai_ready_advanced_flows.csv` is kept because the spec-metric
reproduction depends on it. Its `Source IP` column is pseudonymised: every
routable address is replaced with `host_NNN`. The column is a label and never an
input — the 18 numeric features are what get scored — so the published metrics
reproduce exactly.

---

## Credits

**Aalok — project lead, detection engine and platform.** 62 of the project's 85
features, and the application every other contribution plugs into.

- The live detection engine (`live_backend.py`, 1,856 lines): tshark capture loop,
  2-second windowing, flow engineering, the heuristic rule engine, multi-window
  rolling state for slow attacks, the DNS-tunnel detector, the threat-intel feed,
  the baseline whitelist, and the fusion logic that reconciles every layer's verdict
- The 0–100 threat scoring system — severity, frequency, behaviour, historical and
  confidence components, false-positive gating, risk banding, and the plain-English
  analyst report ([THREAT_SCORING.md](Aalok/THREAT_SCORING.md))
- The Streamlit dashboard (`app.py`, 4,782 lines) — the host application. All seven
  tabs, including the ones presenting the other three contributors' modules, plus
  live telemetry, the firewall integration and auto-blocking
- The Random Forest training and benchmark pipeline, PCAP replay mode, the
  multi-channel alert notifier, and the 18-feature flow engineering all four
  detection layers consume
- The cross-platform desktop build: native-window launcher, PyInstaller recipe,
  and the release packaging
- The test and evidence base — the pytest suite, the six live Kali attack tests,
  the spec-metric reproduction, and the honest per-feature audit of all four
  contributors' work

| Contributor | Scope | Features | Python |
|---|---|---|---|
| **Aalok** | Detection engine, threat scoring, dashboard host, desktop build, test suite | **62** | **8,831 lines** |
| **Rui Yang** | Offline PCAP analysis engine, signature rules, offender scoring, reporting | 9 | 3,843 lines |
| **Megan** | LSTM sequence model, SHAP explainability, retraining pipeline | 8 | 1,608 lines |
| **Aaron** | MITRE ATT&CK technique mapping | 6 | 2,431 lines |

Feature counts and their WORKS / PARTIAL / BROKEN verdicts come from
[FEATURE-TEST-REPORT.md](FEATURE-TEST-REPORT.md), which audits every contributor
on the same evidence standard. Line counts are the Python tracked in this
repository.

Coursework submission, published for review. No reuse licence is granted — see
[SECURITY.md](SECURITY.md) for the terms it should be run under.
