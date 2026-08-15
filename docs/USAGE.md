# Using Hybrid IDS

Assumes it is already installed — see **[INSTALL.md](INSTALL.md)** if not.

---

## First run

1. Start it (double-click `HybridIDS.exe`, or `sudo python3 run_hybrid_ids.py`).
2. The dashboard opens on `http://127.0.0.1:8501`. **It will be empty.** No alert
   database ships with the project — one would contain real captured traffic — so
   the app creates an empty one on first run.
3. Leave it running for a minute. Ordinary background traffic populates the
   telemetry table even when nothing is attacking you.
4. If nothing ever appears, you are almost certainly not running elevated, or the
   wrong network interface was auto-detected. Both are shown in the sidebar.

The sidebar under **Monitoring Controls** is where you pick the capture interface
and start/stop the engine.

---

## Reading an alert

Every capture window is two seconds long. Traffic in that window is grouped by
source IP, turned into 18 behavioural features, and judged by every detection
layer at once. The most serious verdict wins.

An alert gives you four things.

### 1. The threat level

The categorical verdict: `Baseline (Safe)`, `Moderate (Suspicious)`,
`Moderate (Bandwidth Spike)`, or `Severe (Critical Anomaly)`.

### 2. The threat score — 0 to 100

A numeric score built from five components, minus false-positive reduction:

```
score = severity + frequency + behaviour + historical + confidence
```

| Component | What it measures |
|---|---|
| **Severity** | How dangerous this attack type is (0–40) |
| **Frequency** | Connection rate — packets per second |
| **Behaviour** | Port spread, SYN/ACK ratio, RST volume, target fan-out |
| **Historical** | Whether this source has offended before |
| **Confidence** | How sure the Random Forest was |

Two guardrails matter:

- A flow the fusion engine rules **Baseline/Safe** (and which is not on the intel
  feed) scores **0**. This is what stops a speed test at high packets-per-second
  from accumulating a scary-looking score.
- A **threat-intel match floors the score at 75**, regardless of how little
  traffic the source is currently sending. A known-malicious host is dangerous
  even when it is quiet.

The methodology and the justification for each weight is in
**[THREAT_SCORING.md](../Aalok/THREAT_SCORING.md)**.

### 3. The risk band

| Score | Band |
|---|---|
| 0–20 | Normal |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

The band can never contradict the verdict — a Severe flow carries a severity
floor of 30, so it cannot land in Normal.

### 4. The reasoning and the suggested action

Plain-English lines explaining what tripped: the attack type and its base
severity, the connection rate, each behavioural abnormality, prior incidents, and
model confidence — followed by what to do about it.

---

## Blocking a source

1. In **Live SOC Dashboard**, click the alert's row in the telemetry table.
2. Use the block control on the inspector panel that opens.

This installs a real Windows Defender firewall rule named `IDS_BLOCK_<ip>`.
Remove it from the dashboard, or from a terminal:

```
netsh advfirewall firewall delete rule name=IDS_BLOCK_<ip>
```

**Windows only.** On macOS and Linux the button reports itself unsupported rather
than pretending to work — the block is still recorded in the database, but no
packet filter changes.

### Auto-blocking

Off by default. When enabled in the sidebar, a source is blocked automatically
after **3 Severe alerts**, for **1 hour**. Both values are configurable at
runtime.

---

## The tabs

| Tab | What it is for |
|---|---|
| **Live SOC Dashboard** | Real-time alerts, telemetry table, charts, top talkers, per-protocol breakdown, and blocking. This is the main view. |
| **Educational Simulator** | A safe sandbox that walks through each attack type and what it looks like to the engine. Nothing is captured or sent. Use this to learn the system without launching anything. |
| **PCAP Analysis** | Upload a `.pcap` for offline forensics — signature rules, offender scoring, and exportable Word/HTML reports. |
| **Threat Map** | Geolocates attacker IPs from the analysed PCAP onto a world map. Populate it by running a PCAP through the previous tab first. |
| **Model Intelligence** | SHAP explainability for the Random Forest and the LSTM, plus the retraining pipeline. Shows *which features* drove a verdict. |
| **Defense Config** | Manage the threat-intel IP list, the baseline whitelist, and the alert notifier. |
| **Detection Benchmark** | Scores the trained model against a labelled CIC-IDS-2017/2018 benchmark for independent numbers. |

---

## Replaying a PCAP instead of capturing live

Useful for reproducible demos and for grading runs — the same pipeline, no live
NIC, no admin rights:

```bash
cd Aalok/Dashboard
python live_backend.py --replay path/to/capture.pcap
```

Add `--realtime` to insert live-cadence sleeps, which makes a screen recording
look like a real capture rather than a fast-forward.

---

## Getting alerts off the machine

Copy `Aalok/Dashboard/notifier_config.json.example` to `notifier_config.json` and
fill it in. Severe verdicts are then pushed over SMTP, Discord or Slack, throttled
to one per hour per `(source IP, channel)` so a sustained attack cannot flood your
inbox.

The file stores its SMTP password in clear text — SMTP AUTH needs the original
secret. Use a throwaway or app-specific password. It is gitignored; never commit
a filled-in copy.

---

## Suppressing false positives

Copy `baseline.txt.example` to `baseline.txt` and list your known-good IPs, one
per line — your gateway, your DNS resolver, the machine running the dashboard.
Those sources are classified `Baseline (Safe) / Whitelisted Source` and score 0.

Threat intel still wins: a whitelisted IP that also appears on the intel feed is
still flagged. The whitelist suppresses noise, not evidence.

---

## Running the tests

```bash
cd Aalok      && python -m pytest        # detection thresholds, feature engineering
cd "Rui Yang" && python -m pytest        # PCAP rules, scoring, reporting
```

The Aalok suite pins `classify_profile`, `slow_attack_check`, `dns_tunnel_check`
and `engineer_flows`, so threshold drift fails loudly in about a second.

---

## Before you point this at a real network

Read **[SECURITY.md](../SECURITY.md)**. Short version: only monitor a network you
are authorised to monitor, the dashboard has no authentication and is kept private
only by binding to loopback, and the firewall buttons really change your firewall.
