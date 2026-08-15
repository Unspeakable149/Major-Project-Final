# Hybrid IDS — How It Works (Detailed Report)

> Course: CMP3602 Major Project — Diploma in Cybersecurity & Digital Forensics, Temasek Polytechnic.
> Title: *Hybrid Intrusion Detection Using Wireshark Packet Analysis and Behavioural Modelling*.

This document is the long-form companion to `README.md`. It walks through the entire system top-to-bottom: what every file does, how the pipeline is stitched together, every detection layer in the fusion stack, the database schema, the dashboard UI, the post-v1.0 extra features, the distribution channels, and the test/grading workflow.

---

## 1. Project at a Glance

| Aspect | Detail |
|---|---|
| Goal | Catch hostile network traffic on a Windows host in real time, combining classical rule-based signatures with a Random Forest behavioural model. |
| Input | Live packet capture via `tshark` (Wireshark CLI), 2-second windows. Optional offline PCAP replay. |
| Output | SQLite alert log + Streamlit SOC dashboard + one-click Windows Firewall mitigation + (optional) Email/Discord/Slack push notifications. |
| Classifier | Random Forest (primary) trained on weakly-supervised flow-level features. K-Means retained as fallback. |
| Spec targets | Detection Rate > 95%, FPR < 5%, Precision > 90%, F1 > 92%, latency < 10 ms / decision. |
| Distribution | Source repo (developers) **and** standalone Windows installer (`HybridIDS-Setup-1.0.0.exe`). |
| Tests | 17 pytest cases, sub-second, pin every rule threshold + feature builder edge case. |

---

## 2. End-to-End Pipeline

```
                    ┌────────────────────────────────────────────┐
                    │      tshark live capture (2s windows)      │
                    │      — OR — offline PCAP replay (--replay)│
                    └────────────────────────────────────────────┘
                                       │ raw packet CSV
                                       ▼
                    ┌────────────────────────────────────────────┐
                    │  clean_packets()  — type coercion, NaN→0  │
                    └────────────────────────────────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                ▼                                              ▼
   ┌───────────────────────────┐                  ┌─────────────────────────────┐
   │  engineer_flows()         │                  │ engineer_protocol_breakdown │
   │  — 18 per-Source-IP feats │                  │  — per (Src IP, Protocol)   │
   └───────────────────────────┘                  └─────────────────────────────┘
                │                                              │
                ▼                                              ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │ write_alerts() — fusion engine                                      │
   │                                                                     │
   │   Layer 1 — Heuristic rules    (classify_profile)                   │
   │   Layer 2 — Random Forest      (predict + predict_proba)            │
   │   Layer 3 — Rolling state      (slow_attack_check, 15×2s history)   │
   │   Layer 4 — DNS-tunnel check   (T1071.004, > 30 DNS pps/window)     │
   │   Layer 5 — LSTM sequence      (15-window verdict, capped)          │
   │   Layer 6 — Baseline whitelist (force Baseline for known-good IPs)  │
   │   Layer 7 — Threat intel feed  (force Severe for known-malicious)   │
   │                                                                     │
   │   Final precedence:                                                 │
   │   intel > baseline > dns_tunnel > slow > fuse(rule, RF, LSTM*)      │
   │   (* LSTM contribution capped — see §4.5)                           │
   └─────────────────────────────────────────────────────────────────────┘
                │                                              │
                ▼                                              ▼
        ┌──────────────────────┐                  ┌──────────────────────┐
        │ live_threat_logs     │                  │ protocol_breakdown   │
        │ (SQLite table)       │                  │ (SQLite table)       │
        └──────────────────────┘                  └──────────────────────┘
                │                                              │
                └─────────────────────────┬────────────────────┘
                                          ▼
                          ┌───────────────────────────────┐
                          │ Streamlit dashboard (app.py)  │
                          │  • Live telemetry table       │
                          │  • Threat distribution chart  │
                          │  • Top talkers                │
                          │  • Per-protocol breakdown     │
                          │  • Timeline (severity / min)  │
                          │  • One-click firewall block   │
                          │  • Educational simulator tab  │
                          └───────────────────────────────┘
                                          │
                                          ▼
                  Windows Firewall  (netsh advfirewall add rule)
                          + Severe-alert notifier (SMTP/Discord/Slack)
```

The pipeline runs **every `WINDOW_SECONDS` = 2 seconds** in live mode, and **once per 2s window slice** in replay mode (replay walks a static PCAP by `frame.time_epoch`).

---

## 3. Component-by-Component Breakdown

### 3.1 `Dashboard/advanced_parser.py` — Offline Packet Parser (training-time)

- **Purpose**: turn a folder of `.pcap` files into a single flat packet-level CSV (`master_advanced_dataset.csv`).
- **How**: shells out to `tshark -r <pcap> -T fields -e <field>...` and concatenates the resulting per-file CSVs with pandas.
- **Fields extracted** (15): `frame.time_epoch`, `ip.src`, `ip.dst`, `tcp.srcport`, `udp.srcport`, `tcp.dstport`, `udp.dstport`, `_ws.col.Protocol`, `frame.len`, `tcp.flags.{syn,ack,fin,reset}`, `ip.ttl`, `tcp.window_size`.
- **Configurable knobs**: `PCAP_FOLDER`, `TSHARK_PATH`, `MAX_FILES` (set to `None` to process the full corpus; default cap of 2 keeps dry runs fast).
- **Output rows**: one row per packet. Source/Dest ports coalesced from TCP/UDP variants.

### 3.2 `Dashboard/feature_engineer.py` — Per-Flow Aggregator (training-time)

- **Purpose**: turn the packet-level CSV into a per-(Source IP) flow-level CSV (`ai_ready_advanced_flows.csv`) holding 18 behavioural features.
- **How**: pandas `groupby('Source IP').agg(...)` for the simple statistics, a custom `compute_iat_stats()` for inter-arrival times, then derived ratios (`syn_ack_ratio`, `packets_per_second`, `bytes_per_second`, `avg_packet_size`).
- **Robustness**: `flow_duration_sec` is clamped to a floor of `0.1s` so a single-packet flow can't produce infinite pps; `inf`/`-inf`/`NaN` are scrubbed to `0`; `iat_mean`/`iat_std` default to `0.0` for single-packet flows.
- **Output**: `(n_source_ips) × 18` matrix consumed by `trainai_rf.py`.

### 3.3 `Dashboard/trainai_rf.py` — Random Forest Trainer (training-time, primary)

- **Pipeline (9 steps)**: load CSV → select 18 feature columns → derive heuristic (weak-supervision) labels → `StandardScaler` fit → 80/20 stratified split → `RandomForestClassifier(n_estimators=100, class_weight='balanced')` fit → predict + measure per-decision latency → multi-class report + confusion matrix → save `rf_model.pkl` + `rf_scaler.pkl`.
- **Why weak supervision?** Raw PCAPs do not ship ground-truth labels. The RF therefore learns a smoothed non-linear approximation of the rule boundary and gains calibrated `predict_proba` confidences that the heuristic alone cannot provide. Independent validation against a labelled benchmark is delegated to `evaluate_benchmark.py`.
- **Reported metrics**: Accuracy, per-class precision/recall/F1, confusion matrix, **and** the binary attack-vs-benign view aligned with the spec targets (DR/FPR/Precision/F1/latency) with PASS/FAIL stamps.

### 3.4 `Dashboard/trainai.py` — K-Means Fallback Trainer

- Legacy unsupervised path retained so a missing RF model still yields a runnable system.
- 3 clusters (intended baseline/moderate/severe), saved as `advanced_kmeans_model.pkl` + `advanced_data_scaler.pkl`.
- `live_backend.load_models()` prefers RF and silently falls back to K-Means if the RF `.pkl`s are missing.

### 3.5 `Dashboard/evaluate_benchmark.py` — Independent Benchmark Evaluator

- Reads a CIC-IDS-2017 / CIC-IDS-2018 style labelled CSV.
- Aliases the most common CIC column names to this project's 18 feature names (`'Total Fwd Packets' -> total_packets`, etc.).
- Runs the saved RF model + scaler over the benchmark, collapses RF output to attack-vs-benign, and reports the same spec metrics (DR/FPR/Precision/F1/latency) with PASS/FAIL marks.
- Provides **third-party validation** that the model isn't only good at the rule labels it was trained on.

### 3.6 `Dashboard/live_backend.py` — Runtime Engine (live + replay)

The brain of the runtime system. Single file, ~700 lines. Highlights:

| Function | Role |
|---|---|
| `get_wifi_interface()` | `tshark -D` scan, returns the first interface index whose description contains `"wifi"`. Falls back to interface `#1`. |
| `classify_profile(pps, sar, ports, avg_size)` | The heuristic rule engine (Layer 1). Returns `(profile, threat_level)` tuple. |
| `load_threat_intel()` / `load_baseline()` | Read newline-separated IPs from `threat_intel.txt` / `baseline.txt` (both optional). Comments via `#`. |
| `update_rolling()` / `slow_attack_check()` | Maintain bounded 15×2s history per Source IP, fire the multi-window slow-attack rules. |
| `load_models()` | Prefer `rf_model.pkl`+`rf_scaler.pkl`, fall back to K-Means if missing. |
| `init_db()` | Create `live_threat_logs` and `protocol_breakdown` tables if missing, additive-only schema migration. |
| `capture_window(interface)` | Run a single `tshark -i <iface> -a duration:2 -w temp_live.pcap` cycle and extract fields into `temp_raw.csv`. |
| `clean_packets(df)` | Type coercion, flag normalisation, NaN→0, multi-value field splitting. |
| `engineer_flows(df)` | Build the 18-feature flow table (mirrors the offline engineer + adds row-level defensive guards). |
| `engineer_protocol_breakdown(df)` | Sibling aggregator: `(Source IP, Protocol)` packet/byte counts for the dashboard panel + DNS-tunnel rule. |
| `dns_tunnel_check(per_protocol_rows)` | Layer 4 — fires when DNS packets from one source exceed 30 / window. |
| `write_protocol_breakdown(per_proto_df)` | Persists per-(IP, protocol) counts to `protocol_breakdown` table. |
| `fuse(*threats)` | Picks the max severity from a tuple of threat strings. |
| `_load_lstm_safe()` / `_lstm_predict_scaled(...)` | Layer 5 — loads `Megan/lstm_model.py` if PyTorch is present, then returns a 15-window sequence verdict per source IP. Never raises; absent torch simply disables the layer. |
| `apply_lstm_cap(...)` | Folds the LSTM verdict into `fuse()`'s inputs, downgrading an unconfirmed or partial-history Severe to Moderate. |
| `write_alerts(...)` | The fusion engine — runs Layers 1-7 per flow, writes one row to `live_threat_logs`, fires the notifier on Severe verdicts. **All flows in a window are batch-scored** via a single `model.predict / predict_proba` call. |
| `replay_pcap(...)` | Walks a static PCAP in 2s windows by `frame.time_epoch`, runs the full pipeline, prints a SUMMARY banner at the end. With `--realtime`, sleeps 2s between windows for video demos. |
| `main()` | Loads model + DB + intel + baseline, dispatches between live mode and `--replay` mode. |

### 3.7 `Dashboard/app.py` — Streamlit SOC Dashboard

Two tabs:

**Tab 1 — Live SOC Dashboard**
1. Sidebar controls: *Enable Live Monitoring* checkbox, refresh interval (2/5/10/30s), severity filter chips, engine-status pill (`MONITORING`/`PAUSED`).
2. Four KPI metrics across the top: total flows logged, critical threats, unique source IPs, blocked IPs.
3. Left pane (3/4 width): **Live Network Telemetry** table — `Time / Source IP / Packets-Sec / Avg Window / SYN-ACK Ratio / Total Bytes / Traffic Profile / Threat Level / Confidence (%)`. Rows are colour-coded by severity (red Severe, amber Moderate, green Baseline). Export-to-CSV button below the table.
4. Right pane (1/4 width): **Threat Distribution** bar chart + **Top Talkers** mini-table.
5. **Per-Protocol Breakdown** panel — Source-IP selectbox → bar chart of packets-by-protocol pulled from the `protocol_breakdown` table.
6. **Threat Activity Timeline** — multi-series line chart (Severe / Moderate / Baseline counts per minute).
7. **One-Click Threat Mitigation** — for each unmitigated Severe source IP, renders a red panel with a `Block IP` button. The button shells out to `netsh advfirewall firewall add rule name="IDS_BLOCK_<ip>" dir=in action=block remoteip=<ip>` and tracks blocked IPs in `st.session_state`.
8. **Blocked IP Registry** — table of all currently-blocked IPs + an unblock action (`netsh ... delete rule name="IDS_BLOCK_<ip>"`).

**Tab 2 — Educational Simulator**
- Radio selector for five scenarios: Normal Web Browsing / Reconnaissance (Port Scan) / DDoS Flood / Brute-Force Login / C2 Beacon (Stealth).
- A "Detection Reasoning" panel that breaks down *which* feature values trigger *which* rule branch.
- A live JavaScript canvas animation (source → firewall → server) coloured + paced per scenario.
- A **Behavioural Signatures** table comparing all five scenarios on a single grid (pps, ports, sar, detection path, classification).

### 3.8 `Dashboard/notifier.py` — Severe-Alert Notifier (post-v1.0 #6)

- One public function: `notify_severe(alert: dict)` (fire-and-forget).
- Three optional channels: SMTP email, Discord webhook, Slack webhook.
- Config from `notifier_config.json` (gitignored). Missing/malformed config → silent no-op.
- Throttled to one notification per `(source_ip, channel)` per `THROTTLE_SECONDS = 3600`. Throttle state lives in a module-level dict, reset on process restart.
- Custom User-Agent on all webhook POSTs: `HybridIDS/1.0 (Severe-Alert Notifier)` — Discord rejects the default `Python-urllib/3.X` UA.
- All exceptions are caught and logged with `[!]` prefix so a broken notifier cannot crash the capture loop.

### 3.9 `Dashboard/start_system.bat` — One-Click Launcher (web-app mode)

1. Self-elevates to Administrator (tshark + netsh need it).
2. Pre-flight checks: tshark present at `C:\Program Files\Wireshark\tshark.exe`; Python on `PATH`; `rf_model.pkl` exists.
3. Starts the backend in a new console window: `python live_backend.py`.
4. Starts the dashboard in a second console: `python -m streamlit run app.py --server.headless true --server.port 8501`.
5. Polls `http://localhost:8501` up to 20 times with 1s gaps; when it responds, opens the default browser.

### 3.10 `installer/launcher.py` — Frozen-EXE Launcher (installed-app mode)

This is the entry point PyInstaller compiles into `HybridIDS.exe` for the standalone installer. Single OS process, no subprocesses:

- **Main thread**: Streamlit web server via `streamlit.web.bootstrap.run(...)`. Bootstrap installs signal handlers, must run on the main thread on Windows.
- **Daemon thread #1**: `live_backend.main()` — the capture/classification loop.
- **Daemon thread #2**: `pystray` system-tray icon (green shield) with `Open Dashboard` + `Stop and Exit` menu items.
- **Daemon thread #3**: dashboard waiter — polls `http://127.0.0.1:<port>`, opens an Edge/Chrome `--app=` window once the dashboard binds.

Other launcher details:
- A sentinel env var (`HYBRID_IDS_LAUNCHER_ACTIVE=1`) hard-stops a child re-spawn — defence-in-depth against PyInstaller bootstrap loops.
- Frozen windowed builds have no usable stdout/stderr, so `sys.stdout`/`sys.stderr` are routed to a rotating log file at `%LOCALAPPDATA%\Hybrid IDS\launcher.log`.
- Free-port discovery via `socket.bind` so a busy `:8501` is handled gracefully.
- Streamlit flag overrides forced in code (`server.headless=true`, `server.fileWatcherType=none`, `browser.gatherUsageStats=false`) so the frozen build never tries to open a developer browser tab or watch source files.

---

## 4. Detection Logic — The Fusion Stack in Detail

### 4.1 Layer 1 — Heuristic Rule Engine (`classify_profile`)

| Condition | Profile | Threat |
|---|---|---|
| `pps > 500 and sar > 5` | DDoS SYN Flood | Severe (Critical Anomaly) |
| `pps > 1000` | High-Volume Flood Attack | Severe (Critical Anomaly) |
| `pps > 300 and avg_size > 800` | Speed Test / Large Data Transfer | Moderate (Bandwidth Spike) |
| `ports > 20` | Port Scan / Reconnaissance | Moderate (Suspicious) |
| `pps <= 5 and avg_size < 150` | Ping / Background Telemetry | Baseline (Safe) |
| (else) | Standard Web Traffic | Baseline (Safe) |

Thresholds were tuned empirically against the Bulk PCAPS corpus + Kali nmap/hping3 attack runs, and are pinned by `tests/test_classifier.py`.

### 4.2 Layer 2 — Random Forest (`predict` + `predict_proba`)

- `RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')`.
- Trained on the 18 standard-scaled flow features.
- Labels via `assign_behavioral_label()` — same thresholds as Layer 1 (weak supervision). The RF learns a smoothed approximation of the rule boundary plus calibrated `predict_proba` confidences.
- Inference is **batched per window**: one `model.predict(scaled_all)` + one `predict_proba(scaled_all)` call per capture window over the full feature matrix. (This avoids joblib spawning a fresh ThreadPool per flow, which used to freeze on attack pcaps with thousands of source IPs per window.)

### 4.3 Layer 3 — Multi-Window Rolling State (`slow_attack_check`)

- Each Source IP has a bounded FIFO history of the last `ROLLING_WINDOWS = 15` window summaries (≈ 30 s).
- After at least 5 windows of history (≈ 10 s) the rules fire:
  - `rolling_unique_ports > 60` → **Slow Port Scan (multi-window)** — Moderate.
  - `rolling_syn > 150 and rolling_packets > 200` → **Sustained SYN / Brute-Force Probe** — Moderate.
- Catches stealth attacks that stay below the single-window pps threshold but accumulate signal over time.

### 4.4 Layer 4 — DNS-Tunnel Check (`dns_tunnel_check`)

- Per (Source IP, Protocol) rows pulled from `engineer_protocol_breakdown(df)`.
- If any source IP's DNS packets exceed `30 packets / WINDOW_SECONDS = 15 pps`, the verdict is flagged **DNS Tunnel / C2 Channel — Moderate (Suspicious)**.
- Mapped to MITRE ATT&CK T1071.004 (Application Layer Protocol: DNS) — covers DNS-over-application-layer C2 channels.

### 4.5 Layer 5 — LSTM Sequence Model (`_lstm_predict_scaled` / `apply_lstm_cap`)

- A 2-layer LSTM (`Megan/lstm_model.py`) reads the last **15 capture windows (≈ 30 s)** of the *same 18 scaled features* the Random Forest sees, kept per source IP in `_lstm_buffers` (LRU-bounded to `MAX_TRACKED_IPS`, like `ROLLING_STATE`).
- It votes once it has ≥ 2 windows; shorter histories are left-padded with zeros, and `has_full_history` records whether the sequence was complete.
- Its **raw** verdict is always logged to `sig_lstm`, but what it may contribute to the fused level is **capped** by `apply_lstm_cap()`:
  - Baseline / Moderate → folded in as-is (the LSTM alone can raise Baseline → Moderate, which is the slow-scan case it exists to catch).
  - Severe → only counted as Severe when the buffer holds a full 15-window sequence **and** some other layer independently reached Moderate+. Otherwise it is downgraded to Moderate.
- Rationale for the cap: unlike the RF, this model has no drift/accuracy monitoring, and a 4-second buffer is enough for it to vote — so it is not allowed to trigger the top severity band unilaterally.
- Optional: if PyTorch or `lstm_model.pt` is missing, the layer is skipped entirely and the other four behavioural layers are unaffected. Both ship in the packaged `.exe`, so it runs there too — earlier builds excluded `torch` for size and quietly lost this layer.

### 4.6 Layer 6 — Baseline Whitelist (`baseline.txt`)

- Newline-separated known-good IPs (gateway / DNS / dashboard host). `#` lines are comments.
- Force-classifies matching source IPs as **Baseline (Safe) — Whitelisted Source** regardless of rule trips or RF prediction.
- Eliminates false positives from speed tests, Windows Update bursts, etc. on infrastructure you control.
- Optional; missing file → empty set.

### 4.7 Layer 7 — Threat Intelligence Feed (`threat_intel.txt`)

- Newline-separated known-malicious IPs (e.g. AbuseIPDB / FireHOL / Emerging Threats / Spamhaus DROP).
- Force-escalates matching source IPs to **Severe (Critical Anomaly) — Known Malicious IP (Threat Intel Match)** regardless of behavioural metrics.
- Optional; missing file → empty set.

### 4.8 Precedence (Final Verdict Selection)

```
intel  >  baseline  >  dns_tunnel  >  slow  >  lstm  >  fuse(rule, RF, LSTM)
```

Concretely (from `write_alerts()`):

```python
fuse_inputs, effective_lstm_threat = apply_lstm_cap(
    [rf_threat, heuristic_threat, slow_threat, dns_threat],
    lstm_threat, lstm_full_history,
)
threat = fuse(*fuse_inputs)
if intel_hit:
    threat = "Severe (Critical Anomaly)"
    profile = "Known Malicious IP (Threat Intel Match)"
elif src_ip in baseline_ips:
    threat = "Baseline (Safe)"
    profile = "Whitelisted Source"
elif dns_hit:
    profile = "DNS Tunnel / C2 Channel"
elif slow_hit and SEVERITY_RANK[slow_threat] >= SEVERITY_RANK[threat]:
    profile = slow_profile
elif (effective_lstm_threat and effective_lstm_threat != "Baseline (Safe)"
      and SEVERITY_RANK[effective_lstm_threat] >= SEVERITY_RANK[threat]):
    profile = "LSTM Sequence Anomaly (multi-window)"
```

- Threat intel always wins — a known-malicious IP that also appears on the whitelist still ends up Severe.
- Baseline only overrides rule/RF/slow/LSTM elevations — it never silences intel.
- DNS-tunnel, slow and LSTM profiles are surfaced as the `traffic_profile` string when they win the precedence battle so the dashboard shows *why* the verdict was Moderate.
- The LSTM sits last among the behavioural profiles: it only names the profile when nothing more specific already explained the same severity.

---

## 5. The 18 Behavioural Features

| Category | Features |
|---|---|
| **Packet-level** | `total_packets`, `total_bytes`, `avg_packet_size`, `packet_size_std` |
| **Flow-level** | `flow_duration_sec`, `packets_per_second`, `bytes_per_second`, `iat_mean`, `iat_std` |
| **Session-level** | `total_syn_flags`, `total_ack_flags`, `total_fin_flags`, `total_rst_flags`, `syn_ack_ratio` |
| **Behavioural** | `unique_target_ips`, `unique_target_ports` |
| **Network-layer** | `avg_ttl`, `avg_window_size` |

All 18 are computed identically in `feature_engineer.py` (offline) and `engineer_flows()` (online) so training-time and runtime distributions cannot drift.

---

## 6. SQLite Schema (`ids_logs.db`)

### `live_threat_logs`
```sql
CREATE TABLE live_threat_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT,           -- HH:MM:SS
    source_ip       TEXT,
    packets_per_sec REAL,
    avg_window_size REAL,
    syn_ack_ratio   REAL,
    total_bytes     INTEGER,
    traffic_profile TEXT,           -- e.g. "DDoS SYN Flood", "Whitelisted Source"
    threat_level    TEXT,           -- "Baseline (Safe)" | "Moderate ..." | "Severe ..."
    confidence      REAL DEFAULT 0.0  -- RF predict_proba max
);
```

### `protocol_breakdown` (added in feature #10)
```sql
CREATE TABLE protocol_breakdown (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    protocol  TEXT,                -- "TCP" | "DNS" | "TLSv1.2" | ...
    packets   INTEGER,
    bytes     INTEGER
);
```

Schema is **additive-only**: `init_db()` uses `CREATE TABLE IF NOT EXISTS` and `ALTER TABLE ... ADD COLUMN` guarded by `try/except` for the `confidence` column, so existing DBs auto-migrate on the next boot.

---

## 7. Extra Features (Post-v1.0 Enhancements)

A second track of opt-in features sits alongside the v1.0 core path. Every feature is silent / no-op when its config file or CLI flag is absent, so the baseline v1.0.0 behaviour is preserved when nothing is configured.

### Feature #6 — Severe-Alert Notifier
- **What**: pushes Severe verdicts out of the dashboard via SMTP email, Discord webhook, and/or Slack webhook.
- **Throttle**: one notification per `(source IP, channel)` per hour.
- **Config**: `Dashboard/notifier_config.json` (gitignored). Template ships as `notifier_config.json.example` with all channels disabled.
- **Files**: `Dashboard/notifier.py` (new), `Dashboard/live_backend.py` (hook in `write_alerts()`).
- **Why it matters**: operator doesn't need to keep the dashboard tab open — Severe alerts arrive on phone (Discord push, email, Slack).
- **Fail-safe**: missing config / malformed JSON / SMTP timeout / HTTP error → logged warning, no crash.

### Feature #7 — Offline PCAP Replay Mode
- **What**: `live_backend.py --replay <pcap>` reads a static `.pcap` instead of capturing live, through the same engineer / classify / log / notify pipeline.
- **Flag**: `--realtime` sleeps 2 s between windows for live-cadence demo recordings; omit it for full CPU speed.
- **CLI override**: `--interface <id>` for live mode (skips Wi-Fi auto-detect).
- **Why it matters**: reproducible grading runs (no attacker VM, no admin shell), regression archive (replay any old attack pcap after a code change), faster threshold-tuning loop.
- **Internal architecture**: pcap is loaded once via tshark, sorted by `frame.time_epoch`, and partitioned into `WINDOW_SECONDS`-wide slices. Each slice runs through `engineer_flows()` + `engineer_protocol_breakdown()` + `write_alerts()`. A SUMMARY banner totals up the run.

### Feature #8 — Baseline Whitelist File
- **What**: `Dashboard/baseline.txt` is a newline-separated list of known-good IPs. Matching source IPs are force-classified Baseline (Safe) / Whitelisted Source.
- **Pattern**: mirrors the existing `threat_intel.txt` loader. Precedence is `intel > baseline > rule/RF`, so a whitelisted IP that *also* appears on the intel feed is still Severe.
- **Why it matters**: kills the false positives that real home networks generate (gateway during Windows Update, internal DNS server, dashboard host itself during a speed test).
- **Reversible**: delete `baseline.txt` → behaviour reverts to pure detection. No code change to disable.
- **Note**: the actual `baseline.txt` is **gitignored** in the submission build because it ships operator-specific IPs. `baseline.txt.example` documents the copy-and-edit workflow.

### Feature #9 — Unit Test Suite
- **What**: `pytest` suite that pins the heuristic rule engine + slow-attack rules + DNS-tunnel rule + flow feature builder edge cases.
- **Count**: **17 tests, runs in under a second**, no tshark / model / DB dependency.
- **Files**: `tests/test_classifier.py` (14 cases), `tests/test_engineer.py` (3 cases), `conftest.py`, `pytest.ini`, `tests/__init__.py`.
- **Why it matters**: tune a threshold from 500 → 400 by mistake → red test in 0.6 s, not a user complaint a week later. Executable spec for new contributors. CI-friendly (pure functions, no admin, no network).
- **Coverage**:
  - 6 parametrised `classify_profile` cases (all six rule branches).
  - 4 `slow_attack_check` cases (below threshold, port scan, sustained SYN, quiet history).
  - 4 `dns_tunnel_check` cases (above threshold, below threshold, non-DNS rows, empty input).
  - 3 `engineer_flows` edge cases (empty DataFrame, all-blank Source IP, single-packet flow).

### Feature #10 — Per-Protocol Breakdown Panel + DNS-Tunnel Detector
- **What**: every capture window also aggregates packets by `(Source IP, Protocol)` and writes to the new `protocol_breakdown` SQLite table. The dashboard surfaces this as a bar chart below Top Talkers — pick a Source IP, see its traffic mix.
- **DNS-tunnel rule**: when DNS pps from one source exceeds 30 in a 2 s window, the verdict is `DNS Tunnel / C2 Channel — Moderate (Suspicious)` (MITRE T1071.004).
- **Why it matters**: forensic triage at a glance (`host X is 80% DNS` vs `host X is 80% TCP/HTTP`), and a new detection axis for stealth C2 that pps/sar rules miss.
- **Schema-safe**: brand-new sibling table; `live_threat_logs` unchanged. Empty `protocol_breakdown` shows a friendly `st.info("No per-protocol data yet for this IP.")` instead of crashing.

### Cross-Cutting Principles for All Extras
1. **Opt-in by default**: missing config file or CLI flag → feature is silently off.
2. **No silent failures**: errors log `[!]` warning but never crash the capture loop.
3. **Mirror existing patterns**: threat-intel loader → baseline loader; live path → replay path.
4. **No back-compat hacks**: where a refactor is cleaner, make the change and document it.
5. **Document every feature**: paragraph in `README.md` + entry in the dev journal.

---

## 8. Distribution

Two parallel ways to run the project:

| Channel | Audience | What you get |
|---|---|---|
| **Web App** (this repo) | Developers, evaluators with Python | Clone, train, run `start_system.bat`. Full source + retraining pipeline. |
| **Installer EXE** (`installer/` folder builds it) | End users | Branded Windows installer `HybridIDS-Setup-1.0.0.exe`, tray-icon launcher, no Python required. |

### Installer Build Pipeline
1. **PyInstaller** (`installer/HybridIDS.spec`) packages `installer/launcher.py` + the Dashboard folder + `rf_model.pkl` + `rf_scaler.pkl` into a one-folder bundle (`dist/HybridIDS/`).
2. **Inno Setup** (`installer/installer.iss`) wraps the PyInstaller bundle into a branded Windows installer that:
   - Detects whether Wireshark / tshark is already installed and offers to download it if not.
   - Registers under **Settings → Apps & Features** with publisher / version / support URL metadata.
   - Adds Start Menu shortcuts (app + dashboard URL).
   - Requests UAC elevation when the app launches (tshark + netsh require it).
3. **`installer/build.ps1`** runs both steps and produces `installer/output/HybridIDS-Setup-<version>.exe`.

### Installed-App Runtime
- Start Menu → **Hybrid IDS** → UAC prompt → tray icon (green shield) appears → default browser opens to the dashboard.
- Right-click tray icon → **Open Dashboard** / **Stop and Exit**.
- All state (`launcher.log`, `ids_logs.db`) lives under the installed app directory; logs additionally go to `%LOCALAPPDATA%\Hybrid IDS\launcher.log`.

---

## 9. Testing & Validation

### 9.1 Unit Tests
```
python -m pytest tests/ -v
```
Expected:
```
17 passed in <1s
```

### 9.2 Spec-Target Metrics (from `trainai_rf.py`)
The trainer prints the binary attack-vs-benign view aligned with the project spec:
```
Detection Rate   :  XX.XX %    target > 95%   [PASS/FAIL]
False Positive   :  XX.XX %    target <  5%   [PASS/FAIL]
Precision        :  XX.XX %    target > 90%   [PASS/FAIL]
F1-Score         :  XX.XX %    target > 92%   [PASS/FAIL]
Latency          :   X.XXX ms  target < 10 ms [PASS/FAIL]
```

### 9.3 Independent Benchmark
```
python Dashboard/evaluate_benchmark.py path/to/CIC-IDS-2017.csv
```
Same metric block, but on a labelled third-party dataset → defends the model against the criticism that it only learned its own rule boundary.

### 9.4 Real-Attack Validation
Validated against a Kali Linux VM (VirtualBox, Bridged networking):

| Attack | Command | Expected verdict |
|---|---|---|
| TCP SYN port scan | `sudo nmap -sS <target>` | Port Scan / Reconnaissance — Moderate |
| SYN flood | `sudo hping3 -S --flood -V -p 80 <target>` | High-Volume Flood / DDoS SYN Flood — Severe |
| Slow brute force | Sustained low-rate SSH attempts | Sustained SYN / Brute-Force Probe — Moderate (via rolling-state layer) |

*Attack the gateway router, not the host machine* — VirtualBox's bridge driver routes VM-to-host traffic internally and bypasses the physical NIC tshark is listening on.

### 9.5 Reproducible Demo via Replay
```
python Dashboard/live_backend.py --replay path\to\capture.pcap --realtime
```
Same engineer → classify → log → notify pipeline as live mode, but deterministic and admin-free. Suitable for grading runs and video recordings.

---

## 10. Spec Compliance (CMP3602 Deliverables)

| Deliverable | Status | Where it lives |
|---|---|---|
| Packet capture (Wireshark / tshark) | Done | `Dashboard/advanced_parser.py`, `Dashboard/live_backend.py:capture_window` |
| Feature extraction pipeline (packet, flow, IAT, session, behavioural) | Done | `Dashboard/feature_engineer.py`, `Dashboard/live_backend.py:engineer_flows` |
| Signature detection engine | Done | `Dashboard/live_backend.py:classify_profile` |
| ML behavioural model (Random Forest) | Done | `Dashboard/trainai_rf.py`, `rf_model.pkl` |
| Fusion / decision engine | Done | `Dashboard/live_backend.py:write_alerts` (Layers 1-6) |
| Real-time processing loop | Done | `Dashboard/live_backend.py:main` |
| Alert logging & dashboard | Done | `ids_logs.db`, `Dashboard/app.py` |
| Evaluation against benchmark dataset | Done | `Dashboard/evaluate_benchmark.py` |
| Active response (firewall rule push) | Done | `Dashboard/app.py:apply_firewall_block` (Optional v2) |
| LSTM behavioural model | Pending | Optional v2 — out of scope for v1.0 |
| SHAP explainability | Pending | Optional v2 |
| Model retraining pipeline | Pending | Optional v2 |

### Post-v1.0 extras layered on top:

| # | Feature | Status |
|---|---|---|
| 6 | Severe-Alert Notifier (Email / Discord / Slack) | Done |
| 7 | Offline PCAP Replay Mode | Done |
| 8 | Baseline Whitelist File | Done |
| 9 | Unit Test Suite (17 cases) | Done |
| 10 | Per-Protocol Breakdown Panel + DNS-Tunnel Detector | Done |

---

## 11. Quick Reference — Runbook

| Task | Command (run from repo root) |
|---|---|
| Train the model end-to-end | `python Dashboard/advanced_parser.py && python Dashboard/feature_engineer.py && python Dashboard/trainai_rf.py` |
| Launch the system (live, web-app mode) | `Dashboard\start_system.bat` (auto-elevates) |
| Replay a pcap offline | `python Dashboard\live_backend.py --replay path\to\capture.pcap` |
| Replay a pcap at live cadence | `python Dashboard\live_backend.py --replay path\to\capture.pcap --realtime` |
| Evaluate against a labelled benchmark | `python Dashboard\evaluate_benchmark.py path\to\CIC-IDS-2017.csv` |
| Run the unit-test suite | `python -m pytest tests/ -v` |
| Build the installer | `.\installer\build.ps1` |
| Smoke-test the notifier | `python Dashboard\test_notifier.py` |

---

## 12. Source-of-Truth Files

| File | Role |
|---|---|
| `README.md` | Public-facing project description (the GitHub front page). |
| `how_it_works.md` | **This document** — long-form architectural narrative. |
| `EXTRA_FEATURES.md` | Per-feature integration journal (one section per extra). |
| `WEEKLY_JOURNALS.md` / `WEEKLY_JOURNALS_V2.md` | Per-week development log (local-only, gitignored). |
| `TEST_RESULTS.md` | Real-attack validation logs (local-only, gitignored). |
| `pytest.ini` + `conftest.py` | Test runner config; `conftest.py` injects `Dashboard/` into `sys.path` so `import live_backend` works from the repo root. |
| `.gitignore` | Excludes operator-specific IPs (`Dashboard/baseline.txt`), secrets (`Dashboard/notifier_config.json`), trained `.pkl`s, large PCAPs, dev journals, install footprint (`Hybrid IDS/`), build artefacts. |

