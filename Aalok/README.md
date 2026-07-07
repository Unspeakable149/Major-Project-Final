# Hybrid Intrusion Detection Using Wireshark Packet Analysis and Behavioral Modeling

Major Project (CMP3602) - Diploma in Cybersecurity & Digital Forensics, Temasek Polytechnic.

Real-time IDS combining signature rules + a Random Forest behavioral model. Classifies flows as Baseline / Moderate / Severe. Uses tshark for capture, scikit-learn for ML, SQLite for alerts, Streamlit for the dashboard.

## System Architecture

```
[ tshark live capture (2s windows) ]
              |
              v
[ Pandas flow engineering - 18 features per Source IP ]
              |
       +------+------+
       |             |
       v             v
[ RF model ]   [ Heuristic rules ]
       \             /
        v           v
        [ Fusion: max severity ]
              |
              v
   [ SQLite alert log ] -> [ Streamlit dashboard ]
                                |
                                v
                  [ One-Click firewall mitigation ]
```

## Components

### Training pipeline (offline, run once)
| File | Purpose |
|---|---|
| `Dashboard/advanced_parser.py` | Parses PCAP files via tshark, extracts packet-level fields |
| `Dashboard/feature_engineer.py` | Groups packets into flows per Source IP, derives 18 behavioral features (packet, flow, IAT, session, behavioral) |
| `Dashboard/trainai_rf.py` | Trains Random Forest classifier, reports DR/FPR/Precision/F1/latency vs spec targets, saves `rf_model.pkl` + `rf_scaler.pkl` |
| `Dashboard/trainai.py` | Legacy unsupervised K-Means trainer, fallback only |
| `Dashboard/evaluate_benchmark.py` | Evaluates the trained RF model against a labeled benchmark CSV (CIC-IDS-2017/2018) |

### Runtime engine
| File | Purpose |
|---|---|
| `Dashboard/live_backend.py` | Live capture loop - 2-second tshark windows, flow engineering, hybrid classification, writes alerts to `ids_logs.db` |
| `Dashboard/app.py` | Streamlit SOC dashboard - live threat table, charts, top talkers, one-click firewall block |
| `Dashboard/start_system.bat` | Launches the backend and dashboard simultaneously |
| `Dashboard/debug_flags.py` | Inspect raw tshark output when flag parsing misbehaves |

## Extra Features (Post-v1.0 Enhancements)

A second track of opt-in features sits alongside the v1.0 core path. Every feature is silent / no-op when its config file is missing, so the baseline IDS behaviour is preserved when nothing is configured.

| # | Feature | Module | Purpose |
|---|---------|--------|---------|
| 6 | Severe-Alert Notifier | `Dashboard/notifier.py` + `notifier_config.json` | Pushes Severe verdicts off the box via SMTP / Discord / Slack with one-per-hour throttling per `(source IP, channel)`. |
| 7 | Offline PCAP Replay Mode | `Dashboard/live_backend.py --replay <pcap>` | Reads a static PCAP through the same pipeline as live capture for reproducible demos and grading runs. `--realtime` adds live-cadence sleeps for video recordings. |
| 8 | Baseline Whitelist | `Dashboard/baseline.txt` | Newline-separated known-good IPs are auto-classified `Baseline (Safe) / Whitelisted Source`, suppressing false positives on gateway / DNS / dashboard hosts. Intel still wins. |
| 9 | Unit Test Suite | `tests/` + `pytest.ini` + `conftest.py` | 17 pytest cases pinning `classify_profile`, `slow_attack_check`, `dns_tunnel_check`, and `engineer_flows`. Threshold drift fails loud in under a second. |
| 10 | Per-Protocol Breakdown Panel | `protocol_breakdown` table + `app.py` panel + `dns_tunnel_check()` | Aggregates packets/bytes per `(Source IP, Protocol)` each window. Dashboard bar chart per IP. Detects DNS-tunnel C2 (T1071.004) when DNS pps > 30. |
| 11 | Threat Scoring & Analysis Report | `compute_threat_score()` in `live_backend.py` + `render_threat_report()` in `app.py` | Folds the fused verdict + severity / frequency / behaviour / historical / confidence into a **0-100 Threat Score**, a risk band (Normal→Critical), and an analyst report (reasons + suggested actions). Methodology and weight justification in [`THREAT_SCORING.md`](THREAT_SCORING.md). |

Each feature is wired so the core v1.0.0 path stays unchanged when its config / file / data is absent. See the paragraphs under **Detection Logic** for runtime details and the section under **Running Locally** for CLI entry points.

## Detection Logic

**Heuristic rules** (`classify_profile()` in `live_backend.py`):
- `pps > 500` and `syn_ack_ratio > 5` → DDoS SYN Flood (Severe)
- `pps > 1000` → High-Volume Flood Attack (Severe)
- `pps > 300` and `avg_size > 800` → Bandwidth Spike (Moderate)
- `unique_target_ports > 20` → Port Scan (Moderate)
- `pps <= 5` and `avg_size < 150` → Ping/Telemetry (Baseline)
- else → Standard Web Traffic (Baseline)

**Random Forest** predicts 0/1/2 (Baseline/Moderate/Severe) with confidence via `predict_proba`. The fusion engine takes the higher severity between RF and heuristics.

**Multi-window rolling state** tracks per-source-IP aggregates across the last 15 capture windows (~30s) so the engine catches attacks that hide below a single window's pps threshold:
- `rolling_unique_ports > 60` → Slow Port Scan
- `rolling_syn > 150` and `rolling_packets > 200` → Sustained SYN / Brute-Force Probe

**Threat Intelligence Feed** (`threat_intel.txt`, optional): newline-separated known-malicious IPv4 addresses. Any captured source IP on the list is auto-escalated to Severe regardless of behavioral metrics. Populate from AbuseIPDB / FireHOL / Spamhaus DROP / Emerging Threats.

**Baseline Whitelist** (`baseline.txt`, optional): newline-separated known-good IPv4 addresses (gateway, internal DNS, dashboard host). Matching source IPs are forced to Baseline (Safe) with profile `Whitelisted Source` even when rule / RF would have elevated them - eliminates false positives from speed tests or OS updates on infrastructure you control. Precedence is `intel > baseline > rule/RF`, so a whitelisted IP that *also* appears on the threat-intel feed still escalates to Severe. Copy `Dashboard/baseline.txt.example` to `Dashboard/baseline.txt` and list one IP per line.

**Severe-Alert Notifier** (`notifier.py`, optional): pushes Severe alerts out of the dashboard via SMTP email, Discord webhook, and/or Slack webhook. Throttled to one notification per (source IP, channel) per hour to prevent alert storms during sustained attacks. Copy `Dashboard/notifier_config.json.example` to `Dashboard/notifier_config.json` and enable the channels you need (the real config file is gitignored so credentials never enter source control). Missing or malformed config silently disables the notifier - the IDS keeps running.

**Threat Scoring & Analysis Report** (`compute_threat_score()`, always on): after fusion decides the categorical verdict, this layer produces a numeric **0-100 Threat Score** by combining several independent factors — attack-type severity, connection frequency, behavioural abnormality, per-source history, and detection confidence — minus a false-positive-reduction term. The score maps to a risk band (Normal / Low / Medium / High / Critical) and drives an analyst-readable **Threat Analysis Report** in the flow drill-down: the reasons behind the score and the suggested actions. The fused verdict gates the additive model, so a flow ruled Baseline/Safe (or whitelisted) scores 0 — benign heavy traffic like a speed test never accumulates a misleading number. Full methodology, the weight tables, and the literature justification are in [`THREAT_SCORING.md`](THREAT_SCORING.md).

**Per-Protocol Breakdown + DNS Tunnel check**: each window also tracks packets/bytes by (Source IP, Protocol) in a separate SQLite table `protocol_breakdown`. Dashboard shows this as a bar chart per IP, so you can tell normal web traffic (TCP/HTTP/TLS) apart from DNS-heavy traffic that looks like a C2 tunnel. `dns_tunnel_check()` flags any source pushing more than 30 DNS pps in a 2s window as Moderate. Order of precedence: intel > baseline > dns_tunnel > slow > rule/RF.

**Unit tests** (`tests/`): pytest cases for the rule engine and flow builder. `test_classifier.py` checks `(profile, threat)` tuples from `classify_profile()`, `slow_attack_check()`, and `dns_tunnel_check()`. `test_engineer.py` checks `engineer_flows()` against empty / blank / single-packet inputs. 17 tests, runs in under a second, no tshark / model / DB needed. Run: `python -m pytest tests/ -v`.

## Feature Set (18 per flow)

| Category | Features |
|---|---|
| Packet-level | `total_packets`, `total_bytes`, `avg_packet_size`, `packet_size_std` |
| Flow-level | `flow_duration_sec`, `packets_per_second`, `bytes_per_second`, `iat_mean`, `iat_std` |
| Session-level | `total_syn_flags`, `total_ack_flags`, `total_fin_flags`, `total_rst_flags`, `syn_ack_ratio` |
| Behavioral | `unique_target_ips`, `unique_target_ports` |
| Network-layer | `avg_ttl`, `avg_window_size` |

## Distribution

Two ways to run this project:

| Option | Audience | What you get |
|---|---|---|
| **Web App (this repo)** | Developers, evaluators with Python | Clone, train, run via `start_system.bat`. Full source + retraining pipeline. |
| **Installer EXE** (`installer/` folder builds it) | End users | Branded Windows installer `HybridIDS-Setup-*.exe`. Tray-icon launcher, no Python required. Available from the project's GitHub Releases page. |

To build the installer locally, see [`installer/README.md`](installer/README.md).

## Running Locally (Web App Mode)

Requirements: Windows, Wireshark (with tshark at `C:\Program Files\Wireshark\tshark.exe`), Python 3.10+, packages: `pandas`, `numpy`, `scikit-learn`, `joblib`, `streamlit`.

1. **Train the model** (one-time, or re-run after updating feature set):
   ```
   python Dashboard/advanced_parser.py
   python Dashboard/feature_engineer.py
   python Dashboard/trainai_rf.py
   ```
2. **Launch the system** (as Administrator, required for tshark live capture and firewall rule injection):
   ```
   Dashboard\start_system.bat
   ```
3. Open the dashboard at `http://localhost:8501`.
4. **Optional - benchmark evaluation**:
   ```
   python Dashboard/evaluate_benchmark.py <path-to-CIC-IDS-2017.csv>
   ```
5. **Optional - offline PCAP replay** (reproducible demos / grading without live attacker setup):
   ```
   python Dashboard/live_backend.py --replay path\to\capture.pcap
   python Dashboard/live_backend.py --replay path\to\capture.pcap --realtime
   ```
   Replay walks the PCAP in `WINDOW_SECONDS`-wide chunks through the same flow-engineering + classification + alerting pipeline as live mode. `--realtime` sleeps between windows so the dashboard timeline animates as it would during a live capture; omit it to process at full CPU speed.

## Testing With Real Attacks

Validated against a Kali Linux VM (VirtualBox, Bridged networking):
- `sudo nmap -sS <target>` → flagged as Port Scan / Moderate
- `sudo hping3 -S --flood -V -p 80 <target>` → flagged as High-Volume Flood / Severe

Attack the gateway router (not the host machine) - VirtualBox's bridge driver routes VM-to-host traffic internally, bypassing the physical NIC tshark is listening on.

## Spec Targets vs Implementation

| Metric | Target | Reported by |
|---|---|---|
| Detection Rate (TP / (TP+FN)) | > 95% | `trainai_rf.py`, `evaluate_benchmark.py` |
| False Positive Rate (FP / (FP+TN)) | < 5% | `trainai_rf.py`, `evaluate_benchmark.py` |
| Precision (TP / (TP+FP)) | > 90% | `trainai_rf.py`, `evaluate_benchmark.py` |
| F1-Score | > 92% | `trainai_rf.py`, `evaluate_benchmark.py` |
| Latency per decision | < 10 ms | `trainai_rf.py`, `evaluate_benchmark.py` |

## Spec Compliance (CMP3602 Deliverables)

| Deliverable | Status |
|---|---|
| Packet capture (Wireshark/tshark) | Done |
| Feature extraction pipeline (packet, flow, IAT, session, behavioral) | Done |
| Signature detection engine | Done |
| ML behavioral model (Random Forest) | Done |
| Fusion/decision engine | Done |
| Real-time processing loop | Done |
| Alert logging & dashboard | Done |
| Evaluation against benchmark dataset | Done (`evaluate_benchmark.py`) |
| Active response (firewall rule push) | Done (Optional v2) |
| LSTM behavioral model | Pending (Optional v2) |
| SHAP explainability | Pending (Optional v2) |
| Model retraining pipeline | Pending (Optional v2) |

## Note on Label Source

`trainai_rf.py` derives labels using the same heuristic rules the runtime engine uses (weak supervision) because raw PCAP captures don't ship ground-truth labels. The RF model therefore learns a smoothed, non-linear approximation of the rule boundary and adds calibrated `predict_proba` confidences that the heuristic alone can't provide. For independent validation, use `evaluate_benchmark.py` against CIC-IDS-2017 (or any labeled flow CSV).

## Data Note

The `Bulk PCAPS/`, `archive/`, and intermediate `*.csv`/`*.pkl` files are excluded from this repository via `.gitignore` due to size (~22 GB). They are regenerable from public sources (CIC-IDS-2017, custom captures) and via the training pipeline.
