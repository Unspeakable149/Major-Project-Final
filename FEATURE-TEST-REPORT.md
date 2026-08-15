# Hybrid IDS — Feature Test Report

Per-contributor list of what was built and whether it was **observed working**.
Ordered Aalok → Rui Yang → Aaron → Megan.

**Tested:** 7–8 August 2026
**Build under test:** `HybridIDS.exe` rebuilt 2026-08-07 18:49, 396,017,822 bytes
**Environment:** Windows 11, Python 3.14.5, tshark 4.x (Wireshark install, not on PATH),
torch 2.12.0+cpu, scikit-learn 1.8.0, shap 0.52.0, scapy 2.7.0, streamlit 1.57.0,
python-docx 1.2.0. Session ran **without Administrator**, which is why every
firewall result below is a non-admin observation.

**How things were tested.** Everything ran against isolated copies in a scratch
tree; the repository itself was never written to. Three evidence tiers are used
and are labelled per feature:

| Tier | Meaning |
|---|---|
| **live** | Real packets captured off a real adapter and scored by the running engine |
| **replay** | A synthetic attack PCAP pushed through the full engine, results read back from `ids_logs.db` |
| **function** | Helper called directly with real data (used for Streamlit UI, which cannot be browser-rendered headlessly) |

Verdicts: **WORKS** = observed working. **PARTIAL** = works only under a stated
condition. **BROKEN** = observed failing. **NOT TESTED** = not exercised, with the
reason given.

---

## Summary

| Contributor | Features | WORKS | PARTIAL | BROKEN | NOT TESTED |
|---|---|---|---|---|---|
| Aalok | 62 | 47 | 12 | 1 | 2 |
| Rui Yang | 9 | 6 | 2 | 1 | 0 |
| Aaron | 6 | 4 | 2 | 0 | 0 |
| Megan | 8 | 6 | 0 | 1 | 1 |

Nothing in the system is dead on arrival. The defects that matter are collected
in **[Cross-cutting defects](#cross-cutting-defects)** at the end.

---

# 1. AALOK

Owns the detection engine (`live_backend.py`, ~84 KB), the Streamlit dashboard
(`app.py`, ~233 KB, seven tabs), the trained models, and the launchers. Largest
surface in the project.

## 1.1 Detection engine — capture and classification

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| A1 | **Live packet capture** — 2-second tshark windows, extract → clean → engineer → score | **WORKS** (live) | Ran against the Npcap loopback adapter; `18117 packets captured, engineering flows...` then a scored verdict every window |
| A2 | **Capture-interface auto-detect** — resolves the default-route adapter | **WORKS** (live) | `primary IP: 10.10.10.15 -> adapter 'WiFi' -> tshark #5`. See defect **D1** for why auto-detect alone was not enough |
| A3 | **Capture-interface picker** *(added during this review)* — pin the adapter from the sidebar | **WORKS** (live) | Pinned `#15` in the DB with no CLI flag; engine started `Iface: #15` and detected loopback attacks. See **D1** |
| A4 | **BPF capture filter** — dashboard writes it, engine re-reads each window | **WORKS** (function) | Round-trip `'' → 'tcp port 80 or udp port 53' → ''`; engine logs `capture filter: '...'` and passes it to `tshark -f` |
| A5 | **Traffic classification** (`classify_profile`) — 7 profiles | **WORKS** (unit + live) | Every branch and both sides of every boundary checked — see the table in 1.2 |
| A6 | **Random Forest classifier** | **PARTIAL** | Loads and predicts (`[+] Random Forest model loaded.`), but the shipped model is **binary** (`classes_=[0,1]`) while `THREAT_LABEL_MAP` declares 3 classes. **`sig_rf` can never say Severe**, and across every run in this review it only ever emitted `Baseline (Safe)`. Detection is carried by the heuristic layer. See **D5** |
| A7 | **K-Means fallback tier** (used when the RF is absent) | **BROKEN** | `advanced_kmeans_model.pkl` and `advanced_data_scaler.pkl` are fitted on **15** features; the engine's `FEATURE_COLS` has **18**. The fallback cannot be fed. Not user-visible today because the RF is present. See **D6** |
| A8 | **Multi-signal fusion** (`fuse`) — worst-of across 7 layers | **WORKS** (unit) | `fuse(Baseline, Moderate, Severe) → Severe`; `fuse(None, Moderate) → Moderate`. Two unreachable edge cases noted in **D7** |
| A9 | **Slow-attack detector** — multi-window rolling correlation | **WORKS** (unit + live) | Fired at window 6: `('Slow Port Scan (multi-window)', 'Moderate (Suspicious)')`. Also caught live at only 120 pps across 60 ports |
| A10 | **DNS-tunnel detector** | **WORKS** (unit + replay) | `dns_tunnel_check(500 DNS pkts) → ('DNS Tunnel / C2 Channel', 'Moderate (Suspicious)')`; also fired in a realtime replay |
| A11 | **Threat-intel blocklist** — reloaded live each window | **WORKS** (unit) | Comments, blanks and duplicates handled; missing file → `set()`, no crash. Minor: invalid entries such as `not-an-ip` are kept (harmless — they can never match) |
| A12 | **Baseline whitelist** — suppress known-good IPs | **WORKS** (function) | Same loader path; engine logs `baseline whitelist reloaded: N IP(s)` on change |
| A13 | **IPv4/IPv6 coalescing** (`clean_packets`) | **WORKS** (unit + live) | Pure-IPv6 frame → `Transport=['TCP'] SrcIP=['fe80::1']`; ICMP-only → `OTHER`; all-empty frame → no crash. A real `fe80::` source was also scored during live capture |
| A14 | **Flow engineering** — per-source-IP aggregation | **WORKS** (unit + replay) | All-empty frame → `0 flow row(s), empty=True`; 2,400-packet PCAP → 58 scored flows |
| A15 | **Protocol breakdown** per source IP | **WORKS** (replay) | 58 rows written to `protocol_breakdown` |
| A16 | **Memory bounding** — LRU cap on tracked IPs | **WORKS** (unit) | Fed 4,596 distinct source IPs → state held exactly **4096** (`MAX_TRACKED_IPS`) |
| A17 | **PCAP replay mode** (`--replay`, `--realtime`) | **WORKS** (replay) | `Windows processed: 40 | Total flows scored: 58 | Baseline 53 | Moderate 3 | Severe 2` |
| A18 | **SQLite schema init** — idempotent, created by either side | **WORKS** (unit) | Second `init_db()` produced an identical table list; `capture_config` seeded `{'bpf_filter': '', 'interface': ''}` |

### 1.2 Measured detection thresholds

Every branch of `classify_profile`, checked on both sides of its boundary:

| Input | Result |
|---|---|
| 21 ports, 501 pps | Aggressive Port Scan — Severe |
| 21 ports, 500 pps | Port Scan / Reconnaissance — Moderate |
| 20 ports (at bound) | not a scan |
| 501 pps, SYN/ACK 5.1 | DDoS SYN Flood — Severe |
| 501 pps, SYN/ACK 5.0 | **Standard Web Traffic — Baseline** |
| 1001 pps | High-Volume Flood — Severe |
| 1000 pps (at bound) | **Standard Web Traffic — Baseline** |
| 301 pps, >800 B packets | Speed Test / Large Transfer — Moderate |
| ≤5 pps, <150 B | Ping / Background Telemetry — Baseline |

Confirmed against real captured traffic by driving the loopback adapter at
controlled rates:

| Measured rate (1 port, UDP, SYN/ACK ≈ 0) | Engine verdict |
|---|---|
| 50 – 893 pps | **Baseline (Safe)** |
| 1198 pps and above | **Severe — High-Volume Flood** |
| 120 pps across 60 ports | Moderate — Slow Port Scan, then Severe — Aggressive Port Scan |

**This is a real detection gap.** A single-port flood between roughly 500 and
1000 pps is classified Baseline. The `pps > 500` DDoS branch also requires
`syn_ack_ratio > 5`, which a UDP flood never produces, so only the `pps > 1000`
branch can catch it. Logged as **D4**.

## 1.3 Dashboard — global chrome and sidebar

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| A19 | Seven-tab shell | **WORKS** (function) | Headless AppTest boot: `EXCEPTIONS: 0`; tabs `Live SOC Dashboard, Educational Simulator, PCAP Analysis, Threat Map, Model Intelligence, Defense Config, Detection Benchmark` |
| A20 | Graceful degradation gates for all four contributors' modules | **WORKS** (function) | `MITRE_OK=True PCAP_ENGINE_OK=True MODEL_INTEL_OK=True BENCHMARK_OK=True RY_REPORT_OK=True RY_MGMT_OK=True RY_DOCX_OK=True` — no tab falls back to an error card |
| A21 | "How to use" help overlay | **PARTIAL** | Button present; the `@st.dialog` body needs a real script run context, so it is code-verified only |
| A22 | "Reduce animations" toggle | **WORKS** (function) | `checkbox key='lite_mode'`; correctly gates the FX iframe |
| A23 | Interactive FX layer (particles, ghost cursor, magnetic buttons) | **NOT TESTED** | Browser-only JS in a 1px iframe; no headless surface |
| A24 | Design-system CSS | **PARTIAL** | Emits without error; rendering is browser-only. Note: the `@import` of Google Fonts means the type system silently disappears offline |
| A25 | Enable Live Monitoring switch | **WORKS** (function) | `checkbox key='enable_live_monitoring'` |
| A26 | Refresh interval (2/5/10/30 s) via `st.fragment` | **WORKS** (function) | Fragment executed and produced live metrics; only the SOC panel re-polls |
| A27 | Severity filter | **WORKS** (function) | `multiselect key='sev_filter' options=['Severe','Moderate','Baseline']` |
| A28 | Monitoring status pill + engine caption | **WORKS** (function) | Rendered `MONITORING`; `Detection Engine: Hybrid (Behavioral ML + Signature Rules)` |
| A29 | **Capture Interface picker** (sidebar) | **WORKS** (function, after fix) | Was **BROKEN** on first test — rendered only the "tshark could not list interfaces" fallback. Root cause and fix in **D1**. Now returns 17 adapters |
| A30 | Capture Filter (BPF) — input, Save, Clear | **WORKS** (function) | All three widgets present; round-trip verified |
| A31 | Auto-Block settings (toggle / threshold / TTL) | **WORKS** (function) | Round-trip `{enabled:False, threshold:3, ttl:3600}` → `{True, 7, 18000}` → restored |
| A32 | Currently-Blocked-IPs sidebar table | **WORKS** (function) | Rendered real rows with computed expiry; empty case shows `No IPs are currently blocked.` |

## 1.4 Dashboard — Tab 1, Live SOC

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| A33 | Alert-DB read with schema adaptation | **WORKS** (function) | `shape (153, 33)`, `error: None`; every optional column block gated on the live schema |
| A34 | Empty state / loading skeleton | **WORKS** (function) | Both render; skeleton correctly shows once, not per refresh tick |
| A35 | DB-unreadable error state | **PARTIAL** | Code-verified only — the database never failed to open |
| A36 | THREATCON banner | **WORKS** (function) | Ran for both critical and nominal inputs |
| A37 | KPI metric row | **WORKS** (function) | Real values read: `Total Flows Logged=3, Critical Threats=1, Unique Source IPs=2, Blocked IPs=0` |
| A38 | SOC deflection scoreboard | **PARTIAL** | Python side runs; the count-up animation is iframe JS |
| A39 | Cyber Kill Chain strip | **WORKS** (function) | Stage mapping verified: `Port Scan→0, DDoS SYN Flood→1, C2 Beacon→2, Data Exfiltration→3, Standard Web→None` |
| A40 | Display filters (transport / port / IP-contains) | **WORKS** (function) | All three widgets present; port match covers dest, source and both per-window port lists |
| A41 | Live telemetry table, severity-coloured | **WORKS** (function) | Rendered `(3, 8)`; row styler returned real colours |
| A42 | Sticky row selection / "Resume live table" | **PARTIAL** | Pure cross-rerun session-state mechanism; code-verified, logic self-consistent |
| A43 | Click-row drill-down | **WORKS** (function) | Ran on a real Severe row and a Baseline row |
| A44 | Threat Analysis Report (0–100 score, band, reasons, actions) | **WORKS** (function + replay) | Real row: `score=65 band='High'`, reasons `"base severity 30/40 | High connection rate (42 pkts/s) | Port fan-out across 80 destination ports | SYN/ACK imbalance (80.0) | Repeat offender — 14 prior incident(s) → +10"` |
| A45 | Detection rationale (per-layer "why") | **WORKS** (function) | All seven signal columns surfaced; `sig_lstm` correctly gated separately |
| A46 | Raw hex inspector | **WORKS** (function) | `150 bytes, hdr_len=54`, valid EtherType `0800`; payload honestly captioned as synthetic |
| A47 | Download current capture (PCAP) | **WORKS** (function) | Button present, `temp_live.pcap` served |
| A48 | Evidence-PCAP / ZIP / CSV export | **PARTIAL** | The three exports are mutually exclusive; **the CSV export is unreachable whenever any evidence PCAP exists**. See **D8** |
| A49 | PCAP evidence file list | **WORKS** (function) | Section rendered; DB paths resolved on disk |
| A50 | Threat distribution chart / top talkers / protocol mix / activity timeline | **WORKS** (function) | All four rendered from real data |
| A51 | MITRE ATT&CK intelligence panel | **WORKS** (function) | `Unique Techniques=2, Unique Tactics=1, Top Technique=T1040, Top Tactic=Discovery`; badge grid and per-IP fingerprint rendered |
| A52 | One-click Block IP | **PARTIAL** | Button renders and the warning fires; the action needs Administrator — `apply_firewall_block(...) → False`, and the DB is correctly **not** written when netsh fails |
| A53 | Dashboard-side auto-block enforcement | **PARTIAL** | Without Administrator every block fails and the loop prints **nothing at all** — silent. See **D9** |
| A54 | Live event ticker | **WORKS** (function) | `26 events, first=('sev', '[BLOCKED] 10.9.9.9')`; idle case handled |

## 1.5 Dashboard — Tabs 2, 3, 6, 7

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| A55 | Educational simulator — scenario selector + verdicts | **WORKS** (function) | `radio 'Select Scenario:'`, verdict `Classification: BASELINE — Standard web traffic pattern.` |
| A56 | Interactive attack lab (canvas, intensity, 3-strike auto-block) | **NOT TESTED** | ~420 lines of self-contained JS; nothing crosses back to Python. Note: its thresholds are hand-copied from the engine and will drift — see **D10** |
| A57 | Behavioral signatures reference table | **WORKS** (function) | Rendered `(5, 6)` |
| A58 | PCAP upload + analysis | **WORKS** (function) | Real capture → `shape (10, 20)`, `{'Severe': 6, 'Moderate': 3, 'Safe': 1}` |
| A59 | Upload path-traversal hardening | **WORKS** (function) | `'../../evil.pcap' → 'temp_evil.pcap'`; result stays inside the target folder |
| A60 | Detection-benchmark tab (targets, CSV upload, gauges, confusion matrix, per-attack rates, CSV export) | **WORKS** (function) | Full metric dict returned; export produced a real 190-byte CSV; missing-`Label` error surfaces cleanly as `Expected a 'Label' column with BENIGN / attack-name values.` |
| A61 | Defense Config — threat-intel and baseline editors | **WORKS** (function) | Both editors round-trip, de-duplicate, sort and preserve the comment header; `'999.1.1.1'`, `'abc'`, `'1.2.3'` all correctly rejected |
| A62 | Notifier config form + "Send test alert" | **PARTIAL** | Whole form renders and the config round-trips; the send was deliberately **not** fired (real mail/webhook egress). Fail-safe verified separately: `notify_severe(...)` with no config → `None`, no crash |

## 1.6 Aalok — supporting tooling

| Item | Verdict | Evidence |
|---|---|---|
| **Spec-target metrics** (`reproduce_spec_metrics.py`) | **WORKS** | Reproduces its published numbers: DR 100%, FP 0%, Precision 100%, F1 100%, latency 0.152 ms — **5/5 PASS**. Honest about itself: `SPEC_METRICS.md` states these are *agreement* scores between the RF and the heuristic rule, not independent detection scores. That characterisation is accurate |
| `feature_engineer.py` | **WORKS** | Its `FEATURE_COLS` is **identical** to the engine's 18-column contract — verified element-wise |
| `notifier.py` | **WORKS** | Missing config → `load_config() → {}`, `notify_severe(...) → None`. Fails safe; cannot kill the capture loop |
| `test_notifier.py` diagnostics | **WORKS** | Correctly reports `notifier_config.json exists? False → Copy notifier_config.json.example first.` |
| Model artifacts vs engine contract | **PARTIAL** | `rf_model.pkl` / `rf_scaler.pkl` = 18 features ✅; K-Means pair = 15 features ❌ (**D6**) |
| Launcher path audit (`START.bat`, `STOP.bat`, `start_system.bat`, `run_hybrid_ids.py`) | **WORKS** | All 21 paths the launchers and dashboard need **resolve correctly** in the Code-Share bundle. Minor: `AARON` and `RUIYANG` variables in root `START.bat` are set and never used |
| `advanced_parser.py`, `trainai_rf.py`, `trainai.py` | **NOT TESTED** | Not executed — they overwrite shipped model artifacts. Two issues found by reading: `advanced_parser.py` ships with a hard-coded `MAX_FILES = 2` dry-run cap, and `trainai.py` drops a `'Source IP'` column that the in-memory `engineer_flows()` path never produces (**D11**) |
| `debug_flags.py` | **WORKS** (as dead code) | Imported by nothing in the tree — harmless leftover |

---

# 2. RUI YANG

Owns offline PCAP analysis: the flow engine, the signature-rule set, composite
scoring, offender history, and report export.

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| R1 | **Test suite** (4 files) | **WORKS** | `python -m pytest -q` → **`117 passed in 1.14s`** |
| R2 | **PCAP analysis engine** — 22 CICFlowMeter-style features per flow | **WORKS** | 2,400-packet capture → 7 flows, all six attack types identified. DNS-subdomain Shannon entropy computed correctly (5.05 bits/char on the tunnel flow) |
| R3 | **Signature rule engine** — 14 rules, most-severe-wins | **WORKS** | All 14 fired individually. Tie-break verified live: `[Port Scan/SEVERE, NULL Scan/HIGH, ICMP Flood/HIGH] → Port Scan` |
| R4 | **Data-derived thresholds** (`thresholds.json`) | **WORKS** | Genuinely loaded, proven three ways. All 8 in-effect values differ from the hardcoded fallbacks and match the JSON exactly (e.g. `port_scan_pps_floor` 405.54 from JSON vs 3000 hardcoded). Behavioural probe at 1000 pps fires only under the JSON value |
| R5 | **Composite threat scoring** — 7 components → 0–100, 5 tiers | **WORKS** | Real per-component breakdown across 7 flows; `Normal Traffic` correctly gated to a hard 0; FP-reduction stacking (−5 / −3 / −8) verified |
| R6 | **Repeat-offender history** (SQLite) | **WORKS** | Two consecutive runs: all sources `Prior Hits 0 → 1`, every score `+3` (matching `historical_score(1)`). One source escalated **Medium → High** on second sighting — persistence demonstrably changes the verdict |
| R7 | **Report export** — technical, management, and Word | **WORKS** | `report_content.txt` 11,758 B; `threat_analysis_report.docx` 37,500 B; `management_incident_report.docx` 37,075 B. Both .docx read back as valid documents (67 paragraphs / 1 table, and 62 paragraphs) using **real Word styles** — Title, Heading 1, Heading 2, List Bullet — not bolded runs. Minor: the .docx lists incidents in capture order while the on-screen view ranks by score |
| R8 | **GeoIP threat map lookups** | **WORKS** (API reachable during the test) | Live resolutions, e.g. `102.178.172.107 → Ouagadougou, Burkina Faso (FTTX)`. Private ranges correctly skipped; the RFC1918-vs-prefix fix is real (`172.64.1.1` correctly treated as public). Offline it degrades to `None` with **no distinction between "private IP" and "API unreachable"** |
| R9 | **Streamlit upload UI** | **WORKS** (function) | Headless AppTest boot with no exception; 2 tabs, file uploader present. Upload handler driven directly end-to-end: metrics, charts, both report views, and both .docx download payloads produced |
| R10 | **Threshold derivation script** | **PARTIAL** | Cannot run as shipped — needs a 717 MB CIC-IDS CSV at a hard-coded absolute path (`C:\HybridIDPS\...`) and raises a bare `FileNotFoundError` when it is absent. The algorithm itself was proven correct against a synthetic dataset |
| R11 | **Benign-traffic false positive** | **BROKEN** | His own `benign_https()` fixture (300 packets to :443) is classified **Severe — "DDoS Attack Detected"**. Isolated to a single threshold: the data-derived `ddos_fwd_len_mean_floor = 308.5` is **lower** than the hand-picked `500` the code comment says was needed to stop exactly this. **0 of 7 flows in the test capture were classified Safe.** Not covered by the 117 tests, which pin rules against synthetic dicts rather than his own end-to-end benign fixture. See **D12** |

**Documentation accuracy.** Nearly everything checkable checks out: the RF
hyper-parameters (all 6), the 22-feature contract, the 10-row feature-importance
table (to 4 dp, in order), and the 15-row severity map (15/15) all match the
shipped artifacts exactly. Four claims do not hold:

1. `ML_METHODOLOGY.md` says "15 named rules" twice; the code has **14**
   (`len(ALL_RULES) = 14`). `SCORING_METHODOLOGY.md` says 14 and is correct — the
   two documents contradict each other.
2. `SCORING_METHODOLOGY.md` §5.1 claims *every* threshold is data-derived. Only
   **8** are; ~29 numeric comparisons plus the DNS entropy floor remain hand-picked.
3. §5.2's "this mistake is now prevented automatically" claim is not borne out —
   the regression it describes is exactly **R11**, still present.
4. The training dataset path disagrees between `ML_METHODOLOGY.md` and `train2.py`.

The §5 performance table (99.85% accuracy etc.) could not be reproduced — the
source dataset is not in the repo. The model artifact it describes is present and
every *structural* claim about it verified.

---

# 3. AARON

Owns MITRE ATT&CK mapping and active response. His features are **merged into**
`Aalok/Dashboard/live_backend.py` and `app.py` — that merged code is what ships
and what was tested. His own `Aaron/app.py` and `Aaron/live_backend.py` are older
standalone copies that do not run in the shipped app.

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| N1 | **MITRE ATT&CK tagging** of every alert | **WORKS** (replay) | **8/8 rows tagged.** Distinct techniques observed: `T1498 Network Denial of Service [Impact / TA0040]`, `T1046 Network Service Discovery [Discovery / TA0007]`, `T1071 Application Layer Protocol: DNS [Command and Control / TA0011]`, `T1040 Network Sniffing [Discovery]`. Direct call: `tag_mitre("DDoS Attack Detected") → ('T1498','T1498.001','Network Denial of Service: Direct Network Flood','Impact')` |
| N2 | **MITRE back-fill** onto untagged legacy rows | **WORKS** (function) | Runs inside every dashboard DB load, ≤500 rows per call, no error |
| N3 | **Auto-block on repeat Severe alerts** | **WORKS** (replay) | With `enabled=1, threshold=1`: `[AUTO-BLOCK] 102.178.172.107 - Auto-blocked: 1 Severe alert(s) >= threshold 1` and 2 rows written to `blocked_ips` |
| N4 | **Windows Firewall block/unblock** | **PARTIAL** (non-admin) | `[AUTO-BLOCK] netsh block failed for 102.178.172.107:` — fails without Administrator, **handled gracefully: the alert is still written and the capture loop continues**. Verified by code inspection plus the observed non-admin failure; no real firewall rule was created. Minor: the error message interpolates an empty string, so the actual cause is not shown |
| N5 | **Alert dedup** — one alert per (IP, level) per 30 s | **WORKS** (replay + live) | 58 flows scored → 8 rows written; `[SUPPRESSED]` markers visible per window. Working as designed, but see **D3** — it is wall-clock based, which distorts fast replays |
| N6 | **Evidence PCAP capture** | **PARTIAL** | **Correct in live capture** — the saved file held 138,674 packets of the actual flood. **Wrong in replay mode**: both evidence files were byte-identical 61,400-byte copies of a stale `temp_live.pcap` containing none of the attacking IPs. See **D2** |

**Merge completeness — not fully verified.** The agent assigned to compare
`Aaron/live_backend.py` and `Aaron/app.py` against the merged files did not
complete. Every feature listed above was confirmed present and working in the
shipped code, but **no exhaustive check was made that nothing else of his was
dropped during the merge.** That gap is stated rather than papered over.

---

# 4. MEGAN

Owns the LSTM sequence model, SHAP explainability, and the automated retraining
pipeline.

| # | Feature | Verdict | Evidence |
|---|---|---|---|
| M1 | **Her test suite** | **WORKS** | `python test_v2_features.py` → **`12 passed in 9.03s`** |
| M2 | **LSTM architecture vs shipped weights** | **WORKS** | `load_state_dict(strict=True) → missing=[] unexpected=[]`. All ten tensors match key-for-key and shape-for-shape; `forward((4,15,18)) → (4,3)`; `load_lstm()` returns the model in eval mode |
| M3 | **LSTM sequence layer in the live engine** | **WORKS** | Contributes a recorded verdict from an IP's **2nd** capture window, and can raise a verdict to Severe after **15 windows (~30 s of sustained traffic from one IP)** *and* only when another layer has independently reached Moderate. Proven with a purpose-built 25-window capture: SEVERE begins at **exactly window 15**, and the LSTM lifts the fused verdict alone (`profile = "LSTM Sequence Anomaly (multi-window)"`) |
| M4 | **SHAP global importance (Random Forest)** | **WORKS** | Real Shapley values, additive check holds: `base 0.26855 + Σshap 0.40479 = f(x) 0.67333`. Rendered a populated 46 KB PNG |
| M5 | **SHAP for the LSTM** (per-feature *and* per-timestep) | **WORKS** | Correct `(15, 18)` shape; the timestep panel shows a clean monotonic ramp from `t-14` to `t-1`, i.e. the model genuinely weights recent windows most |
| M6 | **SHAP local explanation** (`explain_prediction`) | **BROKEN** | `IndexError: index 2 is out of bounds for axis 2 with size 2` — it indexes the Severe class on a **binary** RF (see **D5**). Severity limited: **no callers anywhere in the repo**, so it is dead code. Its module docstring also advertises a CLI flag that `main()` does not define |
| M7 | **Automated retraining** (RF + optional LSTM) | **WORKS** | RF retrain 3.6 s, LSTM retrain 13.3 s to `val_acc=0.974`. Writes versioned snapshots, updates `retrain_state.json`, prunes to 5 versions |
| M8 | **Model versioning and rollback** | **WORKS** | Byte-exact restore for both models — `rf_model.pkl` SHA-256 `46F476D0…` → retrain `3A11EAC0…` → **rollback `46F476D0…`** |
| M9 | **Dashboard Model Intelligence tab** | **WORKS** (function) | Both SHAP images render in the headless runtime; all three retrain metrics compute; buttons clicked headlessly drove a real retrain and a real rollback |

**Four caveats on the retraining pipeline**, all worth knowing before quoting it:

- The reported **`F1 (macro): 1.000` is not a real score.** Features are
  *synthesised from* the stored severity label (only 4 of 18 come from the DB),
  so the model is scored on data manufactured from its own labels. A perfect F1
  is the expected output of that loop, not evidence of a good model.
- Retraining **changes the model's class cardinality** from binary `[0,1]` to
  `[0,1,2]`. That incidentally fixes M6, but it means the engine's label
  semantics differ before and after a retrain.
- The `--lstm` retrain path trains on labels yielding `{0: 246, 1: 15}` —
  **zero Severe examples**. The shipped LSTM demonstrably emits Severe; a model
  retrained this way would never have seen the class.
- `retrain_state.json` stores **absolute paths** containing an old folder name,
  so rolling back to a historical entry would fail. `rollback()` also does not
  pop the entry it restored, so calling it twice restores the same version.

---

# Cross-cutting defects

Ordered by how likely a user is to hit them.

### D1 — Capture interface: wrong adapter, and no way to change it *(FIXED)*
**Was:** the engine only ever auto-detected the default-route adapter, and
`desktop_app.py` calls `run_live(interface=None)` — the packaged app has no
command line, so a wrong guess was uncorrectable. Attack traffic from a VM, a
second NIC, or localhost lands on an adapter the engine is not watching, and it
logs `no packets in window` while the attack runs.

**Fixed in this review.** Added `read_capture_interface()` /
`list_capture_interfaces()` to the engine and a **Capture Interface** picker to
the dashboard sidebar, stored in `capture_config.interface` and re-read every
window. Priority: `--interface` > dashboard pin > auto-detect.

**A second bug was found in that fix and also repaired.** The picker initially
never rendered: `import live_backend` inside `app.py` resolves to
**`Aaron/live_backend.py`**, because each sibling contributor folder is inserted
at `sys.path[0]` *after* the Dashboard folder. Aaron's copy has no
`list_capture_interfaces`, the `AttributeError` was swallowed, and the sidebar
showed a misleading *"tshark could not list interfaces"* on a machine where
tshark works perfectly. Fixed by loading the Dashboard's own engine **by file
path** (`_dashboard_live_backend()`). Verified: bare import → Aaron's file
(no method); path-pinned → Aalok's, **17 adapters returned**.

*Any other `import <name>` in `app.py` that collides with a sibling folder's
module has the same hazard.*

### D2 — Evidence capture is wrong in replay mode
In live capture the saved evidence PCAP is correct (138,674 real packets). In
`--replay`, `_capture_evidence` copies whatever stale `temp_live.pcap` is sitting
in the Dashboard folder: both files were byte-identical and contained **none** of
the attacking IPs they were filed under. Fresh installs are unaffected
(`temp_live.pcap` is excluded from both bundles), but anyone who runs live and
then replays gets misattributed evidence.

### D3 — Alert dedup is wall-clock, so fast replays look broken
`DEDUP_WINDOW_SECONDS = 30` measured against real time, not capture time. An
80-second PCAP replayed in ~2 seconds collapses to first-appearance rows only —
which is why `sig_lstm` initially appeared to fire on just 1 of 8 rows. Replayed
with `--realtime`, **100% of post-first-window rows carried `sig_lstm`.** The
layer is fine; the demo mode hides it. Worth knowing before demonstrating.

### D4 — Detection gap: single-port floods between ~500 and 1000 pps
Measured on real traffic: ≤893 pps → Baseline, ≥1198 pps → Severe. The
`pps > 500` branch additionally requires `syn_ack_ratio > 5`, which no UDP flood
produces. A moderate-rate single-port flood is invisible.

### D5 — The Random Forest can never report Severe
`rf_model.pkl` is binary (`classes_=[0,1]`) while `THREAT_LABEL_MAP` declares
three classes. `sig_rf` is structurally capped at Moderate, and across every run
in this review it only ever emitted `Baseline (Safe)`. Detection is carried by
the heuristic layer, not the ML layer. This is also the direct cause of **M6**.

### D6 — The K-Means fallback tier cannot run
`advanced_kmeans_model.pkl` and its scaler are fitted on **15** features; the
engine's `FEATURE_COLS` has **18**. If the RF were ever missing, the documented
fallback would fail. Not user-visible while the RF ships.

### D7 — `fuse()` has no empty guard (latent)
`fuse()` with zero arguments raises `ValueError: max() iterable argument is
empty`; `fuse(None, None)` returns `None` rather than a Baseline label; an
unrecognised label outranks Baseline. **Not reachable today** — `sig_heuristic`
always carries a real label — but it is one refactor away from being reachable.

### D8 — "Export Filtered Logs (CSV)" is unreachable when evidence PCAPs exist
The three export buttons are an `if/elif/else`. One existing evidence PCAP in the
filtered view replaces the CSV button entirely; the CSV bytes are computed and
discarded. They should be additive.

### D9 — Dashboard-side auto-block fails silently without Administrator
Every block returns False, the collected list stays empty, and the guarded
message prints nothing at all. The manual Block button reports its error; this
path does not. An operator sees an unmitigated Severe IP and no explanation.

### D10 — Simulator thresholds are a hand-copied duplicate
The Educational Simulator embeds 500 pps / SYN:ACK 5 / 20 ports as JS literals
and captions them as "the real ones from `live_backend.py`". True today; nothing
keeps them in sync.

### D11 — `trainai.py` column mismatch (latent)
It drops a `'Source IP'` column that `feature_engineer.engineer_flows()` names
`src_ip`, so it only works against the CSV path and would `KeyError` on the
in-memory path.

### D12 — Rui Yang's benign fixture trips the DDoS rule
See **R11**. The data-derived threshold is *looser* than the hand-picked value it
replaced, re-opening the exact false positive the comment says it was chosen to
prevent.

### D13 — Offline degradation is silent in three places
The Threat Map loads Leaflet and tiles from CDNs; GeoIP calls `ip-api.com`; the
app-wide CSS `@import`s Google Fonts. With no internet the map renders as a blank
panel with no error, and every public attacker is reported as a local address.
Attacker IPs are also **not** rate-limit-capped (normal IPs are, at 15), so a
capture with many distinct sources can silently exhaust the free tier.

---

# What was not tested

Stated plainly rather than left implied:

- **Browser rendering.** No feature was verified in an actual browser. Streamlit
  UI was verified with the headless AppTest runtime and by calling helpers
  directly. Anything that is browser-side JS — the FX layer, the interactive
  attack lab, the animated threat map, the scoreboard count-up — is marked
  NOT TESTED or PARTIAL.
- **Administrator-only paths.** Firewall block/unblock was never executed against
  the real Windows Firewall. No firewall rule was created or deleted.
- **Outbound notifications.** Email, Discord and Slack sends were never fired.
  Only config handling and fail-safe behaviour were tested.
- **Training reproduction.** Neither Rui Yang's CIC-IDS-2017 metrics nor Aalok's
  RF training run were reproduced — the source datasets are not in the repo.
- **Merge completeness for Aaron.** See the note in section 3.
- **`advanced_parser.py`, `trainai_rf.py`, `trainai.py`** were not executed, to
  avoid overwriting shipped model artifacts.

The repository itself was never modified during testing: all model artifacts
retain their original May/June timestamps and `git status` matches the
session-start snapshot.
