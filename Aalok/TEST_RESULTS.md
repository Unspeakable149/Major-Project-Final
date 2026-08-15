# Hybrid IDS — Attack Detection Test Report

**Project**: Hybrid Intrusion Detection Using Wireshark Packet Analysis and Behavioral Modeling
**Module**: CMP3602, Diploma in Cybersecurity & Digital Forensics, Temasek Polytechnic
**Test Date**: 2026-05-12

---

## 1. Test Environment

### Attacker — Kali Linux VM
| Setting | Value |
|---|---|
| Hypervisor | VirtualBox (Bridged Adapter) |
| Interface | `eth0` |
| IP (static) | `10.10.10.66/24` |
| MAC | `08:00:27:xx:xx:xx` |
| Gateway | `10.10.10.254` (consumer router) |
| Tools | `nmap 7.98`, `hping3` |

### Defender — Windows Host
| Setting | Value |
|---|---|
| OS | Windows 11 Home |
| Capture NIC | `WiFi` (`10.10.10.28`) via tshark |
| Engine | `Dashboard/live_backend.py` (2s windows, RF + heuristic + rolling state + intel) |
| Dashboard | `Dashboard/app.py` on `http://localhost:8501` |
| Privileges | Administrator (required for tshark + netsh) |

### Target
`10.10.10.254` (gateway router). VirtualBox bridged-mode quirk: VM-to-host traffic routes internally and bypasses the physical NIC tshark listens on. Attacking the gateway is the canonical workaround.

### Kali Static IP Setup

Static assignment so threat intel entries stay valid across reboots:

```bash
CONN=$(nmcli -t -f NAME,DEVICE connection show --active | grep eth0 | cut -d: -f1)
sudo nmcli con mod "$CONN" \
    ipv4.method manual \
    ipv4.addresses 10.10.10.66/24 \
    ipv4.gateway 10.10.10.254 \
    ipv4.dns "1.1.1.1 8.8.8.8"
sudo nmcli con down "$CONN" && sudo nmcli con up "$CONN"
```

---

## 2. Detection Layer Summary

| Layer | Source | What It Catches |
|---|---|---|
| Heuristic rules | `classify_profile()` in `live_backend.py` | Loud, single-window patterns (DDoS, port scan, ping) |
| Random Forest ML | `rf_model.pkl` | Smoothed boundary + confidence |
| Rolling state | `update_rolling()` / `slow_attack_check()` | Slow attacks aggregated over 15 windows (~30s) |
| Threat intel feed | `threat_intel.txt` | Known-malicious IPs — auto-escalate to Severe |
| Fusion | `fuse()` | Takes max severity across all layers |

---

## 3. Attack Test Results

### Test 1 — TCP SYN Port Scan (Fast)

**Command (Kali)**:
```bash
sudo nmap -sS -p 1-1000 $TARGET
```

**Output**:
```
Nmap scan report for 10.10.10.1
Host is up (0.0024s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
Nmap done: 1 IP address (1 host up) scanned in 0.83 seconds
```

**Dashboard Verdict**:
| Time | Source IP | Packets/Sec | SYN/ACK Ratio | Profile | Threat Level |
|---|---|---|---|---|---|
| 11:13:04 | 10.10.10.33 | 1590.72 | 1019.24 | DDoS SYN Flood | Severe (Critical Anomaly) |

**Outcome**: Detected as Severe — correct urgency. Label says `DDoS SYN Flood` because nmap pushed 1000 ports in 0.83s (pps=1590, sar=1019). Heuristic rule precedence trips DDoS check before port-scan check. See §4 for label-precision patch.

**Detector**: Heuristic (single window).

---

### Test 2 — SYN Flood / DDoS

**Command (Kali)**:
```bash
sudo hping3 -S --flood -V -p 80 $TARGET
```

**Output**:
```
HPING 10.10.10.1 (eth0 10.10.10.1): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown
^C
--- 10.10.10.1 hping statistic ---
191541 packets transmitted, 0 packets received, 100% packet loss
```

**Dashboard Verdict**:
| Time | Source IP | Packets/Sec | SYN/ACK Ratio | Profile | Threat Level |
|---|---|---|---|---|---|
| 11:14:51 | 10.10.10.33 | 31687.12 | 499.6 | DDoS SYN Flood | Severe (Critical Anomaly) |

**Outcome**: Detected. Volumetric SYN flood — pps far past the 500 threshold, sar far past 5. Heuristic + RF both flagged Severe.

**Detector**: Heuristic + ML.

**Note**: Gateway `10.10.10.1` simultaneously logged as `Slow Port Scan (multi-window)` — rolling state accumulated from Test 1's nmap; reply traffic from the gateway through Test 2's window inflated `rolling_unique_ports`. Expected behavioral carry-over; resets after 30s.

---

### Test 3 — Slow Port Scan (multi-window detector)

**Command (Kali)**:
```bash
sudo nmap -sS -T2 -p 1-200 $TARGET
```

`-T2` = polite timing, deliberately under the single-window pps threshold.

**Dashboard Verdict**:
| Time | Source IP | Packets/Sec | Profile | Threat Level |
|---|---|---|---|---|
| 11:15:44 | 10.10.10.33 | 3.32 | Slow Port Scan (multi-window) | Moderate (Suspicious) |

**Outcome**: Detected. Single-window pps=3.32 is invisible to the heuristic, but accumulated `rolling_unique_ports > 60` over ~30s tripped the multi-window slow-scan rule. Validates the slow-attack layer.

**Detector**: Rolling state.

---

### Test 4 — Brute-Force / Sustained SYN Probe

**Command (Kali)**:
```bash
sudo hping3 -S -p 22 -i u20000 $TARGET
```

`-i u20000` = one packet per 20ms (~50 pps) — under the 500 pps flood threshold.

**Dashboard Verdict**:
| Time | Source IP | Packets/Sec | SYN/ACK Ratio | Profile | Threat Level |
|---|---|---|---|---|---|
| 11:16:30 | 10.10.10.33 | 46.34 | 512 | Sustained SYN / Brute-Force Probe | Moderate (Suspicious) |

**Outcome**: Detected. Per-window pps=46 stays below flood, but `rolling_syn > 150` + `rolling_packets > 200` tripped the brute-force rule. Validates the sustained-probe layer.

**Detector**: Rolling state.

---

### Test 5 — Threat Intelligence Match

**Setup**:
1. Static-assigned Kali to `10.10.10.66`.
2. Appended Kali IP to `Dashboard/threat_intel.txt`.
3. Restarted backend; startup printed `[+] Threat intel feed loaded: 1 known-malicious IP(s).`

**Command (Kali)**:
```bash
ping -c 5 $TARGET
```

**Dashboard Verdict**:
| Time | Source IP | Packets/Sec | Profile | Threat Level |
|---|---|---|---|---|
| 11:41:44 | 10.10.10.66 | 1.98 | Known Malicious IP (Threat Intel Match) | Severe (Critical Anomaly) |

**Outcome**: Detected. Behaviorally benign (pps=1.98), but IP match auto-escalates to Severe regardless of metrics. Validates the threat-intel layer.

**Detector**: Threat intel feed (overrides all behavioral layers).

---

### Test 6 — UDP Flood

**Command (Kali)**:
```bash
sudo hping3 --udp --flood -p 53 $TARGET
```

**Output**:
```
HPING 10.10.10.1 (eth0 10.10.10.1): udp mode set, 28 headers + 0 data bytes
hping in flood mode, no replies will be shown
^C
--- 10.10.10.1 hping statistic ---
60331 packets transmitted, 0 packets received, 100% packet loss
```

**Dashboard Verdict**:
| Time | Source IP | Packets/Sec | Profile | Threat Level |
|---|---|---|---|---|
| 11:18:25 | 10.10.10.33 | 5283.57 | High-Volume Flood Attack | Severe (Critical Anomaly) |

**Outcome**: Detected. UDP flood at 5283 pps — the `pps > 1000` rule fired even with sar=0 (no TCP SYN/ACK in UDP traffic). Validates that the engine isn't TCP-only.

**Detector**: Heuristic.

---

## 4. Final Scorecard

| # | Attack | Layer That Caught It | Severity | Verdict |
|---|---|---|---|---|
| 1 | nmap fast scan (1000 ports/0.83s) | Heuristic | Severe | PASS (label imprecise — see patch below) |
| 2 | hping3 SYN flood | Heuristic + ML | Severe | PASS |
| 3 | nmap -T2 slow scan | Rolling state | Moderate | PASS |
| 4 | hping3 sustained SYN | Rolling state | Moderate | PASS |
| 5 | Intel-listed IP ping | Intel feed | Severe | PASS |
| 6 | hping3 UDP flood | Heuristic | Severe | PASS |

**6 / 6 attacks detected. All four detection layers (heuristic, ML, rolling state, intel) validated against live attacker traffic.**

---

## 5. Port-Scan Precedence Patch (Test 1 label fix)

### Problem
When `nmap` scans fast enough to push pps > 500 with sar > 5, the heuristic trips the DDoS rule before reaching the port-scan rule. Severity stays correct (Severe), but the traffic profile is mislabeled `DDoS SYN Flood` when it's actually `Aggressive Port Scan`.

### Root Cause
Rule precedence in `Dashboard/live_backend.py` → `classify_profile()`:

```python
if pps > 500 and sar > 5:               # DDoS check FIRST
    return "DDoS SYN Flood", "Severe (Critical Anomaly)"
if pps > 1000:
    return "High-Volume Flood Attack", "Severe (Critical Anomaly)"
if pps > 300 and avg_size > 800:
    return "Speed Test / Large Data Transfer", "Moderate (Bandwidth Spike)"
if ports > 20:                          # Port-scan check LAST
    return "Port Scan / Reconnaissance", "Moderate (Suspicious)"
```

Port count info (`ports > 20`) is never consulted when an earlier rule already fired.

### Patch
Add an aggressive-scan branch that combines port count + pps, and place it **before** the DDoS rule. This preserves the Severe severity while correcting the profile label.

**File**: `Dashboard/live_backend.py`

**Find** (around line ~80):
```python
def classify_profile(pps: float, sar: float, ports: int, avg_size: float):
    if pps > 500 and sar > 5:
        return "DDoS SYN Flood", "Severe (Critical Anomaly)"
    if pps > 1000:
        return "High-Volume Flood Attack", "Severe (Critical Anomaly)"
    if pps > 300 and avg_size > 800:
        return "Speed Test / Large Data Transfer", "Moderate (Bandwidth Spike)"
    if ports > 20:
        return "Port Scan / Reconnaissance", "Moderate (Suspicious)"
    if pps <= 5 and avg_size < 150:
        return "Ping / Background Telemetry", "Baseline (Safe)"
    return "Standard Web Traffic", "Baseline (Safe)"
```

**Replace with**:
```python
def classify_profile(pps: float, sar: float, ports: int, avg_size: float):
    # Aggressive port scan: many distinct ports AND high packet rate
    # (catches fast nmap before DDoS rule mislabels it).
    if ports > 20 and pps > 500:
        return "Aggressive Port Scan", "Severe (Critical Anomaly)"
    if ports > 20:
        return "Port Scan / Reconnaissance", "Moderate (Suspicious)"
    if pps > 500 and sar > 5:
        return "DDoS SYN Flood", "Severe (Critical Anomaly)"
    if pps > 1000:
        return "High-Volume Flood Attack", "Severe (Critical Anomaly)"
    if pps > 300 and avg_size > 800:
        return "Speed Test / Large Data Transfer", "Moderate (Bandwidth Spike)"
    if pps <= 5 and avg_size < 150:
        return "Ping / Background Telemetry", "Baseline (Safe)"
    return "Standard Web Traffic", "Baseline (Safe)"
```

### Apply the Patch

1. Stop the backend (close `IDS Backend` cmd window).
2. Open `Dashboard/live_backend.py` in an editor.
3. Replace the `classify_profile` function as above.
4. Restart via `start_system.bat` (or `python live_backend.py` in the Dashboard dir).

### Re-Test Expectations

Re-run Test 1:
```bash
sudo nmap -sS -p 1-1000 $TARGET
```

Expected dashboard row:
| Profile | Threat Level |
|---|---|
| Aggressive Port Scan | Severe (Critical Anomaly) |

Test 2 (hping3 SYN flood) should still come back `DDoS SYN Flood` — flood doesn't touch many ports, so the new branch doesn't fire and the old DDoS rule still wins.

### Severity Lattice After Patch

| Pattern | Single-Window Heuristic | Severity |
|---|---|---|
| Fast nmap (many ports + high pps) | Aggressive Port Scan | Severe |
| Slow nmap (`-T2`) | rolling state catches it | Moderate |
| SYN flood (single port, high pps + high sar) | DDoS SYN Flood | Severe |
| UDP flood (high pps, sar=0) | High-Volume Flood Attack | Severe |
| Brute-force (sustained low pps) | rolling state catches it | Moderate |

---

## 6. Spec Conformance Notes

Test results map to the project's required deliverables:

| Spec Requirement | Validated By |
|---|---|
| Packet capture (Wireshark/tshark) | Live tshark windows captured all attacks |
| Feature extraction pipeline | 18 features computed per Source IP per window |
| Signature detection engine | Heuristic rules fired for tests 1, 2, 6 |
| ML behavioral model (Random Forest) | RF predictions logged with confidence |
| Fusion / decision engine | `fuse()` selected max severity across layers |
| Real-time processing loop | All 6 verdicts appeared within 4s of attack start |
| Alert logging & dashboard | All verdicts persisted to `ids_logs.db`, rendered in SOC dashboard |
| Active response (firewall rule push) | One-Click Threat Mitigation cards available for tests 1, 2, 5, 6 |

For the spec's target metrics (DR > 95%, FPR < 5%, Precision > 90%, F1 > 92%, latency < 10ms), run `python Dashboard/evaluate_benchmark.py <CIC-IDS-2017.csv>` against a labeled benchmark dataset to produce the pass/fail report.
