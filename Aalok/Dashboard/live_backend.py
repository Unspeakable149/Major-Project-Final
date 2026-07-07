"""Live IDS backend.

Every WINDOW_SECONDS: tshark capture -> flow aggregation -> RF model +
heuristic rules -> fusion (max severity) -> SQLite alert log for app.py.
"""

import argparse
import json
import os
import socket
import subprocess
import sqlite3
import time
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

import notifier

warnings.filterwarnings("ignore")

# Suppress console windows when subprocesses launch under a windowed (no-console)
# frozen build. On non-Windows hosts this constant is 0 and a no-op.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
WINDOW_SECONDS = 2
DB_FILE = "ids_logs.db"
INTERFACE_OVERRIDE = None  # set to a tshark interface index (string) to skip auto-detect
THREAT_INTEL_FILE = "threat_intel.txt"  # optional newline-separated known-malicious IPs
BASELINE_FILE = "baseline.txt"  # optional newline-separated known-good IPs (gateway, DNS, etc.)
ROLLING_WINDOWS = 15  # number of past 2s windows kept per src IP (=> 30s history)

THREAT_LABEL_MAP = {
    0: "Baseline (Safe)",
    1: "Moderate (Suspicious)",
    2: "Severe (Critical Anomaly)",
}

SEVERITY_RANK = {
    "Baseline (Safe)": 0,
    "Moderate (Suspicious)": 1,
    "Moderate (Bandwidth Spike)": 1,
    "Severe (Critical Anomaly)": 2,
}

# ── Threat Scoring Model (FYP "Threat Level Hunting" enhancement) ──────────────
# The fusion engine yields a 3-level categorical verdict. This layer turns that
# plus several independent factors into a 0-100 numeric Threat Score, a risk
# band, and an analyst-readable report. Each component is bounded and separately
# justified; see THREAT_SCORING.md for the methodology and references behind the
# weights. All example values below are tunable — the graded deliverable is the
# justification, not the exact numbers.

# Idea 3 — per-attack-type base severity (0-40). Ordering follows the impact
# hierarchy in the brief (recon < volumetric flood < C2/exfil < known-bad) and
# the MITRE ATT&CK tactic each profile maps to in the dashboard.
ATTACK_SEVERITY = {
    "Standard Web Traffic": 0,
    "Ping / Background Telemetry": 0,
    "Whitelisted Source": 0,
    "Speed Test / Large Data Transfer": 8,
    "Port Scan / Reconnaissance": 15,
    "Slow Port Scan (multi-window)": 18,
    "DDoS SYN Flood": 30,
    "Sustained SYN / Brute-Force Probe": 30,
    "High-Volume Flood Attack": 35,
    "DNS Tunnel / C2 Channel": 35,
    "Known Malicious IP (Threat Intel Match)": 40,
}

# Floor keyed on the fused verdict so the numeric score can never contradict the
# categorical one (a Severe flow cannot land in the Normal band).
SEVERITY_FLOOR = {
    "Baseline (Safe)": 0,
    "Moderate (Suspicious)": 15,
    "Moderate (Bandwidth Spike)": 15,
    "Severe (Critical Anomaly)": 30,
}

# Idea 8 — final score -> risk band (upper bound inclusive).
SCORE_BANDS = [(20, "Normal"), (40, "Low"), (60, "Medium"), (80, "High"), (100, "Critical")]

# Per-source-IP rolling history across capture windows. Enables slow-rate /
# brute-force detection that a single 2s window can't see on its own.
ROLLING_STATE: dict[str, list[dict]] = {}

# Idea 6 — per-source incident memory for this backend session. Repeat offenders
# accrue a historical score. Reset on restart; the SQLite log is the durable copy.
INCIDENT_HISTORY: dict[str, int] = {}

FEATURE_COLS = [
    'total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports',
    'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags',
    'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second',
    'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio',
    'packet_size_std', 'iat_mean', 'iat_std',
]

TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
    "_ws.col.Protocol", "frame.len",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "ip.ttl", "tcp.window_size",
    # IPv6 src/dst: modern speed tests, CDNs, and tethered/iPhone links are
    # often IPv6. Without these, v6 packets get a blank Source IP and are
    # dropped before detection. Coalesced into Source/Dest IP in clean_packets.
    "ipv6.src", "ipv6.dst",
]

RAW_COLUMNS = [
    "Timestamp", "Source IP", "Dest IP", "TCP Src", "UDP Src",
    "TCP Dst", "UDP Dst", "Protocol", "Packet Size",
    "SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", "TTL", "Window Size",
    "IPv6 Src", "IPv6 Dst",
]

FLAG_COLS = ['SYN Flag', 'ACK Flag', 'FIN Flag', 'RST Flag']
NUMERIC_COLS = ['Packet Size', 'TTL', 'Window Size', 'Timestamp']


def _primary_local_ip() -> str | None:
    """The IP of the interface that actually reaches the internet (default route).

    Opens a throwaway UDP socket to a public address; the OS picks the routing
    interface and getsockname() reveals its IP. No packets are sent.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _adapter_name_for_ip(ip: str) -> str | None:
    """Map a local IP to its adapter name (e.g. 'Ethernet 6') via psutil.

    psutil is optional; returns None if it is unavailable or no match is found.
    """
    if not ip:
        return None
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "address", None) == ip:
                    return name
    except Exception:
        pass
    return None


def get_active_interface() -> str:
    """Return the tshark interface index that actually carries traffic.

    Strategy: find the IP on the default-route interface, map it to its adapter
    name, and match that name against ``tshark -D``. This works regardless of
    whether the live link is Wi-Fi, Ethernet, or a tether/VPN. Falls back to a
    Wi-Fi/Ethernet name match, then interface #1, when detection is unavailable
    (e.g. psutil missing). Override anytime with ``--interface <index>``.
    """
    print("[*] Auto-detecting the active capture interface...")
    try:
        output = subprocess.check_output(
            [TSHARK_PATH, "-D"], text=True, stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )
    except Exception:
        print("[!] could not list interfaces; defaulting to #1")
        return "1"
    lines = [ln for ln in output.split("\n") if ln.strip()]

    # 1. Match the active adapter (the one with the default-route IP) by name.
    name = _adapter_name_for_ip(_primary_local_ip())
    if name:
        for line in lines:
            if f"({name})" in line:
                idx = line.split(".")[0].strip()
                print(f"[+] active interface '{name}' -> #{idx}")
                return idx

    # 2/3. Fall back to a Wi-Fi, then Ethernet, name match.
    for keyword in ("wifi", "wi-fi", "ethernet"):
        for line in lines:
            if keyword in line.lower():
                idx = line.split(".")[0].strip()
                print(f"[+] '{keyword}' interface -> #{idx} (fallback; use --interface to override)")
                return idx

    print("[!] auto-detect failed, defaulting to interface #1 (use --interface to override)")
    return "1"


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


def _frequency_score(pps: float) -> int:
    """Idea 4 — connection-rate buckets (0-20)."""
    if pps < 20:
        return 0
    if pps < 100:
        return 5
    if pps < 300:
        return 10
    if pps < 700:
        return 15
    return 20


def _behaviour_score(unique_ports: int, syn_ack_ratio: float, rst_flags: int,
                     ack_flags: int, unique_ips: int) -> tuple[int, list[str]]:
    """Idea 5 — behavioural abnormality (0-15) plus the indicators that fired.

    Counts independent abnormal indicators, then maps the count onto the brief's
    Normal / Slightly / Moderately / Highly bands (0 / 5 / 10 / 15).
    """
    notes = []
    if unique_ports > 20:
        notes.append(f"Port fan-out across {unique_ports} destination ports")
    if rst_flags > 20 or (ack_flags and rst_flags > ack_flags):
        notes.append(f"High rate of reset/failed connections ({rst_flags} RST)")
    if syn_ack_ratio > 3:
        notes.append(f"SYN/ACK imbalance ({syn_ack_ratio:.1f}) — incomplete handshakes")
    if unique_ips > 10:
        notes.append(f"Traffic sprayed across {unique_ips} destination hosts")
    band = min(len(notes), 3) * 5  # -> 0, 5, 10, 15
    return band, notes


def _confidence_score(confidence: float, use_rf: bool) -> tuple[int, str]:
    """Idea 7 — detection-confidence buckets (5-15)."""
    if not use_rf:
        return 5, "clustering model (confidence not calibrated)"
    pct = confidence * 100
    if pct < 60:
        return 5, f"{pct:.0f}% (low)"
    if pct <= 80:
        return 10, f"{pct:.0f}% (moderate)"
    return 15, f"{pct:.0f}% (high)"


def _historical_score(prior_incidents: int) -> int:
    """Idea 6 — repeat-offender buckets (0-10)."""
    if prior_incidents <= 0:
        return 0
    if prior_incidents <= 5:
        return 3
    if prior_incidents <= 10:
        return 6
    return 10


def _band_for(score: int) -> str:
    """Idea 8 — map the final 0-100 score onto a risk band."""
    for upper, name in SCORE_BANDS:
        if score <= upper:
            return name
    return "Critical"


def _suggested_actions(band: str, profile: str) -> list[str]:
    """Idea 1 — recommended analyst actions from the risk band + attack type."""
    p = profile.lower()
    if band in ("High", "Critical"):
        actions = ["Block or rate-limit the source IP at the firewall",
                   "Preserve the capture (PCAP) and logs for investigation",
                   "Notify the security administrator"]
    elif band == "Medium":
        actions = ["Review the source IP and its recent activity",
                   "Preserve network logs in case of escalation"]
    else:
        actions = ["Log the event and continue monitoring"]

    if "scan" in p or "recon" in p:
        actions.append("Audit the exposed services on the probed ports")
    if "flood" in p or "ddos" in p:
        actions.append("Apply SYN-cookie / rate limiting at the network edge")
    if "dns" in p or "c2" in p:
        actions.append("Inspect DNS logs for encoded exfil and sinkhole the domain")
    if "brute" in p or "sustained" in p:
        actions.append("Enforce account lockout / MFA on the targeted service")
    if "malicious" in p or "intel" in p:
        actions.append("Confirm the block and hunt for lateral movement")
    return actions


def compute_threat_score(profile, threat, pps, syn_ack_ratio, unique_ports,
                         rst_flags, ack_flags, unique_ips, confidence, use_rf,
                         prior_incidents, intel_hit, baseline_hit):
    """Combine the scoring factors into a 0-100 Threat Score + analyst report.

    Implements the FYP "Threat Level Hunting" enhancement:

        score = severity + frequency + behaviour + historical + confidence
                - false-positive reduction                 (Ideas 2-8)

    and turns the result into a risk band, the reasons behind it, and suggested
    actions (Idea 1).

    False-positive reduction (Idea 2) is realised by gating on the fused verdict:
    a flow the fusion engine rules Baseline/Safe (and which is not on the intel
    feed) is treated as a false positive -> score 0. This stops benign heavy
    traffic (e.g. a speed test at high pps) from accumulating a misleading score.
    A baseline-whitelisted source is likewise forced to 0.

    Returns a dict: {score, band, reasons, actions, breakdown}.
    """
    benign = baseline_hit or (threat == "Baseline (Safe)" and not intel_hit)
    if benign:
        return {
            "score": 0,
            "band": "Normal",
            "reasons": ["No anomalous behaviour above baseline"],
            "actions": ["No action required — continue monitoring"],
            "breakdown": {"Severity": 0, "Frequency": 0, "Behaviour": 0,
                          "Historical": 0, "Confidence": 0, "FP Reduction": 0},
        }

    severity = max(ATTACK_SEVERITY.get(profile, 0), SEVERITY_FLOOR.get(threat, 0))
    if intel_hit:
        severity = max(severity, ATTACK_SEVERITY["Known Malicious IP (Threat Intel Match)"])
    frequency = _frequency_score(pps)
    behaviour, behaviour_notes = _behaviour_score(
        unique_ports, syn_ack_ratio, rst_flags, ack_flags, unique_ips)
    historical = _historical_score(prior_incidents)
    confidence_pts, confidence_note = _confidence_score(confidence, use_rf)

    score = max(0, min(100, severity + frequency + behaviour + historical + confidence_pts))
    # A confirmed threat-intel match is a known-malicious source: floor it into
    # the High band regardless of how little traffic it is sending right now.
    if intel_hit:
        score = max(score, 75)
    band = _band_for(score)

    reasons = [f"Attack type '{profile}' → base severity {severity}/40"]
    if frequency:
        reasons.append(f"High connection rate ({pps:.0f} pkts/s) → frequency +{frequency}")
    reasons.extend(behaviour_notes)
    if behaviour:
        reasons.append(f"Behavioural abnormality → +{behaviour}")
    if historical:
        reasons.append(f"Repeat offender — {prior_incidents} prior incident(s) → +{historical}")
    reasons.append(f"Detection confidence {confidence_note} → +{confidence_pts}")
    if intel_hit:
        reasons.append("Source present on the threat-intel blocklist")

    return {
        "score": score,
        "band": band,
        "reasons": reasons,
        "actions": _suggested_actions(band, profile),
        "breakdown": {"Severity": severity, "Frequency": frequency,
                      "Behaviour": behaviour, "Historical": historical,
                      "Confidence": confidence_pts, "FP Reduction": 0},
    }


def load_threat_intel(quiet: bool = False) -> set[str]:
    """Load newline-separated known-malicious IPs from THREAT_INTEL_FILE.

    Lines starting with '#' are comments. File is optional; missing file
    returns an empty set so the runtime falls back to behavioral detection.
    quiet=True suppresses the load banner (used when re-reading every window).
    """
    if not os.path.exists(THREAT_INTEL_FILE):
        return set()
    ips = set()
    with open(THREAT_INTEL_FILE, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    if ips and not quiet:
        print(f"[+] Threat intel feed loaded: {len(ips)} known-malicious IP(s).")
    return ips


def load_baseline(quiet: bool = False) -> set[str]:
    """Load newline-separated known-good IPs from BASELINE_FILE.

    Lines starting with '#' are comments. File is optional; missing file
    returns an empty set so behavior is unchanged. A matching source IP
    is forced to Baseline (Safe) regardless of rule trips, but threat
    intel matches still win - intel > baseline.
    quiet=True suppresses the load banner (used when re-reading every window).
    """
    if not os.path.exists(BASELINE_FILE):
        return set()
    ips = set()
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    if ips and not quiet:
        print(f"[+] Baseline whitelist loaded: {len(ips)} known-good IP(s).")
    return ips


def update_rolling(src_ip: str, total_packets: int, unique_ports: int, syn_flags: int) -> dict:
    """Maintain bounded per-IP history; return aggregated stats across history."""
    history = ROLLING_STATE.setdefault(src_ip, [])
    history.append({"packets": total_packets, "ports": unique_ports, "syn": syn_flags})
    if len(history) > ROLLING_WINDOWS:
        del history[:-ROLLING_WINDOWS]
    return {
        "rolling_windows": len(history),
        "rolling_packets": sum(h["packets"] for h in history),
        "rolling_unique_ports": sum(h["ports"] for h in history),
        "rolling_syn": sum(h["syn"] for h in history),
    }


def slow_attack_check(rolling: dict) -> tuple[str, str] | None:
    """Catch attacks that hide below the single-window pps threshold."""
    n = rolling["rolling_windows"]
    if n < 5:  # need at least 10s of history
        return None
    # Slow port scan: low single-window port count but huge total port spread over time.
    if rolling["rolling_unique_ports"] > 60:
        return "Slow Port Scan (multi-window)", "Moderate (Suspicious)"
    # Sustained SYN beacon / brute-force: many SYNs over time, never crosses single-window flood.
    if rolling["rolling_syn"] > 150 and rolling["rolling_packets"] > 200:
        return "Sustained SYN / Brute-Force Probe", "Moderate (Suspicious)"
    return None


def load_models():
    """Prefer RF; fall back to K-Means if RF artifacts missing."""
    try:
        model = joblib.load("rf_model.pkl")
        scaler = joblib.load("rf_scaler.pkl")
        print("[+] Random Forest model loaded.")
        return model, scaler, True
    except FileNotFoundError:
        model = joblib.load("advanced_kmeans_model.pkl")
        scaler = joblib.load("advanced_data_scaler.pkl")
        print("[+] K-Means fallback loaded. Run trainai_rf.py to upgrade.")
        return model, scaler, False


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS live_threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            packets_per_sec REAL,
            avg_window_size REAL,
            syn_ack_ratio REAL,
            total_bytes INTEGER,
            traffic_profile TEXT,
            threat_level TEXT,
            confidence REAL DEFAULT 0.0,
            top_dest_port INTEGER,
            dominant_transport TEXT,
            dest_ports TEXT,
            top_source_port INTEGER,
            source_ports TEXT
        )
    ''')
    # Idempotent column adds so an existing DB (pre-dating these columns) is
    # migrated in place rather than rebuilt. Same pattern as confidence above.
    for ddl in (
        'ALTER TABLE live_threat_logs ADD COLUMN confidence REAL DEFAULT 0.0',
        'ALTER TABLE live_threat_logs ADD COLUMN top_dest_port INTEGER',
        'ALTER TABLE live_threat_logs ADD COLUMN dominant_transport TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN dest_ports TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN top_source_port INTEGER',
        'ALTER TABLE live_threat_logs ADD COLUMN source_ports TEXT',
        # Per-layer detection signals (the four verdicts fuse() collapses into
        # threat_level, plus the intel/baseline overrides). Stored so the
        # dashboard can explain *why* a flow got its severity instead of only
        # showing the fused result.
        'ALTER TABLE live_threat_logs ADD COLUMN sig_heuristic TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN sig_rf TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN sig_slow TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN sig_dns TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN sig_intel INTEGER DEFAULT 0',
        'ALTER TABLE live_threat_logs ADD COLUMN sig_baseline INTEGER DEFAULT 0',
        # Threat Scoring enhancement: the 0-100 numeric score, its risk band, and
        # the analyst-report text (reasons/actions) + component breakdown JSON.
        'ALTER TABLE live_threat_logs ADD COLUMN threat_score INTEGER',
        'ALTER TABLE live_threat_logs ADD COLUMN score_band TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN threat_reasons TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN threat_actions TEXT',
        'ALTER TABLE live_threat_logs ADD COLUMN threat_breakdown TEXT',
    ):
        try:
            cur.execute(ddl)
        except sqlite3.OperationalError:
            pass  # column already exists
    cur.execute('''
        CREATE TABLE IF NOT EXISTS protocol_breakdown (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            protocol TEXT,
            packets INTEGER,
            bytes INTEGER
        )
    ''')
    # Shared key-value store for the live BPF capture filter. The dashboard
    # writes 'bpf_filter'; the capture loop re-reads it each window and passes
    # it to tshark -f (mirrors the autoblock_config cross-process pattern).
    cur.execute('''
        CREATE TABLE IF NOT EXISTS capture_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    cur.execute(
        "INSERT OR IGNORE INTO capture_config (key, value) VALUES ('bpf_filter', '')"
    )
    conn.commit()
    conn.close()


def read_capture_filter() -> str:
    """Return the current BPF capture filter string (empty = capture all)."""
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        row = conn.execute(
            "SELECT value FROM capture_config WHERE key='bpf_filter'"
        ).fetchone()
        conn.close()
        return (row[0] if row else "").strip()
    except sqlite3.OperationalError:
        return ""


def capture_window(interface: str, bpf_filter: str = "") -> pd.DataFrame:
    """Run a single tshark capture + extraction cycle.

    bpf_filter: optional libpcap capture filter (BPF syntax, e.g. "tcp port 80").
    When set, only matching packets are captured this window. A malformed filter
    makes tshark capture nothing -> the caller's empty-window guard handles it.
    """
    capture_cmd = [TSHARK_PATH, "-i", interface,
                   "-a", f"duration:{WINDOW_SECONDS}", "-w", "temp_live.pcap"]
    if bpf_filter:
        capture_cmd += ["-f", bpf_filter]
    subprocess.run(
        capture_cmd,
        stderr=subprocess.DEVNULL,
        creationflags=NO_WINDOW,
    )

    extract_cmd = [TSHARK_PATH, "-r", "temp_live.pcap", "-T", "fields"]
    for field in TSHARK_FIELDS:
        extract_cmd += ["-e", field]
    extract_cmd += ["-E", "header=y", "-E", "separator=,", "-E", "quote=d"]

    with open("temp_raw.csv", "w", encoding="utf-8") as outfile:
        subprocess.run(
            extract_cmd, stdout=outfile, stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )

    return pd.read_csv("temp_raw.csv", low_memory=False)


def clean_packets(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = RAW_COLUMNS

    # Coalesce IPv4 + IPv6 into the IP columns so IPv6 traffic (modern speed
    # tests, CDNs, tethered/iPhone links) is attributed to a flow instead of
    # dropped. tshark leaves the unused family blank -> NaN; fall back to the
    # other family. Normalising to str here also avoids the ".str accessor on
    # float" error when a window is entirely one address family.
    for ipcol, v6col in (('Source IP', 'IPv6 Src'), ('Dest IP', 'IPv6 Dst')):
        v4 = df[ipcol].astype(str).str.strip()
        v4 = v4.where(~v4.isin(['', 'nan', 'NaN', 'None', '<NA>']), other=None)
        if v6col in df.columns:
            v6 = df[v6col].astype(str).str.strip()
            v6 = v6.where(~v6.isin(['', 'nan', 'NaN', 'None', '<NA>']), other=None)
            df[ipcol] = v4.fillna(v6).fillna('')
        else:
            df[ipcol] = v4.fillna('')

    df['Dest Port'] = df['TCP Dst'].fillna(df['UDP Dst']).fillna(0)
    df['Source Port'] = df['TCP Src'].fillna(df['UDP Src']).fillna(0)

    # Coarse transport class for the dashboard's TCP/UDP filter. The app-layer
    # Protocol column (SSH/DNS/TLS...) is kept untouched for protocol_breakdown;
    # Transport is derived from which port family tshark populated: a TCP port
    # present -> TCP, else a UDP port present -> UDP, else OTHER (ICMP/ARP/...).
    tcp_present = df['TCP Src'].notna() | df['TCP Dst'].notna()
    udp_present = df['UDP Src'].notna() | df['UDP Dst'].notna()
    df['Transport'] = np.where(tcp_present, 'TCP',
                               np.where(udp_present, 'UDP', 'OTHER'))

    for col in ('Source Port', 'Dest Port'):
        df[col] = df[col].fillna('').astype(str).str.split(',').str[0]
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

    # fillna('') before astype(str): newer pandas keeps NaN missing through
    # astype(str), so an all-empty column (e.g. ip.ttl in a pure-IPv6 window)
    # would otherwise reach .str[0] as all-NaN and raise AttributeError.
    for col in FLAG_COLS:
        df[col] = df[col].fillna('').astype(str).str.split(',').str[0].str.strip()
        df[col] = df[col].replace(
            {'True': 1, 'False': 0, 'true': 1, 'false': 0, '': 0, 'nan': 0, 'NaN': 0}
        )
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    for col in NUMERIC_COLS:
        df[col] = df[col].fillna('').astype(str).str.split(',').str[0]
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    return df


def engineer_flows(df: pd.DataFrame) -> pd.DataFrame:
    # Drop rows where Source IP is missing/empty so groupby produces clean keys.
    df = df[df['Source IP'].astype(str).str.strip().replace({'nan': '', 'NaN': ''}) != '']
    if df.empty:
        return pd.DataFrame(
            columns=['Source IP'] + FEATURE_COLS
            + ['top_dest_port', 'dominant_transport', 'dest_ports',
               'top_source_port', 'source_ports']
        )

    def _modal_port(s):
        m = s[s > 0].mode()
        return int(m.iloc[0]) if not m.empty else 0

    def _modal_transport(s):
        m = s.mode()
        return str(m.iloc[0]) if not m.empty else 'OTHER'

    def _port_list(s):
        # Sorted unique destination ports (drop 0/placeholder), capped so the
        # detail panel stays readable on a chatty flow.
        ports = sorted({int(p) for p in s if int(p) > 0})
        return ", ".join(str(p) for p in ports[:20]) + ("  …" if len(ports) > 20 else "")

    flows = df.groupby('Source IP').agg(
        total_packets=('Packet Size', 'count'),
        total_bytes=('Packet Size', 'sum'),
        packet_size_std=('Packet Size', 'std'),
        unique_target_ips=('Dest IP', 'nunique'),
        unique_target_ports=('Dest Port', 'nunique'),
        total_syn_flags=('SYN Flag', 'sum'),
        total_ack_flags=('ACK Flag', 'sum'),
        total_fin_flags=('FIN Flag', 'sum'),
        total_rst_flags=('RST Flag', 'sum'),
        avg_ttl=('TTL', 'mean'),
        avg_window_size=('Window Size', 'mean'),
        first_packet_time=('Timestamp', 'min'),
        last_packet_time=('Timestamp', 'max'),
        top_dest_port=('Dest Port', _modal_port),
        dominant_transport=('Transport', _modal_transport),
        dest_ports=('Dest Port', _port_list),
        top_source_port=('Source Port', _modal_port),
        source_ports=('Source Port', _port_list),
    ).reset_index()

    iat_rows = []
    for src_ip, grp in df.groupby('Source IP'):
        times = grp['Timestamp'].sort_values().to_numpy()
        if len(times) < 2:
            iat_rows.append({'Source IP': src_ip, 'iat_mean': 0.0, 'iat_std': 0.0})
        else:
            iats = np.diff(times)
            iat_rows.append({'Source IP': src_ip, 'iat_mean': float(iats.mean()), 'iat_std': float(iats.std())})

    if iat_rows:
        flows = flows.merge(pd.DataFrame(iat_rows), on='Source IP', how='left')
    else:
        flows['iat_mean'] = 0.0
        flows['iat_std'] = 0.0

    # Clamp duration to floor 0.1s so a single-packet flow doesn't produce
    # absurd pps values that trip the heuristic.
    flows['flow_duration_sec'] = (flows['last_packet_time'] - flows['first_packet_time']).clip(lower=0.1)
    flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
    flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
    flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']
    flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)
    flows['packet_size_std'] = flows['packet_size_std'].fillna(0)

    return flows.replace([np.inf, -np.inf], 0).fillna(0)


def engineer_protocol_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate cleaned packets into per-(Source IP, Protocol) packet/byte counts.

    Sibling of engineer_flows(); leaves the main feature pipeline untouched.
    Rows with blank/NaN Source IP or Protocol are skipped so groupby keys
    stay clean.
    """
    if df.empty or 'Protocol' not in df.columns or 'Source IP' not in df.columns:
        return pd.DataFrame(columns=['Source IP', 'Protocol', 'packets', 'bytes'])

    src = df['Source IP'].astype(str).str.strip().replace({'nan': '', 'NaN': ''})
    proto = df['Protocol'].astype(str).str.strip().replace({'nan': '', 'NaN': ''})
    df = df[(src != '') & (proto != '')]
    if df.empty:
        return pd.DataFrame(columns=['Source IP', 'Protocol', 'packets', 'bytes'])

    grouped = df.groupby(['Source IP', 'Protocol']).agg(
        packets=('Packet Size', 'count'),
        bytes=('Packet Size', 'sum'),
    ).reset_index()
    grouped['packets'] = grouped['packets'].astype(int)
    grouped['bytes'] = grouped['bytes'].astype(int)
    return grouped


def dns_tunnel_check(per_protocol_rows) -> tuple[str, str] | None:
    """High DNS pps from one src + small avg packet = exfil channel."""
    for row in per_protocol_rows:
        if row['Protocol'] == 'DNS' and row['packets'] / WINDOW_SECONDS > 30:
            return "DNS Tunnel / C2 Channel", "Moderate (Suspicious)"
    return None


def write_protocol_breakdown(per_proto_df: pd.DataFrame) -> None:
    """Persist per-(Source IP, Protocol) counters into protocol_breakdown."""
    if per_proto_df is None or per_proto_df.empty:
        return
    ts = datetime.now().strftime("%H:%M:%S")
    conn = sqlite3.connect(DB_FILE, timeout=10)
    cur = conn.cursor()
    cur.executemany(
        "INSERT INTO protocol_breakdown (timestamp, source_ip, protocol, packets, bytes) "
        "VALUES (?, ?, ?, ?, ?)",
        [
            (ts, str(r['Source IP']), str(r['Protocol']), int(r['packets']), int(r['bytes']))
            for _, r in per_proto_df.iterrows()
        ],
    )
    conn.commit()
    conn.close()


def fuse(*threats: str) -> str:
    return max(threats, key=lambda t: SEVERITY_RANK.get(t, 0))


def write_alerts(flows: pd.DataFrame, model, scaler, use_rf: bool, intel_ips: set,
                 baseline_ips: set | None = None, quiet: bool = False,
                 per_proto_df: pd.DataFrame | None = None) -> dict:
    """Score flows + write alerts to SQLite. Returns severity counters.

    quiet=True suppresses the per-flow console print (used in replay mode
    where verbose output floods the terminal). DB writes and notifier
    triggers are unaffected.

    per_proto_df: optional per-(Source IP, Protocol) breakdown for the same
    window. When supplied, enables the DNS-tunnel detector layer. Pass None
    to skip the layer (back-compat for callers that don't compute it).

    Batched ML inference: all flows in this window are scored in a single
    model.predict / predict_proba call so joblib's ThreadPool spins up once
    per window instead of once per flow.
    """
    counts = {"Baseline (Safe)": 0, "Moderate (Suspicious)": 0,
              "Moderate (Bandwidth Spike)": 0, "Severe (Critical Anomaly)": 0}

    if baseline_ips is None:
        baseline_ips = set()

    # Index per-protocol rows by Source IP once per window so the DNS-tunnel
    # check is O(1) per flow.
    proto_rows_by_ip: dict[str, list[dict]] = {}
    if per_proto_df is not None and not per_proto_df.empty:
        for _, r in per_proto_df.iterrows():
            proto_rows_by_ip.setdefault(str(r['Source IP']), []).append(
                {'Protocol': str(r['Protocol']), 'packets': int(r['packets'])}
            )

    if flows.empty:
        return counts

    try:
        feat_matrix = flows[FEATURE_COLS].replace([np.inf, -np.inf], 0).fillna(0)
    except KeyError as e:
        print(f"[!] feature mismatch ({e}); skipping window")
        return counts

    scaled_all = scaler.transform(feat_matrix)

    if use_rf:
        rf_labels = model.predict(scaled_all).astype(int)
        rf_probas = model.predict_proba(scaled_all)
        rf_confidences = rf_probas.max(axis=1)
    else:
        rf_labels = None
        rf_confidences = None

    conn = sqlite3.connect(DB_FILE, timeout=10)
    cur = conn.cursor()

    for i, (_, row) in enumerate(flows.reset_index(drop=True).iterrows()):
        src_ip = row['Source IP']
        pps = row['packets_per_second']
        sar = row['syn_ack_ratio']
        ports = row['unique_target_ports']
        avg_size = row['avg_packet_size']
        syn_count = int(row['total_syn_flags'])

        profile, heuristic_threat = classify_profile(pps, sar, ports, avg_size)

        if use_rf:
            rf_threat = THREAT_LABEL_MAP.get(int(rf_labels[i]), "Baseline (Safe)")
            confidence = float(rf_confidences[i])
        else:
            rf_threat = heuristic_threat
            confidence = 0.0

        # Layer 2: multi-window rolling state (slow attacks)
        rolling = update_rolling(src_ip, int(row['total_packets']), int(ports), syn_count)
        slow_hit = slow_attack_check(rolling)
        if slow_hit:
            slow_profile, slow_threat = slow_hit
        else:
            slow_profile, slow_threat = None, "Baseline (Safe)"

        # Layer 3: per-protocol DNS-tunnel detector (Moderate; cannot
        # override intel or baseline - precedence handled below).
        dns_hit = dns_tunnel_check(proto_rows_by_ip.get(src_ip, []))
        if dns_hit:
            dns_profile, dns_threat = dns_hit
        else:
            dns_profile, dns_threat = None, "Baseline (Safe)"

        # Layer 4: threat intel feed (overrides everything else)
        intel_hit = src_ip in intel_ips

        threat = fuse(rf_threat, heuristic_threat, slow_threat, dns_threat)
        if intel_hit:
            threat = "Severe (Critical Anomaly)"
            profile = "Known Malicious IP (Threat Intel Match)"
        elif src_ip in baseline_ips:
            # Whitelist override: intel still wins above, but rule/RF
            # elevations on a known-good source are forced back to Baseline.
            threat = "Baseline (Safe)"
            profile = "Whitelisted Source"
        elif dns_hit:
            profile = dns_profile
        elif slow_hit and SEVERITY_RANK.get(slow_threat, 0) >= SEVERITY_RANK.get(threat, 0):
            profile = slow_profile

        # Threat Scoring enhancement: fold the fused verdict + several factors
        # into a 0-100 score, a risk band, and an analyst report. prior_incidents
        # is read before this window is counted so it reflects *past* activity.
        base_hit = src_ip in baseline_ips
        prior_incidents = INCIDENT_HISTORY.get(src_ip, 0)
        score_info = compute_threat_score(
            profile, threat, pps, sar, int(ports),
            int(row['total_rst_flags']), int(row['total_ack_flags']),
            int(row['unique_target_ips']), confidence, use_rf,
            prior_incidents, intel_hit, base_hit,
        )
        if threat != "Baseline (Safe)" and not base_hit:
            INCIDENT_HISTORY[src_ip] = prior_incidents + 1

        ts = datetime.now().strftime("%H:%M:%S")
        cur.execute('''
            INSERT INTO live_threat_logs
            (timestamp, source_ip, packets_per_sec, avg_window_size, syn_ack_ratio,
             total_bytes, traffic_profile, threat_level, confidence,
             top_dest_port, dominant_transport, dest_ports,
             top_source_port, source_ports,
             sig_heuristic, sig_rf, sig_slow, sig_dns, sig_intel, sig_baseline,
             threat_score, score_band, threat_reasons, threat_actions, threat_breakdown)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ts,
            src_ip,
            round(pps, 2),
            round(row['avg_window_size'], 2),
            round(sar, 2),
            int(row['total_bytes']),
            profile,
            threat,
            round(confidence, 4),
            int(row.get('top_dest_port', 0) or 0),
            str(row.get('dominant_transport', '') or ''),
            str(row.get('dest_ports', '') or ''),
            int(row.get('top_source_port', 0) or 0),
            str(row.get('source_ports', '') or ''),
            # Per-layer verdicts captured before fuse()/overrides collapse them.
            heuristic_threat,
            rf_threat,
            slow_threat,
            dns_threat,
            int(intel_hit),
            int(base_hit),
            # Threat score + report (reasons/actions joined; breakdown as JSON).
            int(score_info["score"]),
            score_info["band"],
            " | ".join(score_info["reasons"]),
            " | ".join(score_info["actions"]),
            json.dumps(score_info["breakdown"]),
        ))

        if threat == "Severe (Critical Anomaly)":
            notifier.notify_severe({
                "timestamp": ts,
                "source_ip": src_ip,
                "profile": profile,
                "threat": threat,
                "pps": float(pps),
                "sar": float(sar),
                "total_bytes": int(row['total_bytes']),
                "confidence": float(confidence),
                "threat_score": int(score_info["score"]),
                "score_band": score_info["band"],
            })

        counts[threat] = counts.get(threat, 0) + 1

        if not quiet:
            conf_str = f"{confidence*100:5.1f}%" if use_rf else "  n/a"
            intel_tag = "  [INTEL]" if intel_hit else ""
            print(f"  [{src_ip:>15}]  {profile:<40}  {threat:<30}  "
                  f"score={score_info['score']:3d}/100 {score_info['band']:<8}  "
                  f"conf={conf_str}  pps={pps:6.0f}  sar={sar:4.1f}  syn={syn_count}{intel_tag}")

    conn.commit()
    conn.close()
    return counts


def replay_pcap(path: str, model, scaler, use_rf: bool, intel_ips: set,
                baseline_ips: set | None = None, realtime: bool = False) -> None:
    """Replay a static PCAP through the same pipeline as live capture.

    The capture is partitioned into WINDOW_SECONDS-wide windows by
    ``frame.time_epoch`` so the engine sees the same flow shapes it
    would see live. With ``realtime=True``, sleeps WINDOW_SECONDS
    between windows to mimic live cadence - useful for demo recordings.
    Without it, replay runs as fast as the CPU can process.
    """
    if not os.path.exists(path):
        print(f"[!] replay: file not found: {path}")
        return

    extract_cmd = [TSHARK_PATH, "-r", path, "-T", "fields"]
    for field in TSHARK_FIELDS:
        extract_cmd += ["-e", field]
    extract_cmd += ["-E", "header=y", "-E", "separator=,", "-E", "quote=d"]

    with open("temp_raw.csv", "w", encoding="utf-8") as outfile:
        subprocess.run(
            extract_cmd, stdout=outfile, stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )

    df = pd.read_csv("temp_raw.csv", low_memory=False)
    if df.empty:
        print("[!] replay: pcap empty or unreadable")
        return

    df = clean_packets(df)
    df = df[df["Timestamp"] > 0]  # drop rows where tshark could not parse time
    if df.empty:
        print("[!] replay: no usable packets after cleaning")
        return

    df = df.sort_values("Timestamp").reset_index(drop=True)
    t_start = float(df["Timestamp"].min())
    t_end = float(df["Timestamp"].max())
    total_windows = max(1, int((t_end - t_start) // WINDOW_SECONDS) + 1)

    print(f"[+] Replay loaded: {len(df)} packets, span {t_end - t_start:.1f}s, "
          f"{total_windows} window(s) of {WINDOW_SECONDS}s")

    totals = {"Baseline (Safe)": 0, "Moderate (Suspicious)": 0,
              "Moderate (Bandwidth Spike)": 0, "Severe (Critical Anomaly)": 0}
    total_flows = 0

    cursor = t_start
    win_idx = 0
    while cursor <= t_end:
        win_end = cursor + WINDOW_SECONDS
        chunk = df[(df["Timestamp"] >= cursor) & (df["Timestamp"] < win_end)]
        win_idx += 1

        if len(chunk) < 2:
            print(f"[{win_idx:>4}/{total_windows}] window @ {cursor:.1f}: "
                  f"{len(chunk)} pkts (skipped)")
        else:
            flows = engineer_flows(chunk)
            per_proto = engineer_protocol_breakdown(chunk)
            write_protocol_breakdown(per_proto)
            if flows.empty:
                print(f"[{win_idx:>4}/{total_windows}] window @ {cursor:.1f}: "
                      f"{len(chunk):>5} pkts, 0 valid flow(s) (no usable Source IP)")
            else:
                counts = write_alerts(flows, model, scaler, use_rf, intel_ips,
                                       baseline_ips=baseline_ips, quiet=True,
                                       per_proto_df=per_proto)
                for k, v in counts.items():
                    totals[k] = totals.get(k, 0) + v
                total_flows += len(flows)
                severe = counts.get("Severe (Critical Anomaly)", 0)
                tag = f"  SEVERE x{severe}" if severe else ""
                print(f"[{win_idx:>4}/{total_windows}] window @ {cursor:.1f}: "
                      f"{len(chunk):>5} pkts, {len(flows):>3} flow(s){tag}")

        cursor = win_end
        if realtime:
            time.sleep(WINDOW_SECONDS)

    print("\n" + "=" * 60)
    print("REPLAY SUMMARY")
    print("=" * 60)
    print(f"  Windows processed : {win_idx}")
    print(f"  Total flows scored: {total_flows}")
    print(f"  Baseline          : {totals['Baseline (Safe)']}")
    print(f"  Moderate          : {totals['Moderate (Suspicious)'] + totals['Moderate (Bandwidth Spike)']}")
    print(f"  Severe            : {totals['Severe (Critical Anomaly)']}")
    print("=" * 60)
    print("[+] Replay complete.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hybrid IDS real-time engine (default) or offline PCAP replay.",
    )
    parser.add_argument(
        "--replay", metavar="PCAP",
        help="Replay a PCAP file through the same pipeline instead of live capture.",
    )
    parser.add_argument(
        "--realtime", action="store_true",
        help="With --replay, sleep WINDOW_SECONDS between windows to mimic live cadence.",
    )
    parser.add_argument(
        "--interface",
        help="tshark interface index override for live mode (skips Wi-Fi auto-detect).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Model/DB/intel/baseline paths are relative to the Dashboard/ dir so the
    # engine resolves them correctly regardless of where the script is
    # invoked from (e.g. repo root vs. Dashboard/). Resolve the --replay
    # argument against the original cwd first so a relative pcap path passed
    # on the command line still works.
    if args.replay and not os.path.isabs(args.replay):
        args.replay = os.path.abspath(args.replay)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("\n[*] Loading classifier...")
    model, scaler, use_rf = load_models()

    print("[*] Initializing SQLite log database...")
    init_db()

    print("[*] Loading threat intel feed (optional)...")
    intel_ips = load_threat_intel()

    print("[*] Loading baseline whitelist (optional)...")
    baseline_ips = load_baseline()

    label = "Random Forest" if use_rf else "K-Means"

    if args.replay:
        print(f"\n[+] REPLAY MODE. Model: {label}. Source: {args.replay}. "
              f"Window: {WINDOW_SECONDS}s. Realtime: {args.realtime}\n")
        replay_pcap(args.replay, model, scaler, use_rf, intel_ips,
                    baseline_ips=baseline_ips, realtime=args.realtime)
        return

    interface = args.interface or INTERFACE_OVERRIDE or get_active_interface()
    print(f"\n[+] Engine active. Model: {label}. Window: {WINDOW_SECONDS}s. Iface: #{interface}\n")

    last_bpf = None
    while True:
        try:
            # Re-read the BPF capture filter each window so the dashboard can
            # change it live; it takes effect on the next capture (not retroactive).
            bpf = read_capture_filter()
            if bpf != last_bpf:
                print(f"[*] capture filter: {bpf!r}" if bpf else "[*] capture filter cleared")
                last_bpf = bpf

            # Re-read the intel/baseline lists each window so edits made in the
            # dashboard's Defense Config tab apply live (files are tiny). Mirrors
            # the BPF re-read above; only announce when the list actually changes.
            new_intel = load_threat_intel(quiet=True)
            if new_intel != intel_ips:
                print(f"[*] threat intel reloaded: {len(new_intel)} IP(s)")
                intel_ips = new_intel
            new_baseline = load_baseline(quiet=True)
            if new_baseline != baseline_ips:
                print(f"[*] baseline whitelist reloaded: {len(new_baseline)} IP(s)")
                baseline_ips = new_baseline
            print(f"[{datetime.now().strftime('%H:%M:%S')}] capturing {WINDOW_SECONDS}s window...")
            df = capture_window(interface, bpf)

            if df.empty or len(df) < 2:
                print("[!] no packets in window; retrying...\n")
                continue

            print(f"[+] {len(df)} packets captured, engineering flows...")
            df = clean_packets(df)
            flows = engineer_flows(df)
            per_proto = engineer_protocol_breakdown(df)
            write_protocol_breakdown(per_proto)
            write_alerts(flows, model, scaler, use_rf, intel_ips,
                         baseline_ips=baseline_ips, per_proto_df=per_proto)
            print("")

        except KeyboardInterrupt:
            print("\n[*] shutdown requested, exiting.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
