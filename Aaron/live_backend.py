"""Live IDS backend.

Every WINDOW_SECONDS: tshark capture -> flow aggregation -> RF model +
heuristic rules -> fusion (max severity) -> SQLite alert log for app.py.
"""

import argparse
import os
import shutil
import subprocess
import sqlite3
import sys
import time
import warnings
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

# ── Cross-folder integration ────────────────────────────────────────────────
# This engine lives in Aaron/ but the Dashboard is the backbone runtime: the
# trained models, the shared SQLite alert DB (ids_logs.db), the notifier module,
# and the intel/baseline feeds all live in a sibling Dashboard folder at the repo
# root. Discover that Dashboard (preferring a submission copy) instead of
# hardcoding a sibling name, so this folder is self-contained. Put it on sys.path
# so `import notifier` resolves, and chdir into it at startup (see main) so every
# relative data path points at the shared files instead of this folder.
# mitre_mapping stays importable from this folder (the script dir is on sys.path).
import glob as _glob


def _discover_dashboard() -> str:
    """Find the sibling Dashboard runtime at the repo root.

    Order: (1) honor the current working directory if a launcher already put us
    inside a Dashboard (e.g. START.bat's /D), (2) otherwise scan repo-root
    siblings — keying off feature_engineer.py — preferring a 'submission' copy,
    (3) fall back to ../Aalok/Dashboard for the main repo.
    """
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "feature_engineer.py")):
        return cwd
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cands = sorted(_glob.glob(os.path.join(repo_root, "*", "Dashboard", "feature_engineer.py")))
    for c in cands:
        if "submission" in c.lower():
            return os.path.dirname(c)
    if cands:
        return os.path.dirname(cands[0])
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Aalok", "Dashboard"))


SHARED_DIR = _discover_dashboard()
if SHARED_DIR not in sys.path:
    sys.path.insert(0, SHARED_DIR)

# Ensure this folder is importable for mitre_mapping regardless of how the script
# was launched (don't rely on the launcher putting the script dir on sys.path).
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
if _SELF_DIR not in sys.path:
    sys.path.insert(0, _SELF_DIR)

import notifier
from mitre_mapping import tag_mitre

warnings.filterwarnings("ignore")

# Suppress console windows when subprocesses launch under a windowed (no-console)
# frozen build. On non-Windows hosts this constant is 0 and a no-op.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _find_tshark() -> str:
    """Locate tshark portably so this runs on any machine, not just one layout.

    Order: TSHARK_PATH env override -> tshark on PATH -> the standard Windows
    install locations -> bare 'tshark' (resolved on PATH at call time).
    """
    import shutil
    env = os.environ.get("TSHARK_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("tshark")
    if found:
        return found
    for cand in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark",
    ):
        if os.path.exists(cand):
            return cand
    return "tshark"


TSHARK_PATH = _find_tshark()
WINDOW_SECONDS = 2
DB_FILE = "ids_logs.db"
INTERFACE_OVERRIDE = None  # set to a tshark interface index (string) to skip auto-detect
THREAT_INTEL_FILE = "threat_intel.txt"  # optional newline-separated known-malicious IPs
BASELINE_FILE = "baseline.txt"  # optional newline-separated known-good IPs (gateway, DNS, etc.)
ROLLING_WINDOWS = 15  # number of past 2s windows kept per src IP (=> 30s history)

# Alert deduplication: suppress re-alerting the same (src_ip, severity) within
# this many seconds.  30 s keeps the DB/dashboard clean while still logging a
# fresh row whenever an attacker is *still* active after the window expires.
DEDUP_WINDOW_SECONDS = 30

# Auto-block defaults (overridden at runtime by values in autoblock_config table).
AUTOBLOCK_DEFAULT_THRESHOLD   = 3     # Severe alerts before auto-blocking an IP
AUTOBLOCK_DEFAULT_TTL_SECONDS = 3600  # Block duration (1 hour)

# Directory where Severe-incident PCAP evidence is saved.  Created at startup
# if it does not already exist.
EVIDENCE_DIR = "evidence"

# Runtime dedup state: last_alert_ts[src_ip][threat_level] = unix timestamp
# Uses defaultdict so missing keys are created on first access.
_last_alert_ts: dict[str, dict[str, float]] = defaultdict(dict)

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

# Per-source-IP rolling history across capture windows. Enables slow-rate /
# brute-force detection that a single 2s window can't see on its own.
ROLLING_STATE: dict[str, list[dict]] = {}

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
]

RAW_COLUMNS = [
    "Timestamp", "Source IP", "Dest IP", "TCP Src", "UDP Src",
    "TCP Dst", "UDP Dst", "Protocol", "Packet Size",
    "SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", "TTL", "Window Size",
]

FLAG_COLS = ['SYN Flag', 'ACK Flag', 'FIN Flag', 'RST Flag']
NUMERIC_COLS = ['Packet Size', 'TTL', 'Window Size', 'Timestamp']


def get_wifi_interface() -> str:
    print("[*] Auto-detecting Wi-Fi interface...")
    try:
        output = subprocess.check_output(
            [TSHARK_PATH, "-D"], text=True, stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )
        for line in output.split('\n'):
            if "wifi" in line.lower():
                idx = line.split('.')[0]
                print(f"[+] using interface #{idx}")
                return idx
    except Exception:
        pass
    print("[!] auto-detect failed, defaulting to interface #1")
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


def load_threat_intel() -> set[str]:
    """Load newline-separated known-malicious IPs from THREAT_INTEL_FILE.

    Lines starting with '#' are comments. File is optional; missing file
    returns an empty set so the runtime falls back to behavioral detection.
    """
    if not os.path.exists(THREAT_INTEL_FILE):
        return set()
    ips = set()
    with open(THREAT_INTEL_FILE, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    if ips:
        print(f"[+] Threat intel feed loaded: {len(ips)} known-malicious IP(s).")
    return ips


def load_baseline() -> set[str]:
    """Load newline-separated known-good IPs from BASELINE_FILE.

    Lines starting with '#' are comments. File is optional; missing file
    returns an empty set so behavior is unchanged. A matching source IP
    is forced to Baseline (Safe) regardless of rule trips, but threat
    intel matches still win - intel > baseline.
    """
    if not os.path.exists(BASELINE_FILE):
        return set()
    ips = set()
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    if ips:
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
            evidence_path TEXT DEFAULT NULL,
            mitre_technique_id TEXT DEFAULT NULL,
            mitre_sub_technique_id TEXT DEFAULT NULL,
            mitre_technique_name TEXT DEFAULT NULL,
            mitre_tactic TEXT DEFAULT NULL,
            mitre_tactic_id TEXT DEFAULT NULL
        )
    ''')
    # Migrate existing DBs: add columns introduced after initial release.
    for col, definition in [
        ("confidence",             "REAL DEFAULT 0.0"),
        ("evidence_path",          "TEXT DEFAULT NULL"),
        ("mitre_technique_id",     "TEXT DEFAULT NULL"),
        ("mitre_sub_technique_id", "TEXT DEFAULT NULL"),
        ("mitre_technique_name",   "TEXT DEFAULT NULL"),
        ("mitre_tactic",           "TEXT DEFAULT NULL"),
        ("mitre_tactic_id",        "TEXT DEFAULT NULL"),
    ]:
        try:
            cur.execute(f"ALTER TABLE live_threat_logs ADD COLUMN {col} {definition}")
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
    # ── blocked_ips: persists auto/manual blocks with expiry timestamp ───────
    cur.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            blocked_at  REAL    NOT NULL,
            ttl_seconds INTEGER NOT NULL DEFAULT 3600,
            reason      TEXT
        )
    ''')
    # ── autoblock_config: key-value store shared between backend + dashboard ─
    cur.execute('''
        CREATE TABLE IF NOT EXISTS autoblock_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    cur.executemany(
        "INSERT OR IGNORE INTO autoblock_config (key, value) VALUES (?, ?)",
        [
            ("enabled",     "0"),
            ("threshold",   str(AUTOBLOCK_DEFAULT_THRESHOLD)),
            ("ttl_seconds", str(AUTOBLOCK_DEFAULT_TTL_SECONDS)),
        ],
    )
    conn.commit()
    conn.close()
    # Ensure the evidence directory exists on disk.
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def capture_window(interface: str) -> pd.DataFrame:
    """Run a single tshark capture + extraction cycle."""
    subprocess.run(
        [TSHARK_PATH, "-i", interface, "-a", f"duration:{WINDOW_SECONDS}", "-w", "temp_live.pcap"],
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
    df['Dest Port'] = df['TCP Dst'].fillna(df['UDP Dst']).fillna(0)

    for col in FLAG_COLS:
        df[col] = df[col].astype(str).str.split(',').str[0].str.strip()
        df[col] = df[col].replace(
            {'True': 1, 'False': 0, 'true': 1, 'false': 0, '': 0, 'nan': 0, 'NaN': 0}
        )
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    for col in NUMERIC_COLS:
        df[col] = df[col].astype(str).str.split(',').str[0]
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    return df


def engineer_flows(df: pd.DataFrame) -> pd.DataFrame:
    # Drop rows where Source IP is missing/empty so groupby produces clean keys.
    df = df[df['Source IP'].astype(str).str.strip().replace({'nan': '', 'NaN': ''}) != '']
    if df.empty:
        return pd.DataFrame(columns=['Source IP'] + FEATURE_COLS)

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


# ── Auto-block helpers ────────────────────────────────────────────────────────

def _read_autoblock_config(conn: sqlite3.Connection) -> dict:
    """Read auto-block settings from the DB config table.

    Returns a dict with keys: enabled (bool), threshold (int), ttl_seconds (int).
    Falls back to module-level defaults if rows are missing.
    """
    rows = conn.execute("SELECT key, value FROM autoblock_config").fetchall()
    raw = dict(rows)
    return {
        "enabled":     bool(int(raw.get("enabled", "0"))),
        "threshold":   int(raw.get("threshold",   str(AUTOBLOCK_DEFAULT_THRESHOLD))),
        "ttl_seconds": int(raw.get("ttl_seconds", str(AUTOBLOCK_DEFAULT_TTL_SECONDS))),
    }


def _maybe_auto_block(conn: sqlite3.Connection, cur, src_ip: str,
                      threat: str, cfg: dict) -> None:
    """Insert a blocked_ips row and push a firewall rule when the Severe-hit
    threshold is reached.

    Called inside write_alerts() after each non-suppressed Severe alert is
    written to live_threat_logs. Skips quietly when auto-block is disabled,
    when the IP is already blocked, or when the hit count is below threshold.
    """
    if not cfg["enabled"]:
        return
    if threat != "Severe (Critical Anomaly)":
        return

    # Already blocked?
    already = conn.execute(
        "SELECT 1 FROM blocked_ips WHERE ip = ?", (src_ip,)
    ).fetchone()
    if already:
        return

    # Count lifetime Severe alerts for this IP.
    count = conn.execute(
        "SELECT COUNT(*) FROM live_threat_logs "
        "WHERE source_ip = ? AND threat_level = 'Severe (Critical Anomaly)'",
        (src_ip,),
    ).fetchone()[0]

    if count < cfg["threshold"]:
        return

    reason = f"Auto-blocked: {count} Severe alert(s) >= threshold {cfg['threshold']}"
    cur.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, ttl_seconds, reason) "
        "VALUES (?, ?, ?, ?)",
        (src_ip, time.time(), cfg["ttl_seconds"], reason),
    )
    print(f"  [AUTO-BLOCK] {src_ip} — {reason}")
    _apply_firewall_block(src_ip)


def _expire_blocks(conn: sqlite3.Connection, cur) -> None:
    """Delete rows from blocked_ips whose TTL has elapsed and remove the
    corresponding firewall rules.

    Called once per capture-window loop iteration so expiry is effectively
    cron-style without requiring a separate scheduler thread.
    """
    now = time.time()
    expired = conn.execute(
        "SELECT ip FROM blocked_ips WHERE (? - blocked_at) >= ttl_seconds",
        (now,),
    ).fetchall()
    for (ip,) in expired:
        cur.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        print(f"  [AUTO-BLOCK] block expired, removing rule for {ip}")
        _remove_firewall_block(ip)


def _apply_firewall_block(ip: str) -> None:
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
        capture_output=True, text=True, creationflags=NO_WINDOW,
    )
    if result.returncode != 0:
        print(f"  [AUTO-BLOCK] netsh block failed for {ip}: {result.stderr.strip()}")


def _remove_firewall_block(ip: str) -> None:
    rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        capture_output=True, text=True, creationflags=NO_WINDOW,
    )


def _is_suppressed(src_ip: str, threat_level: str) -> bool:
    """Return True if an identical (src_ip, threat_level) alert was written
    within DEDUP_WINDOW_SECONDS.  Side-effect: updates the timestamp when the
    alert is *not* suppressed so the next call starts the window fresh.
    """
    now = time.time()
    last = _last_alert_ts[src_ip].get(threat_level, 0.0)
    if now - last < DEDUP_WINDOW_SECONDS:
        return True          # suppress — too soon since last identical alert
    _last_alert_ts[src_ip][threat_level] = now
    return False


def _capture_evidence(src_ip: str) -> str | None:
    """Copy temp_live.pcap into the evidence directory before the next capture
    overwrites it.  Returns the destination path on success, or None if the
    source file is missing (e.g. first-window race or replay mode).

    Filename format: evidence/YYYYMMDD_HHMMSS_<ip>.pcap
    IP dots are replaced with underscores so the filename is always valid on
    Windows and Linux.
    """
    src = "temp_live.pcap"
    if not os.path.exists(src):
        return None
    safe_ip = src_ip.replace(".", "_")
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(EVIDENCE_DIR, f"{ts_str}_{safe_ip}.pcap")
    try:
        shutil.copy2(src, dest)
        return dest
    except OSError as exc:
        print(f"[!] evidence capture failed for {src_ip}: {exc}")
        return None


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

    # ── Auto-block: expire stale blocks first, then read current config ──────
    _expire_blocks(conn, cur)
    conn.commit()
    autoblock_cfg = _read_autoblock_config(conn)

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

        # ── Alert deduplication ──────────────────────────────────────────────
        # Skip writing identical (src_ip, threat_level) rows that arrived
        # within DEDUP_WINDOW_SECONDS.  The counter is still incremented so
        # callers see correct window totals, but the DB (and Streamlit table)
        # stay clean.
        counts[threat] = counts.get(threat, 0) + 1
        if _is_suppressed(src_ip, threat):
            if not quiet:
                conf_str = f"{confidence*100:5.1f}%" if use_rf else "  n/a"
                intel_tag = "  [INTEL]" if intel_hit else ""
                print(f"  [{src_ip:>15}]  {profile:<40}  {threat:<30}  "
                      f"conf={conf_str}  pps={pps:6.0f}  sar={sar:4.1f}  syn={syn_count}"
                      f"  [SUPPRESSED]{intel_tag}")
            continue  # skip DB insert and notifier for this flow

        # ── PCAP evidence capture (Severe only) ─────────────────────────────
        # Copy the current temp_live.pcap before the next window overwrites it.
        evidence_path: str | None = None
        if threat == "Severe (Critical Anomaly)":
            evidence_path = _capture_evidence(src_ip)
            if evidence_path and not quiet:
                print(f"  [EVIDENCE] saved → {evidence_path}")

        ts = datetime.now().strftime("%H:%M:%S")

        # ── MITRE ATT&CK tagging ─────────────────────────────────────────────
        m_tid, m_sub, m_name, m_tactic, m_tactic_id = tag_mitre(profile)

        cur.execute('''
            INSERT INTO live_threat_logs
            (timestamp, source_ip, packets_per_sec, avg_window_size, syn_ack_ratio,
             total_bytes, traffic_profile, threat_level, confidence, evidence_path,
             mitre_technique_id, mitre_sub_technique_id, mitre_technique_name,
             mitre_tactic, mitre_tactic_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            evidence_path,
            m_tid,
            m_sub,
            m_name,
            m_tactic,
            m_tactic_id,
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
            })
            # ── Auto-block check (runs after the alert row is committed) ────
            _maybe_auto_block(conn, cur, src_ip, threat, autoblock_cfg)

        if not quiet:
            conf_str = f"{confidence*100:5.1f}%" if use_rf else "  n/a"
            intel_tag = "  [INTEL]" if intel_hit else ""
            print(f"  [{src_ip:>15}]  {profile:<40}  {threat:<30}  "
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
    # chdir into Aalok's shared Dashboard (the backbone runtime) so the alert DB,
    # models, intel/baseline feeds, and evidence/ all resolve there — NOT this
    # folder. Falls back to this script's dir if the shared folder is missing.
    os.chdir(SHARED_DIR if os.path.isdir(SHARED_DIR) else os.path.dirname(os.path.abspath(__file__)))

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

    interface = args.interface or INTERFACE_OVERRIDE or get_wifi_interface()
    print(f"\n[+] Engine active. Model: {label}. Window: {WINDOW_SECONDS}s. Iface: #{interface}\n")

    while True:
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] capturing {WINDOW_SECONDS}s window...")
            df = capture_window(interface)

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
