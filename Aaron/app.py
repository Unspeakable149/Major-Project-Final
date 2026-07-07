import os
import sqlite3
import subprocess
import time

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from mitre_mapping import tag_mitre, tactic_color, mitre_url, TACTIC_COLORS

st.set_page_config(
    page_title="Hybrid IDS — SOC Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    [data-testid="stMetric"] {
        background-color: #1E1E2E;
        border: 1px solid #2E2E3E;
        border-radius: 8px;
        padding: 16px 20px;
    }
    [data-testid="stMetricLabel"] { font-size: 13px; color: #888; }
    [data-testid="stMetricValue"] { font-size: 28px; font-weight: 700; }
    .section-divider { border-top: 1px solid #2E2E3E; margin: 20px 0; }
    .threat-header {
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #888;
        margin-bottom: 8px;
    }
    .block-panel {
        background-color: #1E1E2E;
        border: 1px solid #3A1A1A;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .ip-label { font-family: monospace; font-size: 15px; color: #FF6B6B; font-weight: 600; }
    .blocked-label { font-family: monospace; font-size: 14px; color: #888; }
    .reasoning-card {
        background-color: #15151F;
        border-left: 3px solid #4A6FA5;
        border-radius: 4px;
        padding: 12px 16px;
        margin: 8px 0;
        font-size: 13px;
        color: #DDD;
    }
    .reasoning-card code { color: #FFB347; background: #0E0E18; padding: 1px 5px; border-radius: 3px; }
    .status-pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 10px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.05em;
    }
    .status-online { background: #003A1F; color: #00E68A; }
    .status-paused { background: #3A2000; color: #FFB347; }
</style>
""", unsafe_allow_html=True)


# blocked_ips state is now persisted in SQLite (blocked_ips table) so it
# survives Streamlit reruns and full page reloads. session_state is not used
# for block tracking anymore.


def apply_firewall_block(ip_address):
    """Add a Windows Defender Firewall inbound block rule for the given IP.

    Uses ``netsh advfirewall`` to install a rule named ``IDS_BLOCK_<ip>``.
    Returns True on success, False if netsh exits non-zero (e.g. rule already
    exists or insufficient privileges).
    """
    rule_name = f"IDS_BLOCK_{ip_address.replace('.', '_')}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def remove_firewall_block(ip_address):
    rule_name = f"IDS_BLOCK_{ip_address.replace('.', '_')}"
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        capture_output=True, text=True
    )
    return result.returncode == 0


# ── Auto-block DB helpers ─────────────────────────────────────────────────────

def _ensure_autoblock_tables(conn: sqlite3.Connection) -> None:
    """Idempotently create blocked_ips and autoblock_config tables.

    Called once per session via st.cache_resource so it only runs on cold start.
    live_backend.py creates these tables at startup too; this guards against the
    dashboard opening before the backend has run at all.
    """
    conn.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            blocked_at  REAL    NOT NULL,
            ttl_seconds INTEGER NOT NULL DEFAULT 3600,
            reason      TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS autoblock_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    conn.executemany(
        "INSERT OR IGNORE INTO autoblock_config (key, value) VALUES (?, ?)",
        [("enabled", "0"), ("threshold", "3"), ("ttl_seconds", "3600")],
    )
    conn.commit()


@st.cache_resource
def _get_db_conn() -> sqlite3.Connection:
    """Return a single long-lived SQLite connection shared across Streamlit reruns.

    check_same_thread=False is safe here because Streamlit's server is
    single-threaded per session. Using a cached connection avoids the
    overhead of re-opening ids_logs.db on every rerun.
    """
    conn = sqlite3.connect("ids_logs.db", check_same_thread=False, timeout=15)
    _ensure_autoblock_tables(conn)
    return conn


def _read_autoblock_config() -> dict:
    conn = _get_db_conn()
    rows = conn.execute("SELECT key, value FROM autoblock_config").fetchall()
    raw = dict(rows)
    return {
        "enabled":     bool(int(raw.get("enabled", "0"))),
        "threshold":   int(raw.get("threshold",   "3")),
        "ttl_seconds": int(raw.get("ttl_seconds", "3600")),
    }


def _write_autoblock_config(enabled: bool, threshold: int, ttl_seconds: int) -> None:
    conn = _get_db_conn()
    conn.executemany(
        "INSERT OR REPLACE INTO autoblock_config (key, value) VALUES (?, ?)",
        [
            ("enabled",     str(int(enabled))),
            ("threshold",   str(threshold)),
            ("ttl_seconds", str(ttl_seconds)),
        ],
    )
    conn.commit()


def _load_blocked_ips() -> pd.DataFrame:
    """Return the current blocked_ips table with human-readable expiry columns."""
    conn = _get_db_conn()
    df = pd.read_sql(
        "SELECT ip, blocked_at, ttl_seconds, reason FROM blocked_ips ORDER BY blocked_at DESC",
        conn,
    )
    if df.empty:
        return df
    now = time.time()
    df["Expires At"] = pd.to_datetime(df["blocked_at"] + df["ttl_seconds"], unit="s")
    df["Remaining"]  = df.apply(
        lambda r: f"{max(0, int(r.ttl_seconds - (now - r.blocked_at))) // 60} min", axis=1
    )
    return df.rename(columns={"ip": "Source IP", "reason": "Reason"})[
        ["Source IP", "Expires At", "Remaining", "Reason"]
    ]


def _block_ip_to_db(ip: str, ttl_seconds: int, reason: str) -> bool:
    """Insert a manual block row into blocked_ips and push the firewall rule."""
    success = apply_firewall_block(ip)
    if success:
        conn = _get_db_conn()
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, ttl_seconds, reason) "
            "VALUES (?, ?, ?, ?)",
            (ip, time.time(), ttl_seconds, reason),
        )
        conn.commit()
    return success


def _unblock_ip_from_db(ip: str) -> bool:
    """Remove a block from blocked_ips and delete the firewall rule."""
    success = remove_firewall_block(ip)
    if success:
        conn = _get_db_conn()
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()
    return success


def _backfill_mitre(conn: sqlite3.Connection) -> None:
    """Back-fill MITRE columns on rows written before this upgrade."""
    cur = conn.cursor()
    cur.execute(
        "SELECT id, traffic_profile FROM live_threat_logs "
        "WHERE mitre_technique_id IS NULL LIMIT 500"
    )
    rows = cur.fetchall()
    if not rows:
        return
    updates = []
    for row_id, profile in rows:
        tid, sub, name, tactic, tac_id = tag_mitre(profile or "")
        updates.append((tid, sub, name, tactic, tac_id, row_id))
    cur.executemany(
        "UPDATE live_threat_logs SET mitre_technique_id=?, mitre_sub_technique_id=?, "
        "mitre_technique_name=?, mitre_tactic=?, mitre_tactic_id=? WHERE id=?",
        updates,
    )
    conn.commit()


def load_threat_logs():
    try:
        conn = sqlite3.connect('ids_logs.db', timeout=15)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(live_threat_logs)")
        existing_cols = [row[1] for row in cursor.fetchall()]

        has_confidence = 'confidence' in existing_cols
        has_evidence   = 'evidence_path' in existing_cols
        has_mitre      = 'mitre_technique_id' in existing_cols

        conf_col    = "ROUND(confidence * 100, 1) AS \"Confidence (%)\"," if has_confidence else ""
        evid_col    = "evidence_path AS \"Evidence Path\","               if has_evidence   else ""
        mitre_cols  = (
            "mitre_technique_id   AS \"ATT&CK ID\"    ,"
            "mitre_sub_technique_id AS \"Sub-Technique\"  ,"
            "mitre_technique_name AS \"ATT&CK Technique\"  ,"
            "mitre_tactic         AS \"ATT&CK Tactic\"  ,"
            "mitre_tactic_id      AS \"Tactic ID\"  ,"
        ) if has_mitre else ""

        # Back-fill older rows that pre-date MITRE tagging
        if has_mitre:
            _backfill_mitre(conn)

        query = f"""
            SELECT timestamp        AS "Time",
                   source_ip        AS "Source IP",
                   packets_per_sec  AS "Packets/Sec",
                   avg_window_size  AS "Avg Window",
                   syn_ack_ratio    AS "SYN/ACK Ratio",
                   total_bytes      AS "Total Bytes",
                   traffic_profile  AS "Traffic Profile",
                   threat_level     AS "Threat Level",
                   {conf_col}
                   {evid_col}
                   {mitre_cols}
                   id
            FROM live_threat_logs
            ORDER BY id DESC
            LIMIT 500
        """

        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def detection_engine_status():
    if os.path.exists("rf_model.pkl"):
        return "Hybrid (Behavioral ML + Signature Rules)"
    if os.path.exists("advanced_kmeans_model.pkl"):
        return "Hybrid (Anomaly Clustering + Signature Rules)"
    return "Signature Rules Only"


def highlight_threat_row(row):
    threat = str(row.get("Threat Level", ""))
    base = [""] * len(row)
    idx = row.index.tolist().index("Threat Level") if "Threat Level" in row.index else -1
    if idx == -1:
        return base
    if "Severe" in threat:
        base[idx] = "background-color: #4A0A0A; color: #FF6B6B; font-weight: bold"
    elif "Moderate" in threat:
        base[idx] = "background-color: #3A2000; color: #FFB347; font-weight: bold"
    elif "Baseline" in threat:
        base[idx] = "background-color: #003A1F; color: #00E68A"
    return base


st.title("Hybrid Intrusion Detection System")
st.caption("Real-time network behavioral analysis with hybrid signature + machine learning detection")

tab1, tab2 = st.tabs(["Live SOC Dashboard", "Educational Simulator"])

with tab1:
    st.sidebar.header("Monitoring Controls")
    enable_live = st.sidebar.checkbox("Enable Live Monitoring", value=False)
    refresh_rate = st.sidebar.selectbox("Refresh Interval (seconds)", [2, 5, 10, 30], index=1)
    severity_filter = st.sidebar.multiselect(
        "Show severity levels",
        options=["Severe", "Moderate", "Baseline"],
        default=["Severe", "Moderate", "Baseline"],
    )
    st.sidebar.markdown("---")
    status_class = "status-online" if enable_live else "status-paused"
    status_text = "MONITORING" if enable_live else "PAUSED"
    st.sidebar.markdown(
        f'<span class="status-pill {status_class}">{status_text}</span>',
        unsafe_allow_html=True,
    )
    st.sidebar.caption(f"Detection Engine: {detection_engine_status()}")

    # ── Auto-block sidebar panel ──────────────────────────────────────────────
    st.sidebar.markdown("---")
    st.sidebar.markdown("**⚡ Auto-Block Settings**")

    ab_cfg = _read_autoblock_config()

    auto_block_on = st.sidebar.toggle(
        "Auto-block Severe ≥ N hits",
        value=ab_cfg["enabled"],
        help=(
            "When enabled, any source IP that accumulates N or more Severe alerts "
            "is automatically blocked via a Windows Firewall inbound rule. "
            "The block is removed after the TTL expires — no manual action required."
        ),
    )
    hit_threshold = st.sidebar.number_input(
        "Severe-hit threshold (N)", min_value=1, max_value=50,
        value=ab_cfg["threshold"], step=1,
    )
    ttl_hours = st.sidebar.slider(
        "Block expiry (hours)", min_value=1, max_value=24,
        value=ab_cfg["ttl_seconds"] // 3600,
    )

    new_ttl_seconds = ttl_hours * 3600
    if (
        auto_block_on    != ab_cfg["enabled"]
        or hit_threshold != ab_cfg["threshold"]
        or new_ttl_seconds != ab_cfg["ttl_seconds"]
    ):
        _write_autoblock_config(auto_block_on, hit_threshold, new_ttl_seconds)
        st.sidebar.success("Auto-block settings saved.", icon="✅")

    # ── Active blocks panel (DB-backed, survives reruns) ─────────────────────
    st.sidebar.markdown("**Currently Blocked IPs**")
    blocked_df = _load_blocked_ips()
    if blocked_df.empty:
        st.sidebar.caption("No IPs are currently blocked.")
    else:
        st.sidebar.dataframe(blocked_df, hide_index=True, use_container_width=True)

    if enable_live:
        logs_df = load_threat_logs()

        if logs_df.empty:
            st.info("Connected to alert database. Waiting for network telemetry...")
        else:
            def severity_of(value: str) -> str:
                if "Severe" in str(value):
                    return "Severe"
                if "Moderate" in str(value):
                    return "Moderate"
                return "Baseline"

            logs_df["__sev__"] = logs_df["Threat Level"].map(severity_of)
            filtered_df = logs_df[logs_df["__sev__"].isin(severity_filter)].drop(columns="__sev__")
            logs_df = logs_df.drop(columns="__sev__")

            severe_mask = logs_df["Threat Level"] == "Severe (Critical Anomaly)"
            severe_df = logs_df[severe_mask]
            unique_sources = logs_df["Source IP"].nunique()
            # Read blocked count from DB so it reflects auto-blocks too.
            _db_blocked = _load_blocked_ips()
            blocked_count = len(_db_blocked)

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Flows Logged", len(logs_df))
            m2.metric("Critical Threats", len(severe_df))
            m3.metric("Unique Source IPs", unique_sources)
            m4.metric("Blocked IPs", blocked_count)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

            table_col, chart_col = st.columns([3, 1])

            with table_col:
                st.markdown('<p class="threat-header">Live Network Telemetry</p>', unsafe_allow_html=True)
                # Hide internal columns from the visible table.
                _hide_cols = [c for c in ("Evidence Path", "id") if c in filtered_df.columns]
                display_df = filtered_df.drop(columns=_hide_cols).head(100)
                try:
                    st.dataframe(
                        display_df.style.apply(highlight_threat_row, axis=1),
                        use_container_width=True,
                        height=420
                    )
                except Exception:
                    st.dataframe(display_df, use_container_width=True, height=420)

                csv_bytes = filtered_df.drop(
                    columns=[c for c in ("id",) if c in filtered_df.columns]
                ).to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="Export Filtered Logs (CSV)",
                    data=csv_bytes,
                    file_name=f"ids_threat_logs_{int(time.time())}.csv",
                    mime="text/csv",
                )

                # ── PCAP Evidence Downloads ───────────────────────────────────
                if "Evidence Path" in logs_df.columns:
                    evidence_rows = logs_df[
                        logs_df["Evidence Path"].notna() &
                        (logs_df["Threat Level"] == "Severe (Critical Anomaly)")
                    ][["Time", "Source IP", "Evidence Path"]].drop_duplicates(
                        subset=["Evidence Path"]
                    ).head(20)

                    if not evidence_rows.empty:
                        st.markdown(
                            '<p class="threat-header" style="margin-top:14px;">PCAP Evidence Files</p>',
                            unsafe_allow_html=True,
                        )
                        for _, ev_row in evidence_rows.iterrows():
                            ev_path = ev_row["Evidence Path"]
                            ev_ip   = ev_row["Source IP"]
                            ev_time = ev_row["Time"]
                            ev_col_info, ev_col_btn = st.columns([4, 1])
                            with ev_col_info:
                                st.markdown(
                                    f'<div class="reasoning-card">'
                                    f'🔴 <b>{ev_ip}</b> &nbsp;·&nbsp; {ev_time} &nbsp;·&nbsp; '
                                    f'<code>{os.path.basename(ev_path)}</code>'
                                    f'</div>',
                                    unsafe_allow_html=True,
                                )
                            with ev_col_btn:
                                if os.path.exists(ev_path):
                                    with open(ev_path, "rb") as fh:
                                        st.download_button(
                                            label="⬇ PCAP",
                                            data=fh.read(),
                                            file_name=os.path.basename(ev_path),
                                            mime="application/vnd.tcpdump.pcap",
                                            key=f"evdl_{ev_path}",
                                        )
                                else:
                                    st.caption("file missing")

            with chart_col:
                st.markdown('<p class="threat-header">Threat Distribution</p>', unsafe_allow_html=True)
                threat_counts = logs_df["Threat Level"].value_counts().reset_index()
                threat_counts.columns = ["Threat Level", "Count"]
                st.bar_chart(threat_counts.set_index("Threat Level"))

                st.markdown('<p class="threat-header">Top Talkers</p>', unsafe_allow_html=True)
                top_ips = logs_df["Source IP"].value_counts().head(5).reset_index()
                top_ips.columns = ["Source IP", "Flows"]
                st.dataframe(top_ips, use_container_width=True, hide_index=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown('<p class="threat-header">Per-Protocol Breakdown</p>', unsafe_allow_html=True)
            selected_ip = st.selectbox(
                "Inspect Source IP",
                logs_df["Source IP"].unique(),
                key="per_proto_ip",
            )
            try:
                proto_conn = sqlite3.connect('ids_logs.db', timeout=15)
                proto_df = pd.read_sql_query(
                    "SELECT protocol, SUM(packets) AS pkts FROM protocol_breakdown "
                    "WHERE source_ip = ? GROUP BY protocol",
                    proto_conn, params=[selected_ip],
                )
                proto_conn.close()
            except Exception:
                proto_df = pd.DataFrame()
            if not proto_df.empty:
                st.bar_chart(proto_df.set_index("protocol"))
            else:
                st.info("No per-protocol data yet for this IP.")

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown('<p class="threat-header">Threat Activity Timeline</p>', unsafe_allow_html=True)

            timeline_df = logs_df.copy()
            timeline_df["Severity"] = timeline_df["Threat Level"].map(
                lambda v: "Severe" if "Severe" in str(v) else ("Moderate" if "Moderate" in str(v) else "Baseline")
            )
            timeline_pivot = (
                timeline_df.groupby(["Time", "Severity"]).size().unstack(fill_value=0).sort_index()
            )
            for sev in ["Severe", "Moderate", "Baseline"]:
                if sev not in timeline_pivot.columns:
                    timeline_pivot[sev] = 0
            st.line_chart(timeline_pivot[["Severe", "Moderate", "Baseline"]])

            # ═══════════════════════════════════════════════════════════
            # MITRE ATT&CK INTELLIGENCE PANEL
            # ═══════════════════════════════════════════════════════════
            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown('<p class="threat-header">MITRE ATT&CK® Intelligence</p>', unsafe_allow_html=True)

            mitre_cols_present = "ATT&CK ID" in logs_df.columns

            if mitre_cols_present and logs_df["ATT&CK ID"].notna().any():
                mitre_df = logs_df[logs_df["ATT&CK ID"].notna() & (logs_df["ATT&CK ID"] != "N/A")].copy()

                if not mitre_df.empty:
                    # ── Summary metrics row ──────────────────────────────────
                    unique_techniques = mitre_df["ATT&CK ID"].nunique()
                    unique_tactics    = mitre_df["ATT&CK Tactic"].nunique()
                    top_technique     = mitre_df["ATT&CK ID"].value_counts().idxmax()
                    top_tactic        = mitre_df["ATT&CK Tactic"].value_counts().idxmax()

                    mm1, mm2, mm3, mm4 = st.columns(4)
                    mm1.metric("Unique Techniques", unique_techniques)
                    mm2.metric("Unique Tactics",    unique_tactics)
                    mm3.metric("Top Technique",     top_technique)
                    mm4.metric("Top Tactic",         top_tactic)

                    # ── Tactic filter ────────────────────────────────────────
                    all_tactics = sorted(mitre_df["ATT&CK Tactic"].dropna().unique().tolist())
                    selected_tactics = st.multiselect(
                        "Filter by Tactic", options=all_tactics, default=all_tactics,
                        key="mitre_tactic_filter",
                    )
                    filtered_mitre = mitre_df[mitre_df["ATT&CK Tactic"].isin(selected_tactics)]

                    # ── Badge grid ───────────────────────────────────────────
                    st.markdown("**Observed Techniques**")
                    technique_counts = (
                        filtered_mitre.groupby(["ATT&CK ID", "Sub-Technique", "ATT&CK Technique", "ATT&CK Tactic", "Tactic ID"])
                        .size().reset_index(name="hits")
                        .sort_values("hits", ascending=False)
                    )

                    badge_html = "<div style='display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;'>"
                    for _, trow in technique_counts.iterrows():
                        tid   = trow["ATT&CK ID"]
                        sub   = trow.get("Sub-Technique", "") or ""
                        name  = trow["ATT&CK Technique"]
                        tact  = trow["ATT&CK Tactic"]
                        hits  = trow["hits"]
                        color = tactic_color(tact)
                        display_id = sub if sub else tid
                        url   = mitre_url(tid, sub)
                        badge_html += (
                            f"<a href='{url}' target='_blank' style='text-decoration:none;'>"
                            f"<div style='background:{color}22;border:1px solid {color}88;"
                            f"border-radius:6px;padding:6px 12px;font-size:12px;color:#DDD;"
                            f"min-width:120px;'>"
                            f"<div style='font-family:monospace;font-weight:700;color:{color};'>{display_id}</div>"
                            f"<div style='font-size:11px;color:#AAA;margin-top:2px;'>{name[:32]}</div>"
                            f"<div style='font-size:10px;color:#666;margin-top:1px;'>{tact} · {hits} hit(s)</div>"
                            f"</div></a>"
                        )
                    badge_html += "</div>"
                    st.markdown(badge_html, unsafe_allow_html=True)

                    # ── Tactic distribution bar chart ────────────────────────
                    tact_chart_col, tech_table_col = st.columns([1, 2])

                    with tact_chart_col:
                        st.markdown("**Tactic Distribution**")
                        tactic_dist = filtered_mitre["ATT&CK Tactic"].value_counts().reset_index()
                        tactic_dist.columns = ["Tactic", "Count"]
                        st.bar_chart(tactic_dist.set_index("Tactic"))

                    with tech_table_col:
                        st.markdown("**Technique Drill-Down**")
                        drill = technique_counts.rename(columns={
                            "ATT&CK ID": "Technique ID",
                            "Sub-Technique": "Sub-Technique",
                            "ATT&CK Technique": "Name",
                            "ATT&CK Tactic": "Tactic",
                            "hits": "Hits",
                        })[["Technique ID", "Sub-Technique", "Name", "Tactic", "Hits"]]
                        st.dataframe(drill, use_container_width=True, hide_index=True)

                    # ── Per-IP ATT&CK fingerprint ────────────────────────────
                    st.markdown("**Source IP ATT&CK Fingerprint**")
                    selected_mitre_ip = st.selectbox(
                        "Select IP to fingerprint",
                        filtered_mitre["Source IP"].unique(),
                        key="mitre_ip_select",
                    )
                    ip_techniques = (
                        filtered_mitre[filtered_mitre["Source IP"] == selected_mitre_ip]
                        [["ATT&CK ID", "Sub-Technique", "ATT&CK Technique", "ATT&CK Tactic", "Traffic Profile"]]
                        .drop_duplicates()
                    )
                    st.dataframe(ip_techniques, use_container_width=True, hide_index=True)

                else:
                    st.info("No non-benign MITRE-tagged events in the current filtered view.")
            else:
                st.info(
                    "MITRE ATT&CK columns not yet in database. "
                    "Run live_backend.py once to auto-migrate, or run `python mitre_backfill.py`."
                )

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown('<p class="threat-header">One-Click Threat Mitigation</p>', unsafe_allow_html=True)

            # Fetch current DB block state (survives reruns — not session_state).
            _current_blocked_ips = set(_load_blocked_ips()["Source IP"].tolist()) if not _load_blocked_ips().empty else set()
            severe_ips = severe_df["Source IP"].unique().tolist()
            unmitigated = [ip for ip in severe_ips if ip not in _current_blocked_ips]

            if unmitigated:
                st.warning(f"{len(unmitigated)} critical threat source(s) detected and awaiting mitigation.")

                _ab_cfg_now = _read_autoblock_config()
                _block_ttl  = _ab_cfg_now["ttl_seconds"]

                for ip in unmitigated:
                    ip_flows = len(severe_df[severe_df["Source IP"] == ip])
                    col_info, col_btn = st.columns([5, 1])
                    with col_info:
                        st.markdown(
                            f'<div class="block-panel">'
                            f'<span class="ip-label">{ip}</span>'
                            f'&nbsp;&nbsp;&nbsp;Severe (Critical Anomaly)'
                            f'&nbsp;&nbsp;|&nbsp;&nbsp;{ip_flows} alert(s) logged'
                            f'</div>',
                            unsafe_allow_html=True
                        )
                    with col_btn:
                        if st.button("Block IP", key=f"block_{ip}", type="primary"):
                            reason = f"Manual block via SOC dashboard"
                            success = _block_ip_to_db(ip, _block_ttl, reason)
                            if success:
                                ttl_label = f"{_block_ttl // 3600}h" if _block_ttl >= 3600 else f"{_block_ttl // 60}m"
                                st.success(f"Firewall rule applied for {ip}. Expires in {ttl_label}.")
                            else:
                                st.error(
                                    f"Unable to apply firewall rule for {ip}. "
                                    f"Administrator privileges required."
                                )
            elif severe_ips:
                st.success("All detected critical threat sources have been mitigated.")
            else:
                st.info("No critical threats detected in the current dataset.")

            _blocked_now = _load_blocked_ips()
            if not _blocked_now.empty:
                st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
                st.markdown('<p class="threat-header">Blocked IP Registry</p>', unsafe_allow_html=True)

                registry_col, action_col = st.columns([3, 2])

                with registry_col:
                    st.dataframe(_blocked_now, use_container_width=True, hide_index=True)

                with action_col:
                    st.caption("Remove a firewall rule to restore access for a previously blocked IP.")
                    ip_to_unblock = st.selectbox(
                        "Select IP to unblock",
                        _blocked_now["Source IP"].tolist(),
                        label_visibility="collapsed"
                    )
                    if st.button("Remove Block", key="unblock_btn"):
                        success = _unblock_ip_from_db(ip_to_unblock)
                        if success:
                            st.success(f"Firewall rule removed. {ip_to_unblock} is now unblocked.")
                            st.rerun()
                        else:
                            st.error(
                                f"Could not remove the rule for {ip_to_unblock}. "
                                f"Administrator privileges required."
                            )

        time.sleep(refresh_rate)
        st.rerun()

    else:
        st.info("Live monitoring is paused. Enable it from the sidebar to begin real-time analysis.")
        st.markdown("---")
        st.markdown("**System Overview**")
        col_a, col_b, col_c = st.columns(3)
        col_a.markdown("**Capture Layer**\n\nLive packet capture across the active network interface in 2-second windows.")
        col_b.markdown("**Detection Layer**\n\n" + detection_engine_status() + " with multi-window correlation.")
        col_c.markdown("**Response Layer**\n\nOne-click firewall isolation and persistent alert logging.")


with tab2:
    st.subheader("Network Traffic and Attack Simulator")
    st.markdown("Visualize how different network behaviors trigger the detection engine.")

    scenario = st.radio(
        "Select Scenario:",
        ("Normal Web Browsing", "Reconnaissance (Port Scan)", "DDoS Flood",
         "Brute-Force Login", "C2 Beacon (Stealth)"),
        horizontal=True
    )

    if scenario == "Normal Web Browsing":
        sim_mode = "normal"
        st.success("Classification: BASELINE — Standard web traffic pattern. No anomaly detected.")
        reasoning = [
            ("packets/sec", "low", "well below the 300 pps moderate threshold"),
            ("syn_ack_ratio", "~1.0", "balanced — every SYN is acknowledged"),
            ("unique_dest_ports", "1–3", "far below the 20-port scan threshold"),
            ("traffic_profile", "Standard Web Traffic", "no rule matched"),
        ]
    elif scenario == "Reconnaissance (Port Scan)":
        sim_mode = "scan"
        st.warning("Classification: MODERATE — Sequential port probing across many destination ports.")
        reasoning = [
            ("unique_dest_ports", "> 20", "triggers `ports > 20` Port Scan rule"),
            ("packets/sec", "moderate", "sustained probing, not flood-level"),
            ("syn_ack_ratio", "elevated", "many SYNs sent, few ACKs returned (closed ports)"),
            ("traffic_profile", "Port Scan / Reconnaissance", "Moderate severity"),
        ]
    elif scenario == "DDoS Flood":
        sim_mode = "ddos"
        st.error("Classification: SEVERE — Extreme SYN packet rate with anomalous SYN/ACK ratio.")
        reasoning = [
            ("packets/sec", "> 500", "triggers high-volume flood rule"),
            ("syn_ack_ratio", "> 5", "overwhelming SYNs vs returning ACKs"),
            ("total_syn_flags", "very high", "SYN flood signature"),
            ("traffic_profile", "DDoS SYN Flood", "Severe — fusion engine picks max severity"),
        ]
    elif scenario == "Brute-Force Login":
        sim_mode = "brute"
        st.warning("Classification: MODERATE — Sustained authentication attempts across many windows.")
        reasoning = [
            ("rolling_syn (30s)", "> 150", "multi-window slow-attack detector trips"),
            ("packets/sec (single window)", "low", "below the 500 pps single-window flood threshold"),
            ("unique_dest_ports", "1", "all targeting one auth port (e.g. 22 / 3389)"),
            ("traffic_profile", "Sustained SYN / Brute-Force Probe", "caught by rolling-state layer"),
        ]
    else:
        sim_mode = "c2"
        st.warning("Classification: MODERATE — Low-and-slow periodic beacon, likely command-and-control.")
        reasoning = [
            ("packets/sec", "very low", "stealth — single-window heuristic alone misses this"),
            ("iat_std", "near 0", "highly regular beacon interval (telemetry-like rhythm)"),
            ("unique_dest_ips", "1", "single hard-coded callback host"),
            ("detection path", "ML + rolling state", "ML flags rhythmic IAT pattern as suspicious"),
        ]

    reasoning_html = "".join(
        f'<div class="reasoning-card"><b>{label}</b>: <code>{value}</code> — {note}</div>'
        for label, value, note in reasoning
    )
    st.markdown("**Detection Reasoning**", help="Which feature values trigger which rule path.")
    st.markdown(reasoning_html, unsafe_allow_html=True)

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                margin: 0; padding: 0;
                background-color: #0E1117;
                color: white;
                font-family: 'Segoe UI', sans-serif;
                overflow: hidden;
            }}
            canvas {{
                display: block;
                margin: 0 auto;
                background-color: #1A1A2E;
                border-radius: 8px;
                border: 1px solid #2E2E4E;
            }}
            #legend {{
                text-align: center;
                margin-top: 10px;
                font-size: 12px;
                color: #aaa;
            }}
            .dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 4px; }}
        </style>
    </head>
    <body>
        <canvas id="networkCanvas" width="820" height="280"></canvas>
        <div id="legend">
            <span><span class="dot" style="background:#00FFAA;"></span>Safe (Port 80/443)</span>
            &nbsp;&nbsp;
            <span><span class="dot" style="background:#FFCC00;"></span>Probe / Brute-Force</span>
            &nbsp;&nbsp;
            <span><span class="dot" style="background:#FF3333;"></span>SYN Flood</span>
            &nbsp;&nbsp;
            <span><span class="dot" style="background:#9B6BFF;"></span>C2 Beacon</span>
        </div>
        <script>
            const canvas = document.getElementById('networkCanvas');
            const ctx = canvas.getContext('2d');
            const mode = "{sim_mode}";

            const nodes = {{
                source: {{ x: 110, y: 140, label: "Source Host" }},
                firewall: {{ x: 410, y: 140, label: "Firewall / IDS" }},
                server: {{ x: 710, y: 140, label: "Target Server" }}
            }};

            let packets = [];
            let scanPort = 1;
            let frameCount = 0;

            class Packet {{
                constructor() {{
                    this.x = nodes.source.x;
                    this.y = nodes.source.y + (Math.random() - 0.5) * 20;
                    this.targetX = nodes.firewall.x;
                    this.targetY = nodes.firewall.y;
                    this.stage = 1;
                    this.speed = (mode === 'ddos') ? 9 : (mode === 'c2' ? 3 : 4);
                    this.alpha = 1.0;
                    if (mode === 'normal') {{
                        this.port = Math.random() > 0.5 ? 80 : 443;
                        this.color = "#00FFAA";
                        this.radius = 4;
                    }} else if (mode === 'scan') {{
                        this.port = scanPort++;
                        if (scanPort > 1024) scanPort = 1;
                        this.color = "#FFCC00";
                        this.radius = 3;
                    }} else if (mode === 'ddos') {{
                        this.port = 80;
                        this.color = "#FF3333";
                        this.radius = 5;
                    }} else if (mode === 'brute') {{
                        this.port = (Math.random() > 0.5) ? 22 : 3389;
                        this.color = "#FFCC00";
                        this.radius = 4;
                    }} else {{
                        this.port = 443;
                        this.color = "#9B6BFF";
                        this.radius = 4;
                    }}
                }}

                update() {{
                    const dx = this.targetX - this.x;
                    const dy = this.targetY - this.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist > this.speed) {{
                        this.x += (dx / dist) * this.speed;
                        this.y += (dy / dist) * this.speed;
                    }} else {{
                        if (this.stage === 1) {{
                            this.stage = 2;
                            this.targetX = nodes.server.x;
                            this.targetY = nodes.server.y;
                        }} else {{
                            this.stage = 3;
                        }}
                    }}
                }}

                draw() {{
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                    ctx.fillStyle = this.color;
                    ctx.globalAlpha = 0.9;
                    ctx.fill();
                    ctx.globalAlpha = 1.0;
                    ctx.fillStyle = "rgba(255,255,255,0.6)";
                    ctx.font = "9px monospace";
                    ctx.fillText(":" + this.port, this.x + 6, this.y - 4);
                }}
            }}

            function drawNode(node, fillColor, borderColor) {{
                ctx.shadowColor = borderColor;
                ctx.shadowBlur = 12;
                ctx.fillStyle = fillColor;
                ctx.beginPath();
                ctx.roundRect(node.x - 36, node.y - 28, 72, 56, 6);
                ctx.fill();
                ctx.shadowBlur = 0;
                ctx.strokeStyle = borderColor;
                ctx.lineWidth = 1.5;
                ctx.stroke();
                ctx.fillStyle = "rgba(255,255,255,0.85)";
                ctx.font = "11px 'Segoe UI'";
                ctx.textAlign = "center";
                ctx.fillText(node.label, node.x, node.y + 44);
            }}

            function drawConnections() {{
                ctx.beginPath();
                ctx.moveTo(nodes.source.x + 36, nodes.source.y);
                ctx.lineTo(nodes.firewall.x - 36, nodes.firewall.y);
                ctx.strokeStyle = "#2E3A4E";
                ctx.lineWidth = 2;
                ctx.stroke();

                ctx.beginPath();
                ctx.moveTo(nodes.firewall.x + 36, nodes.firewall.y);
                ctx.lineTo(nodes.server.x - 36, nodes.server.y);
                ctx.strokeStyle = "#2E3A4E";
                ctx.lineWidth = 2;
                ctx.stroke();
            }}

            function spawnRateFor(mode) {{
                if (mode === 'ddos') return 0.85;
                if (mode === 'scan') return 0.25;
                if (mode === 'brute') return 0.12;
                if (mode === 'c2') return 0.0;  // beacon uses fixed-interval spawning
                return 0.04;
            }}

            function animate() {{
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                frameCount++;

                drawConnections();
                drawNode(nodes.source,   "#1A2A3A", "#3A6A9A");
                drawNode(nodes.firewall, "#1A2A1A", "#3A7A3A");
                drawNode(nodes.server,   "#2A1A1A", "#7A2A2A");

                const burstCount = (mode === 'ddos') ? 4 : 1;

                // C2 beacon: fire a single packet every ~90 frames (regular cadence).
                if (mode === 'c2') {{
                    if (frameCount % 90 === 0) packets.push(new Packet());
                }} else if (Math.random() < spawnRateFor(mode)) {{
                    for (let i = 0; i < burstCount; i++) packets.push(new Packet());
                }}

                for (let i = packets.length - 1; i >= 0; i--) {{
                    packets[i].update();
                    packets[i].draw();
                    if (packets[i].stage === 3) packets.splice(i, 1);
                }}

                if (packets.length > 300) packets.splice(0, packets.length - 300);

                requestAnimationFrame(animate);
            }}

            animate();
        </script>
    </body>
    </html>
    """

    components.html(html_code, height=380)

    st.markdown("---")
    st.markdown("**Behavioral Signatures by Scenario**")
    sig_data = {
        "Scenario": [
            "Normal Web Browsing", "Reconnaissance (Port Scan)", "DDoS SYN Flood",
            "Brute-Force Login", "C2 Beacon (Stealth)"
        ],
        "Typical Packets/Sec": ["< 5", "10 — 50", "> 500", "low (sustained)", "very low (periodic)"],
        "Unique Dest Ports": ["1 — 3", "> 20", "1", "1 (22 / 3389)", "1 (443)"],
        "SYN/ACK Ratio": ["~1.0", "~1.2", "> 5.0", "elevated", "~1.0"],
        "Detection Path": [
            "Rules", "Rules", "Rules + ML",
            "Rolling multi-window state",
            "ML pattern + rolling state"
        ],
        "Threat Classification": [
            "Baseline (Safe)", "Moderate (Suspicious)", "Severe (Critical Anomaly)",
            "Moderate (Suspicious)", "Moderate (Suspicious)"
        ]
    }
    st.dataframe(pd.DataFrame(sig_data), use_container_width=True, hide_index=True)
