"""Threat Analysis Report — Enhancement Idea 1 (Rui Yang FYP).

Turns raw per-flow detections into an analyst-readable report:
  - what was detected (attack type counts)
  - an overall threat score + level (from scoring.py)
  - dynamic "Possible Reasons" derived from the actual feature values
  - dynamic "Suggested Actions" mapped to what was seen
  - GeoIP enrichment for the top attacking sources

Import-only (no page-level Streamlit calls).
"""
from collections import Counter


# ── Dynamic "Possible Reasons" ───────────────────────────────
def build_reasons(alerts_df):
    """Derive human-readable reasons from the actual flow evidence."""
    reasons = []
    reason_names = set(alerts_df['Reason'])

    if any('Port Scan' in r or 'NULL Scan' in r or 'Xmas Scan' in r for r in reason_names):
        reasons.append("Multiple reconnaissance / port-scanning attempts detected")

    if any('DDoS' in r or 'DoS' in r or 'Flood' in r for r in reason_names):
        reasons.append("High connection / packet rate consistent with flooding")

    if any('Brute Force' in r for r in reason_names):
        reasons.append("Repeated short connection attempts on login services (FTP/SSH)")

    if any('DNS Tunneling' in r for r in reason_names):
        reasons.append("Unusually large / encoded DNS queries — possible tunnelling")

    if any('Suspicious Port' in r or 'Bot' in r for r in reason_names):
        reasons.append("Traffic to known malware / C2 ports observed")

    if any('Telnet' in r for r in reason_names):
        reasons.append("Unencrypted Telnet usage — credentials exposed in clear text")

    if any('Bandwidth' in r or 'Oversized' in r for r in reason_names):
        reasons.append("Abnormal bandwidth / oversized packets outside baseline")

    if any('ML Anomaly' in r for r in reason_names):
        reasons.append("Machine-learning model flagged statistical anomalies in flow behaviour")

    # Evidence-backed quantitative line
    total_alerts = len(alerts_df)
    unique_srcs  = alerts_df['Src IP'].nunique()
    reasons.append(
        f"{total_alerts} suspicious flow(s) across {unique_srcs} distinct source IP(s)"
    )
    return reasons


# ── Dynamic "Suggested Actions" ──────────────────────────────
def build_actions(alerts_df):
    """Map detected behaviour to concrete recommended actions."""
    actions = []
    reason_names = set(alerts_df['Reason'])

    # Always-useful baseline actions
    actions.append("Review the top source IP addresses listed below")
    actions.append("Preserve the network logs / this PCAP for investigation")

    if any('Flood' in r or 'DDoS' in r or 'DoS' in r for r in reason_names):
        actions.append("Apply firewall rate-limiting on the affected destination ports")

    if any('Brute Force' in r for r in reason_names):
        actions.append("Enforce account lockout / fail2ban on SSH/FTP and rotate credentials")

    if any('Suspicious Port' in r or 'Bot' in r for r in reason_names):
        actions.append("Block the flagged malware/C2 ports at the perimeter firewall")

    if any('Telnet' in r for r in reason_names):
        actions.append("Disable Telnet and migrate to SSH")

    if any('DNS Tunneling' in r for r in reason_names):
        actions.append("Inspect DNS payloads and restrict outbound DNS to trusted resolvers")

    actions.append("Notify the security administrator / escalate as per SOC playbook")
    return actions


# ── Attack-type tally ────────────────────────────────────────
def attack_breakdown(alerts_df):
    """Counter of detected attack types for the 'Detected' checklist."""
    return Counter(alerts_df['Reason'])


# ── GeoIP enrichment for the report ──────────────────────────
def top_attackers(alerts_df, get_ip_location, limit=5):
    """Return the busiest attacking source IPs, geo-enriched where public.

    get_ip_location is injected (from pcap_engine) so this module stays free of
    network/Streamlit dependencies.
    """
    counts = alerts_df['Src IP'].value_counts().head(limit)
    rows = []
    for ip, n in counts.items():
        loc = get_ip_location(ip)
        if loc:
            where = f"{loc.get('city','?')}, {loc.get('country','?')} ({loc.get('isp','?')})"
        else:
            where = "Private / local address"
        rows.append({"ip": ip, "flows": int(n), "origin": where})
    return rows


# ── Per-attack detail (for individual cards when few attacks) ─
# Maps ONE detection reason to its single most relevant reason + action, so each
# attack can get its own focused card instead of a merged list.
_REASON_FOR = [
    (("Port Scan", "NULL Scan", "Xmas Scan"),
     "Reconnaissance: many ports probed from one source in a short window."),
    (("DDoS", "DoS", "Flood"),
     "Flooding: abnormally high packet/connection rate aimed at one service."),
    (("Brute Force",),
     "Repeated short login attempts — credential-guessing on FTP/SSH."),
    (("DNS Tunneling",),
     "Oversized / encoded DNS queries — data may be tunnelled over port 53."),
    (("Suspicious Port",),
     "Traffic to a known malware / C2 port."),
    (("Bot",),
     "Beacon-like traffic to a control port — possible bot check-in."),
    (("Telnet",),
     "Unencrypted Telnet — credentials exposed in clear text."),
    (("Oversized", "Bandwidth"),
     "Packet size / bandwidth well outside the normal baseline."),
    (("ML Anomaly",),
     "Statistical anomaly flagged by the ML model (no single rule matched)."),
]

_ACTION_FOR = [
    (("Port Scan", "NULL Scan", "Xmas Scan"),
     "Block the source IP and watch for follow-up connection attempts."),
    (("DDoS", "DoS", "Flood"),
     "Apply rate-limiting on the target port and consider upstream filtering."),
    (("Brute Force",),
     "Enable account lockout / fail2ban and rotate any exposed credentials."),
    (("DNS Tunneling",),
     "Inspect DNS payloads and restrict outbound DNS to trusted resolvers."),
    (("Suspicious Port",),
     "Block the malware/C2 port at the perimeter and scan the internal host."),
    (("Bot",),
     "Isolate the internal host and hunt for a bot/implant."),
    (("Telnet",),
     "Disable Telnet; migrate the service to SSH."),
    (("Oversized", "Bandwidth"),
     "Verify the endpoint and cap bandwidth if the spike is unexpected."),
    (("ML Anomaly",),
     "Triage manually — confirm whether the flow is benign or a novel attack."),
]


def _match(reason, table, default):
    for keys, text in table:
        if any(k in reason for k in keys):
            return text
    return default


def reason_for_attack(reason):
    """Single focused reason line for one detected attack type."""
    return _match(reason, _REASON_FOR,
                  "Traffic flagged as suspicious by the detection engine.")


def action_for_attack(reason):
    """Single focused suggested action for one detected attack type."""
    return _match(reason, _ACTION_FOR,
                  "Review the source IP and preserve the logs for investigation.")


def _fmt_origin(loc):
    if loc:
        return f"{loc.get('country','?')} ({loc.get('isp','?')})"
    return "an unresolved / local network"


def dynamic_reason(row, loc):
    """Flow-SPECIFIC reason built from this flow's real values.

    Weaves in source IP, GeoIP origin, target port, packet rate, bandwidth,
    average packet size, flow duration, and repeat-offender status so the
    text describes THIS incident's actual traffic shape, not a generic type -
    this is what tells two flows of the same attack type apart (e.g. a short
    high-rate burst vs. a longer, lower-rate sustained flood) instead of every
    instance of "DDoS Attack Detected" reading identically.
    """
    ip       = row.get("Src IP", "?")
    port     = row.get("Port", "?")
    pps      = row.get("Pkts/s", 0)
    bps      = row.get("Bytes/s", 0)
    avg_size = row.get("Avg Packet Size", 0)
    duration = row.get("Duration (s)", 0)
    prior    = row.get("Prior Hits", 0)
    reason   = str(row.get("Reason", ""))
    origin   = _fmt_origin(loc)

    base = _match(reason, _REASON_FOR,
                  "Traffic flagged as suspicious by the detection engine.")

    detail = f"Source {ip} from {origin} targeted port {port} at ~{pps} packets/s."
    detail += (
        f" Averaged {avg_size:.0f} bytes/packet (~{bps/1000:.1f} KB/s) "
        f"over {duration:.2f}s."
    )
    if prior > 0:
        detail += f" This IP is a repeat offender ({prior} prior incident(s) on record)."
    return f"{base} {detail}"


def dynamic_action(row, loc):
    """Flow-SPECIFIC action built from this flow's real values."""
    ip     = row.get("Src IP", "?")
    port   = row.get("Port", "?")
    prior  = row.get("Prior Hits", 0)
    reason = str(row.get("Reason", ""))

    base = _match(reason, _ACTION_FOR,
                  "Review the source IP and preserve the logs for investigation.")

    action = f"Block {ip} at the firewall and monitor traffic to port {port}. {base}"
    if prior > 0:
        action += " Given the repeat activity, consider a permanent block / escalation."
    return action


def rank_by_threat_score(alerts_df):
    """Order alerts by Threat Score, highest first.

    Previously the "top 5 shown, rest truncated" cap (in upload_app.py /
    Aalok's app.py) just took alerts_df.head(N), i.e. insertion order -
    whichever flow's first packet happened to come earliest in the capture,
    not which one actually mattered most. This makes the shown incidents the
    highest-scoring ones instead.

    An earlier version of this ranked by each score's z-score against the
    capture's own mean/std instead of the raw score. That's not wrong, but
    it's also not doing anything a plain sort doesn't already do: z-score is
    a straight-line rescaling of the same number ((x - mean) / std), so for
    ranking WITHIN one capture it produces the identical order as sorting by
    the raw score - confirmed by comparing both orderings directly. Simpler
    to just sort, rather than compute mean/std for a result that never
    differs from ranking on the field already sitting in the row.
    """
    return alerts_df.sort_values('Threat Score', ascending=False)


def per_attack_cards(alerts_df, get_ip_location):
    """Build one detail dict per attacking flow, for individual cards.

    Each card carries: source IP, target, reason name, threat score/level,
    a focused reason + action, and the attacker's geo origin.
    """
    cards = []
    for _, row in alerts_df.iterrows():
        ip = row.get("Src IP", "—")
        loc = get_ip_location(ip)
        origin = (
            f"{loc.get('city','?')}, {loc.get('country','?')} ({loc.get('isp','?')})"
            if loc else "Private / local address"
        )
        reason_name = str(row.get("Reason", "—"))
        cards.append({
            "src": ip,
            "dst": row.get("Dst IP", "—"),
            "port": row.get("Port", "—"),
            "reason_name": reason_name,
            "score": row.get("Threat Score", "—"),
            "level": row.get("Threat Level", "—"),
            "why": dynamic_reason(row, loc),
            "action": dynamic_action(row, loc),
            "origin": origin,
        })
    return cards
