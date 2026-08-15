import json
import os

# Data-derived thresholds (see derive_thresholds.py): each floor below is
# anchored to a real, already-validated synthetic attack sample's percentile
# rank within CICIDS2017's Normal Traffic distribution, not hand-picked.
# Falls back to the previous hand-picked values if thresholds.json hasn't
# been generated (e.g. the source dataset isn't present on this machine), so
# this module still imports cleanly either way.
_THRESHOLDS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "thresholds.json")
_DEFAULT_THRESHOLDS = {
    "port_scan_pps_floor": 3000,
    "web_attack_pps_floor": 1000,
    "null_scan_pps_floor": 100,
    "dos_pps_floor": 50,
    "ddos_fwd_len_mean_floor": 500,
    "icmp_flood_pps_floor": 50000,
    "high_bandwidth_bytes_floor": 100000000,
    "ddos_min_fwd_packets": 10,
}
try:
    with open(_THRESHOLDS_PATH, "r", encoding="utf-8") as _f:
        THRESHOLDS = {**_DEFAULT_THRESHOLDS, **json.load(_f)}
except (FileNotFoundError, json.JSONDecodeError):
    THRESHOLDS = _DEFAULT_THRESHOLDS

# ── Rule 1: Port Scan ────────────────────────────────────────
# A bare TCP SYN packet with no payload (IP header + TCP header, no options)
# is 40 bytes, not <10 - the old threshold never matched a real scan packet,
# so scans fell through to check_null_scan instead (same byte-size range,
# and it doesn't check the SYN flag). Widened to <60 to keep matching genuine
# tiny scan probes while still excluding payload-carrying floods.
def check_port_scan(flow):
    if (flow.get('Flow Packets/s', 0) > THRESHOLDS['port_scan_pps_floor'] and
            flow.get('Fwd Packet Length Mean', 0) < 60 and      # ← fixed
            flow.get('Flow Duration', 0) > 1000 and
            not (flow.get('ACK Flag Count', 0) > 0 and
                 flow.get('PSH Flag Count', 0) == 0 and
                 flow.get('FIN Flag Count', 0) == 0)):
        return {
            "rule_id":    1,
            "rule_name":  "Port Scan Detected",
            "severity":   "SEVERE",
            "confidence": 90,
            "details":    f"High packet rate ({flow.get('Flow Packets/s', 0):.1f} pkt/s) with tiny packets"
        }
    return None

# ── Rule 2: DDoS ─────────────────────────────────────────────
# Web-facing DDoS targets HTTPS (443) far more than plain HTTP (80) today, so
# both are treated as the same "web service" surface for this rule.
WEB_PORTS = (80, 443)


def check_ddos(flow):
    # No minimum duration/packet-count originally - a handful of large TLS
    # packets (e.g. a normal HTTPS ClientHello/cert exchange) delivered in
    # under 2ms was enough to average >500 bytes/packet, and dividing a
    # tiny packet count by a near-zero duration inflated Flow Packets/s into
    # flood-looking numbers. Confirmed false-positive: a 4-packet, ~1.2ms
    # burst to a legitimate Google IP (172.217.194.94) scored 83/100
    # "Critical" under the old rule. A real flood is SUSTAINED volume, not a
    # few packets in a blip - the synthetic DDoS test fixture (500 packets /
    # ~250ms) clears both floors below with wide margin.
    if (flow.get('Fwd Packet Length Mean', 0) > THRESHOLDS['ddos_fwd_len_mean_floor'] and
            flow.get('Destination Port', 0) in WEB_PORTS and
            flow.get('Flow Bytes/s', 0) > 0 and
            flow.get('Total Fwd Packets', 0) > THRESHOLDS['ddos_min_fwd_packets'] and
            flow.get('Flow Duration', 0) > 50000):              # ← fixed (50ms)
        return {
            "rule_id":    2,
            "rule_name":  "DDoS Attack Detected",
            "severity":   "SEVERE",
            "confidence": 90,
            "details":    f"Large packets ({flow.get('Fwd Packet Length Mean', 0):.1f} bytes) flooding port {flow.get('Destination Port', 0)}"
        }
    return None

# ── Rule 3: DoS ──────────────────────────────────────────────
# pps floor raised from 0.5 -> 50. At 0.5 pkt/s the rule fired on almost any
# sustained connection (e.g. a normal 15s HTTPS session sits around 20 pps),
# which only stayed hidden while this rule was port-80-only because ordinary
# browsing rarely used port 80. Opening it to 443 (the WEB_PORTS fix above)
# exposed that gap immediately - a benign HTTPS flow tripped this as "DoS".
# 50 pps sustained for >0.5s is well above a normal browsing/streaming
# session and back in genuine-flood territory.
def check_dos(flow):
    if (flow.get('Destination Port', 0) in WEB_PORTS and
            flow.get('Flow Duration', 0) > 500000 and
            flow.get('Flow Packets/s', 0) > THRESHOLDS['dos_pps_floor'] and
            flow.get('Fwd Packet Length Mean', 0) > 0 and
            flow.get('Fwd Packet Length Mean', 0) < 500):
        return {
            "rule_id":    3,
            "rule_name":  "DoS Attack Detected",
            "severity":   "SEVERE",
            "confidence": 78,
            "details":    f"Sustained traffic to port {flow.get('Destination Port', 0)} for {flow.get('Flow Duration', 0)/1000000:.1f}s"
        }
    return None

# ── Rule 4: Brute Force ──────────────────────────────────────
def check_brute_force(flow):
    if (flow.get('Destination Port', 0) in [21, 22] and
            flow.get('Fwd Packet Length Mean', 0) < 80 and      # ← fixed + raised to 80
            flow.get('Fwd Packet Length Mean', 0) > 0 and       # ← fixed
            flow.get('Flow Packets/s', 0) > 0.5 and
            flow.get('Flow Duration', 0) > 50000 and
            flow.get('Flow Bytes/s', 0) > 10):
        return {
            "rule_id":    4,
            "rule_name":  "Brute Force Detected",
            "severity":   "HIGH",
            "confidence": 85,
            "details":    f"Repeated connection attempts to port {flow.get('Destination Port', 0)}"
        }
    return None

# ── Rule 5: Bot Activity ─────────────────────────────────────
def check_bot(flow):
    if (flow.get('Destination Port', 0) == 8080 and
            flow.get('Flow Packets/s', 0) > 20):
        return {
            "rule_id":    5,
            "rule_name":  "Bot Activity Detected",
            "severity":   "HIGH",
            "confidence": 72,
            "details":    f"Suspicious traffic to port 8080 at {flow.get('Flow Packets/s', 0):.1f} pkt/s"
        }
    return None

# ── Rule 6: Web Attack ───────────────────────────────────────
def check_web_attack(flow):
    if (flow.get('Destination Port', 0) in WEB_PORTS and
            flow.get('Flow Packets/s', 0) > THRESHOLDS['web_attack_pps_floor'] and
            flow.get('Fwd Packet Length Mean', 0) > 30 and      # ← fixed
            flow.get('Fwd Packet Length Mean', 0) < 300 and     # ← fixed
            flow.get('Flow Bytes/s', 0) > 0):
        return {
            "rule_id":    6,
            "rule_name":  "Web Attack Detected",
            "severity":   "HIGH",
            "confidence": 72,
            "details":    f"Suspicious HTTP(S) traffic at {flow.get('Flow Packets/s', 0):.1f} pkt/s"
        }
    return None

# ── Rule 7: NULL Scan ────────────────────────────────────────
def check_null_scan(flow):
    if (flow.get('FIN Flag Count', 0) == 0 and
            flow.get('PSH Flag Count', 0) == 0 and
            flow.get('ACK Flag Count', 0) == 0 and
            flow.get('Flow Packets/s', 0) > THRESHOLDS['null_scan_pps_floor'] and
            flow.get('Fwd Packet Length Mean', 0) > 0 and       # ← fixed
            flow.get('Fwd Packet Length Mean', 0) < 100 and     # ← fixed
            flow.get('Destination Port', 0) not in [123, 53]):
        return {
            "rule_id":    7,
            "rule_name":  "NULL Scan Detected",
            "severity":   "HIGH",
            "confidence": 82,
            "details":    "TCP packets with no flags — stealth probe attempt"
        }
    return None

# ── Rule 8: Xmas Scan ────────────────────────────────────────
def check_xmas_scan(flow):
    if (flow.get('FIN Flag Count', 0) > 0 and
            flow.get('PSH Flag Count', 0) > 0 and
            flow.get('Fwd Packet Length Mean', 0) < 100):       # ← fixed
        return {
            "rule_id":    8,
            "rule_name":  "Xmas Scan Detected",
            "severity":   "HIGH",
            "confidence": 80,
            "details":    "FIN+PSH flags set — Xmas scan probe detected"
        }
    return None

# ── Rule 9: Telnet ───────────────────────────────────────────
def check_telnet(flow):
    if flow.get('Destination Port', 0) == 23:
        return {
            "rule_id":    9,
            "rule_name":  "Telnet Usage Detected",
            "severity":   "MODERATE",
            "confidence": 72,
            "details":    "Unencrypted Telnet connection on port 23"
        }
    return None

# ── Rule 10: Suspicious Port ─────────────────────────────────
def check_suspicious_port(flow):
    malware_ports = [4444, 1337, 31337, 6666, 6667, 6668]
    if flow.get('Destination Port', 0) in malware_ports:
        return {
            "rule_id":    10,
            "rule_name":  "Suspicious Port Detected",
            "severity":   "SEVERE",
            "confidence": 92,
            "details":    f"Traffic to known malware port {flow.get('Destination Port', 0)}"
        }
    return None

# ── Rule 11: DNS Tunneling ───────────────────────────────────
# Calibrated from Shannon entropy of real hostname vs. base64-style encoded
# subdomain samples (see derive_thresholds.py's session log entry for the
# numbers) - normal hostnames ('mail', 'accounts', 'static') land at 0-2.75
# bits/char, base64-style tunneling payloads at 3.88-4.32. Not derived from
# CICIDS2017 (that dataset has no DNS-query-name column to compute this
# from) - a synthetic calibration, unlike the THRESHOLDS above.
DNS_TUNNEL_ENTROPY_FLOOR = 3.5


def check_dns_tunneling(flow):
    # Keyed off the packet actually parsing as a DNS query (see 'Is DNS Flow'
    # in pcap_engine.py's extract_features), not off Destination Port == 53 -
    # some tunneling tools deliberately run real DNS-protocol traffic on a
    # non-standard port specifically to dodge port-based monitoring. This
    # still can't see DNS-over-HTTPS (encrypted, no DNS layer to parse at
    # all) - a different, unsolved problem, not fixable from packet content.
    if (flow.get('Is DNS Flow', 0) == 1 and
            flow.get('DNS Query Entropy', 0) > DNS_TUNNEL_ENTROPY_FLOOR):
        return {
            "rule_id":    11,
            "rule_name":  "DNS Tunneling Detected",
            "severity":   "HIGH",
            "confidence": 78,
            "details":    f"High-entropy DNS query name ({flow.get('DNS Query Entropy', 0):.2f} bits/char) — possible data exfiltration over DNS"
        }
    return None

# ── Rule 12: ICMP Flood ──────────────────────────────────────
def check_icmp_flood(flow):
    if (flow.get('Flow Packets/s', 0) > THRESHOLDS['icmp_flood_pps_floor'] and
            flow.get('Fwd Packet Length Mean', 0) > 0 and       # ← fixed
            flow.get('Fwd Packet Length Mean', 0) < 100 and     # ← fixed
            flow.get('FIN Flag Count', 0) == 0 and
            flow.get('ACK Flag Count', 0) == 0 and
            flow.get('Flow Bytes/s', 0) > 1000 and
            flow.get('Flow Duration', 0) > 1000):
        return {
            "rule_id":    12,
            "rule_name":  "ICMP Flood Detected",
            "severity":   "HIGH",
            "confidence": 80,
            "details":    f"High volume small packets at {flow.get('Flow Packets/s', 0):.1f} pkt/s"
        }
    return None

# ── Rule 13: Large Payload ───────────────────────────────────
def check_large_payload(flow):
    if flow.get('Max Packet Length', 0) > 60000:
        return {
            "rule_id":    13,
            "rule_name":  "Oversized Packet Detected",
            "severity":   "MODERATE",
            "confidence": 68,
            "details":    f"Packet size {flow.get('Max Packet Length', 0)} bytes"
        }
    return None

# ── Rule 14: High Bandwidth Anomaly ─────────────────────────
def check_high_bandwidth(flow):
    if (flow.get('Flow Bytes/s', 0) > THRESHOLDS['high_bandwidth_bytes_floor'] and
            flow.get('Flow Duration', 0) > 1000 and
            flow.get('Fwd Packet Length Mean', 0) > 0):         # ← fixed
        return {
            "rule_id":    14,
            "rule_name":  "High Bandwidth Anomaly",
            "severity":   "MODERATE",
            "confidence": 65,
            "details":    f"Unusually high bandwidth: {flow.get('Flow Bytes/s', 0):.1f} bytes/s"
        }
    return None

# ── Main Rule Engine ─────────────────────────────────────────
ALL_RULES = [
    check_port_scan,
    check_ddos,
    check_dos,
    check_brute_force,
    check_bot,
    check_web_attack,
    check_null_scan,
    check_xmas_scan,
    check_telnet,
    check_suspicious_port,
    check_dns_tunneling,
    check_icmp_flood,
    check_large_payload,
    check_high_bandwidth,
]

# Severity ranking so we can pick the WORST match when several rules fire on
# one flow (higher number = more severe). Used to resolve overlaps instead of
# just taking whichever rule happens to be listed first.
_SEVERITY_RANK = {
    "SEVERE":   4,
    "HIGH":     3,
    "MODERATE": 2,
    "LOW":      1,
}


def run_rule_engine(flow):
    """Return the single most severe rule match for this flow.

    Previously this returned the FIRST rule that matched, so the result depended
    on rule ORDER — a flow matching both a severe and a moderate rule could be
    reported as the moderate one. Now every matching rule is collected and the
    highest-severity one is returned (ties broken by higher confidence), so the
    verdict reflects the worst threat present, not list position.
    """
    matches = run_all_rules(flow)
    if not matches:
        return None
    return max(
        matches,
        key=lambda r: (_SEVERITY_RANK.get(r.get("severity", ""), 0),
                       r.get("confidence", 0)),
    )


def run_all_rules(flow):
    results = []
    for rule in ALL_RULES:
        result = rule(flow)
        if result:
            results.append(result)
    return results