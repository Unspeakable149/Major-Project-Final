"""PCAP analysis + GeoIP engine (Rui Yang).

Shared logic behind the "PCAP Analysis" and "Threat Map" features. Kept free of
any page-level Streamlit calls (no set_page_config / title) so it can be imported
by both the standalone upload_app and the Aalok SOC dashboard.

All resource paths (models, rules) are anchored to THIS file's location via
__file__, so the models in Rui Yang/models and rules in Rui Yang/scripts resolve
correctly no matter which app imports it or what the current working directory is.
"""
import ipaddress
import math
import os
import sys

from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd
import requests
import streamlit as st
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR

# Anchor to the Rui Yang project root (this file is .../Rui Yang/app/pcap_engine.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(BASE_DIR, 'scripts') not in sys.path:
    sys.path.insert(0, os.path.join(BASE_DIR, 'scripts'))
from rules import run_rule_engine
from scoring import compute_threat_score
from offender_history import OffenderHistory


@st.cache_resource
def load_models():
    """Load and cache Rui Yang's model, scaler and feature list from Rui Yang/models."""
    model         = joblib_load(os.path.join(BASE_DIR, 'models', 'ids_model_live.pkl'))
    scaler        = joblib_load(os.path.join(BASE_DIR, 'models', 'scaler_live.pkl'))
    live_features = joblib_load(os.path.join(BASE_DIR, 'models', 'live_features.pkl'))
    return model, scaler, live_features


def joblib_load(path):
    import joblib
    return joblib.load(path)


@st.cache_data
def get_ip_location(ip):
    """Resolve a public IP to a geo location via ip-api.com. Private IPs return None."""
    try:
        # A plain '172.' prefix check wrongly caught real public ranges, e.g.
        # Cloudflare's edge network (172.64.0.0/13) and Google Cloud
        # (172.253.0.0/16) - both start with "172." but are fully public,
        # so attacker IPs in those ranges were silently dropped from the
        # threat map / GeoIP report. ipaddress.is_private checks the actual
        # RFC 1918 / loopback / link-local ranges instead of a string prefix.
        if ipaddress.ip_address(ip).is_private:
            return None  # skip private/reserved IPs
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        d = r.json()
        if d['status'] == 'success':
            return {
                'ip':      ip,
                'country': d['country'],
                'city':    d['city'],
                'lat':     d['lat'],
                'lon':     d['lon'],
                'isp':     d['isp']
            }
    except Exception:
        return None
    return None


def _shannon_entropy(s):
    """Shannon entropy in bits/char of a string. Empty string -> 0."""
    if not s:
        return 0.0
    length = len(s)
    freq = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def _dns_subdomain_entropy(qname):
    """Entropy of a DNS query's SUBDOMAIN portion, excluding the trailing
    registered-domain + TLD labels (naive heuristic: last 2 dot-separated
    labels). DNS tunneling encodes exfiltrated data into subdomain labels
    (e.g. aG9wZWZ1bGx5.evil.com), which reads as high-entropy near-random
    text; ordinary hostnames (mail, www, api) don't. Computing entropy over
    the FULL qname would dilute the signal with the low-entropy domain/TLD
    suffix that's present on every query, tunneling or not.
    """
    name = qname.decode('utf-8', errors='ignore') if isinstance(qname, bytes) else str(qname)
    name = name.rstrip('.')
    labels = name.split('.')
    subdomain_labels = labels[:-2] if len(labels) > 2 else labels[:1]
    return _shannon_entropy(''.join(subdomain_labels))


def extract_features(packets, live_features):
    lengths  = [len(p) for p in packets]
    times    = [float(p.time) for p in packets]
    duration = (times[-1] - times[0]) * 1000000
    if duration == 0:
        duration = 1

    inter = np.diff(times) * 1000000 if len(times) > 1 else [0]

    # A src->dst flow can span many destination ports (e.g. a port scan), so
    # track every port seen and use the MODE as the representative port for
    # both the ML feature and the report — using whichever packet happened to
    # be last in the capture produced a misleading, order-dependent value.
    port_counts = Counter()
    fin_count = 0
    psh_count = 0
    ack_count = 0
    init_win  = 0
    dns_entropies = []

    for p in packets:
        if TCP in p:
            port_counts[p[TCP].dport] += 1
            flags    = p[TCP].flags
            if flags & 0x01:
                fin_count += 1
            if flags & 0x08:
                psh_count += 1
            if flags & 0x10:
                ack_count += 1
            init_win = p[TCP].window
        elif UDP in p:
            port_counts[p[UDP].dport] += 1

        # DNS tunneling detection is keyed off the packet actually parsing as
        # a DNS query (qr=0), not off Destination Port == 53 - some tunneling
        # tools deliberately run real DNS-protocol traffic on non-standard
        # ports specifically to dodge port-based monitoring. Checking
        # protocol structure instead of port number catches that; it still
        # can't see DNS-over-HTTPS (encrypted, no DNS layer to parse at all -
        # a fundamentally different, unsolved-here problem).
        if p.haslayer(DNS) and p.haslayer(DNSQR) and p[DNS].qr == 0:
            try:
                dns_entropies.append(_dns_subdomain_entropy(p[DNSQR].qname))
            except Exception:
                pass

    dst_port     = port_counts.most_common(1)[0][0] if port_counts else 0
    unique_ports = len(port_counts)
    is_dns_flow  = 1 if dns_entropies else 0
    dns_entropy  = max(dns_entropies) if dns_entropies else 0.0

    mean_len = np.mean(lengths)
    duration_sec = duration / 1000000

    features = {f: 0 for f in live_features}
    features.update({
        'Destination Port':            dst_port,
        'Unique Target Ports':         unique_ports,
        'Flow Duration':               duration,
        'Total Fwd Packets':           len(packets),
        'Total Length of Fwd Packets': sum(lengths),
        'Fwd Packet Length Max':       max(lengths),
        'Fwd Packet Length Min':       min(lengths),
        'Fwd Packet Length Mean':      mean_len,
        'Fwd Packet Length Std':       np.std(lengths),
        'Flow Bytes/s':                sum(lengths) / duration_sec if duration_sec > 0 else 0,
        'Flow Packets/s':              len(packets) / duration_sec if duration_sec > 0 else 0,
        'Flow IAT Mean':               np.mean(inter),
        'Flow IAT Std':                np.std(inter),
        'Flow IAT Max':                np.max(inter),
        'Flow IAT Min':                np.min(inter),
        'Fwd Packets/s':               len(packets) / duration_sec if duration_sec > 0 else 0,
        'FIN Flag Count':              fin_count,
        'PSH Flag Count':              psh_count,
        'ACK Flag Count':              ack_count,
        'Average Packet Size':         mean_len,
        'Min Packet Length':           min(lengths),
        'Max Packet Length':           max(lengths),
        'Init_Win_bytes_forward':      init_win,
        'Is DNS Flow':                 is_dns_flow,
        'DNS Query Entropy':           dns_entropy,
    })
    return features


def analyse_pcap(filepath):
    """Read a PCAP, group into src→dst flows, score each with rules + ML, return a DataFrame."""
    model, scaler, live_features = load_models()
    packets = rdpcap(filepath)

    flows = {}
    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        key = f"{src}→{dst}"
        if key not in flows:
            flows[key] = {'packets': [], 'src': src, 'dst': dst}
        flows[key]['packets'].append(pkt)

    results = []
    # Idea 6: repeat-offender history. `history` persists across uploads (SQLite);
    # `src_incident_count` tracks offences within THIS pcap, seeded from the DB so
    # a known repeat offender starts with its accumulated history immediately.
    history = OffenderHistory()
    src_incident_count = {}
    for flow_key, flow_data in flows.items():
        pkts = flow_data['packets']
        if len(pkts) < 2:
            continue

        features = extract_features(pkts, live_features)

        # Wall-clock window of this flow, for "what time did this happen"
        # in both the technical and management reports.
        pkt_times = [float(p.time) for p in pkts]
        start_ts  = min(pkt_times)
        end_ts    = max(pkt_times)

        # Honest proxy for "was data taken": bytes seen going the OPPOSITE
        # direction (dst->src) on this same IP pair, i.e. how much the
        # would-be victim sent back toward the source during the incident.
        # This is a traffic-volume estimate from flow metadata, NOT content
        # inspection - the engine never looks at payloads, so it cannot name
        # specific files or data. Most real traffic is also TLS-encrypted,
        # which would defeat payload inspection anyway.
        reverse_key  = f"{flow_data['dst']}→{flow_data['src']}"
        reverse_pkts = flows.get(reverse_key, {}).get('packets', [])
        data_sent_back = sum(len(p) for p in reverse_pkts)

        rule_result = run_rule_engine(features)
        rule_fired  = rule_result is not None

        df_feat     = pd.DataFrame([features])[live_features]
        scaled      = scaler.transform(df_feat)
        pred        = model.predict(scaled)[0]
        prob        = model.predict_proba(scaled)[0]
        attack_prob = prob[1]
        ml_conf     = round(attack_prob * 100, 1)
        ml_fired    = (attack_prob > 0.20)

        if rule_fired and (ml_fired or attack_prob > 0.025):
            rule_conf = rule_result['confidence']
            pkt_score  = min(features.get('Flow Packets/s', 0) / 500, 5)
            byte_score = min(features.get('Flow Bytes/s', 0) / 50000, 5)
            size_score = min(features.get('Fwd Packet Length Mean', 0) / 300, 5)
            bonus      = round(pkt_score + byte_score + size_score)
            ml_bonus   = round(attack_prob * 25)
            confidence = min(rule_conf + bonus + ml_bonus, 99)
            severity   = "🔴 Severe"
            reason     = rule_result['rule_name']
            source     = "Rule + ML"
        elif rule_fired:
            severity   = "🟠 Moderate"
            confidence = rule_result['confidence']
            reason     = rule_result['rule_name']
            source     = "Rule Engine"
        elif ml_fired:
            severity   = "🟡 Moderate"
            confidence = ml_conf
            reason     = "ML Anomaly Detected"
            source     = "ML Model"
        else:
            severity   = "✅ Safe"
            confidence = round((1 - attack_prob) * 100, 1)
            reason     = "Normal Traffic"
            source     = "Rule + ML"

        # ── Composite Threat Score (Enhancement Ideas 2-8) ──────
        src_ip = flow_data['src']
        # prior offences = what we've already counted in THIS pcap PLUS the
        # persisted history from previous uploads (seeded once per IP).
        if src_ip not in src_incident_count:
            src_incident_count[src_ip] = history.get_count(src_ip)
        prev_incidents = src_incident_count[src_ip]
        rule_conf = rule_result['confidence'] if rule_fired else 0
        score_info = compute_threat_score(
            features       = features,
            reason         = reason,
            rule_conf      = rule_conf,
            attack_prob    = attack_prob,
            rule_fired     = rule_fired,
            prev_incidents = prev_incidents,
        )
        # Count this source as an offender only if it wasn't Safe, and persist it
        if severity != "✅ Safe":
            src_incident_count[src_ip] = prev_incidents + 1
            history.record(src_ip)

        results.append({
            'Flow':         flow_key,
            'Src IP':       src_ip,
            'Dst IP':       flow_data['dst'],
            'Packets':      len(pkts),
            'Pkts/s':       round(features.get('Flow Packets/s', 0)),
            'Bytes/s':      round(features.get('Flow Bytes/s', 0)),
            'Avg Packet Size': round(features.get('Fwd Packet Length Mean', 0), 1),
            'Duration (s)': round(features.get('Flow Duration', 0) / 1_000_000, 2),
            'Prior Hits':   prev_incidents,
            'Severity':     severity,
            'Confidence':   f"{confidence}%",
            'Threat Score': score_info['score'],
            'Threat Level': f"{score_info['emoji']} {score_info['level']}",
            'Reason':       reason,
            'Source':       source,
            'Port':         features.get('Destination Port', 0),
            'Unique Ports': features.get('Unique Target Ports', 1),
            'Start Time':   datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S'),
            'End Time':     datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S'),
            'Data Sent Back (bytes)': data_sent_back,
        })

    return pd.DataFrame(results)
