"""PCAP analysis + GeoIP engine (Rui Yang).

Shared logic behind the "PCAP Analysis" and "Threat Map" features. Kept free of
any page-level Streamlit calls (no set_page_config / title) so it can be imported
by both the standalone upload_app and the Aalok SOC dashboard.

All resource paths (models, rules) are anchored to THIS file's location via
__file__, so the models in Rui Yang/models and rules in Rui Yang/scripts resolve
correctly no matter which app imports it or what the current working directory is.
"""
import os
import sys

import numpy as np
import pandas as pd
import requests
import streamlit as st
from scapy.all import rdpcap, IP, TCP, UDP

# Anchor to the Rui Yang project root (this file is .../Rui Yang/app/pcap_engine.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(BASE_DIR, 'scripts') not in sys.path:
    sys.path.insert(0, os.path.join(BASE_DIR, 'scripts'))
from rules import run_rule_engine


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
        if ip.startswith(('192.168', '10.', '172.')):
            return None  # skip private IPs
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


def extract_features(packets, live_features):
    lengths  = [len(p) for p in packets]
    times    = [float(p.time) for p in packets]
    duration = (times[-1] - times[0]) * 1000000
    if duration == 0:
        duration = 1

    inter = np.diff(times) * 1000000 if len(times) > 1 else [0]

    dst_port  = 0
    fin_count = 0
    psh_count = 0
    ack_count = 0
    init_win  = 0

    for p in packets:
        if TCP in p:
            dst_port = p[TCP].dport
            flags    = p[TCP].flags
            if flags & 0x01:
                fin_count += 1
            if flags & 0x08:
                psh_count += 1
            if flags & 0x10:
                ack_count += 1
            init_win = p[TCP].window
        elif UDP in p:
            dst_port = p[UDP].dport

    mean_len = np.mean(lengths)
    duration_sec = duration / 1000000

    features = {f: 0 for f in live_features}
    features.update({
        'Destination Port':            dst_port,
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
    for flow_key, flow_data in flows.items():
        pkts = flow_data['packets']
        if len(pkts) < 2:
            continue

        features = extract_features(pkts, live_features)

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

        results.append({
            'Flow':       flow_key,
            'Src IP':     flow_data['src'],
            'Dst IP':     flow_data['dst'],
            'Packets':    len(pkts),
            'Severity':   severity,
            'Confidence': f"{confidence}%",
            'Reason':     reason,
            'Source':     source,
            'Port':       features.get('Destination Port', 0)
        })

    return pd.DataFrame(results)
