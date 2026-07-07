# ── Rule 1: Port Scan ────────────────────────────────────────
def check_port_scan(flow):
    if (flow.get('Flow Packets/s', 0) > 3000 and
            flow.get('Fwd Packet Length Mean', 0) < 10 and      # ← fixed
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
def check_ddos(flow):
    if (flow.get('Fwd Packet Length Mean', 0) > 500 and         # ← fixed
            flow.get('Destination Port', 0) == 80 and
            flow.get('Flow Bytes/s', 0) > 0):
        return {
            "rule_id":    2,
            "rule_name":  "DDoS Attack Detected",
            "severity":   "SEVERE",
            "confidence": 90,
            "details":    f"Large packets ({flow.get('Fwd Packet Length Mean', 0):.1f} bytes) flooding port 80"
        }
    return None

# ── Rule 3: DoS ──────────────────────────────────────────────
def check_dos(flow):
    if (flow.get('Destination Port', 0) == 80 and
            flow.get('Flow Duration', 0) > 500000 and
            flow.get('Flow Packets/s', 0) > 0.5 and
            flow.get('Fwd Packet Length Mean', 0) > 0 and
            flow.get('Fwd Packet Length Mean', 0) < 500):
        return {
            "rule_id":    3,
            "rule_name":  "DoS Attack Detected",
            "severity":   "SEVERE",
            "confidence": 78,
            "details":    f"Sustained traffic to port 80 for {flow.get('Flow Duration', 0)/1000000:.1f}s"
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
    if (flow.get('Destination Port', 0) == 80 and
            flow.get('Flow Packets/s', 0) > 1000 and
            flow.get('Fwd Packet Length Mean', 0) > 30 and      # ← fixed
            flow.get('Fwd Packet Length Mean', 0) < 300 and     # ← fixed
            flow.get('Flow Bytes/s', 0) > 0):
        return {
            "rule_id":    6,
            "rule_name":  "Web Attack Detected",
            "severity":   "HIGH",
            "confidence": 72,
            "details":    f"Suspicious HTTP traffic at {flow.get('Flow Packets/s', 0):.1f} pkt/s"
        }
    return None

# ── Rule 7: NULL Scan ────────────────────────────────────────
def check_null_scan(flow):
    if (flow.get('FIN Flag Count', 0) == 0 and
            flow.get('PSH Flag Count', 0) == 0 and
            flow.get('ACK Flag Count', 0) == 0 and
            flow.get('Flow Packets/s', 0) > 100 and
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
def check_dns_tunneling(flow):
    if (flow.get('Destination Port', 0) == 53 and
            flow.get('Fwd Packet Length Mean', 0) > 200):       # ← fixed
        return {
            "rule_id":    11,
            "rule_name":  "DNS Tunneling Detected",
            "severity":   "HIGH",
            "confidence": 78,
            "details":    f"Oversized DNS packets ({flow.get('Fwd Packet Length Mean', 0):.1f} bytes)"
        }
    return None

# ── Rule 12: ICMP Flood ──────────────────────────────────────
def check_icmp_flood(flow):
    if (flow.get('Flow Packets/s', 0) > 50000 and
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
    if (flow.get('Flow Bytes/s', 0) > 100000000 and
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

def run_rule_engine(flow):
    for rule in ALL_RULES:
        result = rule(flow)
        if result:
            return result
    return None

def run_all_rules(flow):
    results = []
    for rule in ALL_RULES:
        result = rule(flow)
        if result:
            results.append(result)
    return results