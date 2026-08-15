"""Unit tests for the signature rule engine (rules.py).

Covers all 15 rules (14 threshold-based + DNS-tunnelling entropy) with a
"just fires" positive case and at least one "just below threshold" negative
case each, plus run_rule_engine's most-severe-wins resolution.

Several tests exist specifically to PIN historical bugs so they can't
silently regress:
  - WEB_PORTS covers both 80 and 443 (check_ddos/check_dos/check_web_attack) -
    before this, floods against HTTPS were invisible.
  - check_dos's pps floor rejects a normal ~20pps browsing session - the
    original 0.5 floor false-positived on this exact traffic shape.
  - check_ddos requires sustained volume (packet count + duration), not just
    a large-average-packet blip - the original rule scored a 4-packet, ~1ms
    burst to a legitimate Google IP as Critical.
  - check_port_scan's ACK/no-PSH/no-FIN exclusion stops an established
    connection's small packets from reading as a scan.
  - check_dns_tunneling is keyed off actually parsing as a DNS packet, not
    Destination Port == 53 - tunnelling on a non-standard port must still fire.
  - THRESHOLDS are read live from the module dict at call time, not baked in
    at import time, so derive_thresholds.py's output actually takes effect.
"""

import rules


def _flow(**over):
    """A flow dict that fires NO rule by default; tests override just the
    fields relevant to the rule under test."""
    base = {
        'Destination Port': 0,
        'Flow Duration': 0,
        'Total Fwd Packets': 0,
        'Fwd Packet Length Mean': 0,
        'Flow Bytes/s': 0,
        'Flow Packets/s': 0,
        'FIN Flag Count': 0,
        'PSH Flag Count': 0,
        'ACK Flag Count': 0,
        'Max Packet Length': 0,
        'Is DNS Flow': 0,
        'DNS Query Entropy': 0,
    }
    base.update(over)
    return base


# ── Rule 1: Port Scan ─────────────────────────────────────────────────────

def test_port_scan_fires_on_high_rate_tiny_packets():
    flow = _flow(**{
        'Flow Packets/s': rules.THRESHOLDS['port_scan_pps_floor'] + 1,
        'Fwd Packet Length Mean': 40,
        'Flow Duration': 2000,
    })
    result = rules.check_port_scan(flow)
    assert result is not None
    assert result['rule_name'] == "Port Scan Detected"


def test_port_scan_does_not_fire_below_pps_floor():
    flow = _flow(**{
        'Flow Packets/s': rules.THRESHOLDS['port_scan_pps_floor'] - 1,
        'Fwd Packet Length Mean': 40,
        'Flow Duration': 2000,
    })
    assert rules.check_port_scan(flow) is None


def test_port_scan_excludes_established_connection_pattern():
    # ACK set with no PSH/FIN is an ordinary established-connection packet
    # shape, not a scan - even with scan-like rate/size, this must not fire.
    flow = _flow(**{
        'Flow Packets/s': rules.THRESHOLDS['port_scan_pps_floor'] + 1,
        'Fwd Packet Length Mean': 40,
        'Flow Duration': 2000,
        'ACK Flag Count': 5,
        'PSH Flag Count': 0,
        'FIN Flag Count': 0,
    })
    assert rules.check_port_scan(flow) is None


# ── Rule 2: DDoS ───────────────────────────────────────────────────────────

def test_ddos_fires_on_sustained_large_packet_flood():
    flow = _flow(**{
        'Fwd Packet Length Mean': rules.THRESHOLDS['ddos_fwd_len_mean_floor'] + 1,
        'Destination Port': 443,
        'Flow Bytes/s': 1000,
        'Total Fwd Packets': rules.THRESHOLDS['ddos_min_fwd_packets'] + 1,
        'Flow Duration': 60000,
    })
    result = rules.check_ddos(flow)
    assert result is not None
    assert result['rule_name'] == "DDoS Attack Detected"


def test_ddos_fires_on_port_80_too():
    # Pins WEB_PORTS covering both HTTP and HTTPS, not just one.
    flow = _flow(**{
        'Fwd Packet Length Mean': rules.THRESHOLDS['ddos_fwd_len_mean_floor'] + 1,
        'Destination Port': 80,
        'Flow Bytes/s': 1000,
        'Total Fwd Packets': rules.THRESHOLDS['ddos_min_fwd_packets'] + 1,
        'Flow Duration': 60000,
    })
    assert rules.check_ddos(flow) is not None


def test_ddos_does_not_fire_on_short_low_volume_burst():
    # Regression pin: a 4-packet, ~1.2ms burst to a legitimate Google IP
    # previously scored 83/100 "Critical" under the old rule (no volume/
    # duration floor). Large average packet size alone must not be enough.
    flow = _flow(**{
        'Fwd Packet Length Mean': 900,
        'Destination Port': 443,
        'Flow Bytes/s': 1000,
        'Total Fwd Packets': 4,
        'Flow Duration': 1200,
    })
    assert rules.check_ddos(flow) is None


# ── Rule 3: DoS ────────────────────────────────────────────────────────────

def test_dos_fires_on_sustained_moderate_flood():
    flow = _flow(**{
        'Destination Port': 443,
        'Flow Duration': 600000,
        'Flow Packets/s': rules.THRESHOLDS['dos_pps_floor'] + 1,
        'Fwd Packet Length Mean': 200,
    })
    result = rules.check_dos(flow)
    assert result is not None
    assert result['rule_name'] == "DoS Attack Detected"


def test_dos_does_not_fire_on_normal_browsing_session():
    # Regression pin: the original 0.5pps floor false-positived on an
    # ordinary ~20pps HTTPS browsing session once port 443 was in scope.
    flow = _flow(**{
        'Destination Port': 443,
        'Flow Duration': 15_000_000,  # 15s
        'Flow Packets/s': 20,
        'Fwd Packet Length Mean': 200,
    })
    assert rules.check_dos(flow) is None


# ── Rule 4: Brute Force ─────────────────────────────────────────────────────

def test_brute_force_fires_on_repeated_ssh_attempts():
    flow = _flow(**{
        'Destination Port': 22,
        'Fwd Packet Length Mean': 50,
        'Flow Packets/s': 1,
        'Flow Duration': 60000,
        'Flow Bytes/s': 20,
    })
    result = rules.check_brute_force(flow)
    assert result is not None
    assert result['rule_name'] == "Brute Force Detected"


def test_brute_force_does_not_fire_on_unrelated_port():
    flow = _flow(**{
        'Destination Port': 443,
        'Fwd Packet Length Mean': 50,
        'Flow Packets/s': 1,
        'Flow Duration': 60000,
        'Flow Bytes/s': 20,
    })
    assert rules.check_brute_force(flow) is None


# ── Rule 5: Bot Activity ────────────────────────────────────────────────────

def test_bot_fires_on_high_rate_8080_traffic():
    flow = _flow(**{'Destination Port': 8080, 'Flow Packets/s': 21})
    assert rules.check_bot(flow) is not None


def test_bot_does_not_fire_below_rate_floor():
    flow = _flow(**{'Destination Port': 8080, 'Flow Packets/s': 20})
    assert rules.check_bot(flow) is None


# ── Rule 6: Web Attack ──────────────────────────────────────────────────────

def test_web_attack_fires_on_high_rate_moderate_packets():
    flow = _flow(**{
        'Destination Port': 443,
        'Flow Packets/s': rules.THRESHOLDS['web_attack_pps_floor'] + 1,
        'Fwd Packet Length Mean': 100,
        'Flow Bytes/s': 1000,
    })
    result = rules.check_web_attack(flow)
    assert result is not None
    assert result['rule_name'] == "Web Attack Detected"


def test_web_attack_does_not_fire_below_pps_floor():
    flow = _flow(**{
        'Destination Port': 443,
        'Flow Packets/s': rules.THRESHOLDS['web_attack_pps_floor'] - 1,
        'Fwd Packet Length Mean': 100,
        'Flow Bytes/s': 1000,
    })
    assert rules.check_web_attack(flow) is None


# ── Rule 7: NULL Scan ───────────────────────────────────────────────────────

def test_null_scan_fires_on_flagless_tiny_packets():
    flow = _flow(**{
        'Flow Packets/s': rules.THRESHOLDS['null_scan_pps_floor'] + 1,
        'Fwd Packet Length Mean': 40,
        'Destination Port': 8000,
    })
    result = rules.check_null_scan(flow)
    assert result is not None
    assert result['rule_name'] == "NULL Scan Detected"


def test_null_scan_excludes_dns_and_ntp_ports():
    flow = _flow(**{
        'Flow Packets/s': rules.THRESHOLDS['null_scan_pps_floor'] + 1,
        'Fwd Packet Length Mean': 40,
        'Destination Port': 53,
    })
    assert rules.check_null_scan(flow) is None


# ── Rule 8: Xmas Scan ───────────────────────────────────────────────────────

def test_xmas_scan_fires_on_fin_psh_combo():
    flow = _flow(**{'FIN Flag Count': 1, 'PSH Flag Count': 1, 'Fwd Packet Length Mean': 50})
    assert rules.check_xmas_scan(flow) is not None


def test_xmas_scan_does_not_fire_without_both_flags():
    flow = _flow(**{'FIN Flag Count': 1, 'PSH Flag Count': 0, 'Fwd Packet Length Mean': 50})
    assert rules.check_xmas_scan(flow) is None


# ── Rule 9: Telnet ───────────────────────────────────────────────────────────

def test_telnet_fires_on_port_23():
    assert rules.check_telnet(_flow(**{'Destination Port': 23})) is not None


def test_telnet_does_not_fire_on_other_ports():
    assert rules.check_telnet(_flow(**{'Destination Port': 22})) is None


# ── Rule 10: Suspicious Port ─────────────────────────────────────────────────

def test_suspicious_port_fires_on_known_malware_port():
    assert rules.check_suspicious_port(_flow(**{'Destination Port': 4444})) is not None


def test_suspicious_port_does_not_fire_on_ordinary_port():
    assert rules.check_suspicious_port(_flow(**{'Destination Port': 443})) is None


# ── Rule 11: DNS Tunnelling ───────────────────────────────────────────────────

def test_dns_tunneling_fires_on_high_entropy_query():
    flow = _flow(**{'Is DNS Flow': 1, 'DNS Query Entropy': 4.0})
    result = rules.check_dns_tunneling(flow)
    assert result is not None
    assert result['rule_name'] == "DNS Tunneling Detected"


def test_dns_tunneling_does_not_fire_on_ordinary_hostname_entropy():
    flow = _flow(**{'Is DNS Flow': 1, 'DNS Query Entropy': 2.0})
    assert rules.check_dns_tunneling(flow) is None


def test_dns_tunneling_requires_actual_dns_flow():
    # High entropy alone isn't enough - the flow must have actually parsed
    # as a DNS query. Guards against some unrelated field coincidentally
    # exceeding the entropy floor on a non-DNS flow.
    flow = _flow(**{'Is DNS Flow': 0, 'DNS Query Entropy': 5.0})
    assert rules.check_dns_tunneling(flow) is None


def test_dns_tunneling_fires_regardless_of_port():
    # Regression pin: this rule used to gate on Destination Port == 53,
    # which a tunnelling tool could dodge just by using another port.
    # It must fire from DNS-protocol structure alone, port-independent.
    flow = _flow(**{'Is DNS Flow': 1, 'DNS Query Entropy': 4.0, 'Destination Port': 5353})
    assert rules.check_dns_tunneling(flow) is not None


# ── Rule 12: ICMP Flood ──────────────────────────────────────────────────────

def test_icmp_flood_fires_on_extreme_small_packet_rate():
    flow = _flow(**{
        'Flow Packets/s': rules.THRESHOLDS['icmp_flood_pps_floor'] + 1,
        'Fwd Packet Length Mean': 50,
        'Flow Bytes/s': 2000,
        'Flow Duration': 2000,
    })
    assert rules.check_icmp_flood(flow) is not None


def test_icmp_flood_does_not_fire_below_pps_floor():
    flow = _flow(**{
        'Flow Packets/s': rules.THRESHOLDS['icmp_flood_pps_floor'] - 1,
        'Fwd Packet Length Mean': 50,
        'Flow Bytes/s': 2000,
        'Flow Duration': 2000,
    })
    assert rules.check_icmp_flood(flow) is None


# ── Rule 13: Large Payload ────────────────────────────────────────────────────

def test_large_payload_fires_above_60000_bytes():
    assert rules.check_large_payload(_flow(**{'Max Packet Length': 60001})) is not None


def test_large_payload_does_not_fire_at_normal_sizes():
    assert rules.check_large_payload(_flow(**{'Max Packet Length': 1500})) is None


# ── Rule 14: High Bandwidth Anomaly ──────────────────────────────────────────

def test_high_bandwidth_fires_above_floor():
    flow = _flow(**{
        'Flow Bytes/s': rules.THRESHOLDS['high_bandwidth_bytes_floor'] + 1,
        'Flow Duration': 2000,
        'Fwd Packet Length Mean': 500,
    })
    assert rules.check_high_bandwidth(flow) is not None


def test_high_bandwidth_does_not_fire_below_floor():
    flow = _flow(**{
        'Flow Bytes/s': rules.THRESHOLDS['high_bandwidth_bytes_floor'] - 1,
        'Flow Duration': 2000,
        'Fwd Packet Length Mean': 500,
    })
    assert rules.check_high_bandwidth(flow) is None


# ── THRESHOLDS are live, not baked in ────────────────────────────────────────

def test_thresholds_dict_has_all_expected_keys():
    expected = {
        "port_scan_pps_floor", "web_attack_pps_floor", "null_scan_pps_floor",
        "dos_pps_floor", "ddos_fwd_len_mean_floor", "icmp_flood_pps_floor",
        "high_bandwidth_bytes_floor", "ddos_min_fwd_packets",
    }
    assert expected.issubset(rules.THRESHOLDS.keys())
    assert all(v > 0 for k, v in rules.THRESHOLDS.items() if k in expected)


def test_rule_reads_threshold_live_not_at_import_time(monkeypatch):
    # If derive_thresholds.py regenerates thresholds.json with a new value,
    # the rule must pick it up without re-importing the module. Mutating the
    # dict directly simulates that and proves the function reads THRESHOLDS
    # at call time.
    monkeypatch.setitem(rules.THRESHOLDS, 'port_scan_pps_floor', 10)
    flow = _flow(**{'Flow Packets/s': 11, 'Fwd Packet Length Mean': 40, 'Flow Duration': 2000})
    assert rules.check_port_scan(flow) is not None  # fires under the patched, much lower floor


# ── run_rule_engine: most-severe-wins resolution ─────────────────────────────

def test_run_rule_engine_returns_none_for_clean_flow():
    assert rules.run_rule_engine(_flow()) is None


def test_run_rule_engine_picks_most_severe_of_multiple_matches():
    # Regression pin: this used to return the FIRST matching rule, so the
    # result depended on list order in ALL_RULES rather than actual severity.
    # This flow matches both check_suspicious_port (SEVERE) and
    # check_null_scan (HIGH) simultaneously - SEVERE must win.
    flow = _flow(**{
        'Destination Port': 4444,          # suspicious port (SEVERE)
        'Flow Packets/s': rules.THRESHOLDS['null_scan_pps_floor'] + 1,
        'Fwd Packet Length Mean': 40,      # also satisfies null scan (HIGH)
    })
    matches = rules.run_all_rules(flow)
    assert len(matches) >= 2  # both rules genuinely fired

    result = rules.run_rule_engine(flow)
    assert result['rule_name'] == "Suspicious Port Detected"
    assert result['severity'] == "SEVERE"
