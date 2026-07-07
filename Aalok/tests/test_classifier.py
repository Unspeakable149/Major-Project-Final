"""Unit tests for the heuristic rule engine in live_backend.

Covers:
    - classify_profile(): per-window pps/sar/ports/avg_size rule table.
    - slow_attack_check(): multi-window rolling rules for slow scans and
      sustained SYN beacons.

Tests assert exact (profile, threat) tuples so threshold drift fails loud.
"""

import pytest

import live_backend


# classify_profile tests

@pytest.mark.parametrize("pps, sar, ports, avg_size, expected", [
    (600, 10, 1, 200, ("DDoS SYN Flood", "Severe (Critical Anomaly)")),
    (2000, 1, 1, 500, ("High-Volume Flood Attack", "Severe (Critical Anomaly)")),
    (400, 1, 1, 900, ("Speed Test / Large Data Transfer", "Moderate (Bandwidth Spike)")),
    (10, 1, 50, 80, ("Port Scan / Reconnaissance", "Moderate (Suspicious)")),
    (2, 1, 1, 80, ("Ping / Background Telemetry", "Baseline (Safe)")),
    (50, 1, 2, 500, ("Standard Web Traffic", "Baseline (Safe)")),
])
def test_classify_profile(pps, sar, ports, avg_size, expected):
    assert live_backend.classify_profile(pps, sar, ports, avg_size) == expected


# slow_attack_check tests

def _rolling(windows, packets=0, unique_ports=0, syn=0):
    return {
        "rolling_windows": windows,
        "rolling_packets": packets,
        "rolling_unique_ports": unique_ports,
        "rolling_syn": syn,
    }


def test_slow_attack_below_window_threshold():
    assert live_backend.slow_attack_check(_rolling(3, packets=999, unique_ports=999, syn=999)) is None


def test_slow_attack_port_scan():
    result = live_backend.slow_attack_check(
        _rolling(10, packets=100, unique_ports=80, syn=0)
    )
    assert result == ("Slow Port Scan (multi-window)", "Moderate (Suspicious)")


def test_slow_attack_sustained_syn():
    result = live_backend.slow_attack_check(
        _rolling(10, packets=300, unique_ports=10, syn=200)
    )
    assert result == ("Sustained SYN / Brute-Force Probe", "Moderate (Suspicious)")


def test_slow_attack_quiet_history():
    assert live_backend.slow_attack_check(
        _rolling(10, packets=10, unique_ports=10, syn=10)
    ) is None


# dns_tunnel_check tests

def test_dns_tunnel_fires_above_threshold():
    # WINDOW_SECONDS=2, threshold > 30 pps => need > 60 packets in window.
    rows = [{'Protocol': 'DNS', 'packets': 61}]
    assert live_backend.dns_tunnel_check(rows) == (
        "DNS Tunnel / C2 Channel", "Moderate (Suspicious)"
    )


def test_dns_tunnel_silent_below_threshold():
    rows = [{'Protocol': 'DNS', 'packets': 60}]
    assert live_backend.dns_tunnel_check(rows) is None


def test_dns_tunnel_ignores_non_dns():
    rows = [
        {'Protocol': 'TCP', 'packets': 5000},
        {'Protocol': 'UDP', 'packets': 5000},
        {'Protocol': 'HTTP', 'packets': 5000},
    ]
    assert live_backend.dns_tunnel_check(rows) is None


def test_dns_tunnel_empty_rows():
    assert live_backend.dns_tunnel_check([]) is None
