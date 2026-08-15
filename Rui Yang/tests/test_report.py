"""Unit tests for the report-building helpers (report.py).

get_ip_location is always dependency-injected by the caller (pcap_engine),
so these tests use a plain fake instead of hitting the real ip-api.com -
report.py itself has zero network dependency and these tests keep it that
way.
"""

import pandas as pd
import pytest

import report


def _fake_geo(ip):
    """Canned GeoIP responses for a couple of test IPs; None (private) for
    anything else, matching get_ip_location's real contract."""
    known = {
        "8.8.8.8": {"city": "Mountain View", "country": "United States", "isp": "Google LLC"},
        "1.1.1.1": {"city": "Sydney", "country": "Australia", "isp": "Cloudflare"},
    }
    return known.get(ip)


def _alerts_df(rows):
    """rows: list of dicts with at least 'Src IP' and 'Reason'."""
    defaults = {
        "Dst IP": "10.0.0.5", "Port": 443, "Pkts/s": 100, "Bytes/s": 1000,
        "Avg Packet Size": 200, "Duration (s)": 1.0, "Prior Hits": 0,
        "Threat Score": 50, "Threat Level": "🟡 Medium",
    }
    full_rows = []
    for r in rows:
        row = dict(defaults)
        row.update(r)
        full_rows.append(row)
    return pd.DataFrame(full_rows)


# ── build_reasons / build_actions ────────────────────────────────────────────

def test_build_reasons_covers_flood_and_scan_types():
    df = _alerts_df([
        {"Src IP": "8.8.8.8", "Reason": "Port Scan Detected"},
        {"Src IP": "1.1.1.1", "Reason": "DDoS Attack Detected"},
    ])
    reasons = report.build_reasons(df)
    joined = " ".join(reasons)
    assert "reconnaissance" in joined.lower() or "port-scanning" in joined.lower()
    assert "flood" in joined.lower()
    # the quantitative evidence line should always be present
    assert any("2 distinct source IP" in r or "2 suspicious flow" in r for r in reasons)


def test_build_actions_always_includes_baseline_actions():
    df = _alerts_df([{"Src IP": "8.8.8.8", "Reason": "Telnet Usage Detected"}])
    actions = report.build_actions(df)
    assert any("preserve" in a.lower() for a in actions)
    assert any("telnet" in a.lower() for a in actions)


# ── attack_breakdown ──────────────────────────────────────────────────────────

def test_attack_breakdown_counts_by_reason():
    df = _alerts_df([
        {"Src IP": "8.8.8.8", "Reason": "DDoS Attack Detected"},
        {"Src IP": "1.1.1.1", "Reason": "DDoS Attack Detected"},
        {"Src IP": "9.9.9.9", "Reason": "Port Scan Detected"},
    ])
    breakdown = report.attack_breakdown(df)
    assert breakdown["DDoS Attack Detected"] == 2
    assert breakdown["Port Scan Detected"] == 1


# ── top_attackers ─────────────────────────────────────────────────────────────

def test_top_attackers_resolves_known_ip_and_flags_private():
    df = _alerts_df([
        {"Src IP": "8.8.8.8", "Reason": "DDoS Attack Detected"},
        {"Src IP": "10.0.0.1", "Reason": "Port Scan Detected"},  # private, no geo
    ])
    rows = report.top_attackers(df, _fake_geo, limit=5)
    by_ip = {r["ip"]: r for r in rows}
    assert "Mountain View" in by_ip["8.8.8.8"]["origin"]
    assert by_ip["10.0.0.1"]["origin"] == "Private / local address"


def test_top_attackers_respects_limit():
    df = _alerts_df([{"Src IP": f"1.1.1.{i}", "Reason": "DDoS"} for i in range(10)])
    rows = report.top_attackers(df, lambda ip: None, limit=3)
    assert len(rows) == 3


# ── reason_for_attack / action_for_attack lookup ─────────────────────────────

@pytest.mark.parametrize("reason,expected_snippet", [
    ("Port Scan Detected", "Reconnaissance"),
    ("DDoS Attack Detected", "Flooding"),
    ("Brute Force Detected", "credential-guessing"),
    ("DNS Tunneling Detected", "DNS"),
])
def test_reason_for_attack_known_types(reason, expected_snippet):
    assert expected_snippet.lower() in report.reason_for_attack(reason).lower()


def test_reason_for_attack_unknown_type_falls_back_to_default():
    result = report.reason_for_attack("Some Brand New Rule Nobody Wrote Yet")
    assert "detection engine" in result.lower()


def test_action_for_attack_unknown_type_falls_back_to_default():
    result = report.action_for_attack("Some Brand New Rule Nobody Wrote Yet")
    assert "preserve the logs" in result.lower()


# ── dynamic_reason / dynamic_action ───────────────────────────────────────────

def test_dynamic_reason_weaves_in_real_flow_values():
    row = pd.Series({
        "Src IP": "8.8.8.8", "Port": 443, "Pkts/s": 3338, "Bytes/s": 2_000_000,
        "Avg Packet Size": 640, "Duration (s)": 0.21, "Prior Hits": 0,
        "Reason": "DDoS Attack Detected",
    })
    text = report.dynamic_reason(row, _fake_geo("8.8.8.8"))
    assert "8.8.8.8" in text
    assert "443" in text
    assert "3338" in text
    assert "repeat offender" not in text.lower()  # Prior Hits == 0


def test_dynamic_reason_flags_repeat_offenders():
    row = pd.Series({
        "Src IP": "8.8.8.8", "Port": 443, "Pkts/s": 100, "Bytes/s": 1000,
        "Avg Packet Size": 200, "Duration (s)": 1.0, "Prior Hits": 5,
        "Reason": "DDoS Attack Detected",
    })
    text = report.dynamic_reason(row, None)
    assert "repeat offender" in text.lower()
    assert "5 prior incident" in text


def test_dynamic_action_recommends_escalation_for_repeat_offenders():
    row = pd.Series({"Src IP": "8.8.8.8", "Port": 443, "Prior Hits": 3,
                      "Reason": "DDoS Attack Detected"})
    text = report.dynamic_action(row, None)
    assert "block 8.8.8.8" in text.lower()
    assert "escalation" in text.lower()


# ── rank_by_threat_score ──────────────────────────────────────────────────────

def test_rank_by_threat_score_orders_highest_first():
    # Deliberately built out of order, mirroring the real bug this fixed:
    # reports used to show whichever flow appeared first in the file.
    df = _alerts_df([
        {"Src IP": "a", "Reason": "Port Scan Detected", "Threat Score": 58},
        {"Src IP": "b", "Reason": "DDoS Attack Detected", "Threat Score": 86},
        {"Src IP": "c", "Reason": "DoS Attack Detected", "Threat Score": 48},
    ])
    ranked = report.rank_by_threat_score(df)
    assert list(ranked["Src IP"]) == ["b", "a", "c"]
    assert list(ranked["Threat Score"]) == [86, 58, 48]


def test_rank_by_threat_score_does_not_mutate_input():
    df = _alerts_df([
        {"Src IP": "a", "Reason": "x", "Threat Score": 10},
        {"Src IP": "b", "Reason": "y", "Threat Score": 90},
    ])
    original_order = list(df["Src IP"])
    report.rank_by_threat_score(df)
    assert list(df["Src IP"]) == original_order


# ── per_attack_cards ──────────────────────────────────────────────────────────

def test_per_attack_cards_builds_one_card_per_row_in_given_order():
    df = _alerts_df([
        {"Src IP": "8.8.8.8", "Reason": "DDoS Attack Detected", "Threat Score": 86,
         "Threat Level": "🔴 Critical"},
        {"Src IP": "1.1.1.1", "Reason": "Port Scan Detected", "Threat Score": 58,
         "Threat Level": "🟡 Medium"},
    ])
    cards = report.per_attack_cards(df, _fake_geo)
    assert len(cards) == 2
    assert cards[0]["src"] == "8.8.8.8"
    assert cards[0]["score"] == 86
    assert "Mountain View" in cards[0]["origin"]
    assert cards[0]["why"]  # dynamic_reason text present
    assert cards[0]["action"]  # dynamic_action text present
