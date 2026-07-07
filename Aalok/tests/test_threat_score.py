"""Unit tests for the Threat Scoring model in live_backend.

Covers the FYP "Threat Level Hunting" enhancement:
    - the per-factor bucket helpers (frequency / behaviour / confidence /
      historical) so threshold drift fails loud;
    - compute_threat_score() end-to-end: benign short-circuit (false-positive
      reduction), band mapping, the intel floor, and the analyst-report shape.
"""

import pytest

import live_backend as lb


# ── Per-factor bucket helpers ─────────────────────────────────────────────────

@pytest.mark.parametrize("pps, expected", [
    (0, 0), (19, 0), (20, 5), (99, 5), (100, 10),
    (299, 10), (300, 15), (699, 15), (700, 20), (5000, 20),
])
def test_frequency_score(pps, expected):
    assert lb._frequency_score(pps) == expected


@pytest.mark.parametrize("prior, expected", [
    (0, 0), (1, 3), (5, 3), (6, 6), (10, 6), (11, 10), (500, 10),
])
def test_historical_score(prior, expected):
    assert lb._historical_score(prior) == expected


@pytest.mark.parametrize("conf, use_rf, expected", [
    (0.0, False, 5),   # clustering model -> low bucket
    (0.50, True, 5),
    (0.60, True, 10),
    (0.80, True, 10),
    (0.81, True, 15),
    (0.99, True, 15),
])
def test_confidence_score(conf, use_rf, expected):
    pts, _note = lb._confidence_score(conf, use_rf)
    assert pts == expected


def test_behaviour_score_bands():
    # No abnormal indicators -> Normal (0).
    band, notes = lb._behaviour_score(2, 1.0, 0, 10, 1)
    assert band == 0 and notes == []
    # Three+ indicators saturate at Highly Abnormal (15).
    band, notes = lb._behaviour_score(50, 9.0, 40, 5, 20)
    assert band == 15 and len(notes) >= 3


@pytest.mark.parametrize("score, band", [
    (0, "Normal"), (20, "Normal"), (21, "Low"), (40, "Low"),
    (41, "Medium"), (60, "Medium"), (61, "High"), (80, "High"),
    (81, "Critical"), (100, "Critical"),
])
def test_band_for(score, band):
    assert lb._band_for(score) == band


# ── compute_threat_score end-to-end ───────────────────────────────────────────

def _score(**over):
    base = dict(
        profile="Standard Web Traffic", threat="Baseline (Safe)", pps=5,
        syn_ack_ratio=1.0, unique_ports=2, rst_flags=0, ack_flags=10,
        unique_ips=1, confidence=0.9, use_rf=True, prior_incidents=0,
        intel_hit=False, baseline_hit=False,
    )
    base.update(over)
    return lb.compute_threat_score(**base)


def test_benign_flow_scores_zero():
    r = _score()
    assert r["score"] == 0 and r["band"] == "Normal"


def test_false_positive_reduction_on_heavy_baseline():
    # High-rate traffic the fusion engine still rules Baseline (e.g. a speed
    # test) must not accumulate a score -> the FP-reduction term zeroes it.
    r = _score(profile="Speed Test / Large Data Transfer", pps=900)
    assert r["score"] == 0 and r["band"] == "Normal"


def test_whitelisted_source_forced_to_zero():
    r = _score(profile="DDoS SYN Flood", threat="Severe (Critical Anomaly)",
               pps=1500, syn_ack_ratio=40, baseline_hit=True)
    assert r["score"] == 0


def test_severe_flow_scores_high():
    r = _score(profile="DDoS SYN Flood", threat="Severe (Critical Anomaly)",
               pps=1500, syn_ack_ratio=40, rst_flags=5, ack_flags=2,
               prior_incidents=12, confidence=0.95)
    assert r["score"] >= 80 and r["band"] == "Critical"
    assert r["breakdown"]["Severity"] == 30
    assert r["breakdown"]["Frequency"] == 20


def test_score_never_exceeds_100():
    r = _score(profile="High-Volume Flood Attack", threat="Severe (Critical Anomaly)",
               pps=5000, syn_ack_ratio=99, unique_ports=99, rst_flags=99,
               ack_flags=1, unique_ips=99, prior_incidents=99, confidence=1.0)
    assert 0 <= r["score"] <= 100


def test_intel_match_floored_to_high():
    # A known-malicious IP sending little traffic is still floored into High.
    r = _score(profile="Known Malicious IP (Threat Intel Match)",
               threat="Severe (Critical Anomaly)", pps=10, confidence=0.0,
               use_rf=False, intel_hit=True)
    assert r["score"] >= 75 and r["band"] in ("High", "Critical")


def test_report_shape():
    r = _score(profile="Port Scan / Reconnaissance", threat="Moderate (Suspicious)",
               pps=250, syn_ack_ratio=8, unique_ports=45)
    assert isinstance(r["reasons"], list) and r["reasons"]
    assert isinstance(r["actions"], list) and r["actions"]
    assert set(r["breakdown"]) == {
        "Severity", "Frequency", "Behaviour", "Historical",
        "Confidence", "FP Reduction",
    }
