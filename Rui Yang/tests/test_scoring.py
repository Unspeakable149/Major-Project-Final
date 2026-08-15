"""Unit tests for the composite threat-scoring model (scoring.py).

Covers each sub-score's boundary bands individually (so threshold drift
fails loud and points at the exact band that moved), then
compute_threat_score() end-to-end for the cases that matter most:
  - the Normal-Traffic zero-score gate - this pins a real historical bug
    where severity_score()'s default (15 for any unlisted reason) leaked a
    nonzero score onto flows the report itself was labelling "Safe";
  - score capping at 0-100;
  - the full breakdown dict shape the report layer depends on.
"""

import pytest

import scoring


# ── Per-factor bucket helpers ────────────────────────────────────────────────

@pytest.mark.parametrize("pps, expected", [
    (0, 0), (19, 0), (20, 5), (99, 5), (100, 10),
    (299, 10), (300, 15), (699, 15), (700, 20), (5000, 20),
])
def test_frequency_score(pps, expected):
    assert scoring.frequency_score({'Flow Packets/s': pps}) == expected


@pytest.mark.parametrize("prior, expected", [
    (0, 0), (1, 3), (5, 3), (6, 6), (10, 6), (11, 10), (500, 10),
])
def test_historical_score(prior, expected):
    assert scoring.historical_score(prior) == expected


@pytest.mark.parametrize("rule_conf, attack_prob, expected", [
    (0, 0.0, 5),
    (50, 0.0, 5),
    (60, 0.0, 10),
    (80, 0.0, 10),
    (0, 0.81, 15),   # ML probability alone can push it into the top band
    (99, 0.0, 15),
])
def test_confidence_score(rule_conf, attack_prob, expected):
    assert scoring.confidence_score(rule_conf, attack_prob) == expected


@pytest.mark.parametrize("score, level", [
    (0, "Normal"), (20, "Normal"), (21, "Low"), (40, "Low"),
    (41, "Medium"), (60, "Medium"), (61, "High"), (80, "High"),
    (81, "Critical"), (100, "Critical"),
])
def test_threat_level(score, level):
    result_level, emoji = scoring.threat_level(score)
    assert result_level == level
    assert emoji  # every band has some emoji, don't care which exact one


def test_behaviour_score_no_indicators_is_normal():
    features = {
        'Destination Port': 443, 'Flow Bytes/s': 100, 'Flow Packets/s': 5,
        'FIN Flag Count': 1, 'PSH Flag Count': 1, 'ACK Flag Count': 1,
    }
    assert scoring.behaviour_score(features) == 0


def test_behaviour_score_saturates_at_three_plus_indicators():
    features = {
        'Destination Port': 8080,           # unusual port -> flag
        'Flow Bytes/s': 2_000_000,          # bandwidth spike -> flag
        'Flow Packets/s': 5000,             # high rate -> flag
        'FIN Flag Count': 0, 'PSH Flag Count': 0, 'ACK Flag Count': 0,  # stealth -> flag
    }
    assert scoring.behaviour_score(features) == 15


@pytest.mark.parametrize("port, expected_points", [
    (22, 10), (3389, 10),      # remote shell/desktop - worst case
    (3306, 8), (445, 8),       # database / file share
    (53, 6), (88, 6),          # infrastructure / auth
    (443, 0), (0, 0),          # ordinary port - no bonus
])
def test_critical_port_score(port, expected_points):
    points, _label = scoring.critical_port_score({'Destination Port': port})
    assert points == expected_points


def test_critical_port_score_label_present_only_when_scored():
    points, label = scoring.critical_port_score({'Destination Port': 22})
    assert points > 0 and label is not None
    points, label = scoring.critical_port_score({'Destination Port': 443})
    assert points == 0 and label is None


def test_false_positive_reduction_penalises_ml_disagreement():
    features = {'Total Fwd Packets': 100}
    reduction = scoring.false_positive_reduction(features, rule_fired=True, attack_prob=0.01)
    assert reduction == 5


def test_false_positive_reduction_penalises_low_volume():
    features = {'Total Fwd Packets': 2}
    reduction = scoring.false_positive_reduction(features, rule_fired=False, attack_prob=0.5)
    assert reduction == 3


def test_false_positive_reduction_stacks():
    features = {'Total Fwd Packets': 2}
    reduction = scoring.false_positive_reduction(features, rule_fired=True, attack_prob=0.01)
    assert reduction == 8  # both penalties apply


def test_severity_score_known_and_unknown_reasons():
    assert scoring.severity_score("DDoS Attack Detected") == 38
    assert scoring.severity_score("Suspicious Port Detected") == 40
    assert scoring.severity_score("Some Future Rule Nobody Added Yet") == 15  # documented default


# ── compute_threat_score end-to-end ──────────────────────────────────────────

def _score(**over):
    base = dict(
        features={'Flow Packets/s': 5, 'Destination Port': 443, 'Total Fwd Packets': 50},
        reason="Some Attack Detected",
        rule_conf=80,
        attack_prob=0.5,
        rule_fired=True,
        prev_incidents=0,
    )
    base.update(over)
    return scoring.compute_threat_score(**base)


def test_normal_traffic_scores_zero_even_with_unlisted_reason():
    # Regression pin: severity_score()'s default of 15 for any reason not in
    # SEVERITY_BY_RULE used to leak onto flows already labelled Safe by the
    # report layer, since "Normal Traffic" was never in that lookup table.
    r = _score(reason="Normal Traffic", rule_fired=False, attack_prob=0.02)
    assert r["score"] == 0
    assert r["level"] == "Normal"
    assert all(v == 0 for v in r["breakdown"].values())


def test_normal_traffic_gate_requires_rule_not_fired():
    # A flow with reason "Normal Traffic" that a rule DID fire on (edge case,
    # shouldn't happen in practice, but the gate is specifically `not
    # rule_fired`) must NOT be silently zeroed - only genuinely-safe flows
    # should hit the shortcut.
    r = _score(reason="Normal Traffic", rule_fired=True, attack_prob=0.9, rule_conf=90)
    assert r["score"] > 0


def test_severe_flow_scores_high():
    r = _score(
        features={'Flow Packets/s': 5000, 'Destination Port': 22, 'Total Fwd Packets': 500,
                   'Flow Bytes/s': 2_000_000, 'FIN Flag Count': 0, 'PSH Flag Count': 0,
                   'ACK Flag Count': 0},
        reason="DDoS Attack Detected",
        rule_conf=95, attack_prob=0.95, rule_fired=True, prev_incidents=12,
    )
    assert r["score"] >= 80
    assert r["level"] == "Critical"
    assert r["breakdown"]["Severity"] == 38
    assert r["critical_port"] is not None  # port 22 -> SSH bonus


def test_score_never_exceeds_100():
    r = _score(
        features={'Flow Packets/s': 99999, 'Destination Port': 22, 'Total Fwd Packets': 99999,
                   'Flow Bytes/s': 99_000_000, 'FIN Flag Count': 0, 'PSH Flag Count': 0,
                   'ACK Flag Count': 0},
        reason="Suspicious Port Detected",
        rule_conf=100, attack_prob=1.0, rule_fired=True, prev_incidents=999,
    )
    assert 0 <= r["score"] <= 100


def test_score_never_goes_negative():
    # A flow with every false-positive-reduction penalty stacked and a low
    # base severity shouldn't be able to push the total below 0.
    r = _score(
        features={'Flow Packets/s': 1, 'Destination Port': 0, 'Total Fwd Packets': 1},
        reason="Port Scan Detected",  # low severity (15)
        rule_conf=10, attack_prob=0.0, rule_fired=True, prev_incidents=0,
    )
    assert r["score"] >= 0


def test_breakdown_shape_matches_report_expectations():
    r = _score()
    assert set(r["breakdown"]) == {
        "Severity", "Frequency", "Behaviour", "Confidence",
        "Historical", "Critical Port", "FP Reduction",
    }
    assert set(r) == {"score", "level", "emoji", "critical_port", "breakdown"}
