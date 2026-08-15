"""Composite Threat Scoring — Enhancement Ideas 2-8 (Rui Yang FYP).

Implements the additive scoring model from the enhancement brief:

    Threat Score = Severity + Frequency + Behaviour + Confidence + Historical
                   - False-Positive Reduction

Each sub-score is derived DYNAMICALLY from the flow's extracted features and the
rule/ML result, so the numbers change per flow rather than being fixed. The
score is capped to 0-100 and mapped to a 5-tier threat level.

This module is import-only (no Streamlit page calls) so it can be used by the
PCAP engine and the report layer alike.
"""

# ── Idea 3: base severity per attack type ────────────────────
# Values seeded from the enhancement brief, extended for the 14 rules that
# actually exist in rules.py. Justify these in the report via literature review.
SEVERITY_BY_RULE = {
    "Port Scan Detected":       15,
    "DDoS Attack Detected":     38,
    "DoS Attack Detected":      30,
    "Brute Force Detected":     28,
    "Bot Activity Detected":    30,
    "Web Attack Detected":      25,
    "NULL Scan Detected":       18,
    "Xmas Scan Detected":       18,
    "Telnet Usage Detected":    12,
    "Suspicious Port Detected": 40,   # known malware port → highest
    "DNS Tunneling Detected":   35,
    "ICMP Flood Detected":      28,
    "Oversized Packet Detected":20,
    "High Bandwidth Anomaly":   22,
    "ML Anomaly Detected":      20,   # ML-only detection
}


def severity_score(reason):
    """Idea 3 — initial severity based on detected attack type."""
    return SEVERITY_BY_RULE.get(reason, 15)


# ── Critical-service port modifier (context-aware severity) ──
# CVSS-style idea: the SAME attack is more dangerous against a high-value
# service. An attack hitting SSH/RDP/DB/domain ports gets a small bonus, because
# a compromise there has far greater impact than against an arbitrary port.
CRITICAL_PORTS = {
    22:   "SSH (remote shell)",
    23:   "Telnet (remote shell)",
    3389: "RDP (remote desktop)",
    3306: "MySQL database",
    5432: "PostgreSQL database",
    1433: "MS SQL database",
    53:   "DNS (name resolution)",
    445:  "SMB (file sharing)",
    389:  "LDAP (directory)",
    88:   "Kerberos (auth)",
}


def critical_port_score(features):
    """Bonus (max 10) when the attack targets a critical-service port.

    Returns (points, label). Points scale with how sensitive the service is:
    remote-shell / database / auth ports weigh most.
    """
    port = features.get('Destination Port', 0)
    if port in (22, 23, 3389):          # remote shell / desktop — worst case
        return 10, CRITICAL_PORTS[port]
    if port in (3306, 5432, 1433, 445): # database / file share
        return 8, CRITICAL_PORTS[port]
    if port in (53, 389, 88):           # infrastructure / auth
        return 6, CRITICAL_PORTS[port]
    return 0, None


def frequency_score(features):
    """Idea 4 — packets/sec banding (max 20)."""
    pps = features.get('Flow Packets/s', 0)
    if pps < 20:    return 0
    if pps < 100:   return 5
    if pps < 300:   return 10
    if pps < 700:   return 15
    return 20


def behaviour_score(features):
    """Idea 5 — behavioural anomaly indicators (max 15).

    Each abnormal indicator adds a point of concern; the total is banded into
    Normal / Slightly / Moderately / Highly abnormal -> 0 / 5 / 10 / 15.
    """
    flags = 0

    # Accessing an unusual/high destination port
    port = features.get('Destination Port', 0)
    if port in (4444, 1337, 31337, 6666, 6667, 6668, 8080):
        flags += 1

    # Sudden bandwidth spike
    if features.get('Flow Bytes/s', 0) > 1_000_000:
        flags += 1

    # Very high packet rate (recon / flood behaviour)
    if features.get('Flow Packets/s', 0) > 1000:
        flags += 1

    # No-flag / stealth style packets (possible scan)
    if (features.get('FIN Flag Count', 0) == 0 and
            features.get('PSH Flag Count', 0) == 0 and
            features.get('ACK Flag Count', 0) == 0):
        flags += 1

    # Oversized DNS (tunnelling indicator)
    if port == 53 and features.get('Fwd Packet Length Mean', 0) > 200:
        flags += 1

    if flags == 0:  return 0
    if flags == 1:  return 5
    if flags == 2:  return 10
    return 15


def confidence_score(rule_conf, attack_prob):
    """Idea 7 — detection confidence banding (max 15).

    Uses the stronger of the rule confidence and the ML probability so a
    high-certainty detection from either source is rewarded.
    """
    conf_pct = max(rule_conf, attack_prob * 100)
    if conf_pct < 60:   return 5
    if conf_pct <= 80:  return 10
    return 15


def historical_score(prev_incidents):
    """Idea 6 — repeat-offender scoring (max 10).

    prev_incidents = how many times this source IP has already appeared as an
    attacker in the current PCAP (a simple in-session history).
    """
    if prev_incidents <= 0:   return 0
    if prev_incidents <= 5:   return 3
    if prev_incidents <= 10:  return 6
    return 10


def false_positive_reduction(features, rule_fired, attack_prob):
    """Idea 2 — subtract points when a detection looks like a likely FP.

    Keeps the score honest: if the rule fired but ML strongly disagrees, or the
    traffic volume is trivially small, we shave points off.
    """
    reduction = 0
    # Rule fired but ML is very confident it's benign
    if rule_fired and attack_prob < 0.05:
        reduction += 5
    # Extremely low volume flow — little evidence
    if features.get('Total Fwd Packets', 0) < 5:
        reduction += 3
    return reduction


# ── Idea 8: final score + 5-tier level ───────────────────────
def threat_level(score):
    if score <= 20:   return "Normal",   "🟢"
    if score <= 40:   return "Low",      "🔵"
    if score <= 60:   return "Medium",   "🟡"
    if score <= 80:   return "High",     "🟠"
    return "Critical", "🔴"


def compute_threat_score(features, reason, rule_conf, attack_prob,
                         rule_fired, prev_incidents=0):
    """Idea 2 + 8 — combine all components into a final 0-100 score.

    Returns a dict with the total, level, emoji and the per-component breakdown
    (so the report can show exactly how the number was built).
    """
    # Gate on the verdict (mirrors the "FP reduction" design principle): a flow
    # neither rule- nor ML-flagged is Normal Traffic and must score 0. Without
    # this, severity_score()'s default (15 for any unlisted reason) leaked a
    # nonzero score onto flows the report itself was labelling "Safe".
    if reason == "Normal Traffic" and not rule_fired:
        return {
            "score": 0, "level": "Normal", "emoji": "🟢", "critical_port": None,
            "breakdown": {
                "Severity": 0, "Frequency": 0, "Behaviour": 0,
                "Confidence": 0, "Historical": 0, "Critical Port": 0,
                "FP Reduction": 0,
            },
        }

    sev  = severity_score(reason)
    freq = frequency_score(features)
    beh  = behaviour_score(features)
    conf = confidence_score(rule_conf, attack_prob)
    hist = historical_score(prev_incidents)
    fpr  = false_positive_reduction(features, rule_fired, attack_prob)
    port_bonus, port_label = critical_port_score(features)

    total = sev + freq + beh + conf + hist + port_bonus - fpr
    total = max(0, min(total, 100))

    level, emoji = threat_level(total)

    return {
        "score":  total,
        "level":  level,
        "emoji":  emoji,
        "critical_port": port_label,   # None if not a critical-service port
        "breakdown": {
            "Severity":   sev,
            "Frequency":  freq,
            "Behaviour":  beh,
            "Confidence": conf,
            "Historical": hist,
            "Critical Port": port_bonus,
            "FP Reduction": -fpr,
        },
    }
