"""Derive rules.py's hard-coded thresholds from real data instead of trial-and-error.

Every constant in rules.py (pps > 3000, byte-mean < 60, etc.) was originally
picked by testing and patched reactively when it false-positived - see the
bug-fix history in the project's session log. This script computes the same
numbers from the actual training dataset (CICIDS2017, the same dataset
train2.py trains the RF model on) instead: for each rule, find where a real,
already-validated synthetic attack sample sits in the Normal Traffic
distribution for the relevant feature, then set the threshold a few
percentile points below that - low enough to still catch the attack with
margin, high enough that it's a genuine outlier relative to normal traffic,
not an arbitrary guess.

Why not just take a fixed percentile (e.g. "always p99") uniformly: tried
that first. It silently BROKE two already-working detections - the DDoS
Fwd-Packet-Length-Mean floor jumped from a validated 500 to 1397 (above the
test attack's own ~654), and the DoS pps floor jumped from a validated 50 to
2384 (above the test attack's own 152). Anchoring each threshold to a real
attack sample's actual percentile rank, instead of a fixed percentile picked
in the abstract, is what catches that before it ships.

## Known-good attack sample values (from this session's synthetic PCAP tests,
## verified via analyse_pcap() to classify correctly under the CURRENT
## hand-picked thresholds before being used here as an anchor):
##   port_scan  : Flow Packets/s = 5008   (map_test4.pcap, 8.8.4.4)
##   web_attack : Flow Packets/s = 1252   (map_test4.pcap, 9.9.9.10)
##   null_scan  : Flow Packets/s = 334    (map_test4.pcap, 1.0.0.1)
##   dos        : Flow Packets/s = 152    (map_test3.pcap, 9.9.9.9)
##   ddos       : Fwd Packet Length Mean = 654   (map_test.pcap / map_test3.pcap, 8.8.8.8)
##   icmp_flood : Flow Packets/s = 20025      (icmp_flood_isolated.pcap, 8.8.4.9)
##   high_bw    : Flow Bytes/s   = 14,300,422  (icmp_bw_test.pcap, 9.9.9.30)
## Getting a clean icmp_flood sample required working around a real rule
## overlap, not just picking a big number: genuine small-packet high-pps
## floods also satisfy check_port_scan (fwd_len<60) and, once past that,
## check_null_scan (FIN=PSH=ACK=0 is automatic for non-TCP traffic, and
## null_scan's confidence of 82 beats icmp_flood's 80 in the tie-break) -
## meaning check_icmp_flood is structurally very hard to ever see reported
## as the verdict for a REAL ICMP flood under the current rule set. Isolated
## a clean sample by setting the TCP PSH flag (icmp_flood doesn't check it,
## null_scan requires it to be 0) specifically to validate the THRESHOLD
## NUMBER - the underlying overlap is a separate rule-design issue, noted
## here rather than fixed in this pass.

Run once, by hand, whenever the source dataset changes:
    python derive_thresholds.py

Writes thresholds.json next to this script. rules.py loads it at import time.
"""
import json
import os

import pandas as pd

DATASET_PATH = r"C:\HybridIDPS\data\cleaned\cleaned_full_dataset.csv"
OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "thresholds.json")

NEEDED_COLS = [
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Flow Duration",
    "Flow Bytes/s",
    "Total Fwd Packets",
    "Max Packet Length",
    "Attack Type",
]

MARGIN_PCT_POINTS = 3   # how far below the test sample's own percentile rank to set the floor
MIN_PCT = 50            # never go below the median regardless of margin math

print("Loading dataset (717MB / 2.5M rows, may take a minute)...")
df = pd.read_csv(DATASET_PATH, usecols=NEEDED_COLS, low_memory=False)

# The source CSV has a stray repeated-header row baked in as data
# ("Attack Type" literally appearing as a value) - drop it.
df = df[df["Attack Type"] != "Attack Type"]
for col in NEEDED_COLS[:-1]:
    df[col] = pd.to_numeric(df[col], errors="coerce")
df = df.dropna(subset=NEEDED_COLS[:-1])

normal_all = df[df["Attack Type"] == "Normal Traffic"]

# CICFlowMeter (CICIDS2017's feature-extraction tool) divides by Flow Duration
# to get Flow Packets/s and Flow Bytes/s. For very short flows (a handful of
# packets over a duration of only a few *microseconds*) that division blows
# up into numbers like 2,000,000 pps that have nothing to do with a real
# sustained rate - confirmed 22,629 Normal Traffic rows hit pps >= 1,000,000
# purely from 1-13 packet flows lasting 1-13 microseconds. Rate-based columns
# use this filtered subset; Total Fwd Packets / Max Packet Length are raw
# counts/sizes (not rates) and use the full normal set - filtering THEM on
# "Total Fwd Packets > 10" would be circular.
normal_rate = normal_all[
    (normal_all["Total Fwd Packets"] > 10) & (normal_all["Flow Duration"] > 1000)
]
print(f"Normal Traffic: {len(normal_all):,} rows total, "
      f"{len(normal_rate):,} after excluding degenerate near-zero-duration flows")


def safe_floor(col, source, test_value, label, safe_values=()):
    """Threshold a few percentile points below where `test_value` ranks in `source`.

    `safe_values` are OTHER known samples (normal traffic, a different attack
    type) that must NOT clear the resulting floor. First pass at this script
    only anchored below the target attack sample and missed exactly this -
    the DDoS byte-mean floor came out low enough that a normal 254-byte HTTPS
    test flow cleared it too (confirmed via regression test against
    map_test.pcap). If a safe_value would incorrectly clear the initial
    floor, raise the target percentile until it doesn't, bounded by the
    attack sample's own rank so it can never be pushed high enough to miss
    the attack it's meant to catch.
    """
    rank = (source[col] < test_value).mean() * 100
    target_pct = max(MIN_PCT, rank - MARGIN_PCT_POINTS)
    value = float(source[col].quantile(target_pct / 100))

    for safe_value in safe_values:
        while value <= safe_value and target_pct < rank - 0.1:
            target_pct = min(rank - 0.1, target_pct + 1)
            value = float(source[col].quantile(target_pct / 100))
        if value <= safe_value:
            print(f"  WARNING: {label} could not clear safe_value={safe_value} "
                  f"without exceeding the attack sample's own rank p{rank:.2f} - "
                  f"floor stays at {value:.2f}, review this rule's other AND "
                  f"conditions instead of relying on this feature alone.")

    print(f"  {label:<28} test={test_value:<10} rank=p{rank:5.2f}  "
          f"-> floor=p{target_pct:5.2f} = {value:.2f}"
          + (f"  (validated safe against {list(safe_values)})" if safe_values else ""))
    return round(value, 2), round(rank, 2)


# Known-safe reference samples this session's other tests produced, used to
# make sure a floor derived FOR one rule doesn't accidentally let a different,
# already-validated-safe or validated-as-a-different-attack-type flow through.
NORMAL_HTTPS_TEST = {"Flow Packets/s": 2, "Fwd Packet Length Mean": 254,
                      "Total Fwd Packets": 25, "Flow Bytes/s": 396}
WEB_ATTACK_TEST_PACKETS = 600  # must stay excluded from the DDoS packet-count gate specifically

print("\nValidated thresholds (anchored to real synthetic attack samples, "
      "checked against known-safe samples too):")
port_scan_floor, port_scan_rank   = safe_floor("Flow Packets/s", normal_rate, 5008, "port_scan_pps_floor")
web_attack_floor, web_attack_rank = safe_floor("Flow Packets/s", normal_rate, 1252, "web_attack_pps_floor")
null_scan_floor, null_scan_rank   = safe_floor("Flow Packets/s", normal_rate, 334,  "null_scan_pps_floor")
dos_floor, dos_rank               = safe_floor("Flow Packets/s", normal_rate, 152,  "dos_pps_floor")
ddos_len_floor, ddos_len_rank     = safe_floor(
    "Fwd Packet Length Mean", normal_all, 654, "ddos_fwd_len_mean_floor",
    safe_values=[NORMAL_HTTPS_TEST["Fwd Packet Length Mean"]],
)
ddos_pkts_floor, ddos_pkts_rank   = safe_floor(
    "Total Fwd Packets", normal_all, 700, "ddos_min_fwd_packets",
    safe_values=[NORMAL_HTTPS_TEST["Total Fwd Packets"]],
)
icmp_flood_floor, icmp_flood_rank = safe_floor(
    "Flow Packets/s", normal_rate, 20025, "icmp_flood_pps_floor",
    safe_values=[NORMAL_HTTPS_TEST["Flow Packets/s"]],
)
high_bw_floor, high_bw_rank       = safe_floor(
    "Flow Bytes/s", normal_rate, 14_300_422, "high_bandwidth_bytes_floor",
    safe_values=[NORMAL_HTTPS_TEST["Flow Bytes/s"]],
)

thresholds = {
    "_meta": {
        "source": DATASET_PATH,
        "normal_traffic_rows": int(len(normal_all)),
        "normal_traffic_rate_filtered_rows": int(len(normal_rate)),
        "method": "For validated_* entries: threshold sits MARGIN_PCT_POINTS below "
                  "the percentile rank of a real, already-classified-correctly "
                  "synthetic attack sample within Normal Traffic. For unvalidated "
                  "entries: fixed p99.5 (pps/bytes) or p90 (packet count) of "
                  "Normal Traffic, no attack-sample anchor available this session.",
        "validated": {
            "port_scan_pps_floor":     {"test_value": 5008, "test_percentile_rank": port_scan_rank},
            "web_attack_pps_floor":    {"test_value": 1252, "test_percentile_rank": web_attack_rank},
            "null_scan_pps_floor":     {"test_value": 334,  "test_percentile_rank": null_scan_rank},
            "dos_pps_floor":           {"test_value": 152,  "test_percentile_rank": dos_rank},
            "ddos_fwd_len_mean_floor": {"test_value": 654,  "test_percentile_rank": ddos_len_rank,
                                        "checked_safe_against": [NORMAL_HTTPS_TEST["Fwd Packet Length Mean"]]},
            "ddos_min_fwd_packets":    {"test_value": 700,  "test_percentile_rank": ddos_pkts_rank,
                                        "checked_safe_against": [NORMAL_HTTPS_TEST["Total Fwd Packets"]]},
            "icmp_flood_pps_floor":    {"test_value": 20025, "test_percentile_rank": icmp_flood_rank,
                                        "checked_safe_against": [NORMAL_HTTPS_TEST["Flow Packets/s"]],
                                        "note": "Sample isolated via a TCP PSH flag to work around a "
                                                "real overlap with check_port_scan/check_null_scan - "
                                                "see the module docstring."},
            "high_bandwidth_bytes_floor": {"test_value": 14300422, "test_percentile_rank": high_bw_rank,
                                            "checked_safe_against": [NORMAL_HTTPS_TEST["Flow Bytes/s"]]},
        },
        "unvalidated": [],
    },
    "port_scan_pps_floor": port_scan_floor,
    "web_attack_pps_floor": web_attack_floor,
    "null_scan_pps_floor": null_scan_floor,
    "dos_pps_floor": dos_floor,
    "ddos_fwd_len_mean_floor": ddos_len_floor,
    "icmp_flood_pps_floor": icmp_flood_floor,
    "high_bandwidth_bytes_floor": high_bw_floor,
    "ddos_min_fwd_packets": ddos_pkts_floor,
}

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump(thresholds, f, indent=2)

print(f"\nWrote {OUT_PATH}")
