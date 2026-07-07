"""Unit tests for engineer_flows().

Edge cases covered:
    - Empty input -> empty output (no crash).
    - All Source IPs blank/NaN -> empty output with proper columns.
    - Single-packet flow -> one row, duration clamped to 0.1s (no div-by-zero).

Inputs are constructed in the already-cleaned shape that clean_packets()
produces, so the tests stay decoupled from tshark / CSV parsing.
"""

import numpy as np
import pandas as pd

import live_backend


# clean_packets() derives Dest Port, Source Port and Transport from the raw
# tshark columns, so the already-cleaned shape these tests feed engineer_flows
# must include all three (engineer_flows aggregates Transport / Source Port).
CLEANED_COLUMNS = live_backend.RAW_COLUMNS + ["Dest Port", "Source Port", "Transport"]


def _empty_cleaned_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=CLEANED_COLUMNS)


def _packet_row(src_ip="10.0.0.1", dst_ip="10.0.0.2", ts=1700000000.0,
                size=100, syn=0, ack=0, fin=0, rst=0, ttl=64,
                win=1024, dst_port=80):
    return {
        "Timestamp": ts,
        "Source IP": src_ip,
        "Dest IP": dst_ip,
        "TCP Src": 12345,
        "UDP Src": 0,
        "TCP Dst": dst_port,
        "UDP Dst": 0,
        "Protocol": "TCP",
        "Packet Size": size,
        "SYN Flag": syn,
        "ACK Flag": ack,
        "FIN Flag": fin,
        "RST Flag": rst,
        "TTL": ttl,
        "Window Size": win,
        "Dest Port": dst_port,
        "Source Port": 12345,
        "Transport": "TCP",
    }


def test_engineer_flows_empty_input():
    out = live_backend.engineer_flows(_empty_cleaned_frame())
    assert out.empty
    for col in live_backend.FEATURE_COLS:
        assert col in out.columns
    assert "Source IP" in out.columns


def test_engineer_flows_all_blank_source_ips():
    rows = [
        _packet_row(src_ip=""),
        _packet_row(src_ip="nan"),
        _packet_row(src_ip="NaN"),
        _packet_row(src_ip="   "),
    ]
    df = pd.DataFrame(rows, columns=CLEANED_COLUMNS)
    out = live_backend.engineer_flows(df)
    assert out.empty
    for col in live_backend.FEATURE_COLS:
        assert col in out.columns


def test_engineer_flows_single_packet_flow():
    df = pd.DataFrame([_packet_row(size=200, syn=1)], columns=CLEANED_COLUMNS)
    out = live_backend.engineer_flows(df)

    assert len(out) == 1
    row = out.iloc[0]
    assert row["Source IP"] == "10.0.0.1"
    assert row["total_packets"] == 1
    assert row["total_bytes"] == 200
    # Duration floor protects pps/bps from div-by-zero on a single packet.
    assert row["flow_duration_sec"] == 0.1
    assert row["packets_per_second"] == 1 / 0.1
    assert row["bytes_per_second"] == 200 / 0.1
    assert row["avg_packet_size"] == 200
    # iat_mean / iat_std default to 0 when len(times) < 2.
    assert row["iat_mean"] == 0.0
    assert row["iat_std"] == 0.0
    # No inf / NaN survives the final clean pass.
    assert not np.isinf(row[live_backend.FEATURE_COLS].values.astype(float)).any()
    assert not pd.isna(row[live_backend.FEATURE_COLS]).any()
