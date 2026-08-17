"""Engineer per-Source-IP behavioral flow features from the parsed packet dataset.

Input:  master_advanced_dataset.csv  (produced by advanced_parser.py)
Output: ai_ready_advanced_flows.csv  (consumed by trainai_rf.py / trainai.py)

Feature coverage maps to the project spec's feature categories:
    - Packet-level    -> total_packets, total_bytes, avg_packet_size, packet_size_std
    - Flow-level      -> flow_duration_sec, packets_per_second, bytes_per_second,
                         iat_mean, iat_std
    - Session-level   -> total_{syn,ack,fin,rst}_flags, syn_ack_ratio
    - Behavioral      -> unique_target_ips, unique_target_ports
    - Network-layer   -> avg_ttl, avg_window_size
"""

import pandas as pd
import numpy as np
import warnings

warnings.filterwarnings("ignore")

INPUT_CSV = "master_advanced_dataset.csv"
OUTPUT_CSV = "ai_ready_advanced_flows.csv"

NUMERIC_COLS = [
    'Packet Size', 'SYN Flag', 'ACK Flag', 'FIN Flag',
    'RST Flag', 'TTL', 'Window Size', 'Timestamp'
]

# The 18 behavioral features every model (RF, LSTM, SHAP) trains on.
# Kept here as the single source of truth; trainai_rf.py holds the same list.
FEATURE_COLS = [
    'total_packets', 'total_bytes', 'unique_target_ips', 'unique_target_ports',
    'total_syn_flags', 'total_ack_flags', 'total_fin_flags', 'total_rst_flags',
    'avg_ttl', 'avg_window_size', 'flow_duration_sec', 'packets_per_second',
    'bytes_per_second', 'avg_packet_size', 'syn_ack_ratio',
    'packet_size_std', 'iat_mean', 'iat_std',
]

# Raw tshark-style columns engineer_flows() coerces to numeric before aggregating.
RAW_NUMERIC_COLS = [
    'Length', 'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin',
    'tcp.flags.reset', 'tcp.window_size', 'ip.ttl', 'Time',
]

# engineer_flows() works on the canonical tshark names above. Real captures /
# datasets arrive under a few different column conventions, so map the known
# aliases onto the canonical names before aggregating. Only renames when the
# canonical column is absent, so native-schema callers are untouched.
_SCHEMA_ALIASES = {
    # Advanced aggregated dataset (master_advanced_dataset.csv)
    'Source IP': 'Source', 'Dest IP': 'Destination', 'Packet Size': 'Length',
    'Timestamp': 'Time', 'SYN Flag': 'tcp.flags.syn', 'ACK Flag': 'tcp.flags.ack',
    'FIN Flag': 'tcp.flags.fin', 'RST Flag': 'tcp.flags.reset',
    'Window Size': 'tcp.window_size', 'TTL': 'ip.ttl', 'Dest Port': 'tcp.dstport',
    # Live tshark raw capture (temp_raw.csv)
    'ip.src': 'Source', 'ip.dst': 'Destination', 'frame.len': 'Length',
    'frame.time_epoch': 'Time',
}
_FLAG_COLS = ('tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin', 'tcp.flags.reset')


def normalize_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Rename known column aliases to the canonical tshark names engineer_flows
    expects, and coerce boolean-style flag columns (True/False) to 0/1."""
    rename = {a: c for a, c in _SCHEMA_ALIASES.items()
              if a in df.columns and c not in df.columns}
    if rename:
        df = df.rename(columns=rename)
    _bool_map = {'True': 1, 'False': 0, True: 1, False: 0, '1': 1, '0': 0, 1: 1, 0: 0}
    for col in _FLAG_COLS:
        if col in df.columns and df[col].dtype == object:
            df[col] = df[col].map(_bool_map).fillna(0)
    return df


def coerce_numeric(df: pd.DataFrame, columns: list) -> pd.DataFrame:
    for col in columns:
        if col not in df.columns:
            continue
        # fillna('') first: newer pandas keeps NaN missing through astype(str),
        # so an all-empty column would reach .str[0] as all-NaN and raise.
        df[col] = df[col].fillna('').astype(str).str.split(',').str[0]
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    return df


def compute_iat_stats(group: pd.DataFrame) -> pd.Series:
    times = group['Timestamp'].sort_values().to_numpy()
    if len(times) < 2:
        return pd.Series({'iat_mean': 0.0, 'iat_std': 0.0})
    iats = np.diff(times)
    return pd.Series({'iat_mean': float(iats.mean()), 'iat_std': float(iats.std())})


def engineer_flows(raw: pd.DataFrame) -> pd.DataFrame:
    """Aggregate a raw packet DataFrame into per-source-IP behavioral flows.

    Accepts the raw tshark-style schema (``Source``, ``Destination``,
    ``Length``, ``Time``, ``tcp.flags.*``, ``tcp.window_size``,
    ``tcp.dstport``, ``ip.ttl``) and returns one row per source IP with a
    ``src_ip`` key column plus every column listed in FEATURE_COLS.

    This is the in-memory counterpart to main()'s CSV pipeline. The v2 modules
    (lstm_model, shap_explainer) and test_v2_features.py call it directly so
    they never have to touch disk-based intermediate CSVs.
    """
    df = normalize_schema(raw.copy())
    df = coerce_numeric(df, RAW_NUMERIC_COLS)

    # Some captures omit flag / port / ttl columns entirely. Backfill them with
    # zeros (or empty for the IP column) so the groupby below never KeyErrors.
    for col in RAW_NUMERIC_COLS:
        if col not in df.columns:
            df[col] = 0
    if 'Destination' not in df.columns:
        df['Destination'] = ''
    if 'tcp.dstport' not in df.columns:
        df['tcp.dstport'] = 0

    flows = df.groupby('Source').agg(
        total_packets=('Length', 'count'),
        total_bytes=('Length', 'sum'),
        packet_size_std=('Length', 'std'),
        unique_target_ips=('Destination', 'nunique'),
        unique_target_ports=('tcp.dstport', 'nunique'),
        total_syn_flags=('tcp.flags.syn', 'sum'),
        total_ack_flags=('tcp.flags.ack', 'sum'),
        total_fin_flags=('tcp.flags.fin', 'sum'),
        total_rst_flags=('tcp.flags.reset', 'sum'),
        avg_ttl=('ip.ttl', 'mean'),
        avg_window_size=('tcp.window_size', 'mean'),
        first_packet_time=('Time', 'min'),
        last_packet_time=('Time', 'max'),
    ).reset_index().rename(columns={'Source': 'src_ip'})

    # Inter-arrival time stats. compute_iat_stats() keys off a 'Timestamp'
    # column, so alias 'Time' -> 'Timestamp' just for this aggregation.
    iat_stats = (
        df.rename(columns={'Time': 'Timestamp'})
          .groupby('Source')
          .apply(compute_iat_stats)
          .reset_index()
          .rename(columns={'Source': 'src_ip'})
    )
    flows = flows.merge(iat_stats, on='src_ip', how='left')

    flows['flow_duration_sec'] = (flows['last_packet_time'] - flows['first_packet_time']).clip(lower=0.1)
    flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
    flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
    flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']
    flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)
    flows['packet_size_std'] = flows['packet_size_std'].fillna(0)
    flows['iat_mean'] = flows['iat_mean'].fillna(0)
    flows['iat_std'] = flows['iat_std'].fillna(0)

    flows = flows.drop(columns=['first_packet_time', 'last_packet_time'])
    flows = flows.replace([np.inf, -np.inf], 0).fillna(0)
    return flows


def main():
    print("[1/5] Loading parsed packet dataset...")
    df = pd.read_csv(INPUT_CSV, low_memory=False)
    print(f"      {len(df):,} packet rows loaded.")

    print("[2/5] Coercing numeric columns (tshark emits multi-value fields)...")
    df = coerce_numeric(df, NUMERIC_COLS)

    print("[3/5] Aggregating flows grouped by Source IP...")
    flows = df.groupby('Source IP').agg(
        total_packets=('Packet Size', 'count'),
        total_bytes=('Packet Size', 'sum'),
        packet_size_std=('Packet Size', 'std'),
        unique_target_ips=('Dest IP', 'nunique'),
        unique_target_ports=('Dest Port', 'nunique'),
        total_syn_flags=('SYN Flag', 'sum'),
        total_ack_flags=('ACK Flag', 'sum'),
        total_fin_flags=('FIN Flag', 'sum'),
        total_rst_flags=('RST Flag', 'sum'),
        avg_ttl=('TTL', 'mean'),
        avg_window_size=('Window Size', 'mean'),
        first_packet_time=('Timestamp', 'min'),
        last_packet_time=('Timestamp', 'max')
    ).reset_index()

    print("[4/5] Computing inter-arrival time stats per source IP...")
    iat_stats = df.groupby('Source IP').apply(compute_iat_stats).reset_index()
    flows = flows.merge(iat_stats, on='Source IP', how='left')

    print("[5/5] Deriving velocity + ratio features...")
    flows['flow_duration_sec'] = (flows['last_packet_time'] - flows['first_packet_time']).clip(lower=0.1)
    flows['packets_per_second'] = flows['total_packets'] / flows['flow_duration_sec']
    flows['bytes_per_second'] = flows['total_bytes'] / flows['flow_duration_sec']
    flows['avg_packet_size'] = flows['total_bytes'] / flows['total_packets']
    flows['syn_ack_ratio'] = flows['total_syn_flags'] / (flows['total_ack_flags'] + 1)
    flows['packet_size_std'] = flows['packet_size_std'].fillna(0)
    flows['iat_mean'] = flows['iat_mean'].fillna(0)
    flows['iat_std'] = flows['iat_std'].fillna(0)

    final = flows.drop(columns=['first_packet_time', 'last_packet_time'])
    final = final.replace([np.inf, -np.inf], 0).fillna(0)
    final.to_csv(OUTPUT_CSV, index=False)

    print(f"\nSUCCESS. Wrote {OUTPUT_CSV}  shape={final.shape}")
    print(f"Features per flow: {final.shape[1] - 1}")


if __name__ == "__main__":
    main()
