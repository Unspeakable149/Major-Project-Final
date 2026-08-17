"""Parse PCAP files via tshark into a single packet-level CSV dataset.

Run before feature_engineer.py. Set MAX_FILES=None to process the full bulk
PCAP corpus; the default cap keeps dry runs fast.
"""

import os
import subprocess
import pandas as pd
import glob
import warnings

warnings.filterwarnings("ignore")

PCAP_FOLDER = os.environ.get("IDS_PCAP_FOLDER", r"Bulk PCAPS")
TEMP_CSV_FOLDER = "Temp_CSVs"
MASTER_CSV = "master_advanced_dataset.csv"
TSHARK_PATH = os.environ.get("TSHARK_PATH", r"C:\Program Files\Wireshark\tshark.exe")
MAX_FILES = 2  # set to None to parse every PCAP

TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src", "ip.dst",
    "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
    "_ws.col.Protocol", "frame.len",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "ip.ttl", "tcp.window_size",
]

COLUMN_NAMES = [
    "Timestamp", "Source IP", "Dest IP",
    "TCP Src", "UDP Src", "TCP Dst", "UDP Dst",
    "Protocol", "Packet Size",
    "SYN Flag", "ACK Flag", "FIN Flag", "RST Flag",
    "TTL", "Window Size",
]


def build_tshark_command(pcap_path: str) -> list:
    cmd = [TSHARK_PATH, "-r", pcap_path, "-T", "fields"]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]
    cmd += ["-E", "header=y", "-E", "separator=,", "-E", "quote=d"]
    return cmd


def extract_pcap(pcap_path: str) -> None:
    base = os.path.basename(pcap_path).replace('.pcap', '')
    out_csv = os.path.join(TEMP_CSV_FOLDER, f"{base}.csv")
    print(f"  extracting {base}.pcap")
    with open(out_csv, "w", encoding="utf-8") as outfile:
        subprocess.run(build_tshark_command(pcap_path), stdout=outfile, stderr=subprocess.DEVNULL)


def merge_csvs() -> pd.DataFrame | None:
    frames = []
    for csv_file in glob.glob(os.path.join(TEMP_CSV_FOLDER, "*.csv")):
        try:
            df = pd.read_csv(csv_file, on_bad_lines='skip')
            df.columns = COLUMN_NAMES
            frames.append(df)
        except Exception:
            continue
    if not frames:
        return None

    master = pd.concat(frames, ignore_index=True)
    master['Source Port'] = master['TCP Src'].fillna(master['UDP Src']).fillna(0)
    master['Dest Port'] = master['TCP Dst'].fillna(master['UDP Dst']).fillna(0)
    master.drop(columns=['TCP Src', 'UDP Src', 'TCP Dst', 'UDP Dst'], inplace=True)
    fill_cols = ["SYN Flag", "ACK Flag", "FIN Flag", "RST Flag", "TTL", "Window Size"]
    master[fill_cols] = master[fill_cols].fillna(0)
    master.dropna(subset=['Source IP', 'Dest IP'], inplace=True)
    return master


def main():
    os.makedirs(TEMP_CSV_FOLDER, exist_ok=True)

    all_pcaps = glob.glob(os.path.join(PCAP_FOLDER, "*.pcap"))
    pcaps = all_pcaps if MAX_FILES is None else all_pcaps[:MAX_FILES]
    print(f"Discovered {len(all_pcaps)} PCAP files, processing {len(pcaps)}.\n")

    for pcap in pcaps:
        extract_pcap(pcap)

    print("\nMerging per-file CSVs into master dataset...")
    master = merge_csvs()
    if master is None:
        print("ERROR: no data extracted; verify tshark path and PCAP integrity.")
        return

    master.to_csv(MASTER_CSV, index=False)
    print(f"\nSUCCESS. {MASTER_CSV} written: {len(master):,} rows, {master.shape[1]} columns.")


if __name__ == "__main__":
    main()
