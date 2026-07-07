import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os

# Anchor paths to the Rui Yang project root so this runs from any CWD
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Load cleaned dataset ─────────────────────────────────────────────────────
print("Loading cleaned dataset...")
df = pd.read_csv(os.path.join(BASE_DIR, 'data', 'cleaned', 'cleaned_full_dataset.csv'))
print(f"Loaded {df.shape[0]:,} rows\n")

# ── Create output folder for charts ─────────────────────────────────────────
EDA_DIR = os.path.join(BASE_DIR, 'data', 'eda')
os.makedirs(EDA_DIR, exist_ok=True)

# ── 1. Traffic breakdown ─────────────────────────────────────────────────────
print("=" * 60)
print("1. TRAFFIC BREAKDOWN")
print("=" * 60)
counts = df['Attack Type'].value_counts()
print(counts)
print()

# Plot traffic breakdown bar chart
plt.figure(figsize=(10, 6))
counts.plot(kind='bar', color=['green','red','orange','blue','purple','brown','pink'])
plt.title('Traffic Type Distribution in CICIDS2017 Dataset')
plt.xlabel('Attack Type')
plt.ylabel('Number of Records')
plt.xticks(rotation=45, ha='right')

# Fix y-axis cutoff
plt.ylim(0, counts.max() * 1.15)

# Add value labels on top of each bar
for i, v in enumerate(counts):
    plt.text(i, v + 10000, f'{v:,}', ha='center', va='bottom', fontsize=8)

plt.tight_layout()
plt.savefig(os.path.join(EDA_DIR, 'traffic_distribution.png'))
plt.close()
print("Saved: data/eda/traffic_distribution.png")

# ── 2. Key feature comparison ────────────────────────────────────────────────
print()
print("=" * 60)
print("2. KEY FEATURE COMPARISON (Normal vs Attacks)")
print("=" * 60)

features = [
    'Flow Packets/s',
    'Flow Bytes/s',
    'Flow Duration',
    'Packet Length Mean',
    'Fwd Packets/s',
    'Bwd Packets/s'
]

comparison = df.groupby('Attack Type')[features].mean().round(2)
print(comparison.to_string())
print()

# ── 3. Packets per second analysis ───────────────────────────────────────────
print("=" * 60)
print("3. FLOW PACKETS/S — ANOMALY DETECTION THRESHOLDS")
print("=" * 60)

pkt_stats = df.groupby('Attack Type')['Flow Packets/s'].agg(['mean', 'max', 'std']).round(2)
print(pkt_stats)
print()

# Plot packets per second
plt.figure(figsize=(10, 6))
pkt_means = df.groupby('Attack Type')['Flow Packets/s'].mean()
pkt_means.plot(
    kind='bar',
    color=['green','red','orange','blue','purple','brown','pink']
)
plt.title('Average Flow Packets/s by Attack Type')
plt.xlabel('Attack Type')
plt.ylabel('Avg Packets per Second')
plt.xticks(rotation=45, ha='right')

# Fix y-axis cutoff
plt.ylim(0, pkt_means.max() * 1.15)

# Add value labels
for i, v in enumerate(pkt_means):
    plt.text(i, v + 500, f'{v:,.0f}', ha='center', va='bottom', fontsize=8)

plt.tight_layout()
plt.savefig(os.path.join(EDA_DIR, 'packets_per_second.png'))
plt.close()
print("Saved: data/eda/packets_per_second.png")

# ── 4. Flow bytes analysis ───────────────────────────────────────────────────
print()
print("=" * 60)
print("4. FLOW BYTES/S — VOLUME ANOMALY THRESHOLDS")
print("=" * 60)

bytes_stats = df.groupby('Attack Type')['Flow Bytes/s'].agg(['mean', 'max']).round(2)
print(bytes_stats)
print()

# ── 5. Port analysis ─────────────────────────────────────────────────────────
print("=" * 60)
print("5. TOP DESTINATION PORTS PER ATTACK TYPE")
print("=" * 60)

for attack in df['Attack Type'].unique():
    subset = df[df['Attack Type'] == attack]
    top_ports = subset['Destination Port'].value_counts().head(3)
    print(f"\n{attack}:")
    print(top_ports.to_string())

# ── 6. Normal traffic baseline ───────────────────────────────────────────────
print()
print("=" * 60)
print("6. NORMAL TRAFFIC BASELINE (for ML training)")
print("=" * 60)

normal = df[df['Attack Type'] == 'Normal Traffic']
print(f"Total normal records: {len(normal):,}")
print()
print("Normal traffic statistics:")
print(normal[features].describe().round(2).to_string())

# ── 7. Rule thresholds derived from EDA ─────────────────────────────────────
print()
print("=" * 60)
print("7. SUGGESTED RULE THRESHOLDS")
print("=" * 60)

normal_pkt_mean   = normal['Flow Packets/s'].mean()
normal_pkt_std    = normal['Flow Packets/s'].std()
normal_bytes_mean = normal['Flow Bytes/s'].mean()

threshold_pkt   = round(normal_pkt_mean + (3 * normal_pkt_std), 2)
threshold_bytes = round(normal_bytes_mean * 10, 2)

print(f"Normal avg packets/s  : {normal_pkt_mean:.2f}")
print(f"Normal std packets/s  : {normal_pkt_std:.2f}")
print(f"Normal avg bytes/s    : {normal_bytes_mean:.2f}")
print()
print(f"Suggested rule thresholds:")
print(f"  → Flag if Flow Packets/s > {threshold_pkt}  (3 std above normal)")
print(f"  → Flag if Flow Bytes/s   > {threshold_bytes}  (10x above normal)")
print()
print("These thresholds will be used in your rule engine.")

# ── 8. Save comparison table ─────────────────────────────────────────────────
comparison.to_csv(os.path.join(EDA_DIR, 'feature_comparison.csv'))
print()
print("✅ EDA Complete!")
print("   Charts saved to: data/eda/")
print("   Comparison table saved to: data/eda/feature_comparison.csv")