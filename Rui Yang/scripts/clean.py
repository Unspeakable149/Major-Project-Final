import pandas as pd
import numpy as np
import os

# Anchor paths to the Rui Yang project root so this runs from any CWD
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

print("Loading dataset...")
df = pd.read_csv(os.path.join(BASE_DIR, 'data', 'raw', 'cicids2017_cleaned.csv'))

print(f"Original shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")

# Fix column names
df.columns = df.columns.str.strip()

# Fix infinite values
df.replace([np.inf, -np.inf], 0, inplace=True)

# Fix missing values
df.fillna(0, inplace=True)

# Remove duplicates
before = len(df)
df.drop_duplicates(inplace=True)
after = len(df)
print(f"Removed {before - after} duplicates")

# Check label column
print("\nTraffic breakdown:")
for col in ['Label', 'label', 'class', 'attack_type', 'Class', 'Attack Type']:
    if col in df.columns:
        print(df[col].value_counts())
        break

# ── Check for negative values ────────────────────────────────────
print("\n=== NEGATIVE VALUES CHECK ===")
numeric_cols = df.select_dtypes(include=[np.number]).columns
neg_counts = (df[numeric_cols] < 0).sum()
neg_found = neg_counts[neg_counts > 0]
if len(neg_found) > 0:
    print("Negative values found:")
    print(neg_found)
    df[numeric_cols] = df[numeric_cols].clip(lower=0)
    print("Fixed: replaced all negatives with 0")
else:
    print("No negative values found ✅")

# ── Fix impossible zero values ───────────────────────────────────
print("\n=== FIXING IMPOSSIBLE ZEROS ===")

# Flow Duration of 0 is impossible
before = (df['Flow Duration'] == 0).sum()
df['Flow Duration'] = df['Flow Duration'].replace(0, 1)
print(f"Flow Duration zeros fixed: {before}")

# Flow Packets/s of 0 is impossible  
before = (df['Flow Packets/s'] == 0).sum()
df['Flow Packets/s'] = df['Flow Packets/s'].replace(0, 0.001)
print(f"Flow Packets/s zeros fixed: {before}")

# Check if Bytes/s zeros are same rows as Packets/s zeros
zero_bytes = df[df['Flow Bytes/s'] == 0]
print(f"\nFlow Bytes/s zero rows attack types:")
print(zero_bytes['Attack Type'].value_counts())

# ── Check zeros in key columns ───────────────────────────────────
print("\n=== ZERO VALUES IN KEY COLUMNS ===")
key_cols = ['Flow Packets/s', 'Flow Bytes/s',
            'Flow Duration', 'Packet Length Mean']
for col in key_cols:
    zeros = (df[col] == 0).sum()
    print(f"{col}: {zeros:,} zeros")

# ── Check infinite values ────────────────────────────────────────
print("\n=== INFINITE VALUES CHECK ===")
inf_counts = df[numeric_cols].isin([np.inf, -np.inf]).sum()
inf_found = inf_counts[inf_counts > 0]
if len(inf_found) > 0:
    print("Infinite values found:")
    print(inf_found)
    df.replace([np.inf, -np.inf], 0, inplace=True)
    print("Fixed: replaced all inf with 0")
else:
    print("No infinite values found ✅")

# ── Save ONCE at the end with ALL fixes applied ──────────────────
os.makedirs(os.path.join(BASE_DIR, 'data', 'cleaned'), exist_ok=True)
df.to_csv(os.path.join(BASE_DIR, 'data', 'cleaned', 'cleaned_full_dataset.csv'), index=False)

print(f"\n✅ Final clean saved with all fixes applied!")
print(f"Final shape: {df.shape}")
print(f"Missing values: {df.isnull().sum().sum()}")