import pandas as pd

print("Reading temp_raw.csv produced by the last live_backend capture window...\n")
df = pd.read_csv("temp_raw.csv", low_memory=False)

print(f"Total rows: {len(df)}")
print(f"Columns from tshark header: {list(df.columns)}\n")

flag_field_candidates = [c for c in df.columns if 'flags' in c.lower() or 'syn' in c.lower() or 'ack' in c.lower()]
print(f"Flag-related columns: {flag_field_candidates}\n")

for col in flag_field_candidates:
    sample = df[col].dropna().astype(str).head(20).tolist()
    unique_vals = df[col].astype(str).unique()[:15]
    print(f"--- {col} ---")
    print(f"  First 20 raw values:  {sample}")
    print(f"  Unique values seen:   {list(unique_vals)}")
    print(f"  dtype: {df[col].dtype}\n")
