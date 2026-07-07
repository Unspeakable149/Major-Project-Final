import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
import time

# Anchor paths to the Rui Yang project root so this runs from any CWD
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("HYBRID IDPS — ML MODEL TRAINING V3 (Live-Compatible)")
print("=" * 60)

# ── Step 1: Load cleaned dataset ─────────────────────────────
print("\nLoading cleaned dataset...")
df = pd.read_csv(os.path.join(BASE_DIR, 'data', 'cleaned', 'cleaned_full_dataset.csv'))
print(f"Total rows: {df.shape[0]:,}")

# ── Step 2: Select only live-extractable features ─────────────
LIVE_FEATURES = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Length of Fwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd Packets/s',
    'FIN Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'Min Packet Length',
    'Max Packet Length',
    'Init_Win_bytes_forward',
]

print(f"\nUsing {len(LIVE_FEATURES)} live-extractable features")
print("(Features calculable from raw packets without CICFlowMeter)")

X = df[LIVE_FEATURES]
y = df['Attack Type']
y_binary = (y != 'Normal Traffic').astype(int)

print(f"\nNormal traffic:  {(y_binary == 0).sum():,} rows")
print(f"Attack traffic:  {(y_binary == 1).sum():,} rows")

# ── Step 3: Train/test split ──────────────────────────────────
print("\nSplitting 80/20...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_binary,
    test_size=0.2,
    random_state=42,
    stratify=y_binary
)

# ── Step 4: Scale ─────────────────────────────────────────────
print("Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# ── Step 5: Train ─────────────────────────────────────────────
print("\nTraining Random Forest (live-compatible)...")
start = time.time()

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    class_weight='balanced',
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled, y_train)
elapsed = round(time.time() - start, 2)
print(f"Training complete in {elapsed}s ✅")

# ── Step 6: Evaluate ──────────────────────────────────────────
print("\n" + "=" * 60)
print("EVALUATION")
print("=" * 60)

predictions   = model.predict(X_test_scaled)
total         = len(predictions)
detected      = ((predictions == 1) & (y_test == 1)).sum()
missed        = ((predictions == 0) & (y_test == 1)).sum()
fp            = ((predictions == 1) & (y_test == 0)).sum()
tn            = ((predictions == 0) & (y_test == 0)).sum()
total_attacks = (y_test == 1).sum()
total_normal  = (y_test == 0).sum()

accuracy  = (detected + tn) / total * 100
precision = detected / (detected + fp) * 100 if (detected + fp) > 0 else 0
recall    = detected / (detected + missed) * 100 if (detected + missed) > 0 else 0
f1        = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print(f"\nAttack Detection:    {detected:,}/{total_attacks:,} = {detected/total_attacks*100:.1f}%")
print(f"False Positives:     {fp:,}/{total_normal:,} = {fp/total_normal*100:.2f}%")
print(f"\nAccuracy:   {accuracy:.2f}%")
print(f"Precision:  {precision:.2f}%")
print(f"Recall:     {recall:.2f}%")
print(f"F1 Score:   {f1:.2f}%")

# Per attack type
print("\nDetection rate per attack type:")
X_test_copy = X_test.copy()
X_test_copy['Predicted']   = predictions
X_test_copy['Attack Type'] = y.iloc[X_test.index].values

for attack in y.unique():
    if attack == 'Normal Traffic':
        continue
    subset     = X_test_copy[X_test_copy['Attack Type'] == attack]
    detected_a = (subset['Predicted'] == 1).sum()
    total_a    = len(subset)
    rate       = detected_a / total_a * 100
    status     = "✅" if rate >= 80 else "⚠️" if rate >= 50 else "❌"
    print(f"  {status} {attack:<20} {detected_a:>6}/{total_a:<6} = {rate:.1f}%")

# Feature importance
print("\nTop 10 most important features:")
importances = pd.Series(
    model.feature_importances_,
    index=LIVE_FEATURES
).sort_values(ascending=False)

for feat, imp in importances.head(10).items():
    print(f"  {feat:<35} {imp:.4f}")

# ── Step 7: Save ──────────────────────────────────────────────
print("\n" + "=" * 60)
print("SAVING MODEL")
print("=" * 60)

MODELS_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)
joblib.dump(model,        os.path.join(MODELS_DIR, 'ids_model_live.pkl'))
joblib.dump(scaler,       os.path.join(MODELS_DIR, 'scaler_live.pkl'))
joblib.dump(LIVE_FEATURES,os.path.join(MODELS_DIR, 'live_features.pkl'))

print("Saved: models/ids_model_live.pkl  ✅")
print("Saved: models/scaler_live.pkl     ✅")
print("Saved: models/live_features.pkl   ✅")

print(f"\n✅ Live-compatible model ready!")
print(f"   Features: {len(LIVE_FEATURES)} (all extractable from raw packets)")
print(f"   Accuracy: {accuracy:.2f}%")