"""Legacy unsupervised K-Means trainer (fallback when no RF model exists).

Random Forest (trainai_rf.py) is the primary classifier. K-Means is retained
for the "Isolation Forest / K-Means" branch listed in the spec's Phase 3
behavioral modeling alternatives.
"""

import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")


def main():
    print("[1/4] Loading flow dataset...")
    df = pd.read_csv("ai_ready_advanced_flows.csv")

    features = df.drop(columns=['Source IP'])
    features = features.replace([np.inf, -np.inf], 0).fillna(0)

    print("[2/4] Scaling features...")
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)

    print("[3/4] Fitting KMeans (k=3: baseline / moderate / severe)...")
    model = KMeans(n_clusters=3, random_state=42, n_init=10)
    model.fit(scaled)

    print("[4/4] Saving artifacts...")
    joblib.dump(model, "advanced_kmeans_model.pkl")
    joblib.dump(scaler, "advanced_data_scaler.pkl")

    print(f"\nSUCCESS. Flows analysed: {len(df):,}")
    print("Saved advanced_kmeans_model.pkl + advanced_data_scaler.pkl")


if __name__ == "__main__":
    main()
