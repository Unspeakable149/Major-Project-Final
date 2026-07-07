"""LSTM behavioural model — sequence-based intrusion detection.

The LSTM captures temporal patterns across consecutive capture windows that the
per-window Random Forest cannot see (e.g. a slow port scan that stays below the
pps threshold in any single window but shows rising syn counts across 15 windows).

Architecture
------------
Input : (batch, SEQUENCE_LEN, 18)  — last N flow-feature vectors for one source IP
Layers: LSTM(64, 2 layers, dropout=0.3) → Linear(3)
Output: class probabilities for [Baseline, Moderate, Severe]

Training
--------
    python Dashboard/lstm_model.py --train --csv master_advanced_dataset.csv
    python Dashboard/lstm_model.py --train --epochs 30 --lr 0.001

Standalone inference
--------------------
    from lstm_model import load_lstm, predict_lstm
    model = load_lstm()
    sev = predict_lstm(model, sequences, src_ip, feature_row)
"""

import argparse
from collections import defaultdict, deque
from pathlib import Path

import numpy as np
import pandas as pd

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False

from feature_engineer import engineer_flows, FEATURE_COLS
from trainai_rf import assign_behavioral_label as heuristic_label

SEQUENCE_LEN = 15       # ~30 s of 2-second capture windows
INPUT_SIZE = 18
HIDDEN_SIZE = 64
NUM_LAYERS = 2
NUM_CLASSES = 3
DROPOUT = 0.3
BATCH_SIZE = 64
DEFAULT_EPOCHS = 20
DEFAULT_LR = 1e-3

# Models live in whichever Dashboard hosts this run — the one that put
# feature_engineer on the import path — so this Megan/ folder works under any
# host dashboard without hardcoding a sibling folder name.
import feature_engineer as _fe
_DASH = Path(_fe.__file__).resolve().parent
MODEL_PATH = _DASH / "lstm_model.pt"
SCALER_PATH = _DASH / "rf_scaler.pkl"   # reuse RF scaler for normalisation


# ── Model definition ──────────────────────────────────────────────────────────

class LSTMClassifier(nn.Module):
    def __init__(
        self,
        input_size: int = INPUT_SIZE,
        hidden_size: int = HIDDEN_SIZE,
        num_layers: int = NUM_LAYERS,
        num_classes: int = NUM_CLASSES,
        dropout: float = DROPOUT,
    ):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size, hidden_size, num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_size, num_classes)

    def forward(self, x: "torch.Tensor") -> "torch.Tensor":
        # x: (batch, seq_len, input_size)
        out, _ = self.lstm(x)
        out = self.dropout(out[:, -1, :])   # last timestep
        return self.fc(out)


# ── Sequence buffer (used by live_backend) ────────────────────────────────────

class SequenceBuffer:
    """Maintains a rolling buffer of the last SEQUENCE_LEN feature vectors per source IP."""

    def __init__(self, maxlen: int = SEQUENCE_LEN):
        self._buf: dict[str, deque] = defaultdict(lambda: deque(maxlen=maxlen))

    def update(self, flows: pd.DataFrame):
        for _, row in flows.iterrows():
            vec = row[FEATURE_COLS].values.astype(float)
            self._buf[row["src_ip"]].append(vec)

    def get_sequence(self, src_ip: str) -> np.ndarray | None:
        buf = self._buf[src_ip]
        if len(buf) < 2:
            return None
        seq = np.array(buf)                     # (len, 18)
        if len(seq) < SEQUENCE_LEN:
            pad = np.zeros((SEQUENCE_LEN - len(seq), INPUT_SIZE))
            seq = np.vstack([pad, seq])
        return seq.astype(np.float32)           # (SEQUENCE_LEN, 18)


# ── Training helpers ──────────────────────────────────────────────────────────

def _build_sequences(flows: pd.DataFrame, scaler) -> tuple[np.ndarray, np.ndarray]:
    """Build synthetic training sequences by sliding a window over per-IP flow rows.

    Each sequence is SEQUENCE_LEN consecutive flow vectors for the same source IP.
    The label is the maximum heuristic severity within the window.
    """
    if flows.empty:
        return np.empty((0, SEQUENCE_LEN, INPUT_SIZE)), np.empty(0, dtype=int)

    X_seqs, y_labels = [], []

    for _, grp in flows.groupby("src_ip"):
        feats = grp[FEATURE_COLS].fillna(0).values.astype(float)
        # Use pre-assigned label column if present (e.g. from synthetic data),
        # otherwise fall back to heuristic labeling.
        if "label" in grp.columns:
            labels = grp["label"].astype(int).values
        else:
            labels = grp.apply(heuristic_label, axis=1).values

        if scaler is not None:
            feats = scaler.transform(feats)

        for i in range(len(feats)):
            start = max(0, i - SEQUENCE_LEN + 1)
            window = feats[start: i + 1]
            if len(window) < SEQUENCE_LEN:
                pad = np.zeros((SEQUENCE_LEN - len(window), INPUT_SIZE))
                window = np.vstack([pad, window])
            X_seqs.append(window)
            y_labels.append(int(labels[i]))

    return np.array(X_seqs, dtype=np.float32), np.array(y_labels, dtype=np.int64)


def train_lstm(csv_path: Path, epochs: int = DEFAULT_EPOCHS, lr: float = DEFAULT_LR):
    if not _TORCH_AVAILABLE:
        raise ImportError("PyTorch is required. Install with: pip install torch")

    import joblib

    raw = pd.read_csv(csv_path, low_memory=False)
    flows = engineer_flows(raw)
    if flows.empty:
        raise ValueError("No flows extracted from dataset.")

    scaler = None
    if SCALER_PATH.exists():
        scaler = joblib.load(SCALER_PATH)

    print(f"Building sequences from {len(flows):,} flow rows …")
    X, y = _build_sequences(flows, scaler)
    print(f"  Sequences: {len(X):,}  shape={X.shape}")
    print(f"  Label dist: {dict(zip(*np.unique(y, return_counts=True)))}")

    X_t = torch.from_numpy(X)
    y_t = torch.from_numpy(y)

    n_val = max(1, int(len(X_t) * 0.15))
    idx = torch.randperm(len(X_t))
    train_idx, val_idx = idx[n_val:], idx[:n_val]

    train_ds = TensorDataset(X_t[train_idx], y_t[train_idx])
    val_ds = TensorDataset(X_t[val_idx], y_t[val_idx])
    train_dl = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_dl = DataLoader(val_ds, batch_size=BATCH_SIZE)

    model = LSTMClassifier()
    criterion = nn.CrossEntropyLoss()
    optimiser = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimiser, patience=3, factor=0.5)

    print(f"\nTraining LSTM for {epochs} epochs …")
    best_val_acc = 0.0
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for xb, yb in train_dl:
            optimiser.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimiser.step()
            total_loss += loss.item()

        model.eval()
        correct = total = 0
        with torch.no_grad():
            for xb, yb in val_dl:
                preds = model(xb).argmax(dim=1)
                correct += (preds == yb).sum().item()
                total += len(yb)
        val_acc = correct / max(total, 1)
        scheduler.step(1 - val_acc)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), MODEL_PATH)

        if epoch % 5 == 0 or epoch == 1:
            print(f"  Epoch {epoch:3d}/{epochs}  loss={total_loss/len(train_dl):.4f}  val_acc={val_acc:.3f}")

    print(f"\nBest val accuracy: {best_val_acc:.3f}")
    print(f"LSTM model saved: {MODEL_PATH}")
    return model


# ── Inference API (called by live_backend) ────────────────────────────────────

def load_lstm() -> "LSTMClassifier | None":
    """Load model from disk. Returns None if model file or torch is missing."""
    if not _TORCH_AVAILABLE or not MODEL_PATH.exists():
        return None
    model = LSTMClassifier()
    model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu", weights_only=True))
    model.eval()
    return model


def predict_lstm(
    model: "LSTMClassifier",
    sequences: "SequenceBuffer | dict",
    src_ip: str,
    feature_row: pd.Series,
) -> int | None:
    """Return predicted severity (0/1/2) for src_ip, or None if not enough history."""
    if not _TORCH_AVAILABLE or model is None:
        return None

    # sequences can be a SequenceBuffer or a plain dict
    if isinstance(sequences, SequenceBuffer):
        seq = sequences.get_sequence(src_ip)
    else:
        seq = sequences.get(src_ip)

    if seq is None:
        return None

    with torch.no_grad():
        x = torch.from_numpy(seq).unsqueeze(0)  # (1, SEQ_LEN, 18)
        logits = model(x)
        return int(logits.argmax(dim=1).item())


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train the LSTM behavioural model.")
    parser.add_argument("--train", action="store_true", help="Train and save the model")
    parser.add_argument("--csv", type=Path,
                        default=_DASH / "master_advanced_dataset.csv")
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    args = parser.parse_args()

    if args.train:
        if not args.csv.exists():
            print(f"[ERROR] CSV not found: {args.csv}")
            print("Run advanced_parser.py then feature_engineer.py first.")
            return
        train_lstm(args.csv, args.epochs, args.lr)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
