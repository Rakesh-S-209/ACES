"""
train_behavior_model.py
=======================
Offline IsolationForest trainer for the A.C.E.S. behavioral anomaly baseline.

Usage:
    python train_behavior_model.py

Output:
    data/behavior_model.pkl   -- fitted IsolationForest + feature metadata
    (also prints a validation summary to stdout)

Dataset:
    ~/Downloads/BenignTraffic.pcap.csv
    Source: CIC-IoT-2023 / ISCX benign network flow features
    362,361 rows × 39 feature columns (all numeric, no label column)
"""

from __future__ import annotations

import os
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

warnings.filterwarnings("ignore", category=RuntimeWarning)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_DOWNLOADS  = Path(os.environ.get("USERPROFILE", Path.home())) / "Downloads"
_CSV_PATH   = _DOWNLOADS / "BenignTraffic.pcap.csv"
_OUTPUT_DIR = Path("data")
_MODEL_PATH = _OUTPUT_DIR / "behavior_model.pkl"

# ---------------------------------------------------------------------------
# Feature columns
# The dataset has no "Flow Packets/s" or "Flow IAT Mean" in the CIC-IoT
# naming; the equivalent columns in BenignTraffic.pcap.csv are:
#   Rate          → packets per second  (≈ Flow Packets/s)
#   IAT           → inter-arrival time mean  (≈ Flow IAT Mean)
#   Header_Length → avg header size
#   Time_To_Live  → avg TTL
#   Variance      → IAT variance
#   AVG           → avg packet size
#   Std           → std of packet size
#   Number        → packet count per flow
#   Tot size      → total bytes transferred
#   fin/syn/rst/psh/ack/ece/cwr flag counts → TCP flag behaviour
#   Protocol Type → numeric protocol ID
# ---------------------------------------------------------------------------
FEATURE_COLUMNS: list[str] = [
    # Flow rate / timing
    "Rate",
    "IAT",
    "Variance",
    # Packet size statistics
    "Header_Length",
    "AVG",
    "Std",
    "Tot size",
    "Min",
    "Max",
    # Flow metadata
    "Number",
    "Time_To_Live",
    "Protocol Type",
    # TCP flag behaviour (critical for detecting scans)
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "syn_count",
    "fin_count",
    "rst_count",
    "ack_count",
    # Protocol presence (binary/fractional)
    "TCP",
    "UDP",
    "HTTP",
    "HTTPS",
    "DNS",
    "ICMP",
]

# IsolationForest hyper-parameters
# contamination=0.02 means ~2% of baseline samples are treated as outliers,
# giving a tighter boundary than the default 0.1 while still being robust.
IF_N_ESTIMATORS   = 200
IF_CONTAMINATION  = 0.02
IF_MAX_SAMPLES    = "auto"
IF_RANDOM_STATE   = 42


# ---------------------------------------------------------------------------
# Step 1 — Load & clean
# ---------------------------------------------------------------------------

def load_and_clean(csv_path: Path) -> pd.DataFrame:
    print(f"\n[1/5] Loading dataset from {csv_path} ...")
    t0 = time.perf_counter()
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"      Raw shape: {df.shape}  ({time.perf_counter()-t0:.1f}s)")

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Verify all required features are present
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Required feature columns not found in dataset: {missing}\n"
            f"Available columns: {list(df.columns)}"
        )

    # Select only the feature columns we need
    df = df[FEATURE_COLUMNS].copy()

    # Replace ±inf with NaN then drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    n_before = len(df)
    df.dropna(inplace=True)
    n_dropped = n_before - len(df)
    if n_dropped:
        print(f"      Dropped {n_dropped} rows containing NaN/Inf values.")

    print(f"      Clean shape: {df.shape}")
    return df


# ---------------------------------------------------------------------------
# Step 2 — Feature engineering / scaling
# ---------------------------------------------------------------------------

def prepare_features(df: pd.DataFrame) -> tuple[np.ndarray, RobustScaler]:
    """
    Apply RobustScaler (median/IQR) so that the IsolationForest decision
    boundary is not dominated by high-magnitude columns like 'Rate' or
    'Tot size' that span many orders of magnitude.

    RobustScaler is preferred over StandardScaler here because the benign
    traffic distribution has long tails (legitimate high-rate bursts) and
    we do not want those to distort the normalisation centre.
    """
    print("\n[2/5] Scaling features with RobustScaler ...")
    scaler = RobustScaler()
    X = scaler.fit_transform(df.values.astype(np.float64))
    print(f"      Feature matrix shape: {X.shape}")
    print(f"      Feature dtype: {X.dtype}")
    return X, scaler


# ---------------------------------------------------------------------------
# Step 3 — Train IsolationForest
# ---------------------------------------------------------------------------

def train_model(X: np.ndarray) -> IsolationForest:
    print(f"\n[3/5] Training IsolationForest ...")
    print(f"      n_estimators={IF_N_ESTIMATORS}  contamination={IF_CONTAMINATION}"
          f"  max_samples={IF_MAX_SAMPLES}  random_state={IF_RANDOM_STATE}")
    t0 = time.perf_counter()
    model = IsolationForest(
        n_estimators   = IF_N_ESTIMATORS,
        contamination  = IF_CONTAMINATION,
        max_samples    = IF_MAX_SAMPLES,
        random_state   = IF_RANDOM_STATE,
        n_jobs         = -1,   # use all CPU cores
        verbose        = 0,
    )
    model.fit(X)
    elapsed = time.perf_counter() - t0
    print(f"      Training complete in {elapsed:.1f}s")
    return model


# ---------------------------------------------------------------------------
# Step 4 — Validate on a held-out benign sample
# ---------------------------------------------------------------------------

def validate(model: IsolationForest, X: np.ndarray) -> None:
    print("\n[4/5] Validation on 10,000 held-out benign samples ...")
    rng = np.random.default_rng(0)
    idx = rng.choice(len(X), size=min(10_000, len(X)), replace=False)
    X_val = X[idx]

    raw_scores = model.decision_function(X_val)
    # Normalise to [0, 1] using the same formula as BehaviorScorer.predict()
    # clamped = clip(raw, -0.5, 0.5);  score = (0.5 - clamped) / 1.0
    clamped     = np.clip(raw_scores, -0.5, 0.5)
    norm_scores = (0.5 - clamped)

    preds = model.predict(X_val)   # +1 = inlier, -1 = outlier
    n_outliers = int((preds == -1).sum())
    pct_outliers = 100.0 * n_outliers / len(X_val)

    print(f"      Anomaly scores on benign samples:")
    print(f"        mean  = {norm_scores.mean():.4f}")
    print(f"        std   = {norm_scores.std():.4f}")
    print(f"        min   = {norm_scores.min():.4f}")
    print(f"        p50   = {np.percentile(norm_scores, 50):.4f}")
    print(f"        p90   = {np.percentile(norm_scores, 90):.4f}")
    print(f"        p99   = {np.percentile(norm_scores, 99):.4f}")
    print(f"        max   = {norm_scores.max():.4f}")
    print(f"      IF outlier labels: {n_outliers}/{len(X_val)} "
          f"({pct_outliers:.1f}%) flagged as anomalous "
          f"(expected ~{IF_CONTAMINATION*100:.0f}% by contamination param)")
    print(f"      Samples with score >= 0.85 (auto-ban threshold): "
          f"{int((norm_scores >= 0.85).sum())}")
    print(f"      Samples with score >= 0.50 (SOC-alert threshold): "
          f"{int((norm_scores >= 0.50).sum())}")


# ---------------------------------------------------------------------------
# Step 5 — Export model bundle
# ---------------------------------------------------------------------------

def export_model(
    model: IsolationForest,
    scaler: RobustScaler,
    feature_columns: list[str],
    output_path: Path,
) -> None:
    print(f"\n[5/5] Saving model bundle to {output_path} ...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model":           model,
        "scaler":          scaler,
        "feature_columns": feature_columns,
        "n_estimators":    IF_N_ESTIMATORS,
        "contamination":   IF_CONTAMINATION,
        "trained_on":      str(_CSV_PATH),
        "aces_version":    "1.0.0",
    }
    joblib.dump(bundle, output_path, compress=3)
    size_kb = output_path.stat().st_size / 1024
    print(f"      Saved {size_kb:.0f} KB  ->  {output_path.resolve()}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 64)
    print("  A.C.E.S.  IsolationForest Behavioral Baseline Trainer")
    print("=" * 64)

    if not _CSV_PATH.exists():
        print(f"\n[ERROR] Dataset not found: {_CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    df           = load_and_clean(_CSV_PATH)
    X, scaler    = prepare_features(df)
    model        = train_model(X)
    validate(model, X)
    export_model(model, scaler, FEATURE_COLUMNS, _MODEL_PATH)

    print("\n" + "=" * 64)
    print("  Training complete.")
    print(f"  Model saved: {_MODEL_PATH.resolve()}")
    print("=" * 64 + "\n")


if __name__ == "__main__":
    main()
