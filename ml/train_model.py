#!/usr/bin/env python3
"""
Train the production detector and SAVE it to disk.

Fits the chosen supervised detector (HistGBM) on the full labelled dataset, plus
the anomaly detector (IsolationForest, benign-only) for unknown/zero-day traffic,
and serialises everything into one model file that ml/detect.py loads.

Run this once (and re-run whenever you add new training data).

Usage:  python3 ml/train_model.py [features_windows.csv]
Default input:  ~/iiot-captures/features_windows.csv
Output:         ml/models/detector.joblib
"""
import os, sys, warnings
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings("ignore")

META = ["session", "orig_h", "window", "t_start", "label"]
here = os.path.dirname(os.path.abspath(__file__))
out_dir = os.path.join(here, "models"); os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, "detector.joblib")

path = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/iiot-captures/features_windows.csv")
df = pd.read_csv(path)
feats = [c for c in df.columns if c not in META]
X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
y = df["label"].astype(str).values
print(f"[*] training on {path}  ({len(df)} windows, {len(feats)} features)")
print(f"[*] classes: {dict(pd.Series(y).value_counts())}")

# supervised detector
try:
    clf = HistGradientBoostingClassifier(class_weight="balanced", random_state=42)
except TypeError:
    clf = HistGradientBoostingClassifier(random_state=42)
clf.fit(X, y)

# anomaly detector (benign only) + its scaler
scaler = StandardScaler().fit(X[y == "benign"])
iso = IsolationForest(contamination="auto", random_state=42, n_jobs=-1).fit(scaler.transform(X[y == "benign"]))

joblib.dump({"detector": clf, "anomaly": iso, "scaler": scaler,
             "features": feats, "classes": sorted(set(y))}, out_path)
print(f"[*] saved model -> {out_path}")
print("[*] use it with:  python3 ml/detect.py <new_features.csv>")
