#!/usr/bin/env python3
"""
Cross-dataset validation: train on OUR testbed features, test on CIC Modbus 2023.

The decisive generalization test. Trains a HistGBM detector (attack vs benign) on
our own windowed features, then evaluates it on CIC features produced by the SAME
Zeek + build_features pipeline (scripts/cic-process.sh). Also runs the anomaly
layer (IsolationForest, trained on our benign only) against CIC.

Both datasets are collapsed to binary attack/benign, because CIC is labeled here by
attacker IP (185.175.0.7) rather than per-attack-type.

Usage:
    python3 ml/validate_cic.py [own_features.csv] [cic_features.csv]
Defaults:
    own = ~/iiot-captures/features_windows.csv
    cic = ~/cic-modbus/features_windows.csv
"""
import os, sys, warnings
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
warnings.filterwarnings("ignore")

own_path = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/iiot-captures/features_windows.csv")
cic_path = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/cic-modbus/features_windows.csv")

own = pd.read_csv(own_path)
cic = pd.read_csv(cic_path)
print(f"[*] own: {own_path}  ({len(own)} windows)")
print(f"[*] cic: {cic_path}  ({len(cic)} windows)")

# Only genuine flow/protocol features; never leak label columns (is_*, benign,
# n_labels, label) or metadata. Intersect so schema drift (e.g. CIC lacking the
# address features) is handled gracefully.
def feature_cols(df):
    return [c for c in df.columns if c.startswith("cn_") or c.startswith("mb_")]
feats = [c for c in feature_cols(own) if c in set(feature_cols(cic))]
print(f"[*] using {len(feats)} shared features")

def X(df):
    return df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values

def binlabel(df):
    # prefer the multi-label 'benign' flag (our features_windows.csv 'label' is
    # all-benign because features are built with a null attacker IP); fall back to
    # the single-label 'label' column (as CIC's is produced by attacker IP).
    if "benign" in df.columns:
        return np.where(df["benign"].astype(str).isin(["1", "1.0", "True"]), "benign", "attack")
    return np.where(df["label"].astype(str) == "benign", "benign", "attack")

Xo, yo = X(own), binlabel(own)
Xc, yc = X(cic), binlabel(cic)
print(f"[*] own balance: {dict(pd.Series(yo).value_counts())}")
print(f"[*] cic balance: {dict(pd.Series(yc).value_counts())}\n")

# ---- supervised detector: train on own, test on CIC
clf = HistGradientBoostingClassifier(class_weight="balanced", random_state=42) \
    if "class_weight" in HistGradientBoostingClassifier().get_params() \
    else HistGradientBoostingClassifier(random_state=42)
clf.fit(Xo, yo)
pred = clf.predict(Xc)
print("=" * 60)
print("[*] SUPERVISED HistGBM  (trained on testbed -> tested on CIC)")
print(classification_report(yc, pred, labels=["benign", "attack"], zero_division=0))
print("Confusion matrix (rows=true benign/attack, cols=pred benign/attack):")
print(confusion_matrix(yc, pred, labels=["benign", "attack"]))

# ---- anomaly layer: fit on own benign only, flag CIC
sc = StandardScaler().fit(Xo[yo == "benign"])
iso = IsolationForest(contamination="auto", random_state=42, n_jobs=-1).fit(sc.transform(Xo[yo == "benign"]))
flag = iso.predict(sc.transform(Xc)) == -1
print("\n" + "=" * 60)
print("[*] ANOMALY IsolationForest (trained on testbed benign -> CIC flag rate)")
for c in ["benign", "attack"]:
    m = yc == c
    if m.any():
        print(f"    {c:8s} flagged as anomaly: {flag[m].mean():6.1%}  (n={int(m.sum())})")

print("\n[*] Reading: high 'attack' recall = your detector generalizes; a big drop from")
print("    the ~0.98 testbed score is itself a finding (testbed easier than CIC).")
