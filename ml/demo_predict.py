#!/usr/bin/env python3
"""
LIVE DETECTION DEMO — watch the model do what it was trained to do.

Trains the detector on ~70% of the sessions, then takes UNSEEN traffic windows
from the held-out sessions and prints, for each, the TRUE label next to the
model's PREDICTION — so the audience sees it correctly identify each attack.
Then shows the anomaly detector (trained on benign only) flagging attacks.

Usage:  python3 ml/demo_predict.py [features_windows.csv]
Default: ~/iiot-captures/features_windows.csv
"""
import os, sys, warnings
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit
warnings.filterwarnings("ignore")

META = ["session", "orig_h", "window", "t_start", "label"]
path = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/iiot-captures/features_windows.csv")
df = pd.read_csv(path)
feats = [c for c in df.columns if c not in META]
X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
y = df["label"].astype(str).values
groups = df["session"].astype(str).values

# split by SESSION so the test windows are genuinely unseen (no leakage)
tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42).split(X, y, groups))
try:
    clf = HistGradientBoostingClassifier(class_weight="balanced", random_state=42)
except TypeError:
    clf = HistGradientBoostingClassifier(random_state=42)
clf.fit(X[tr], y[tr])
pred = clf.predict(X[te])

yte = y[te]
Xte = X[te]
tedf = df.iloc[te].reset_index(drop=True)
show = [c for c in ["cn_conn_rate", "cn_rej_ratio", "mb_rate", "mb_write_ratio", "mb_read"] if c in feats]
col = {c: feats.index(c) for c in show}

print("=" * 84)
print("LIVE DETECTION  —  model classifying traffic windows it has NEVER seen")
print("=" * 84)
print(f"{'window':<18}{'TRUE':<9}{'PREDICTED':<11}{'?':<3} tell-tale features")
print("-" * 84)
for cls in sorted(set(yte)):
    rows = [i for i in range(len(yte)) if yte[i] == cls][:3]     # up to 3 per class
    for i in rows:
        feat_str = "  ".join(f"{c}={Xte[i][col[c]]:.2f}" for c in show)
        mark = "OK" if pred[i] == yte[i] else "XX"
        w = f"{tedf.iloc[i]['session']}#{int(tedf.iloc[i]['window'])}"
        print(f"{w:<18}{yte[i]:<9}{pred[i]:<11}{mark:<3} {feat_str}")
correct = int((pred == yte).sum())
print("-" * 84)
print(f"On {len(yte)} unseen windows the detector was correct {correct} times ({correct/len(yte):.1%}).")

print("\n" + "=" * 84)
print("ANOMALY / ZERO-DAY  —  detector trained on BENIGN only; % of windows it flags as abnormal")
print("=" * 84)
sc = StandardScaler().fit(X[tr][y[tr] == "benign"])
iso = IsolationForest(contamination="auto", random_state=42, n_jobs=-1).fit(sc.transform(X[tr][y[tr] == "benign"]))
flag = iso.predict(sc.transform(Xte)) == -1
for cls in sorted(set(yte)):
    m = yte == cls
    if m.any():
        print(f"  {cls:<10} flagged abnormal: {flag[m].mean():6.1%}   (n={int(m.sum())})")
print("\n(benign should be low; every attack class should be high — it catches attacks it never trained on.)")
