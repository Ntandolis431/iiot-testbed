#!/usr/bin/env python3
"""
============================================================================
 detect_multilabel.py  --  run the multi-label detector on a feature table
============================================================================
Loads ml/models/detector_multilabel.joblib and, for each window, asks every
per-class head "is this attack present?". A window can be flagged with several
classes at once (e.g. "flood+write"); no positives = benign; benign but
anomaly-flagged = UNKNOWN (possible zero-day).

Usage:  python3 ml/detect_multilabel.py <features.csv> [--out preds.csv]
============================================================================
"""
import os, sys, argparse, warnings
import numpy as np, pandas as pd, joblib
warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser()
ap.add_argument("input")
ap.add_argument("--model", default=os.path.join(HERE, "models", "detector_multilabel.joblib"))
ap.add_argument("--out", default=None)
args = ap.parse_args()

if not os.path.exists(args.model):
    sys.exit(f"[!] no model at {args.model} -- run:  python3 ml/train_multilabel.py")
b = joblib.load(args.model)
heads, iso, scaler, feats, classes = b["heads"], b["anomaly"], b["scaler"], b["features"], b["classes"]
thr = b.get("thresholds", {c: 0.5 for c in classes})   # per-class decision thresholds

df = pd.read_csv(args.input)
for c in feats:
    if c not in df.columns:
        df[c] = 0.0
X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
if len(X) == 0:
    print(f"[!] no windows in {args.input} -- capture empty or too brief."); sys.exit(0)

# per-class prediction (+ probability where available)
pred = np.zeros((len(X), len(classes)), dtype=int)
prob = np.zeros((len(X), len(classes)), dtype=float)
for j, c in enumerate(classes):
    kind, obj = heads[c]
    if kind == "const":
        prob[:, j] = float(obj)
    else:
        try:
            prob[:, j] = obj.predict_proba(X)[:, list(obj.classes_).index(1)]
        except Exception:
            prob[:, j] = obj.predict(X)
    pred[:, j] = (prob[:, j] >= thr.get(c, 0.5)).astype(int)   # tuned threshold

anom = iso.predict(scaler.transform(X)) == -1

def verdict(i):
    active = [classes[j] for j in range(len(classes)) if pred[i, j] == 1]
    if active:
        return "+".join(active)
    return "UNKNOWN(anomaly)" if anom[i] else "benign"

verdicts = [verdict(i) for i in range(len(X))]

out = df[[c for c in ["session", "orig_h", "window", "t_start"] if c in df.columns]].copy()
for j, c in enumerate(classes):
    out["is_" + c] = pred[:, j]
out["verdict"] = verdicts
out_path = args.out or (os.path.splitext(args.input)[0] + "_multilabel_predictions.csv")
out.to_csv(out_path, index=False)

print("=" * 70)
print(f"[*] detected on {len(df)} windows from {args.input}")
n_attack = sum(1 for v in verdicts if v not in ("benign",))
n_multi = sum(1 for i in range(len(X)) if pred[i].sum() >= 2)
print(f"[*] {n_attack} attack/unknown windows, of which {n_multi} are MULTI-attack")
from collections import Counter
print("[*] verdict breakdown:")
for v, k in Counter(verdicts).most_common():
    print(f"      {v:<28} {k}")
print(f"[*] full results -> {out_path}")
