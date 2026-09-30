#!/usr/bin/env python3
"""
The working detector. Loads the saved model (ml/models/detector.joblib) and runs
detection on a feature table produced by build_features.py — i.e. on NEW captured
traffic, not the training data.

For each window it outputs: the predicted class, a confidence, whether the anomaly
detector flags it, and a final verdict (a window predicted benign but flagged
abnormal is reported as UNKNOWN / possible zero-day).

Typical use in the pipeline:
    new pcap -> Zeek -> build_features.py -> detect.py -> predictions

Usage:  python3 ml/detect.py <features.csv> [--out predictions.csv]
Default model:  ml/models/detector.joblib
"""
import os, sys, argparse, warnings
import numpy as np, pandas as pd, joblib
warnings.filterwarnings("ignore")

META = ["session", "orig_h", "window", "t_start", "label"]
here = os.path.dirname(os.path.abspath(__file__))

ap = argparse.ArgumentParser()
ap.add_argument("input", help="features CSV from build_features.py")
ap.add_argument("--model", default=os.path.join(here, "models", "detector.joblib"))
ap.add_argument("--out", default=None, help="where to write predictions (default: alongside input)")
args = ap.parse_args()

if not os.path.exists(args.model):
    sys.exit(f"[!] no model at {args.model} — run:  python3 ml/train_model.py")
bundle = joblib.load(args.model)
clf, iso, scaler, feats = bundle["detector"], bundle["anomaly"], bundle["scaler"], bundle["features"]

df = pd.read_csv(args.input)
# align to the exact feature columns the model was trained on
for c in feats:
    if c not in df.columns:
        df[c] = 0.0
X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values

if len(X) == 0:
    print(f"[!] no traffic windows in {args.input} — the capture was empty or too brief to window.")
    print("    (re-run the attack a little longer so at least ~1 second of traffic is captured.)")
    sys.exit(0)

pred = clf.predict(X)
conf = clf.predict_proba(X).max(axis=1)
anom = iso.predict(scaler.transform(X)) == -1
verdict = np.where((pred == "benign") & anom, "UNKNOWN (anomalous)", pred)

out = df[[c for c in ["session", "orig_h", "window", "t_start"] if c in df.columns]].copy()
out["predicted"] = pred
out["confidence"] = conf.round(3)
out["anomaly"] = anom
out["verdict"] = verdict
out_path = args.out or (os.path.splitext(args.input)[0] + "_predictions.csv")
out.to_csv(out_path, index=False)

# ---- console summary
print("=" * 70)
print(f"[*] detected on {len(df)} windows from {args.input}")
print("[*] verdicts:")
for v, n in out["verdict"].value_counts().items():
    print(f"      {v:<22} {n}")
n_alert = int((verdict != "benign").sum())
print(f"[*] {n_alert} window(s) flagged as attack or unknown "
      f"({n_alert/len(df):.1%} of traffic)")
print(f"[*] full results -> {out_path}")

# if the input happens to carry ground-truth labels, report accuracy too
if "label" in df.columns:
    yb = np.where(df["label"].astype(str) == "benign", "benign", "attack")
    pb = np.where(pred == "benign", "benign", "attack")
    acc = (yb == pb).mean()
    rec = (pb[yb == "attack"] == "attack").mean() if (yb == "attack").any() else float("nan")
    print(f"[*] (labels present) attack-vs-benign accuracy {acc:.1%}, attack recall {rec:.1%}")
