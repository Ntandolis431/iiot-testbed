#!/usr/bin/env python3
"""
============================================================================
 train_multilabel.py  --  Phase 2: multi-label detector (with tuned thresholds)
============================================================================
Detects SEVERAL attack types in the SAME window. Uses BINARY RELEVANCE: one
HistGradientBoosting head per attack class (recon, flood, write, replay, read),
each answering "is THIS attack present in this window?". A window can be flagged
with 0, 1 or several classes at once; 0 positives = benign.

Two input files (deliberate):
  * LIVE capture (features_multilabel.csv): genuine CONCURRENT-attack windows,
    but almost no benign traffic.
  * ORIGINAL capture (features_windows.csv): benign-rich, clean single-attack
    windows (converted here to one-hot multi-label; benign -> all zeros).
Merged -> benign coverage AND real multi-label overlap, same feature space.

Per-class DECISION THRESHOLDS:
  Binary relevance defaults to flagging a class when its probability > 0.5. The
  read/replay heads over-fire at 0.5 (their behaviour overlaps flood/write), so
  we TUNE a threshold per class on the out-of-fold probabilities to maximise
  F1, and save it. Detection then flags a class only when prob >= its threshold.

Evaluation is leakage-safe: grouped CV (GroupKFold), out-of-fold probabilities
-> per-class precision/recall/F1 at the tuned threshold, plus multi-label subset
accuracy, Hamming loss, and an attack-vs-benign headline. Also fits an
IsolationForest (benign only) for unknown/zero-day traffic.

Usage:
    python3 ml/train_multilabel.py \
        --multilabel ~/iiot-live/features_multilabel.csv \
        --singlelabel ~/iiot-captures/features_windows.csv
Output:
    ml/models/detector_multilabel.joblib
============================================================================
"""
import os, sys, argparse, warnings
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             hamming_loss, accuracy_score)
warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
CLASSES = ["recon", "scan", "flood", "write", "replay", "read", "malformed", "mitm"]
LABEL_COLS = ["is_" + c for c in CLASSES]
BLOCK = 15                                   # live windows per synthetic CV group
GRID = np.round(np.arange(0.30, 0.91, 0.05), 2)   # threshold search grid

ap = argparse.ArgumentParser()
ap.add_argument("--multilabel", default=os.path.expanduser("~/iiot-live/features_multilabel.csv"))
ap.add_argument("--singlelabel", default=os.path.expanduser("~/iiot-captures/features_windows.csv"))
ap.add_argument("--out", default=os.path.join(HERE, "models", "detector_multilabel.joblib"))
args = ap.parse_args()

def new_head():
    try:
        return HistGradientBoostingClassifier(class_weight="balanced", random_state=42)
    except TypeError:
        return HistGradientBoostingClassifier(random_state=42)

def proba1(clf, X):
    """probability of class '1' from a fitted binary head."""
    p = clf.predict_proba(X)
    j = list(clf.classes_).index(1) if 1 in clf.classes_ else -1
    return p[:, j] if j >= 0 else np.zeros(len(X))

# ---------------------------------------------------------------- load & merge
def feature_cols(df):
    return [c for c in df.columns if c.startswith("cn_") or c.startswith("mb_")]

frames, FEATURES = [], None
if os.path.exists(args.multilabel):
    m = pd.read_csv(args.multilabel)
    FEATURES = feature_cols(m)
    for c in LABEL_COLS:
        if c not in m.columns:
            m[c] = 0
    grp = "live_" + (pd.to_numeric(m["window"], errors="coerce").fillna(0).astype(int) // BLOCK).astype(str)
    frames.append((m[FEATURES], m[LABEL_COLS].astype(int), grp))
    print(f"[*] multilabel : {len(m)} windows from {args.multilabel}")
else:
    print(f"[!] multilabel file not found: {args.multilabel}")

if os.path.exists(args.singlelabel):
    s = pd.read_csv(args.singlelabel)
    if FEATURES is None:
        FEATURES = feature_cols(s)
    for c in LABEL_COLS:
        s[c] = 0
    lab = s["label"].astype(str)
    for c in CLASSES:
        s.loc[lab == c, "is_" + c] = 1
    frames.append((s[FEATURES], s[LABEL_COLS].astype(int), s["session"].astype(str)))
    print(f"[*] singlelabel: {len(s)} windows from {args.singlelabel} ({int((lab=='benign').sum())} benign)")
else:
    print(f"[!] singlelabel file not found: {args.singlelabel}")

if not frames:
    sys.exit("[!] no input data.")

X = pd.concat([f[0] for f in frames], ignore_index=True).apply(pd.to_numeric, errors="coerce").fillna(0.0)
Y = pd.concat([f[1] for f in frames], ignore_index=True).values
groups = pd.concat([f[2] for f in frames], ignore_index=True).values
X = X[FEATURES].values

n_benign = int((Y.sum(axis=1) == 0).sum())
print(f"[*] merged: {len(X)} windows, {len(FEATURES)} features, {n_benign} benign")
print(f"[*] per-class positives: " + ", ".join(f"{c}={int(Y[:,j].sum())}" for j, c in enumerate(CLASSES)))
print(f"[*] groups: {len(set(groups))}")

# ---------------------------------------------------------------- grouped CV (OOF probabilities)
n_splits = min(5, len(set(groups)))
gkf = GroupKFold(n_splits=n_splits)
oof_p = np.zeros_like(Y, dtype=float)
print(f"\n[*] {n_splits}-fold grouped cross-validation (out-of-fold probabilities)...")
for tr, te in gkf.split(X, Y[:, 0], groups):
    for j in range(len(CLASSES)):
        ytr = Y[tr, j]
        if ytr.min() == ytr.max():
            oof_p[te, j] = float(ytr[0])
        else:
            h = new_head(); h.fit(X[tr], ytr)
            oof_p[te, j] = proba1(h, X[te])

# ---------------------------------------------------------------- tune per-class thresholds
def prf(yt, yp):
    return (precision_score(yt, yp, zero_division=0),
            recall_score(yt, yp, zero_division=0),
            f1_score(yt, yp, zero_division=0))

thresholds = {}
rows_default, rows_tuned = [], []
for j, c in enumerate(CLASSES):
    yt = Y[:, j]
    # default 0.5
    rows_default.append((c,) + prf(yt, (oof_p[:, j] >= 0.5).astype(int)))
    # search grid for best F1 (tie -> higher threshold = more precision)
    best_t, best_f = 0.5, -1.0
    for t in GRID:
        f = f1_score(yt, (oof_p[:, j] >= t).astype(int), zero_division=0)
        if f > best_f + 1e-9 or (abs(f - best_f) <= 1e-9 and t > best_t):
            best_f, best_t = f, float(t)
    thresholds[c] = best_t
    rows_tuned.append((c, best_t) + prf(yt, (oof_p[:, j] >= best_t).astype(int)))

def pred_at(thr_map):
    P = np.zeros_like(Y)
    for j, c in enumerate(CLASSES):
        P[:, j] = (oof_p[:, j] >= thr_map[c]).astype(int)
    return P

pred_def = pred_at({c: 0.5 for c in CLASSES})
pred_tun = pred_at(thresholds)

def block(title, P):
    yt_any = (Y.sum(1) > 0).astype(int); yp_any = (P.sum(1) > 0).astype(int)
    fp = (yp_any[yt_any == 0] == 1).mean() if (yt_any == 0).any() else float("nan")
    print(f"  {title}")
    print(f"    macro-F1 {f1_score(Y,P,average='macro',zero_division=0):.3f}  "
          f"micro-F1 {f1_score(Y,P,average='micro',zero_division=0):.3f}  "
          f"subset-acc {accuracy_score(Y,P):.3f}  hamming {hamming_loss(Y,P):.3f}")
    print(f"    attack-vs-benign: acc {(yt_any==yp_any).mean():.3f}  "
          f"recall {(yp_any[yt_any==1]==1).mean():.3f}  benign-false-alarm {fp:.3f}")

print("\n" + "=" * 68)
print("  MULTI-LABEL PERFORMANCE  (leakage-safe, out-of-fold)")
print("=" * 68)
print(f"  {'class':<9}{'thr':>6}{'precision':>11}{'recall':>9}{'f1':>8}{'support':>9}")
for (c, p0, r0, f0), (c2, t, p1, r1, f1v) in zip(rows_default, rows_tuned):
    print(f"  {c:<9}{t:>6.2f}{p1:>11.3f}{r1:>9.3f}{f1v:>8.3f}{int(Y[:,CLASSES.index(c)].sum()):>9}"
          f"    (@0.50: P{p0:.2f} R{r0:.2f} F{f0:.2f})")
print("-" * 68)
block("default (all @0.50):", pred_def)
block("tuned  (per-class) :", pred_tun)
print("=" * 68)

# ---------------------------------------------------------------- fit final heads
print("\n[*] fitting final per-class heads on all data ...")
heads = {}
for j, c in enumerate(CLASSES):
    yj = Y[:, j]
    if yj.min() == yj.max():
        heads[c] = ("const", int(yj[0]))
    else:
        h = new_head(); h.fit(X, yj); heads[c] = ("model", h)

Xb = X[Y.sum(axis=1) == 0]
scaler = StandardScaler().fit(Xb)
iso = IsolationForest(contamination="auto", random_state=42, n_jobs=-1).fit(scaler.transform(Xb))

os.makedirs(os.path.dirname(args.out), exist_ok=True)
joblib.dump({"heads": heads, "thresholds": thresholds, "anomaly": iso,
             "scaler": scaler, "features": FEATURES, "classes": CLASSES}, args.out)
print(f"[*] tuned thresholds: {thresholds}")
print(f"[*] saved multi-label model -> {args.out}")
print("[*] detect with:  python3 ml/detect_multilabel.py <features.csv>")
