#!/usr/bin/env python3
"""
Cross-dataset DOMAIN ADAPTATION (leakage-safe): testbed -> CIC Modbus 2023.

Zero-shot transfer of a testbed-trained detector to CIC fails because the two
networks have different feature distributions (the well-documented cross-dataset
generalisation gap for ML-based NIDS). This demonstrates the standard remedy --
supervised domain adaptation -- by letting the model see a labelled slice of the
target (CIC) network during training, then evaluating on a held-out CIC test set.

Leakage-safe split: whole benign SESSIONS go entirely to adapt OR to test, so no
window is shared between train and test; the single attack capture is split
TEMPORALLY (first half to adapt, second half to test). Reports BOTH the zero-shot
baseline and the adapted model on the SAME held-out test set.

Usage:
    python3 ml/validate_cic_adapt.py <own_features.csv> <cic_features.csv> [adapt_frac]
"""
import os, sys, warnings
import numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
warnings.filterwarnings("ignore")

own_path = sys.argv[1]
cic_path = sys.argv[2]
ADAPT_FRAC = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
BENIGN_CAP = 20000
RNG = 42

own = pd.read_csv(own_path)
cic = pd.read_csv(cic_path)
print(f"[*] own: {own_path} ({len(own)})")
print(f"[*] cic: {cic_path} ({len(cic)})")

def feature_cols(df):
    return [c for c in df.columns if c.startswith("cn_") or c.startswith("mb_")]
feats = [c for c in feature_cols(own) if c in set(feature_cols(cic))]
print(f"[*] using {len(feats)} shared features; adapt_frac={ADAPT_FRAC}")

def X(df):
    return df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values

def binlabel(df):
    if "benign" in df.columns:
        return np.where(df["benign"].astype(str).isin(["1", "1.0", "True"]), "benign", "attack")
    return np.where(df["label"].astype(str) == "benign", "benign", "attack")

Xo, yo = X(own), binlabel(own)
cic["_bin"] = binlabel(cic)
print(f"[*] own balance: {dict(pd.Series(yo).value_counts())}")
print(f"[*] cic balance: {dict(cic['_bin'].value_counts())}")

# ---- LEAKAGE-SAFE split ----------------------------------------------------------
# whole benign sessions -> adapt or test; single attack session split temporally.
rng = np.random.RandomState(RNG)
bsess = sorted(cic.loc[cic["_bin"] == "benign", "session"].unique())
rng.shuffle(bsess)
n_ad = max(1, int(round(len(bsess) * ADAPT_FRAC)))
adapt_sess, test_sess = set(bsess[:n_ad]), set(bsess[n_ad:])
ben = cic[cic["_bin"] == "benign"]
att = cic[cic["_bin"] == "attack"].sort_values("window")
h = len(att) // 2
adapt_df = pd.concat([ben[ben["session"].isin(adapt_sess)], att.iloc[:h]])
test_df  = pd.concat([ben[ben["session"].isin(test_sess)],  att.iloc[h:]])

def cap_benign_df(df, cap):
    b = df[df["_bin"] == "benign"]; a = df[df["_bin"] == "attack"]
    if len(b) > cap:
        b = b.sample(cap, random_state=RNG)
    return pd.concat([b, a])

adapt_df = cap_benign_df(adapt_df, BENIGN_CAP)
Xc_ad, yc_ad = X(adapt_df), adapt_df["_bin"].values
Xc_te, yc_te = X(test_df),  test_df["_bin"].values
print(f"[*] adapt: {dict(pd.Series(yc_ad).value_counts())}  ({len(adapt_sess)} benign sessions)")
print(f"[*] test : {dict(pd.Series(yc_te).value_counts())}  ({len(test_sess)} benign sessions, held out)")

# save the exact split as reproducible artifacts (drop the helper column)
_out = os.path.dirname(os.path.abspath(cic_path))
adapt_df.drop(columns=["_bin"]).to_csv(os.path.join(_out, "cic_adapt.csv"), index=False)
test_df.drop(columns=["_bin"]).to_csv(os.path.join(_out, "cic_test.csv"), index=False)
print(f"[*] wrote adaptation sample -> {os.path.join(_out, 'cic_adapt.csv')} ({len(adapt_df)} rows)")
print(f"[*] wrote held-out test set -> {os.path.join(_out, 'cic_test.csv')} ({len(test_df)} rows)")

def new_clf():
    try:
        return HistGradientBoostingClassifier(class_weight="balanced", random_state=RNG)
    except TypeError:
        return HistGradientBoostingClassifier(random_state=RNG)

def report(tag, clf, Xte, yte):
    pred = clf.predict(Xte)
    print("\n" + "=" * 60 + f"\n[*] {tag}")
    print(classification_report(yte, pred, labels=["benign", "attack"], zero_division=0))
    cm = confusion_matrix(yte, pred, labels=["benign", "attack"])
    print("Confusion (rows=true benign/attack, cols=pred benign/attack):")
    print(cm)
    tn, fp = cm[0]; fn, tp = cm[1]
    far = fp / (fp + tn) if (fp + tn) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    print(f"    attack recall = {rec:.3f}   benign false-alarm = {far:.4f}")
    return rec, far

clf0 = new_clf().fit(Xo, yo)
r0, f0 = report("ZERO-SHOT  (train: testbed only)", clf0, Xc_te, yc_te)

Xad = np.vstack([Xo, Xc_ad]); yad = np.concatenate([yo, yc_ad])
clf1 = new_clf().fit(Xad, yad)
r1, f1 = report("ADAPTED    (train: testbed + CIC slice)", clf1, Xc_te, yc_te)

print("\n" + "=" * 60)
print("[*] SUMMARY on identical, leakage-safe held-out CIC test set:")
print(f"    zero-shot : attack recall {r0:.3f}  benign false-alarm {f0:.4f}")
print(f"    adapted   : attack recall {r1:.3f}  benign false-alarm {f1:.4f}")
print(f"    test attacks = {int((yc_te=='attack').sum())} (small sample; recall is coarse)")
