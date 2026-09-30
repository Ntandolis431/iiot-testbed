#!/usr/bin/env python3
"""
============================================================================
 live_detect_multilabel.py  --  always-on MULTI-LABEL detector (Phase 2)
============================================================================
Same live loop as live_detect.py, but uses the multi-label model
(detector_multilabel.joblib) and reports ALL attack classes active in each
window at once -- e.g. a window that is flooding AND writing prints
"flood+write" instead of just the single top class.

While zeek-live keeps appending conn.log/modbus.log, this wakes every few
seconds, windows the traffic so far, scores each NEW COMPLETED window, and
streams the concurrent verdict per source. Detection only; blocking is Phase 3.

Prereqs:
  * multi-label model:   python3 ml/train_multilabel.py
  * live capture:        bash scripts/start-live-capture.sh   (host-mounted)

Usage:
  IIOT_CAP_DIR=~/iiot-live python3 ml/live_detect_multilabel.py [--interval 3]
Stop with Ctrl+C.
============================================================================
"""
import os, sys, time, argparse, warnings, subprocess, datetime as dt
from collections import Counter
import numpy as np, pandas as pd, joblib
warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD = os.path.join(REPO, "scripts", "build_features.py")

ap = argparse.ArgumentParser()
ap.add_argument("--cap-dir", default=os.environ.get("IIOT_CAP_DIR", os.path.expanduser("~/iiot-live")))
ap.add_argument("--model", default=os.path.join(HERE, "models", "detector_multilabel.joblib"))
ap.add_argument("--interval", type=float, default=3.0)
ap.add_argument("--window", type=float, default=1.0)
args = ap.parse_args()

if not os.path.exists(args.model):
    sys.exit(f"[!] no model at {args.model} -- run:  python3 ml/train_multilabel.py")
b = joblib.load(args.model)
heads, iso, scaler, feats, classes = b["heads"], b["anomaly"], b["scaler"], b["features"], b["classes"]
thr = b.get("thresholds", {c: 0.5 for c in classes})   # per-class decision thresholds

FEATURES_CSV = os.path.join(args.cap_dir, "features_windows.csv")
ALERTS_CSV = os.path.join(args.cap_dir, "alerts_multilabel.csv")

def now_hms():
    return dt.datetime.now().strftime("%H:%M:%S")

def rebuild_features():
    env = dict(os.environ, IIOT_CAP_DIR=args.cap_dir, ATTACKER_IP="0.0.0.0")
    subprocess.run([sys.executable, BUILD, str(args.window)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def score(df):
    for c in feats:
        if c not in df.columns:
            df[c] = 0.0
    X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
    pred = np.zeros((len(X), len(classes)), dtype=int)
    for j, c in enumerate(classes):
        kind, obj = heads[c]
        if kind == "const":
            p = np.full(len(X), float(obj))
        else:
            try:
                p = obj.predict_proba(X)[:, list(obj.classes_).index(1)]
            except Exception:
                p = obj.predict(X)
        pred[:, j] = (p >= thr.get(c, 0.5)).astype(int)   # tuned threshold
    anom = iso.predict(scaler.transform(X)) == -1
    verdicts = []
    for i in range(len(X)):
        active = [classes[j] for j in range(len(classes)) if pred[i, j] == 1]
        if active:
            verdicts.append("+".join(active))
        else:
            verdicts.append("UNKNOWN(anomaly)" if anom[i] else "benign")
    return verdicts

print("=" * 70)
print(f"[*] live MULTI-LABEL detector up   model={os.path.basename(args.model)}")
print(f"[*] classes  : {classes}")
print(f"[*] watching : {os.path.join(args.cap_dir, 'live')}")
print(f"[*] alerts   : {ALERTS_CSV}")
print(f"[*] cycle    : every {args.interval}s   (Ctrl+C to stop)")
print("=" * 70)

if not os.path.exists(ALERTS_CSV):
    with open(ALERTS_CSV, "w") as f:
        f.write("wall_time,t_start,source,verdict\n")

seen, totals = set(), Counter()
n_windows = n_alerts = n_multi = 0

# prime: ignore whatever already exists so we only report new activity
rebuild_features()
if os.path.exists(FEATURES_CSV):
    try:
        _p = pd.read_csv(FEATURES_CSV)
        for _k in zip(_p["session"], _p["orig_h"], _p["window"]):
            seen.add(_k)
        print(f"[*] primed: ignoring {len(seen)} pre-existing window(s); watching for new traffic.")
    except Exception:
        pass

try:
    while True:
        cycle_t = time.time()
        rebuild_features()
        if not os.path.exists(FEATURES_CSV):
            print(f"[{now_hms()}] waiting for live logs ..."); time.sleep(args.interval); continue
        try:
            df = pd.read_csv(FEATURES_CSV)
        except Exception:
            time.sleep(args.interval); continue
        if len(df) == 0:
            print(f"[{now_hms()}] no windows yet ..."); time.sleep(args.interval); continue

        df["_t"] = pd.to_numeric(df["t_start"], errors="coerce").fillna(0.0)
        complete = df["_t"] + args.window + 1.0 <= cycle_t
        keys = list(zip(df["session"], df["orig_h"], df["window"]))
        fresh_mask = [complete.iloc[i] and (keys[i] not in seen) for i in range(len(df))]
        fresh = df[pd.Series(fresh_mask, index=df.index)]

        if len(fresh) == 0:
            print(f"[{now_hms()}] . no new completed windows  "
                  f"(scored {n_windows}, {n_alerts} alerts, {n_multi} multi-attack)")
            time.sleep(max(0, args.interval - (time.time() - cycle_t))); continue

        verdicts = score(fresh.copy())
        lines = []
        with open(ALERTS_CSV, "a") as af:
            for i in range(len(fresh)):
                k = (fresh.iloc[i]["session"], fresh.iloc[i]["orig_h"], fresh.iloc[i]["window"])
                seen.add(k)
                v = verdicts[i]; src = str(fresh.iloc[i]["orig_h"])
                totals[v] += 1; n_windows += 1
                is_attack = v != "benign"
                is_multi = "+" in v
                tag = ">> " if is_attack else "OK "
                if is_multi:
                    tag = "** "        # highlight concurrent multi-attack windows
                lines.append(f"    {tag}{src:<15} {v}")
                if is_attack:
                    n_alerts += 1
                    af.write(f"{now_hms()},{fresh.iloc[i]['t_start']},{src},{v}\n")
                if is_multi:
                    n_multi += 1

        print(f"[{now_hms()}] +{len(fresh)} window(s):")
        multi = [l for l in lines if l.strip().startswith("**")]
        alerts = [l for l in lines if l.strip().startswith(">>")]
        benign = [l for l in lines if l.strip().startswith("OK")]
        for l in multi:      print(l)
        for l in alerts:     print(l)
        for l in benign[:2]: print(l)
        if len(benign) > 2:
            print(f"    OK ... +{len(benign)-2} more benign")

        time.sleep(max(0, args.interval - (time.time() - cycle_t)))

except KeyboardInterrupt:
    print("\n" + "=" * 70)
    print(f"[*] stopped.  scored {n_windows} windows, {n_alerts} alerts, "
          f"{n_multi} multi-attack windows.")
    print(f"[*] verdict totals: {dict(totals.most_common())}")
    print(f"[*] alert log -> {ALERTS_CSV}")
