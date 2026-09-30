#!/usr/bin/env python3
"""
============================================================================
 live_detect.py  --  always-on, real-time detector (LIVE env)
============================================================================
Phase 1 of the live-environment roadmap.

The batch pipeline detects AFTER a capture. This runs continuously: while
zeek-live keeps appending conn.log / modbus.log, this loop wakes up every
few seconds, turns the traffic so far into 1-second feature windows (reusing
the exact same build_features.py as training), scores each NEW, COMPLETED
window with the saved model, and streams the verdicts as they happen.

It only ever reports a window once (tracked by session+source+window index),
and it holds back the most recent, still-filling window until it is complete,
so verdicts don't flap on partial data.

Detection only -- automated prevention (blocking the attacker) is Phase 3.

Prerequisites:
  * a trained model:   python3 ml/train_model.py
  * a live capture:    bash scripts/start-live-capture.sh   (host-mounted logs)

Usage:
  python3 ml/live_detect.py                          # defaults
  python3 ml/live_detect.py --interval 3
  IIOT_CAP_DIR=~/iiot-live python3 ml/live_detect.py

Stop with Ctrl+C.
============================================================================
"""
import os, sys, time, argparse, warnings, subprocess, datetime as dt
import numpy as np, pandas as pd, joblib
warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD = os.path.join(REPO, "scripts", "build_features.py")
META = ["session", "orig_h", "window", "t_start", "label"]

ap = argparse.ArgumentParser()
ap.add_argument("--cap-dir", default=os.environ.get("IIOT_CAP_DIR", os.path.expanduser("~/iiot-captures")),
                help="capture root that contains the live/ Zeek logs")
ap.add_argument("--model", default=os.path.join(HERE, "models", "detector.joblib"))
ap.add_argument("--interval", type=float, default=3.0, help="seconds between detection cycles")
ap.add_argument("--window", type=float, default=1.0, help="feature window size (must match training)")
args = ap.parse_args()

if not os.path.exists(args.model):
    sys.exit(f"[!] no model at {args.model} -- run:  python3 ml/train_model.py")

bundle = joblib.load(args.model)
clf, iso, scaler, feats = bundle["detector"], bundle["anomaly"], bundle["scaler"], bundle["features"]

FEATURES_CSV = os.path.join(args.cap_dir, "features_windows.csv")
ALERTS_CSV = os.path.join(args.cap_dir, "alerts.csv")

def now_hms():
    return dt.datetime.now().strftime("%H:%M:%S")

def rebuild_features():
    """Re-window the live Zeek logs with the SAME extractor used for training."""
    env = dict(os.environ, IIOT_CAP_DIR=args.cap_dir, ATTACKER_IP="0.0.0.0")
    # ATTACKER_IP is irrelevant here -- we predict from features, we don't use the label column.
    subprocess.run([sys.executable, BUILD, str(args.window)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def score(df):
    for c in feats:
        if c not in df.columns:
            df[c] = 0.0
    X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
    pred = clf.predict(X)
    conf = clf.predict_proba(X).max(axis=1)
    anom = iso.predict(scaler.transform(X)) == -1
    verdict = np.where((pred == "benign") & anom, "UNKNOWN(anomaly)", pred)
    return pred, conf, anom, verdict

print("=" * 70)
print(f"[*] live detector up   model={os.path.basename(args.model)}   window={args.window}s")
print(f"[*] watching : {os.path.join(args.cap_dir, 'live')}")
print(f"[*] alerts   : {ALERTS_CSV}")
print(f"[*] cycle    : every {args.interval}s   (Ctrl+C to stop)")
print("=" * 70)

if not os.path.exists(ALERTS_CSV):
    with open(ALERTS_CSV, "w") as f:
        f.write("wall_time,t_start,source,verdict,confidence\n")

seen = set()                 # (session, orig_h, window) already reported
totals = {}                  # verdict -> count
n_windows = 0
n_alerts = 0

# --- prime: mark whatever already exists as "seen" so we only report NEW
#     activity that happens after the detector starts (avoids dumping history
#     when re-using a capture dir). A fresh dir just primes to nothing.
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
            print(f"[{now_hms()}] waiting for live logs at {os.path.join(args.cap_dir,'live')} ...")
            time.sleep(args.interval); continue

        try:
            df = pd.read_csv(FEATURES_CSV)
        except Exception:
            time.sleep(args.interval); continue
        if len(df) == 0:
            print(f"[{now_hms()}] no windows yet ...")
            time.sleep(args.interval); continue

        # keep only NEW windows that are COMPLETE (t_start + window + 1s <= now)
        df["_t"] = pd.to_numeric(df["t_start"], errors="coerce").fillna(0.0)
        complete = df["_t"] + args.window + 1.0 <= cycle_t
        keys = list(zip(df["session"], df["orig_h"], df["window"]))
        fresh_mask = [complete.iloc[i] and (keys[i] not in seen) for i in range(len(df))]
        fresh = df[pd.Series(fresh_mask, index=df.index)]

        if len(fresh) == 0:
            print(f"[{now_hms()}] . no new completed windows  "
                  f"(scored {n_windows} so far, {n_alerts} alerts)")
            time.sleep(max(0, args.interval - (time.time() - cycle_t)))
            continue

        pred, conf, anom, verdict = score(fresh.copy())

        lines = []
        with open(ALERTS_CSV, "a") as af:
            for i in range(len(fresh)):
                k = (fresh.iloc[i]["session"], fresh.iloc[i]["orig_h"], fresh.iloc[i]["window"])
                seen.add(k)
                v = str(verdict[i]); src = str(fresh.iloc[i]["orig_h"])
                totals[v] = totals.get(v, 0) + 1
                n_windows += 1
                tag = "OK " if v == "benign" else ">> "
                lines.append(f"    {tag}{src:<15} {v:<16} conf={conf[i]:.2f}")
                if v != "benign":
                    n_alerts += 1
                    af.write(f"{now_hms()},{fresh.iloc[i]['t_start']},{src},{v},{conf[i]:.3f}\n")

        print(f"[{now_hms()}] +{len(fresh)} window(s):")
        # show alerts first, then a couple of benign for context
        alerts = [l for l in lines if l.strip().startswith(">>")]
        benign = [l for l in lines if l.strip().startswith("OK")]
        for l in alerts:
            print(l)
        for l in benign[:3]:
            print(l)
        if len(benign) > 3:
            print(f"    OK ... +{len(benign)-3} more benign")

        time.sleep(max(0, args.interval - (time.time() - cycle_t)))

except KeyboardInterrupt:
    print("\n" + "=" * 70)
    print(f"[*] stopped.  scored {n_windows} windows, {n_alerts} alerts.")
    print(f"[*] verdict totals: {dict(sorted(totals.items(), key=lambda x:-x[1]))}")
    print(f"[*] alert log -> {ALERTS_CSV}")
