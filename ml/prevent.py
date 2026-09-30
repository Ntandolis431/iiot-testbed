#!/usr/bin/env python3
"""
============================================================================
 prevent.py  --  Phase 3: ML-triggered IPS (detect -> block)
============================================================================
The always-on detector, plus ACTIVE RESPONSE. It runs the multi-label model on
the live traffic and, when it CONFIRMS an attacker, blocks that source at the
PLC (iptables DROP via scripts/ipsblock.sh) -- the testbed stand-in for an SDN
flow-rule / industrial-firewall action.

This follows the availability-first doctrine of NIST SP 800-82 / IEC 62443 with
four safeguards:
  1. ALLOWLIST   -- the PLC, SCADA (FUXA) and gateway (Node-RED) IPs are resolved
                    at startup and can NEVER be blocked.
  2. CONFIRMATION -- a source must be flagged attack in >= --confirm consecutive
                    completed windows before it is blocked (one bad window can't
                    cut off traffic).
  3. AUTO-EXPIRY -- every block is lifted after --ttl seconds.
  4. CLEAN EXIT  -- on Ctrl+C, every block this process added is removed, so the
                    testbed is left in its normal state.

Honest note: zeek taps the interface before netfilter, so after a block you will
still SEE the blocked host's failed connection attempts. What the block stops is
delivery to OpenPLC -- the malicious Modbus requests never reach the PLC, so the
attack is neutralised (verify: run modbus_write while blocked -> it can't complete).

Prereqs:  trained multi-label model, live capture running, attacker container up.

Usage:
  IIOT_CAP_DIR=~/iiot-live python3 ml/prevent.py --confirm 2 --ttl 60
Stop with Ctrl+C (auto-unblocks everything it blocked).
============================================================================
"""
import os, sys, time, argparse, warnings, subprocess, datetime as dt
from collections import Counter, defaultdict
import numpy as np, pandas as pd, joblib
warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD = os.path.join(REPO, "scripts", "build_features.py")
IPSBLOCK = os.path.join(REPO, "scripts", "ipsblock.sh")

ALLOWLIST_CONTAINERS = ["openplc", "fuxa", "nodered", "mosquitto", "grafana", "influxdb"]

ap = argparse.ArgumentParser()
ap.add_argument("--cap-dir", default=os.environ.get("IIOT_CAP_DIR", os.path.expanduser("~/iiot-live")))
ap.add_argument("--model", default=os.path.join(HERE, "models", "detector_multilabel.joblib"))
ap.add_argument("--interval", type=float, default=3.0)
ap.add_argument("--window", type=float, default=1.0)
ap.add_argument("--confirm", type=int, default=2, help="consecutive attack windows before blocking")
ap.add_argument("--ttl", type=float, default=60.0, help="seconds a block stays in place")
ap.add_argument("--plc", default="openplc")
ap.add_argument("--allow", nargs="*", default=[], help="extra IPs to never block")
ap.add_argument("--dry-run", action="store_true", help="log what it WOULD block, but don't touch iptables")
args = ap.parse_args()

if not os.path.exists(args.model):
    sys.exit(f"[!] no model at {args.model} -- run:  python3 ml/train_multilabel.py")
b = joblib.load(args.model)
heads, iso, scaler, feats, classes = b["heads"], b["anomaly"], b["scaler"], b["features"], b["classes"]
thr = b.get("thresholds", {c: 0.5 for c in classes})

FEATURES_CSV = os.path.join(args.cap_dir, "features_windows.csv")
LOG = os.path.join(args.cap_dir, "prevention_log.csv")

def now_hms():
    return dt.datetime.now().strftime("%H:%M:%S")

def docker_ip(name):
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
            capture_output=True, text=True, timeout=10)
        return out.stdout.strip()
    except Exception:
        return ""

# resolve the allowlist
allowlist = set(a for a in args.allow if a)
for c in ALLOWLIST_CONTAINERS:
    ip = docker_ip(c)
    if ip:
        allowlist.add(ip)
ALLOW_STR = " ".join(sorted(allowlist))

def ips(cmd, ip=""):
    """call the enforcement helper (unless dry-run)."""
    if args.dry_run:
        return
    env = dict(os.environ, PLC=args.plc, IPS_ALLOWLIST=ALLOW_STR)
    subprocess.run(["bash", IPSBLOCK, cmd] + ([ip] if ip else []),
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def logline(event, ip, detail=""):
    with open(LOG, "a") as f:
        f.write(f"{now_hms()},{event},{ip},{detail}\n")

def rebuild_features():
    env = dict(os.environ, IIOT_CAP_DIR=args.cap_dir, ATTACKER_IP="0.0.0.0")
    subprocess.run([sys.executable, BUILD, str(args.window)],
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def verdict_for(df):
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
        pred[:, j] = (p >= thr.get(c, 0.5)).astype(int)
    anom = iso.predict(scaler.transform(X)) == -1
    out = []
    for i in range(len(X)):
        active = [classes[j] for j in range(len(classes)) if pred[i, j] == 1]
        if active:
            out.append("+".join(active))
        else:
            out.append("UNKNOWN(anomaly)" if anom[i] else "benign")
    return out

print("=" * 70)
print(f"[*] ML-triggered IPS up   model={os.path.basename(args.model)}")
print(f"[*] protect PLC : {args.plc}")
print(f"[*] allowlist   : {sorted(allowlist)}  (never blocked)")
print(f"[*] policy      : block after {args.confirm} consecutive attack windows; "
      f"auto-unblock after {args.ttl:.0f}s")
if args.dry_run:
    print("[*] DRY-RUN     : will log intended blocks but NOT touch iptables")
print(f"[*] log         : {LOG}")
print(f"[*] cycle       : every {args.interval}s   (Ctrl+C to stop & unblock all)")
print("=" * 70)

if not os.path.exists(LOG):
    with open(LOG, "w") as f:
        f.write("wall_time,event,ip,detail\n")

seen = set()
strikes = Counter()             # source -> consecutive attack windows
blocked = {}                    # source -> expiry epoch
refused_note = set()            # allowlisted sources we've already noted
totals = Counter()
n_windows = 0

# prime: ignore pre-existing windows
rebuild_features()
if os.path.exists(FEATURES_CSV):
    try:
        _p = pd.read_csv(FEATURES_CSV)
        for _k in zip(_p["session"], _p["orig_h"], _p["window"]):
            seen.add(_k)
        print(f"[*] primed: ignoring {len(seen)} pre-existing window(s).")
    except Exception:
        pass

try:
    while True:
        cycle_t = time.time()

        # 1. expire old blocks
        for ip in [ip for ip, exp in blocked.items() if cycle_t >= exp]:
            ips("unblock", ip); del blocked[ip]; strikes[ip] = 0
            print(f"[{now_hms()}] [UNBLOCK] {ip} (ttl expired)")
            logline("UNBLOCK", ip, "ttl-expired")

        # 2. detect on new completed windows
        rebuild_features()
        if not os.path.exists(FEATURES_CSV):
            time.sleep(args.interval); continue
        try:
            df = pd.read_csv(FEATURES_CSV)
        except Exception:
            time.sleep(args.interval); continue
        if len(df) == 0:
            time.sleep(args.interval); continue

        df["_t"] = pd.to_numeric(df["t_start"], errors="coerce").fillna(0.0)
        complete = df["_t"] + args.window + 1.0 <= cycle_t
        keys = list(zip(df["session"], df["orig_h"], df["window"]))
        mask = [complete.iloc[i] and (keys[i] not in seen) for i in range(len(df))]
        fresh = df[pd.Series(mask, index=df.index)]

        if len(fresh) == 0:
            act = len(blocked)
            print(f"[{now_hms()}] . monitoring  (scored {n_windows}, "
                  f"{act} active block{'s' if act!=1 else ''})")
            time.sleep(max(0, args.interval - (time.time() - cycle_t))); continue

        verdicts = verdict_for(fresh.copy())
        for i in range(len(fresh)):
            k = (fresh.iloc[i]["session"], fresh.iloc[i]["orig_h"], fresh.iloc[i]["window"])
            seen.add(k); n_windows += 1
            src = str(fresh.iloc[i]["orig_h"]); v = verdicts[i]
            totals[v] += 1
            is_attack = v != "benign"

            if not is_attack:
                strikes[src] = 0
                continue
            if src in blocked:
                continue                              # already handled
            if src in allowlist:
                if src not in refused_note:
                    print(f"[{now_hms()}] [ALLOW] {src} flagged '{v}' but allowlisted -- NOT blocking")
                    logline("REFUSE", src, v); refused_note.add(src)
                continue

            strikes[src] += 1
            print(f"[{now_hms()}] >> attack from {src}: {v}  "
                  f"(strike {strikes[src]}/{args.confirm})")
            if strikes[src] >= args.confirm:
                ips("block", src)
                blocked[src] = time.time() + args.ttl
                tag = "WOULD-BLOCK" if args.dry_run else "BLOCK"
                print(f"[{now_hms()}] [{tag}] {src} -> iptables DROP on {args.plc}, "
                      f"expires in {args.ttl:.0f}s   (attack: {v})")
                logline(tag, src, v)

        time.sleep(max(0, args.interval - (time.time() - cycle_t)))

except KeyboardInterrupt:
    print("\n" + "=" * 70)
    print("[*] stopping -- removing all blocks this IPS added ...")
    for ip in list(blocked):
        ips("unblock", ip); logline("UNBLOCK", ip, "shutdown")
        print(f"    [UNBLOCK] {ip}")
    print(f"[*] scored {n_windows} windows.  verdicts: {dict(totals.most_common())}")
    print(f"[*] prevention log -> {LOG}")
    print("[*] tip: confirm nothing is left blocked with:  bash scripts/ipsblock.sh list")
