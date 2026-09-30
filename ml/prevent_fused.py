#!/usr/bin/env python3
"""
============================================================================
 prevent_fused.py -- FUSED, criticality-prioritized IPS (network + residual)
============================================================================
Extends the network-only IPS (prevent.py) into the closed loop the paper
claims: it consumes BOTH detection channels and prioritizes by how much each
threat endangers the plant.

  Channel 1 -- NETWORK: the multi-label NIDS scores each source's traffic and
               flags recon/scan/flood/write/replay/read/malformed/mitm.
  Channel 2 -- CONSEQUENCE: the physical-process-residual detector watches the
               historian (process_telemetry.csv). When the tank leaves its safe
               envelope / the learned residual spikes, an insider issuing valid
               setpoint writes is implicated -- something Channel 1 cannot see.

FUSION + PRIORITY. Every active threat is given a severity:
    CRITICAL(3): insider (physical-safety), flood (availability/DoS)
    HIGH(2)    : write, replay, malformed, mitm
    LOW(1)     : recon, scan, read
Threats are handled highest-severity-first, so an availability/safety threat is
neutralised before a low-risk scan. On a CONSEQUENCE alarm the offending source
is attributed as the non-allowlisted host writing the actuator register.

AVAILABILITY-FIRST safeguards (unchanged, NIST SP 800-82 / IEC 62443):
  allowlist (PLC/SCADA/operator never blocked) - confirmation - TTL auto-expiry -
  clean exit. If the only writer implicated by a CONSEQUENCE alarm is an
  allowlisted control host, the system RAISES A SAFETY ALARM instead of blocking
  (never cut authorised control) -- the honest boundary of IP-based response.

Prereqs: trained NIDS model; a residual model fitted on benign telemetry
    python3 ml/residual_detector.py train <benign_telemetry.csv> ml/models/residual_model.json
Usage:
    IIOT_CAP_DIR=~/iiot-insider python3 ml/prevent_fused.py \
        --residual-model ml/models/residual_model.json \
        --operator-allow 172.19.0.11 --confirm 2 --ttl 60
Stop with Ctrl+C (auto-unblocks everything it added).
============================================================================
"""
import os, sys, time, csv, argparse, warnings, subprocess, datetime as dt
from collections import Counter, defaultdict
import numpy as np, pandas as pd, joblib
warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD = os.path.join(REPO, "scripts", "build_features.py")
IPSBLOCK = os.path.join(REPO, "scripts", "ipsblock.sh")
sys.path.insert(0, HERE)
import residual_detector as rd            # reuse design()/score()

ALLOWLIST_CONTAINERS = ["openplc", "fuxa", "nodered", "mosquitto", "grafana", "influxdb"]
SETPOINT_REG = 10

# severity of each threat class (higher = handled first)
SEVERITY = {"insider": 3, "flood": 3,
            "write": 2, "replay": 2, "malformed": 2, "mitm": 2,
            "recon": 1, "scan": 1, "read": 1}
SEV_NAME = {3: "CRITICAL", 2: "HIGH", 1: "LOW"}

ap = argparse.ArgumentParser()
ap.add_argument("--cap-dir", default=os.environ.get("IIOT_CAP_DIR", os.path.expanduser("~/iiot-insider")))
ap.add_argument("--model", default=os.path.join(HERE, "models", "detector_multilabel.joblib"))
ap.add_argument("--residual-model", default=os.path.join(HERE, "models", "residual_model.json"))
ap.add_argument("--interval", type=float, default=3.0)
ap.add_argument("--window", type=float, default=3.0)
ap.add_argument("--confirm", type=int, default=2)
ap.add_argument("--confirm-insider", type=int, default=1, help="safety threats block faster")
ap.add_argument("--ttl", type=float, default=60.0)
ap.add_argument("--plc", default="openplc")
ap.add_argument("--allow", nargs="*", default=[])
ap.add_argument("--operator-allow", nargs="*", default=[], help="authorised control hosts (never blocked)")
ap.add_argument("--dry-run", action="store_true")
args = ap.parse_args()

if not os.path.exists(args.model):
    sys.exit(f"[!] no NIDS model at {args.model}")
if not os.path.exists(args.residual_model):
    sys.exit(f"[!] no residual model at {args.residual_model} -- fit it first:\n"
             f"    python3 ml/residual_detector.py train <benign_telemetry.csv> {args.residual_model}")

b = joblib.load(args.model)
heads, iso, scaler, feats, classes = b["heads"], b["anomaly"], b["scaler"], b["features"], b["classes"]
thr = b.get("thresholds", {c: 0.5 for c in classes})
import json
rm = json.load(open(args.residual_model))
R_BETA = np.array(rm["beta"]); R_TAU = float(rm["tau"])
R_ENV = rm.get("env", [rd.ENV_LO, rd.ENV_HI, rd.SP_LO, rd.SP_HI])
rd.ENV_LO, rd.ENV_HI, rd.SP_LO, rd.SP_HI = R_ENV

FEATURES_CSV = os.path.join(args.cap_dir, "features_windows.csv")
TELEM_CSV = os.path.join(args.cap_dir, "process_telemetry.csv")
LOG = os.path.join(args.cap_dir, "prevention_fused_log.csv")


def now_hms(): return dt.datetime.now().strftime("%H:%M:%S")

def docker_ip(name):
    try:
        out = subprocess.run(["docker", "inspect", "-f",
              "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
              capture_output=True, text=True, timeout=10)
        return out.stdout.strip()
    except Exception:
        return ""

allowlist = set(a for a in args.allow if a) | set(a for a in args.operator_allow if a)
operator_hosts = set(a for a in args.operator_allow if a)
for c in ALLOWLIST_CONTAINERS:
    ip = docker_ip(c)
    if ip: allowlist.add(ip)
ALLOW_STR = " ".join(sorted(allowlist))


def ips(cmd, ip=""):
    if args.dry_run: return
    env = dict(os.environ, PLC=args.plc, IPS_ALLOWLIST=ALLOW_STR)
    subprocess.run(["bash", IPSBLOCK, cmd] + ([ip] if ip else []),
                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def logline(event, ip, sev, detail=""):
    with open(LOG, "a") as f:
        f.write(f"{now_hms()},{event},{ip},{sev},{detail}\n")

def rebuild_features():
    env = dict(os.environ, IIOT_CAP_DIR=args.cap_dir, ATTACKER_IP="0.0.0.0")
    subprocess.run([sys.executable, BUILD, str(args.window)], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def net_verdicts(df):
    for c in feats:
        if c not in df.columns: df[c] = 0.0
    X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0.0).values
    pred = np.zeros((len(X), len(classes)), dtype=int)
    for j, c in enumerate(classes):
        kind, obj = heads[c]
        if kind == "const":
            p = np.full(len(X), float(obj))
        else:
            try: p = obj.predict_proba(X)[:, list(obj.classes_).index(1)]
            except Exception: p = obj.predict(X)
        pred[:, j] = (p >= thr.get(c, 0.5)).astype(int)
    out = []
    for i in range(len(X)):
        active = [classes[j] for j in range(len(classes)) if pred[i, j] == 1]
        out.append(active)
    return out


# --- residual channel: has the process left its safe envelope recently? --------
_telem_seen = {"n": 0}
def residual_alarm_recent():
    """score telemetry samples appended since last cycle; return True if any alarm."""
    if not os.path.exists(TELEM_CSV):
        return False
    try:
        ts, T = rd.load(TELEM_CSV)
    except Exception:
        return False
    if len(T) < 3:
        return False
    start = max(1, _telem_seen["n"])
    _telem_seen["n"] = len(T)
    alarm, resid, learned, env = rd.score(T, R_BETA, R_TAU)   # aligned to samples 1..N-1
    # look only at samples that are new this cycle
    recent = alarm[start - 1:]
    return bool(recent.any())


print("=" * 70)
print(f"[*] FUSED ML-IPS up   NIDS={os.path.basename(args.model)}  "
      f"residual={os.path.basename(args.residual_model)}")
print(f"[*] protect PLC : {args.plc}")
print(f"[*] allowlist   : {sorted(allowlist)}")
print(f"[*] operators   : {sorted(operator_hosts)}  (authorised control; safety-alarm not block)")
print(f"[*] severity    : CRITICAL insider/flood > HIGH write/replay/malformed/mitm > LOW recon/scan/read")
print(f"[*] policy      : block after {args.confirm} windows ({args.confirm_insider} for safety); "
      f"TTL {args.ttl:.0f}s; highest severity first")
if args.dry_run: print("[*] DRY-RUN     : intended blocks logged, iptables untouched")
print("=" * 70)

if not os.path.exists(LOG):
    with open(LOG, "w") as f:
        f.write("wall_time,event,ip,severity,detail\n")

seen = set(); strikes = Counter(); blocked = {}; refused = set(); totals = Counter(); n_windows = 0

rebuild_features()
if os.path.exists(FEATURES_CSV):
    try:
        _p = pd.read_csv(FEATURES_CSV)
        for _k in zip(_p["session"], _p["orig_h"], _p["window"]): seen.add(_k)
        print(f"[*] primed: ignoring {len(seen)} pre-existing window(s).")
    except Exception:
        pass
residual_alarm_recent()      # prime telemetry cursor

try:
    while True:
        cycle_t = time.time()

        # 1. expire blocks
        for ip in [ip for ip, exp in blocked.items() if cycle_t >= exp]:
            ips("unblock", ip); del blocked[ip]; strikes[ip] = 0
            print(f"[{now_hms()}] [UNBLOCK] {ip} (ttl expired)"); logline("UNBLOCK", ip, "", "ttl")

        rebuild_features()
        if not os.path.exists(FEATURES_CSV):
            time.sleep(args.interval); continue
        try: df = pd.read_csv(FEATURES_CSV)
        except Exception:
            time.sleep(args.interval); continue
        if len(df) == 0:
            time.sleep(args.interval); continue

        df["_t"] = pd.to_numeric(df["t_start"], errors="coerce").fillna(0.0)
        complete = df["_t"] + args.window + 1.0 <= cycle_t
        keys = list(zip(df["session"], df["orig_h"], df["window"]))
        mask = [complete.iloc[i] and (keys[i] not in seen) for i in range(len(df))]
        fresh = df[pd.Series(mask, index=df.index)].copy()

        # 2. CONSEQUENCE channel: process unsafe this cycle?
        phys_unsafe = residual_alarm_recent()

        # collect this cycle's threats: src -> (severity, label)
        threats = {}

        # 2a. network threats on fresh windows
        recent_writers = set()
        if len(fresh) > 0:
            vlist = net_verdicts(fresh)
            for i in range(len(fresh)):
                k = (fresh.iloc[i]["session"], fresh.iloc[i]["orig_h"], fresh.iloc[i]["window"])
                seen.add(k); n_windows += 1
                src = str(fresh.iloc[i]["orig_h"])
                try:
                    if float(fresh.iloc[i].get("mb_write", 0)) > 0: recent_writers.add(src)
                except Exception:
                    pass
                active = vlist[i]
                totals["+".join(active) if active else "benign"] += 1
                for cls in active:
                    sev = SEVERITY.get(cls, 1)
                    if src not in threats or sev > threats[src][0]:
                        threats[src] = (sev, cls)

        # 2b. consequence threat: attribute to non-allowlisted actuator writer(s)
        if phys_unsafe:
            culprits = [w for w in recent_writers if w not in allowlist]
            auth_writers = [w for w in recent_writers if w in operator_hosts]
            if culprits:
                for src in culprits:
                    threats[src] = (SEVERITY["insider"], "insider")
            elif auth_writers or not recent_writers:
                # only authorised control writing (or writer not yet in a fresh window):
                # never cut authorised control -> raise a safety alarm instead.
                print(f"[{now_hms()}] [SAFETY-ALARM] process left safe envelope; "
                      f"no non-allowlisted writer to block (writers={sorted(recent_writers)})")
                logline("SAFETY_ALARM", ";".join(sorted(recent_writers)) or "-", "CRITICAL", "physical-unsafe")

        # 3. act on threats, HIGHEST SEVERITY FIRST
        if not threats:
            act = len(blocked)
            print(f"[{now_hms()}] . monitoring (scored {n_windows}, {act} active block{'s' if act!=1 else ''}"
                  f"{', PROCESS UNSAFE' if phys_unsafe else ''})")
            time.sleep(max(0, args.interval - (time.time() - cycle_t))); continue

        for src, (sev, label) in sorted(threats.items(), key=lambda kv: -kv[1][0]):
            if src in blocked: continue
            if src in allowlist:
                if src not in refused:
                    print(f"[{now_hms()}] [ALLOW] {src} implicated '{label}' but allowlisted -- not blocking")
                    logline("REFUSE", src, SEV_NAME[sev], label); refused.add(src)
                continue
            need = args.confirm_insider if label == "insider" else args.confirm
            strikes[src] += 1
            print(f"[{now_hms()}] >> {SEV_NAME[sev]} threat from {src}: {label} "
                  f"(strike {strikes[src]}/{need})")
            if strikes[src] >= need:
                ips("block", src); blocked[src] = time.time() + args.ttl
                tag = "WOULD-BLOCK" if args.dry_run else "BLOCK"
                print(f"[{now_hms()}] [{tag}] {src} -> DROP on {args.plc} ({SEV_NAME[sev]}: {label}), "
                      f"expires {args.ttl:.0f}s")
                logline(tag, src, SEV_NAME[sev], label)

        time.sleep(max(0, args.interval - (time.time() - cycle_t)))

except KeyboardInterrupt:
    print("\n" + "=" * 70 + "\n[*] stopping -- removing all blocks this IPS added ...")
    for ip in list(blocked):
        ips("unblock", ip); logline("UNBLOCK", ip, "", "shutdown")
        print(f"    [UNBLOCK] {ip}")
    print(f"[*] scored {n_windows} windows.  verdicts: {dict(totals.most_common())}")
    print(f"[*] prevention log -> {LOG}")
