#!/usr/bin/env python3
"""
============================================================================
 build_multilabel.py  --  Phase 2, step 1: multi-label relabelling
============================================================================
The live bots run several attacks AT ONCE, so a single 1-second window can
contain more than one attack. This turns the windowed features into a
MULTI-LABEL dataset: for each window we look up every attack in
attack_ledger.csv whose [start,end] time span overlaps the window, and set a
binary column per attack CLASS. Windows with no overlapping attack -- and all
non-attacker traffic -- are benign (all zeros).

Attack variants collapse to their base class:
    recon, recon2            -> recon
    flood, flood2            -> flood
    write, write2, write3    -> write
    replay                   -> replay
    read                     -> read

Pipeline:
    live Zeek logs --build_features.py--> features_windows.csv
                    + attack_ledger.csv (ground truth, by time)
                    -----------------------------------------> features_multilabel.csv

IMPORTANT: stop scripts/attack-bots.sh (Ctrl+C) before running this, so every
attack has finished and written its end time to the ledger. In-flight attacks
have no ledger row yet, so their windows would be mislabelled benign.

Usage:
    IIOT_CAP_DIR=~/iiot-live python3 ml/build_multilabel.py [window_seconds]
Output:
    $IIOT_CAP_DIR/features_multilabel.csv
============================================================================
"""
import os, sys, csv, subprocess
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD = os.path.join(REPO, "scripts", "build_features.py")

CAP    = os.environ.get("IIOT_CAP_DIR", os.path.expanduser("~/iiot-live"))
W      = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0
PAD    = float(os.environ.get("IIOT_LABEL_PAD", "1.0"))   # widen each attack span by +-PAD s
SKIP_EXTRACT = os.environ.get("IIOT_SKIP_EXTRACT", "0") == "1"  # reuse existing features (relabel only)
LEDGER = os.path.join(CAP, "attack_ledger.csv")
FEATS  = os.path.join(CAP, "features_windows.csv")
OUT    = os.path.join(CAP, "features_multilabel.csv")

CLASSES = ["recon", "scan", "flood", "write", "replay", "read", "malformed", "mitm"]
NORM = {"recon": "recon", "recon2": "recon",
        "scan": "scan",
        "flood": "flood", "flood2": "flood",
        "write": "write", "write2": "write", "write3": "write",
        "replay": "replay", "read": "read",
        "malformed": "malformed", "mitm": "mitm"}

# 1. (re)build features from the live logs so window t_start values are current.
#    ATTACKER_IP here is irrelevant -- we derive labels from the ledger, not from
#    build_features' own single-label column.
if SKIP_EXTRACT and os.path.exists(FEATS):
    print(f"[*] IIOT_SKIP_EXTRACT=1 -- reusing existing {FEATS} (relabelling only)")
else:
    print("[*] extracting windowed features from the live logs ...")
    env = dict(os.environ, IIOT_CAP_DIR=CAP, ATTACKER_IP="0.0.0.0")
    subprocess.run([sys.executable, BUILD, str(W)], env=env, check=True)

# 2. load the ledger -> sorted list of (start, end, class) + attacker IP set.
#    A missing or empty ledger is NOT an error: it means a benign-only capture, so
#    every window is labelled benign.
spans = []
attacker_ips = set()
if os.path.exists(LEDGER):
    with open(LEDGER) as f:
        for row in csv.DictReader(f):
            try:
                s = float(row["start_ts"]); e = float(row["end_ts"])
            except (ValueError, KeyError, TypeError):
                continue                      # skip any half-written line
            cls = NORM.get((row.get("attack") or "").strip())
            if not cls:
                continue
            if e < s:
                s, e = e, s
            ip = (row.get("attacker_ip") or "").strip()
            spans.append((s - PAD, e + PAD, cls, ip))   # pad +-PAD s; keep source IP for per-host labelling
            if ip and ip != "unknown":
                attacker_ips.add(ip)
    spans.sort(key=lambda x: x[0])
if not spans:
    print(f"[i] no attack rows in ledger -- treating every window as benign (benign-only capture).")

# 3. read the feature windows
if not os.path.exists(FEATS):
    sys.exit(f"[!] no features at {FEATS}")
with open(FEATS) as f:
    rows = list(csv.DictReader(f))
if not rows:
    sys.exit(f"[!] {FEATS} has no windows -- was any live traffic captured?")

META = ["session", "orig_h", "window", "t_start", "label"]
feature_names = [c for c in rows[0].keys() if c not in META]

def overlapping_classes(w_start, w_end, orig):
    """attack classes whose [s,e] span overlaps [w_start,w_end) AND were launched
    by THIS window's source host. With a multi-bot swarm, attacks run concurrently
    from different IPs; a window must only carry the label(s) of what its own
    source did, otherwise (e.g.) a long MITM from one bot bleeds onto every other
    attacker's windows."""
    out = set()
    for (s, e, cls, ip) in spans:
        if s >= w_end:
            break                         # spans sorted by start -> none later overlap
        if e > w_start and ip == orig:
            out.add(cls)
    return out

# 4. assign multi-labels by time overlap
out_rows, ml_counter, class_counter = [], Counter(), Counter()
for row in rows:
    w_start = float(row["t_start"]); w_end = w_start + W
    orig = row.get("orig_h", "")
    labels = overlapping_classes(w_start, w_end, orig) if orig in attacker_ips else set()
    rec = {"session": row["session"], "orig_h": orig,
           "window": row["window"], "t_start": row["t_start"]}
    for c in CLASSES:
        rec["is_" + c] = 1 if c in labels else 0
    rec["n_labels"] = len(labels)
    rec["benign"] = 0 if labels else 1
    for fn in feature_names:
        rec[fn] = row.get(fn, 0)
    out_rows.append(rec)
    ml_counter[len(labels)] += 1
    for c in labels:
        class_counter[c] += 1

cols = (["session", "orig_h", "window", "t_start"]
        + ["is_" + c for c in CLASSES] + ["n_labels", "benign"]
        + feature_names)
with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader(); w.writerows(out_rows)

multi = sum(n for k, n in ml_counter.items() if k >= 2)
benign = ml_counter.get(0, 0)
print()
print(f"[*] window = {W}s   attacker IP(s) = {sorted(attacker_ips)}")
print(f"[*] wrote {OUT}")
print(f"[*] {len(out_rows)} windows total  ({benign} benign, {len(out_rows)-benign} attack)")
print(f"[*] per-class positive windows: {dict(sorted(class_counter.items(), key=lambda x:-x[1]))}")
print(f"[*] windows by #concurrent labels: {dict(sorted(ml_counter.items()))}")
print(f"[*] >>> MULTI-LABEL windows (2+ concurrent attacks): {multi} <<<")
