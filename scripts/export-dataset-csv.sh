#!/usr/bin/env bash
# Export the labeled dataset to CSV: merges every session's Zeek logs into
#   $CAP_DIR/modbus_dataset.csv   and   $CAP_DIR/conn_dataset.csv
# Each row gets:
#   label   = the attack name (recon/read/write/...) if it is the attacker's
#             traffic, else "benign"
#   session = which capture session the row came from
#
# Usage:  bash scripts/export-dataset-csv.sh
#   Override attacker IP:  ATTACKER_IP=172.18.0.8 bash scripts/export-dataset-csv.sh
set -euo pipefail
CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"
ATTACKER_IP="${ATTACKER_IP:-172.18.0.8}"

python3 - "$CAP_DIR" "$ATTACKER_IP" <<'PY'
import csv, os, sys, glob, re
from collections import Counter
cap, attacker = sys.argv[1], sys.argv[2]

def base_label(sess):
    # collapse repeated runs: "recon-01","recon_3" -> "recon"
    return re.sub(r"[-_]\d+$", "", sess)

def read_zeek(path):
    if not os.path.exists(path):
        return
    fields = None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                yield dict(zip(fields, line.split("\t")))

def export(logname, outname, include_live):
    rows, allfields = [], []
    for d in sorted(glob.glob(os.path.join(cap, "sessions", "*"))):
        sess = os.path.basename(d)
        for r in read_zeek(os.path.join(d, logname)):
            r["session"] = sess
            r["label"] = base_label(sess) if r.get("id.orig_h") == attacker else "benign"
            rows.append(r)
            for k in r:
                if k not in allfields:
                    allfields.append(k)
    if include_live:
        for r in read_zeek(os.path.join(cap, "live", logname)):
            r["session"] = "live"; r["label"] = "benign"
            rows.append(r)
            for k in r:
                if k not in allfields:
                    allfields.append(k)
    out = os.path.join(cap, outname)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=allfields)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"{out}: {len(rows)} rows  labels={dict(Counter(r['label'] for r in rows))}")

export("modbus.log", "modbus_dataset.csv", include_live=True)
export("conn.log",   "conn_dataset.csv",   include_live=False)
PY
