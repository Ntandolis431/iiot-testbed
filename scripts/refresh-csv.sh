#!/usr/bin/env bash
# Snapshot the continuously-growing Zeek live logs into CSV files.
# Reads:  $CAP_DIR/live/{modbus,conn}.log
# Writes: $CAP_DIR/{modbus,conn}.csv
#
# CAP_DIR defaults to a Linux-native path ($HOME/iiot-captures); override with IIOT_CAP_DIR.
#   bash scripts/refresh-csv.sh
set -euo pipefail

CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"

python3 - "$CAP_DIR" <<'PY'
import csv, os, sys
cap = sys.argv[1]
live = os.path.join(cap, "live")
def conv(name):
    inp = os.path.join(live, name + ".log")
    outp = os.path.join(cap, name + ".csv")
    if not os.path.exists(inp):
        print("skip (not found yet):", inp); return
    fields = None; rows = []
    with open(inp) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                rows.append(line.split("\t"))
    with open(outp, "w", newline="") as f:
        w = csv.writer(f)
        if fields:
            w.writerow(fields)
        w.writerows(rows)
    print(f"{outp}: {len(rows)} rows")
conv("modbus")
conv("conn")
PY
