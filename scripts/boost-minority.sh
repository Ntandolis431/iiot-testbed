#!/usr/bin/env bash
# Boost the small attack classes so each has enough windows to train AND test on.
#   read/write : SUSTAINED campaigns -- loop the operation for DUR seconds so it
#                spans many 1s windows (like flood/replay already do). Realistic:
#                an attacker continuously harvesting data / repeatedly injecting.
#   recon      : a few STRETCHED scans (--scan-delay) that each span many windows
#                and add timing variety (fast full scan vs slow stealthy scan).
#
# Session names use a numeric suffix so the export/feature scripts collapse them
# back to read / write / recon.
#
# Usage:  bash scripts/boost-minority.sh [dur_seconds] [reps]     (default 20 5)
set -uo pipefail
cd "$(dirname "$0")/.."
DUR="${1:-20}"; REPS="${2:-5}"

for f in modbus_read.py modbus_write.py; do docker cp "attacker/$f" "kali:/$f" >/dev/null; done

sustained(){                                  # sustained <label> <script>
  local label="$1" script="$2"
  echo "[*] $label : sustained ${DUR}s of $script"
  bash scripts/capture-start.sh "$label" >/dev/null
  docker exec kali sh -c \
    "end=\$(( \$(date +%s) + $DUR )); while [ \$(date +%s) -lt \$end ]; do python3 /$script openplc >/dev/null 2>&1; done"
  sleep 1
  bash scripts/capture-stop.sh "$label" >/dev/null
  echo "    [+] sessions/$label"
}

recon_slow(){                                 # recon_slow <label>
  local label="$1"
  echo "[*] $label : stretched scan (nmap -sT -p1-4000 --scan-delay 4ms)"
  bash scripts/capture-start.sh "$label" >/dev/null
  docker exec kali nmap -Pn -sT -p 1-4000 --scan-delay 4ms openplc >/dev/null 2>&1 \
    || echo "    [!] nmap nonzero (continuing)"
  sleep 1
  bash scripts/capture-stop.sh "$label" >/dev/null
  echo "    [+] sessions/$label"
}

for i in $(seq 1 "$REPS"); do
  sustained "read-2$i"  modbus_read.py
  sustained "write-2$i" modbus_write.py
done
for i in 1 2 3; do
  recon_slow "recon-3$i"
done

echo
echo "[*] Re-export + rebuild:"
echo "    bash scripts/export-dataset-csv.sh && python3 scripts/build_features.py 1.0"
