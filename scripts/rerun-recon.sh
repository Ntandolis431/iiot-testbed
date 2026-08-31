#!/usr/bin/env bash
# Re-run ONLY the recon scans, correctly this time.
# The earlier batch scanned FUXA's IP by mistake, so nothing was captured at the
# OpenPLC sensor. This scans OpenPLC by HOSTNAME (IP-shuffle proof) with a full
# port range so each scan spans several 1s windows -> enough recon samples.
#
# Usage:  bash scripts/rerun-recon.sh [N]        (default N=10)
set -uo pipefail
cd "$(dirname "$0")/.."
N="${1:-10}"
CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"

echo "[*] Removing broken recon-* sessions (they scanned the wrong host)..."
shopt -s nullglob
for d in "$CAP_DIR"/sessions/recon-*; do
  rm -rf "$d" && echo "    removed $(basename "$d")"
done
shopt -u nullglob

for i in $(seq -w 1 "$N"); do
  label="recon-$i"
  echo "-------------------------------------------------------------"
  echo "[*] $label : nmap -Pn -sT -T4 --max-retries 1 -p- openplc"
  bash scripts/capture-start.sh "$label" >/dev/null
  docker exec kali nmap -Pn -sT -T4 --max-retries 1 -p- openplc \
    || echo "    [!] nmap returned nonzero (continuing)"
  sleep 1
  bash scripts/capture-stop.sh "$label" >/dev/null
  echo "    [+] captured -> sessions/$label"
done

echo
echo "[*] Now re-export and rebuild features:"
echo "    bash scripts/export-dataset-csv.sh"
echo "    python3 scripts/build_features.py 1.0"
