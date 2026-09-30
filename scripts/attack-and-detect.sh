#!/usr/bin/env bash
# Fresh-capture detection for ONE attack:
#   capture -> Zeek -> build_features -> model verdict.
# The model has never seen this traffic, so the result is an honest test.
#
# Usage:
#   bash scripts/attack-and-detect.sh <label> <attack command...>
# Examples:
#   bash scripts/attack-and-detect.sh recon  docker exec kali nmap -Pn -sT -p- openplc
#   bash scripts/attack-and-detect.sh write  docker exec kali python3 /modbus_write.py openplc
#   bash scripts/attack-and-detect.sh flood  docker exec kali python3 /modbus_flood.py openplc 502 15
set -uo pipefail
cd "$(dirname "$0")/.."
LABEL="${1:?usage: attack-and-detect.sh <label> <attack cmd...>}"; shift

# each attack in its own isolated capture dir, so the verdict is just for this attack
LIVE="$HOME/iiot-live/$LABEL"
rm -rf "$LIVE"; mkdir -p "$LIVE/sessions"

echo "==== [$LABEL] capturing + attacking ===="
IIOT_CAP_DIR="$LIVE" bash scripts/capture-start.sh "$LABEL" >/dev/null
"$@"                                             # run the attack
IIOT_CAP_DIR="$LIVE" bash scripts/capture-stop.sh "$LABEL" >/dev/null

echo "==== [$LABEL] extracting features ===="
ATTACKER_IP="${ATTACKER_IP:-172.19.0.8}" IIOT_CAP_DIR="$LIVE" \
  python3 scripts/build_features.py 1.0 | tail -1

echo "==== [$LABEL] MODEL VERDICT ===="
python3 ml/detect.py "$LIVE/features_windows.csv"
