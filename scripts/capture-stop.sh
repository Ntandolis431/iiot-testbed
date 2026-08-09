#!/usr/bin/env bash
# Stop a labeled capture session and extract Zeek features from it.
# Produces, in the session folder:  <label>.pcap, conn.log, modbus.log
#
# Usage:  bash scripts/capture-stop.sh <label>
set -euo pipefail

LABEL="${1:?usage: capture-stop.sh <label>}"
CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"
SESS="$CAP_DIR/sessions/$LABEL"

docker stop "cap-$LABEL" >/dev/null 2>&1 || true
docker rm   "cap-$LABEL" >/dev/null 2>&1 || true

echo "[*] Extracting features with Zeek..."
docker run --rm -v "$SESS:/caps" -w /caps zeek/zeek:latest zeek -C -r "$LABEL.pcap"

echo "[*] Session '$LABEL' saved to: $SESS"
ls -lh "$SESS"
