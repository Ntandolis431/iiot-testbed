#!/usr/bin/env bash
# Summarize the collected labeled dataset (benign live stream + attack sessions).
#
# Usage:  bash scripts/dataset-summary.sh
#   Override attacker IP:  ATTACKER_IP=172.18.0.8 bash scripts/dataset-summary.sh
set -euo pipefail

CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"
ATTACKER_IP="${ATTACKER_IP:-172.18.0.8}"

echo "==================== IIoT Testbed Dataset ===================="
echo "Location:     $CAP_DIR"
echo "Attacker IP:  $ATTACKER_IP  (its traffic = the attack within each session)"
echo

# Benign continuous stream (from start-live-capture.sh), if present
if [ -f "$CAP_DIR/live/modbus.log" ]; then
  n=$(grep -vc '^#' "$CAP_DIR/live/modbus.log" 2>/dev/null || echo 0)
  echo "[benign live stream]   modbus messages: $n"
  echo
fi

printf "%-10s %12s %11s %14s %8s\n" "SESSION" "modbus_msgs" "conn_recs" "attacker_msgs" "pcap"
printf "%-10s %12s %11s %14s %8s\n" "-------" "-----------" "---------" "-------------" "----"
for d in "$CAP_DIR"/sessions/*/; do
  [ -d "$d" ] || continue
  label=$(basename "$d")
  mb=$(grep -vc '^#' "$d/modbus.log" 2>/dev/null || echo 0)
  cn=$(grep -vc '^#' "$d/conn.log" 2>/dev/null || echo 0)
  atk=$(grep -c "$ATTACKER_IP" "$d/modbus.log" 2>/dev/null || echo 0)
  pcap=$(du -h "$d"/*.pcap 2>/dev/null | awk '{print $1}' | head -1)
  printf "%-10s %12s %11s %14s %8s\n" "$label" "$mb" "$cn" "$atk" "${pcap:--}"
done

echo
echo "==================== Modbus function codes per session ===================="
for d in "$CAP_DIR"/sessions/*/; do
  [ -d "$d" ] || continue
  echo "--- $(basename "$d") ---"
  grep -oE '(READ|WRITE)_[A-Z_]+' "$d/modbus.log" 2>/dev/null | sort | uniq -c || echo "  (none)"
done
