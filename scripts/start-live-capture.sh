#!/usr/bin/env bash
# Persistent live Zeek capture of OpenPLC's Modbus traffic.
# Zeek sniffs OpenPLC's interface continuously and appends
#   $CAP_DIR/live/conn.log  and  $CAP_DIR/live/modbus.log
# for as long as it runs.
#
# Capture data is stored on a LINUX-NATIVE path by default ($HOME/iiot-captures)
# for clean permissions and speed -- NOT in the repo (traffic data is gitignored
# anyway, and the Windows filesystem causes locking issues under WSL).
# Override the location with:  IIOT_CAP_DIR=/some/path bash scripts/start-live-capture.sh
#
# Stop:  docker stop zeek-live   (or: docker rm -f zeek-live)
set -euo pipefail

CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"
mkdir -p "$CAP_DIR/live"

docker rm -f zeek-live >/dev/null 2>&1 || true

docker run -d --name zeek-live \
  --net=container:openplc \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$CAP_DIR/live:/logs" \
  -w /logs \
  --restart unless-stopped \
  zeek/zeek:latest \
  zeek -i eth0 -C

echo "zeek-live started."
echo "Live feature logs are growing in: $CAP_DIR/live  (conn.log, modbus.log)"
echo "Snapshot them to CSV any time with:  bash scripts/refresh-csv.sh"
echo "(CSV snapshots are written to: $CAP_DIR/)"
