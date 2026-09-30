#!/usr/bin/env bash
# ============================================================================
#  collect-dataset.sh  --  long-run dataset collection toward HOURS of traffic
# ============================================================================
# Builds a large, realistic, LABELLED dataset by running the testbed unattended:
#
#   * a continuous BENIGN SCADA poller  (the benign majority class)
#   * a SPARSE multi-bot attack swarm   (attacks are a realistic minority)
#   * Zeek capture, ROTATED into hourly session dirs so no single log balloons
#
# At stop (target reached or Ctrl+C) it builds the labelled multi-label dataset
# from every session using the attack ledger.
#
# NOTE: "hours of traffic" is wall-clock. HOURS=120 means ~5 DAYS of continuous
# capture -- the machine must stay on. Expect several GB of logs. Tune the attack
# density with MAX_CONC / MIN_GAP / MAX_GAP (defaults keep benign dominant).
#
# Usage:
#   HOURS=120 IIOT_CAP_DIR=~/iiot-dataset bash scripts/collect-dataset.sh
#   HOURS=2 bash scripts/collect-dataset.sh          # short trial run first!
#
# Stop early anytime with Ctrl+C -- it still builds the dataset from what it has.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

HOURS="${HOURS:-120}"
export IIOT_CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-dataset}"
NET="${NET:-iiot-testbed_iiot-net}"
IMG="${IMG:-iiot-attacker}"
NBOTS="${NBOTS:-6}"
PLC="${PLC:-openplc}"
SESS="$IIOT_CAP_DIR/sessions"; mkdir -p "$SESS"

# sparse attacks so benign dominates (realistic OT traffic mix)
export MAX_CONC="${MAX_CONC:-2}" MIN_GAP="${MIN_GAP:-20}" MAX_GAP="${MAX_GAP:-90}"

swarm_pid=""; ZEEK="zeek-collect"; PCAP="pcap-collect"; wd_pid=""

# --- PLC Modbus watchdog: revive the runtime if an attack kills it -----------
# The DoS/malformed attacks can crash OpenPLC's Modbus server. Without this the
# rest of the run would capture only rejected connections. The watchdog restarts
# the PLC runtime so outages are transient (and themselves captured), keeping the
# other attack classes meaningful.
PLC_WEB="${PLC_WEB:-http://127.0.0.1:8080}"
PLC_USER="${PLC_USER:-openplc}"; PLC_PASS="${PLC_PASS:-openplc}"
WD_EVENTS="$IIOT_CAP_DIR/plc_restarts.csv"

# A real Modbus read against the PLC *inside the docker network* -- NOT a TCP
# connect to the published port, because docker-proxy accepts that even when the
# runtime is dead (which silently defeated the watchdog).
plc_modbus_up() {
  # probe from a DEDICATED host (wd-probe) that the MITM attack never targets, so
  # ARP-spoofing of the benign pollers can't fool the watchdog into false restarts.
  docker exec -i wd-probe python3 - "$PLC" >/dev/null 2>&1 <<'PY'
import sys
from pymodbus.client import ModbusTcpClient as C
h = sys.argv[1] if len(sys.argv) > 1 else "openplc"
c = C(h, port=502, timeout=2)
ok = c.connect()
r = c.read_holding_registers(0, count=1) if ok else None
c.close()
sys.exit(0 if (ok and r is not None and not r.isError()) else 1)
PY
}
plc_start() {
  local jar; jar="$(mktemp)"
  curl -s -c "$jar" --data "username=$PLC_USER&password=$PLC_PASS" "$PLC_WEB/login" -o /dev/null
  curl -s -b "$jar" "$PLC_WEB/start_plc" -o /dev/null
  rm -f "$jar"
}
watchdog() {
  mkdir -p "$IIOT_CAP_DIR"
  [ -f "$WD_EVENTS" ] || echo "ts,event" > "$WD_EVENTS"
  local downs=0
  while :; do
    if plc_modbus_up; then
      downs=0
    else
      downs=$((downs+1))
      if [ "$downs" -ge 2 ]; then                 # 2 consecutive misses = real outage
        echo "$(date +%s.%N),modbus_down_restart" >> "$WD_EVENTS"
        echo "    [watchdog $(date '+%H:%M:%S')] Modbus down -- restarting PLC runtime"
        plc_start
        sleep 5                                    # grace period after restart
      fi
    fi
    sleep 15
  done
}

built=0
build_final() {
  [ "$built" = 1 ] && return; built=1
  echo "[*] building labelled multi-label dataset from all sessions ..."
  IIOT_CAP_DIR="$IIOT_CAP_DIR" python3 ml/build_multilabel.py 1.0 || \
    echo "[!] build_multilabel failed -- run it manually against $IIOT_CAP_DIR"
}
cleanup() {
  echo; echo "[*] stopping collection ..."
  [ -n "$swarm_pid" ] && kill "$swarm_pid" 2>/dev/null || true
  [ -n "$wd_pid" ] && kill "$wd_pid" 2>/dev/null || true
  docker rm -f "$ZEEK" "$PCAP" benign-scada wd-probe >/dev/null 2>&1 || true
  for i in $(seq 2 "${NBENIGN:-1}"); do docker rm -f "benign-scada-$i" >/dev/null 2>&1 || true; done
  for i in $(seq 1 "$NBOTS"); do docker rm -f "attacker-$i" >/dev/null 2>&1 || true; done
  build_final
  echo "[*] done. dataset dir: $IIOT_CAP_DIR"
  exit 0
}
trap cleanup INT TERM

# preflight
if [ "$(docker inspect -f '{{.State.Running}}' "$PLC" 2>/dev/null)" != "true" ]; then
  echo "[!] $PLC not running -- start the stack first: docker compose up -d"; exit 1
fi

echo "======================================================================"
echo "[*] DATASET COLLECTION toward ${HOURS}h  (~$(python3 -c "print(round($HOURS/24,1))") days)"
echo "[*] dir     : $IIOT_CAP_DIR"
echo "[*] bots    : $NBOTS (sparse: MAX_CONC=$MAX_CONC gap ${MIN_GAP}-${MAX_GAP}s)"
echo "[*] benign  : continuous SCADA poller"
echo "======================================================================"

# 1. benign SCADA baseline -- NBENIGN independent poller hosts (distinct IPs), so
#    benign traffic comes from several SCADA/HMI clients like a real network.
NBENIGN="${NBENIGN:-1}"
for i in $(seq 1 "$NBENIGN"); do
  nm="benign-scada"; [ "$i" -gt 1 ] && nm="benign-scada-$i"
  docker rm -f "$nm" >/dev/null 2>&1 || true
  docker run -d --name "$nm" --network "$NET" "$IMG" sleep infinity >/dev/null
  docker cp attacker/. "$nm":/ >/dev/null
  docker exec -d "$nm" python3 /benign_poller.py "$PLC" 502 0.6
done
echo "[*] $NBENIGN benign SCADA poller host(s) running."

# dedicated watchdog probe host (never a MITM target) -- used only for liveness checks
docker rm -f wd-probe >/dev/null 2>&1 || true
docker run -d --name wd-probe --network "$NET" "$IMG" sleep infinity >/dev/null
echo "[*] watchdog probe host ready."

# 1b. PLC Modbus watchdog (auto-revive runtime if an attack crashes it)
watchdog & wd_pid=$!
echo "[*] PLC watchdog running (restarts logged to $WD_EVENTS)."

# 2. sparse attack swarm (background) -- unless BENIGN_ONLY (clean benign capture)
if [ "${BENIGN_ONLY:-0}" = 1 ]; then
  echo "[*] BENIGN_ONLY mode: no attackers -- capturing clean benign traffic only."
  [ -f "$IIOT_CAP_DIR/attack_ledger.csv" ] || \
    echo "start_ts,end_ts,attack,params,attacker_ip" > "$IIOT_CAP_DIR/attack_ledger.csv"
else
  IIOT_CAP_DIR="$IIOT_CAP_DIR" N="$NBOTS" bash scripts/attack-swarm.sh > "$IIOT_CAP_DIR/swarm.log" 2>&1 &
  swarm_pid=$!
  echo "[*] attack swarm running (log: $IIOT_CAP_DIR/swarm.log)."
fi

# 3. hourly-rotated Zeek capture until HOURS reached
target=$(python3 -c "print(int($HOURS*3600))")
start=$(date +%s); hour=0
while :; do
  elapsed=$(( $(date +%s) - start ))
  [ "$elapsed" -ge "$target" ] && { echo "[*] reached ${HOURS}h."; cleanup; }
  hour=$((hour+1))
  d="$SESS/collect-$(printf '%04d' "$hour")"; mkdir -p "$d"
  docker rm -f "$ZEEK" "$PCAP" >/dev/null 2>&1 || true
  # raw packet capture (true .pcap) alongside the Zeek logs, same netns
  docker run -d --name "$PCAP" --net="container:$PLC" \
    --cap-add=NET_RAW --cap-add=NET_ADMIN -v "$d:/logs" -w /logs \
    "$IMG" tcpdump -i eth0 -s 0 -U -w /logs/capture.pcap >/dev/null \
    || echo "    [!] pcap sidecar failed to start (Zeek logs still captured)"
  docker run -d --name "$ZEEK" --net="container:$PLC" \
    --cap-add=NET_RAW --cap-add=NET_ADMIN -v "$d:/logs" -w /logs \
    zeek/zeek:latest zeek -i eth0 -C >/dev/null
  remain=$(( target - elapsed )); chunk=$(( remain < 3600 ? remain : 3600 ))
  echo "    [$(date '+%m-%d %H:%M:%S')] session collect-$(printf '%04d' "$hour"): capturing ${chunk}s (pcap+zeek)  (elapsed $(( elapsed/3600 ))h)"
  sleep "$chunk"
  docker rm -f "$ZEEK" "$PCAP" >/dev/null 2>&1 || true
done
