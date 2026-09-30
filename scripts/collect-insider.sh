#!/usr/bin/env bash
# ============================================================================
#  collect-insider.sh -- capture for the authenticated-insider / residual experiment
# ============================================================================
# Runs the tank-level process under NORMAL operation and injects a few
# authenticated-insider events (valid Modbus setpoint writes that push the tank
# past its safe envelope). Produces, in one capture dir:
#
#   * process_telemetry.csv  -- historian feed for the residual detector
#   * insider_ledger.csv     -- ground-truth timing of each insider event
#   * sessions/collect-0001/ -- Zeek logs + pcap (network feed) for the NIDS
#
# Benign traffic = realistic SCADA reads (benign_poller) + LEGITIMATE operator
# setpoint changes (operator_setpoint). The insider's write is, on the wire,
# identical to a legitimate setpoint change -- so the NIDS cannot tell them
# apart; only the residual detector (on the telemetry) can.
#
# Usage:
#   bash scripts/collect-insider.sh                     # ~18 min default
#   WARMUP=600 N_INSIDER=4 bash scripts/collect-insider.sh
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

export IIOT_CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-insider}"
NET="${NET:-iiot-testbed_iiot-net}"
IMG="${IMG:-iiot-attacker}"
PLC="${PLC:-openplc}"
NBENIGN="${NBENIGN:-3}"                 # benign SCADA reader hosts
WARMUP="${WARMUP:-300}"                 # benign-only seconds before first insider (train residual)
N_INSIDER="${N_INSIDER:-3}"             # number of insider events
INSIDER_GAP="${INSIDER_GAP:-120}"       # benign seconds between insider events
HARMFUL="${HARMFUL:-1500}"             # harmful setpoint (overflow); try 20 for dry-run
HOLD="${HOLD:-25}"                      # seconds to hold the harmful setpoint
COOLDOWN="${COOLDOWN:-60}"

SESS="$IIOT_CAP_DIR/sessions/collect-0001"; mkdir -p "$SESS"
ZEEK="ins-zeek"; PCAP="ins-pcap"; HIST="ins-hist"; OP="ins-operator"; INS="ins-attacker"

cleanup() {
  echo; echo "[*] stopping insider capture ..."
  docker rm -f "$ZEEK" "$PCAP" "$HIST" "$OP" "$INS" ins-benign-1 ins-benign-2 ins-benign-3 >/dev/null 2>&1 || true
  echo "[*] building network features from the capture ..."
  IIOT_CAP_DIR="$IIOT_CAP_DIR" python3 ml/build_multilabel.py 3.0 >/dev/null 2>&1 || true
  if [ -s "$IIOT_CAP_DIR/features_multilabel.csv" ]; then
    echo "    [ok] network features -> $IIOT_CAP_DIR/features_multilabel.csv"
  else
    echo "    [!] features not built -- run manually:"
    echo "        IIOT_CAP_DIR=\"$IIOT_CAP_DIR\" python3 ml/build_multilabel.py 3.0"
  fi
  echo "[*] done. capture dir: $IIOT_CAP_DIR"
  echo "    telemetry : $IIOT_CAP_DIR/process_telemetry.csv"
  echo "    ledger    : $IIOT_CAP_DIR/insider_ledger.csv"
  echo "    features  : $IIOT_CAP_DIR/features_multilabel.csv"
  exit 0
}
trap cleanup INT TERM

if [ "$(docker inspect -f '{{.State.Running}}' "$PLC" 2>/dev/null)" != "true" ]; then
  echo "[!] $PLC not running -- start the stack first: docker compose up -d"; exit 1
fi

echo "======================================================================"
echo "[*] INSIDER capture -> $IIOT_CAP_DIR"
echo "[*] benign readers: $NBENIGN   warmup: ${WARMUP}s   insiders: $N_INSIDER (hold ${HOLD}s, gap ${INSIDER_GAP}s)"
echo "[*] harmful setpoint: $HARMFUL"
echo "======================================================================"

# empty ledger header so build_multilabel treats attacker traffic correctly
[ -f "$IIOT_CAP_DIR/attack_ledger.csv" ] || \
  echo "start_ts,end_ts,attack,params,attacker_ip" > "$IIOT_CAP_DIR/attack_ledger.csv"

# 1. benign SCADA readers
for i in $(seq 1 "$NBENIGN"); do
  docker rm -f "ins-benign-$i" >/dev/null 2>&1 || true
  docker run -d --name "ins-benign-$i" --network "$NET" "$IMG" sleep infinity >/dev/null
  docker cp attacker/. "ins-benign-$i":/ >/dev/null
  docker exec -d "ins-benign-$i" python3 /benign_poller.py "$PLC" 502 0.6
done
echo "[*] $NBENIGN benign reader host(s) polling."

# 2. legitimate operator setpoint control (benign writes)
docker rm -f "$OP" >/dev/null 2>&1 || true
docker run -d --name "$OP" --network "$NET" "$IMG" sleep infinity >/dev/null
docker cp attacker/. "$OP":/ >/dev/null
docker exec -d "$OP" python3 /operator_setpoint.py "$PLC" 502 8 200 700
echo "[*] legitimate operator setpoint control running (band [200,700])."

# 3. process historian (telemetry -> CAP via bind mount)
docker rm -f "$HIST" >/dev/null 2>&1 || true
docker run -d --name "$HIST" -v "$IIOT_CAP_DIR:/out" --network "$NET" "$IMG" sleep infinity >/dev/null
docker cp attacker/. "$HIST":/ >/dev/null
docker exec -d "$HIST" python3 /process_logger.py "$PLC" 502 0.2 /out/process_telemetry.csv
echo "[*] process historian logging telemetry every 0.2s."

# 4. insider host (idle until scheduled)
docker rm -f "$INS" >/dev/null 2>&1 || true
docker run -d --name "$INS" -v "$IIOT_CAP_DIR:/out" --network "$NET" "$IMG" sleep infinity >/dev/null
docker cp attacker/. "$INS":/ >/dev/null

# 5. network capture (Zeek + pcap in the PLC netns)
docker run -d --name "$PCAP" --net="container:$PLC" --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$SESS:/logs" -w /logs "$IMG" tcpdump -i eth0 -s 0 -U -w /logs/capture.pcap >/dev/null \
  || echo "    [!] pcap sidecar failed (Zeek logs still captured)"
docker run -d --name "$ZEEK" --net="container:$PLC" --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$SESS:/logs" -w /logs zeek/zeek:latest zeek -i eth0 -C >/dev/null
echo "[*] network capture running (session collect-0001)."

echo "[*] warmup: ${WARMUP}s of benign operation (for residual training) ..."
sleep "$WARMUP"

for k in $(seq 1 "$N_INSIDER"); do
  echo "[*] --- insider event $k/$N_INSIDER (setpoint=$HARMFUL, hold ${HOLD}s) ---"
  docker exec -e IIOT_CAP_DIR=/out -i "$INS" python3 /insider_write.py "$PLC" 502 "$HARMFUL" "$HOLD" 400
  if [ "$k" -lt "$N_INSIDER" ]; then
    echo "[*] benign gap ${INSIDER_GAP}s ..."
    sleep "$INSIDER_GAP"
  fi
done

echo "[*] cooldown ${COOLDOWN}s ..."
sleep "$COOLDOWN"
cleanup
