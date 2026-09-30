#!/usr/bin/env bash
# ============================================================================
#  demo-prevent-insider.sh -- live FUSED prevention demo (RQ2 + RQ3-insider)
# ============================================================================
# Shows the closed loop end to end: normal operation, an authenticated-insider
# setpoint attack, the CONSEQUENCE (residual) channel catching it, the fused IPS
# attributing it to the unknown writer and BLOCKING that source at the PLC, and
# the tank RECOVERING while every legitimate host keeps working untouched.
#
# Availability-first: operator / historian / readers / PLC / SCADA are allowlisted
# (never blocked). Only the unknown insider host is eligible for a block.
#
# Prereqs:
#   * stack up (docker compose up -d), new sensors.st loaded & running
#   * residual model fitted:
#       python3 ml/residual_detector.py train <benign_telemetry.csv> ml/models/residual_model.json
#   * netshoot image present (docker pull nicolaka/netshoot) for iptables
#
# Usage:
#   bash scripts/demo-prevent-insider.sh              # REAL blocking
#   DRYRUN=1 bash scripts/demo-prevent-insider.sh     # log intended blocks only
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

export IIOT_CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-prevent}"
NET="${NET:-iiot-testbed_iiot-net}"
IMG="${IMG:-iiot-attacker}"
PLC="${PLC:-openplc}"
NBENIGN="${NBENIGN:-3}"
WARMUP="${WARMUP:-40}"
HARMFUL="${HARMFUL:-1500}"
HOLD="${HOLD:-50}"           # long enough to see block + recovery while insider keeps trying
TTL="${TTL:-45}"
RESID_MODEL="${RESID_MODEL:-ml/models/residual_model.json}"
DRYRUN="${DRYRUN:-0}"

SESS="$IIOT_CAP_DIR/sessions/collect-0001"; mkdir -p "$SESS"
ZEEK="pv-zeek"; PCAP="pv-pcap"; HIST="pv-hist"; OP="pv-operator"; INS="pv-insider"
PREV_PID=""

ipof() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null; }

cleanup() {
  echo; echo "[*] stopping prevention demo ..."
  [ -n "$PREV_PID" ] && kill "$PREV_PID" 2>/dev/null || true
  sleep 2
  bash scripts/ipsblock.sh flush >/dev/null 2>&1 || true
  docker rm -f "$ZEEK" "$PCAP" "$HIST" "$OP" "$INS" pv-benign-1 pv-benign-2 pv-benign-3 >/dev/null 2>&1 || true
  echo "[*] done. logs:"
  echo "    prevention : $IIOT_CAP_DIR/prevention_fused_log.csv"
  echo "    telemetry  : $IIOT_CAP_DIR/process_telemetry.csv"
  echo "    insider    : $IIOT_CAP_DIR/insider_ledger.csv"
  exit 0
}
trap cleanup INT TERM

[ "$(docker inspect -f '{{.State.Running}}' "$PLC" 2>/dev/null)" = "true" ] || { echo "[!] $PLC not running"; exit 1; }
[ -f "$RESID_MODEL" ] || { echo "[!] residual model missing: $RESID_MODEL"; exit 1; }
[ -f "$IIOT_CAP_DIR/attack_ledger.csv" ] || echo "start_ts,end_ts,attack,params,attacker_ip" > "$IIOT_CAP_DIR/attack_ledger.csv"

echo "======================================================================"
echo "[*] FUSED PREVENTION demo -> $IIOT_CAP_DIR   (DRYRUN=$DRYRUN)"
echo "======================================================================"

# 1. benign infrastructure
BENIGN_IPS=""
for i in $(seq 1 "$NBENIGN"); do
  docker rm -f "pv-benign-$i" >/dev/null 2>&1 || true
  docker run -d --name "pv-benign-$i" --network "$NET" "$IMG" sleep infinity >/dev/null
  docker cp attacker/. "pv-benign-$i":/ >/dev/null
  docker exec -d "pv-benign-$i" python3 /benign_poller.py "$PLC" 502 0.6
  BENIGN_IPS="$BENIGN_IPS $(ipof pv-benign-$i)"
done
docker rm -f "$OP" >/dev/null 2>&1 || true
docker run -d --name "$OP" --network "$NET" "$IMG" sleep infinity >/dev/null
docker cp attacker/. "$OP":/ >/dev/null
docker exec -d "$OP" python3 /operator_setpoint.py "$PLC" 502 8 200 700
OP_IP="$(ipof $OP)"

docker rm -f "$HIST" >/dev/null 2>&1 || true
docker run -d --name "$HIST" -v "$IIOT_CAP_DIR:/out" --network "$NET" "$IMG" sleep infinity >/dev/null
docker cp attacker/. "$HIST":/ >/dev/null
docker exec -d "$HIST" python3 /process_logger.py "$PLC" 502 0.2 /out/process_telemetry.csv
HIST_IP="$(ipof $HIST)"

docker rm -f "$INS" >/dev/null 2>&1 || true
docker run -d --name "$INS" -v "$IIOT_CAP_DIR:/out" --network "$NET" "$IMG" sleep infinity >/dev/null
docker cp attacker/. "$INS":/ >/dev/null
INS_IP="$(ipof $INS)"

echo "[*] operator=$OP_IP  historian=$HIST_IP  readers=$BENIGN_IPS"
echo "[*] INSIDER (not allowlisted) = $INS_IP"

# 2. network capture
docker run -d --name "$PCAP" --net="container:$PLC" --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$SESS:/logs" -w /logs "$IMG" tcpdump -i eth0 -s 0 -U -w /logs/capture.pcap >/dev/null 2>&1 || true
docker run -d --name "$ZEEK" --net="container:$PLC" --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$SESS:/logs" -w /logs zeek/zeek:latest zeek -i eth0 -C >/dev/null

# 3. fused IPS (background). Allowlist every legitimate infra host.
DRYFLAG=""; [ "$DRYRUN" = 1 ] && DRYFLAG="--dry-run"
python3 ml/prevent_fused.py --cap-dir "$IIOT_CAP_DIR" \
  --residual-model "$RESID_MODEL" \
  --operator-allow "$OP_IP" \
  --allow "$HIST_IP" $BENIGN_IPS \
  --confirm 2 --confirm-insider 1 --ttl "$TTL" --interval 3 --window 3 $DRYFLAG &
PREV_PID=$!
echo "[*] fused IPS running (pid $PREV_PID)."

echo "[*] warmup ${WARMUP}s (normal operation) ..."
sleep "$WARMUP"

echo "[*] === INSIDER ATTACK: setpoint=$HARMFUL held ${HOLD}s (re-asserting) ==="
docker exec -e IIOT_CAP_DIR=/out -i "$INS" python3 /insider_write.py "$PLC" 502 "$HARMFUL" "$HOLD" 400 1.0

echo "[*] post-attack observation 25s (watch level recover after the block) ..."
sleep 25
cleanup
