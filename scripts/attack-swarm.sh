#!/usr/bin/env bash
# ============================================================================
#  attack-swarm.sh  --  a SWARM of distinct attacker bots (multiple attackers)
# ============================================================================
# Phase 1/2 extension: instead of one attacker host, start N SEPARATE attacker
# containers -- each with its OWN IP on the testbed network -- and run the
# attack orchestrator inside each. The PLC is then hit by several DISTINCT
# sources at the same time ("multiple attackers"), which is different from one
# host doing several attacks at once (that's the multi-label case, already
# covered). Detection is per-source-host, so this exercises concurrent sources.
#
# Each bot logs to the SHARED attack_ledger.csv with its own attacker_ip, so
# the ground truth distinguishes which bot did what.
#
# Usage:
#   N=6 IIOT_CAP_DIR=~/iiot-live bash scripts/attack-swarm.sh
#   N=3 MAX_CONC=2 bash scripts/attack-swarm.sh      # 3 bots, each up to 2 at once
#
# Stop: Ctrl+C -- stops every bot AND removes the attacker containers.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

N="${N:-6}"                                   # number of distinct attacker bots
NET="${NET:-iiot-testbed_iiot-net}"
IMG="${IMG:-iiot-attacker}"
export IIOT_CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-live}"
export MAX_CONC="${MAX_CONC:-1}"              # per bot; swarm gives the concurrency
export MIN_GAP="${MIN_GAP:-1}"
export MAX_GAP="${MAX_GAP:-5}"

pids=(); names=()

# pre-create the shared ledger (avoids 6 bots racing to write the header)
mkdir -p "$IIOT_CAP_DIR"
[ -f "$IIOT_CAP_DIR/attack_ledger.csv" ] || \
  echo "start_ts,end_ts,attack,params,attacker_ip" > "$IIOT_CAP_DIR/attack_ledger.csv"

cleanup() {
  echo; echo "[*] stopping swarm ..."
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  for n in "${names[@]}"; do docker rm -f "$n" >/dev/null 2>&1 || true; done
  echo "[*] ${#names[@]} bot(s) stopped and removed. Ledger kept: $IIOT_CAP_DIR/attack_ledger.csv"
  exit 0
}
trap cleanup INT TERM

echo "======================================================================"
echo "[*] ATTACK SWARM: $N distinct attacker bots on $NET"
echo "[*] each bot: up to $MAX_CONC attack(s) at a time, gap ${MIN_GAP}-${MAX_GAP}s"
echo "[*] ledger : $IIOT_CAP_DIR/attack_ledger.csv"
echo "======================================================================"

# 1. start N attacker containers, each its own IP, scripts copied in
for i in $(seq 1 "$N"); do
  name="attacker-$i"
  docker rm -f "$name" >/dev/null 2>&1 || true
  if ! docker run -d --name "$name" --network "$NET" --privileged "$IMG" >/dev/null; then
    echo "[!] failed to start $name (is image '$IMG' built?  docker build -t $IMG attacker/)"; cleanup
  fi
  docker cp attacker/. "$name":/ >/dev/null
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
  names+=("$name")
  echo "    [$name] ip=$ip"
done

# 2. run the orchestrator inside each bot (each targets the PLC from its own IP)
echo "[*] launching orchestrator in each bot (Ctrl+C to stop & remove all)..."
for n in "${names[@]}"; do
  KALI="$n" bash scripts/attack-bots.sh > "$IIOT_CAP_DIR/bot-$n.log" 2>&1 &
  pids+=($!)
done

echo "[*] swarm running. Watch distinct source IPs light up in the detector,"
echo "    or:  tail -f $IIOT_CAP_DIR/bot-attacker-1.log"
wait
