#!/usr/bin/env bash
# ============================================================================
#  attack-bots.sh  --  continuous, concurrent attack generator (LIVE env)
# ============================================================================
# Phase 1 of the live-environment roadmap.
#
# Instead of running one attack by hand, this keeps a constant adversary alive:
# every "wave" it launches 1..MAX_CONC randomised attacks AT THE SAME TIME
# against the PLC, from the Kali container, then waits a random gap and does it
# again -- forever (or for RUN_FOR seconds).
#
# It also writes an ATTACK LEDGER: one line per attack with its exact start/end
# time, type, parameters and the attacker's IP. That ledger is the ground truth
# that lets Phase 2 label overlapping windows as MULTI-LABEL (e.g. a window that
# is flood + write at once). Generating the live load and generating the
# multi-label training data are therefore the same activity.
#
# Detection does NOT need this ledger; it's for building labelled data later.
#
# Usage:
#   bash scripts/attack-bots.sh                 # forever, up to 3 at a time
#   MAX_CONC=4 MIN_GAP=0 MAX_GAP=3 bash scripts/attack-bots.sh   # heavier load
#   RUN_FOR=300 bash scripts/attack-bots.sh     # run for 5 minutes then stop
#
# Stop: Ctrl+C (any in-flight attacks finish on their own).
# ============================================================================
set -uo pipefail

TARGET="${TARGET:-openplc}"          # PLC hostname on the Docker network
KALI="${KALI:-kali}"                 # attacker container name
MAX_CONC="${MAX_CONC:-3}"            # max concurrent attacks per wave
MIN_GAP="${MIN_GAP:-2}"              # min seconds between waves
MAX_GAP="${MAX_GAP:-8}"              # max seconds between waves
RUN_FOR="${RUN_FOR:-0}"             # total run seconds (0 = forever)
CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"
LEDGER="$CAP_DIR/attack_ledger.csv"
mkdir -p "$CAP_DIR"

# --- preflight: is the attacker container actually up? ----------------------
if [ "$(docker inspect -f '{{.State.Running}}' "$KALI" 2>/dev/null)" != "true" ]; then
  echo "[!] attacker container '$KALI' is not running."
  echo "    Start it first, e.g.:"
  echo "      docker run -d --name kali --network iiot-testbed_iiot-net --privileged iiot-attacker"
  echo "      docker cp attacker/. kali:/"
  exit 1
fi

# attacker IP (recorded for Phase-2 labelling; detection doesn't need it)
ATTACKER_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$KALI" 2>/dev/null | tr -d '[:space:]')"
[ -z "$ATTACKER_IP" ] && ATTACKER_IP="unknown"

# ledger header (only when the file is new -- appends across runs otherwise)
[ -f "$LEDGER" ] || echo "start_ts,end_ts,attack,params,attacker_ip" > "$LEDGER"

echo "======================================================================"
echo "[*] LIVE attack bots"
echo "[*] attacker : $KALI ($ATTACKER_IP)"
echo "[*] target   : $TARGET"
echo "[*] load     : up to $MAX_CONC concurrent / wave, gap ${MIN_GAP}-${MAX_GAP}s"
echo "[*] ledger   : $LEDGER"
[ "$RUN_FOR" != 0 ] && echo "[*] duration : ${RUN_FOR}s" || echo "[*] duration : forever (Ctrl+C to stop)"
echo "======================================================================"

# catalogue of attack types (each maps to a script/tool below)
ATTACKS=(recon recon2 scan flood flood2 write write2 write3 replay read malformed mitm)

rand() { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }   # rand LO HI  (inclusive)

# build_cmd <name>  -> sets CMD (args after `docker exec`) and PARAMS (for ledger)
build_cmd() {
  case "$1" in
    recon)  local hp; hp=$(rand 1000 10000); CMD="$KALI nmap -Pn -sT -T4 -p 1-$hp $TARGET"; PARAMS="ports=1-$hp" ;;
    recon2) local ep; ep=$(rand 500 3000);   CMD="$KALI python3 /recon2.py $TARGET 1 $ep"; PARAMS="ports=1-$ep" ;;
    flood)  local d;  d=$(rand 5 20);         CMD="$KALI python3 /modbus_flood.py $TARGET 502 $d"; PARAMS="dur=${d}s" ;;
    flood2) local d;  d=$(rand 5 20);         CMD="$KALI python3 /modbus_flood2.py $TARGET 502 $d"; PARAMS="dur=${d}s" ;;
    write)                                    CMD="$KALI python3 /modbus_write.py $TARGET 502"; PARAMS="fixed" ;;
    write2) local r;  r=$(rand 30 90);        CMD="$KALI python3 /write2.py $TARGET 502 $r"; PARAMS="rounds=$r" ;;
    write3) local o;  o=$(rand 100 500);      CMD="$KALI python3 /write3.py $TARGET 502 $o"; PARAMS="ops=$o" ;;
    replay) local c;  c=$(rand 20 60);        CMD="$KALI python3 /modbus_replay.py $TARGET 502 $c"; PARAMS="cycles=$c" ;;
    read)                                     CMD="$KALI python3 /modbus_read.py $TARGET 502"; PARAMS="enum" ;;
    scan)      local mu; mu=$(rand 10 30);    CMD="$KALI python3 /modbus_scan.py $TARGET 502 $mu"; PARAMS="units=0-$mu" ;;
    malformed) local nf; nf=$(rand 20 60);    CMD="$KALI python3 /modbus_malformed.py $TARGET 502 $nf"; PARAMS="frames=$nf" ;;
    mitm)      local md; md=$(rand 15 30);    CMD="$KALI bash /mitm.sh $TARGET benign-scada $md"; PARAMS="dur=${md}s" ;;
  esac
}

# launch <name>  -> run the attack in the background, log it to the ledger
launch() {
  local name="$1"
  build_cmd "$name"
  local params="$PARAMS" cmd="$CMD"
  (
    start="$(date +%s.%N)"
    printf '    -> %-7s (%s)\n' "$name" "$params"
    docker exec $cmd >/dev/null 2>&1
    end="$(date +%s.%N)"
    # one short, atomic append per attack (safe under concurrency: <PIPE_BUF)
    printf '%s,%s,%s,%s,%s\n' "$start" "$end" "$name" "$params" "$ATTACKER_IP" >> "$LEDGER"
  ) &
}

START_ALL="$(date +%s)"
wave=0
while :; do
  wave=$((wave + 1))
  k=$(rand 1 "$MAX_CONC")
  picks="$(printf '%s\n' "${ATTACKS[@]}" | shuf | head -n "$k")"
  ts="$(date +%H:%M:%S)"
  echo "[$ts | wave $wave] launching $k concurrent attack(s):"
  for a in $picks; do launch "$a"; done
  wait                                   # let this wave overlap in time, then finish

  if [ "$RUN_FOR" != 0 ] && [ $(( $(date +%s) - START_ALL )) -ge "$RUN_FOR" ]; then
    echo "[*] reached RUN_FOR=${RUN_FOR}s -- stopping."
    break
  fi
  sleep "$(rand "$MIN_GAP" "$MAX_GAP")"
done
