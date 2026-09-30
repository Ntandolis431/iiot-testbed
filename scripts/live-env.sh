#!/usr/bin/env bash
# ============================================================================
#  live-env.sh  --  bring up / tear down the LIVE testbed environment
# ============================================================================
# Phase 1 of the live-environment roadmap.
#
# The "always-on" environment is three pieces sharing ONE capture directory
# (IIOT_CAP_DIR, default ~/iiot-live):
#
#     1. zeek-live      -- sniffs the PLC and appends conn.log/modbus.log
#                          (host-mounted so the detector can read them)
#     2. attack-bots    -- continuous concurrent attacks   (own terminal)
#     3. live_detect    -- continuous real-time detection   (own terminal)
#
# This script sets up #1 (and checks the stack + attacker), then tells you the
# two commands to run for #2 and #3. Keeping the bots and the detector in their
# own terminals is deliberate: the demo shows attacks on one side and detections
# appearing on the other.
#
# Usage:
#   bash scripts/live-env.sh up       # start capture, print next steps
#   bash scripts/live-env.sh status   # what's running
#   bash scripts/live-env.sh down     # stop the live capture
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

export IIOT_CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-live}"
KALI="${KALI:-kali}"
NET="${NET:-iiot-testbed_iiot-net}"
IMG="${IMG:-iiot-attacker}"
CMD="${1:-up}"

running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]; }

case "$CMD" in
up)
  # 1. stack must be up (need openplc at least)
  if ! running openplc; then
    echo "[!] openplc is not running. Bring the stack up first:"
    echo "      docker compose up -d"
    exit 1
  fi
  echo "[*] openplc is up."

  # 2. attacker container
  if running "$KALI"; then
    echo "[*] attacker '$KALI' already running."
  else
    echo "[*] starting attacker '$KALI' ..."
    docker rm -f "$KALI" >/dev/null 2>&1 || true
    docker run -d --name "$KALI" --network "$NET" --privileged "$IMG" >/dev/null
    docker cp attacker/. "$KALI":/ >/dev/null
    echo "[*] attacker started and scripts copied."
  fi

  # 3. host-mounted live capture (so live_detect can read the logs)
  #    NOTE: the compose file also runs a zeek-live into a docker VOLUME we
  #    can't read from the host; stop it so we have exactly one readable capture.
  docker rm -f zeek-live >/dev/null 2>&1 || true
  IIOT_CAP_DIR="$IIOT_CAP_DIR" bash scripts/start-live-capture.sh

  echo
  echo "======================================================================"
  echo "  Live capture is running. Now open TWO terminals:"
  echo "======================================================================"
  echo "  (one-time, if you haven't trained the model on your data yet:)"
  echo "     python3 ml/train_model.py ~/iiot-captures/features_windows.csv"
  echo
  echo "  Terminal A  --  continuous attacks:"
  echo "     IIOT_CAP_DIR=$IIOT_CAP_DIR bash scripts/attack-bots.sh"
  echo
  echo "  Terminal B  --  real-time detection:"
  echo "     IIOT_CAP_DIR=$IIOT_CAP_DIR python3 ml/live_detect.py"
  echo
  echo "  Stop everything:  Ctrl+C in A and B, then  bash scripts/live-env.sh down"
  echo "======================================================================"
  ;;

status)
  for c in openplc "$KALI" zeek-live; do
    if running "$c"; then echo "  [up]   $c"; else echo "  [down] $c"; fi
  done
  echo "  IIOT_CAP_DIR=$IIOT_CAP_DIR"
  [ -f "$IIOT_CAP_DIR/attack_ledger.csv" ] && \
    echo "  ledger rows: $(( $(wc -l < "$IIOT_CAP_DIR/attack_ledger.csv") - 1 ))"
  [ -f "$IIOT_CAP_DIR/alerts.csv" ] && \
    echo "  alert rows : $(( $(wc -l < "$IIOT_CAP_DIR/alerts.csv") - 1 ))"
  ;;

down)
  echo "[*] stopping live capture (zeek-live) ..."
  docker rm -f zeek-live >/dev/null 2>&1 || true
  echo "[*] done. (attacker '$KALI' left running; remove with: docker rm -f $KALI)"
  echo "[*] logs & ledger kept in: $IIOT_CAP_DIR"
  ;;

*)
  echo "usage: bash scripts/live-env.sh [up|status|down]"; exit 1 ;;
esac
