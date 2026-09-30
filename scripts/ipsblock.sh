#!/usr/bin/env bash
# ============================================================================
#  ipsblock.sh  --  enforcement helper for the ML-triggered IPS (Phase 3)
# ============================================================================
# Adds / removes an iptables DROP rule for a source IP inside the PLC's network
# namespace. It runs iptables in an ephemeral privileged container that SHARES
# openplc's netns (the same trick zeek-live and capture-start use), with
# NET_ADMIN so it can edit openplc's firewall. Rules live in openplc's netns and
# persist as long as openplc runs.
#
# This is the testbed stand-in for what an SDN flow-rule or an industrial
# firewall does in production: drop the malicious source at the protected asset.
#
# SAFEGUARD: refuses to block any IP in IPS_ALLOWLIST (PLC / SCADA / gateway).
#
# Note (honest): a libpcap capture (zeek-live) taps the interface on RX BEFORE
# netfilter, so after a block zeek still SEES the attacker's connection attempts.
# What the block stops is delivery to the PLC application -- the malicious Modbus
# requests never reach OpenPLC, so the attack is neutralised. Failed attempts
# from the blocked host are expected.
#
# Usage:
#   IPS_ALLOWLIST="172.19.0.2 172.19.0.3" bash scripts/ipsblock.sh block   <ip>
#   bash scripts/ipsblock.sh unblock <ip>
#   bash scripts/ipsblock.sh list
#   bash scripts/ipsblock.sh flush          # remove all source-DROP rules we added
# ============================================================================
set -uo pipefail

PLC="${PLC:-openplc}"
IMG="${IPS_IMG:-nicolaka/netshoot}"
ALLOWLIST="${IPS_ALLOWLIST:-}"       # space-separated IPs never to block

ipt() { docker run --rm --net="container:$PLC" --cap-add=NET_ADMIN "$IMG" iptables "$@"; }

cmd="${1:-}"; ip="${2:-}"

case "$cmd" in
block)
  [ -z "$ip" ] && { echo "[!] usage: ipsblock.sh block <ip>"; exit 1; }
  for a in $ALLOWLIST; do
    if [ "$a" = "$ip" ]; then
      echo "[ALLOW] $ip is allowlisted (PLC/SCADA/gateway) -- refusing to block"; exit 3
    fi
  done
  if ipt -C INPUT -s "$ip" -j DROP 2>/dev/null; then
    echo "[=] $ip already blocked"
  else
    ipt -I INPUT -s "$ip" -j DROP && echo "[BLOCK] $ip -> DROP on $PLC"
  fi
  ;;
unblock)
  [ -z "$ip" ] && { echo "[!] usage: ipsblock.sh unblock <ip>"; exit 1; }
  removed=0
  while ipt -C INPUT -s "$ip" -j DROP 2>/dev/null; do
    ipt -D INPUT -s "$ip" -j DROP; removed=1
  done
  [ "$removed" = 1 ] && echo "[UNBLOCK] $ip" || echo "[=] $ip was not blocked"
  ;;
list)
  ipt -S INPUT
  ;;
flush)
  ipt -S INPUT | sed -n 's/^-A INPUT -s \([0-9.]*\)\/32 -j DROP$/\1/p' | while read -r src; do
    [ -n "$src" ] && ipt -D INPUT -s "$src" -j DROP && echo "[UNBLOCK] $src"
  done
  ;;
*)
  echo "usage: ipsblock.sh block|unblock|list|flush [ip]"; exit 1 ;;
esac
