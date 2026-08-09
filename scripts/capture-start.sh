#!/usr/bin/env bash
# Start a LABELED capture session at OpenPLC (for one attack scenario).
# Runs until you call capture-stop.sh with the same label.
#
# Captures on interface "any" inside OpenPLC's network namespace, so it works
# regardless of how Docker numbers OpenPLC's interfaces (it is attached to both
# the default bridge and iiot-net).
#
# Usage:  bash scripts/capture-start.sh <label> [bpf_filter]
#   e.g.  bash scripts/capture-start.sh recon
#         bash scripts/capture-start.sh flood 'tcp port 502'
set -euo pipefail

LABEL="${1:?usage: capture-start.sh <label> [bpf_filter]}"
BPF="${2:-}"                                   # empty = capture ALL traffic
CAP_DIR="${IIOT_CAP_DIR:-$HOME/iiot-captures}"
SESS="$CAP_DIR/sessions/$LABEL"
mkdir -p "$SESS"

docker rm -f "cap-$LABEL" >/dev/null 2>&1 || true
docker run -d --name "cap-$LABEL" \
  --net=container:openplc \
  -v "$SESS:/caps" \
  --entrypoint sh nicolaka/netshoot \
  -c "tcpdump -i any -w /caps/$LABEL.pcap $BPF"

# Wait until tcpdump is actually sniffing before returning, so fast attacks
# (e.g. a 1-second port scan) aren't missed due to a capture-start race.
echo -n "[*] Warming up capture"
for _ in 1 2 3 4 5; do
  if docker logs "cap-$LABEL" 2>&1 | grep -q "listening on"; then break; fi
  echo -n "."; sleep 1
done
echo

echo "[*] Capturing session '$LABEL' -> $SESS/$LABEL.pcap"
echo "[*] Run your attack now, then:  bash scripts/capture-stop.sh $LABEL"
