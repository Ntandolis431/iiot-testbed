#!/usr/bin/env bash
# Process CIC Modbus 2023 (external scenario + benign) into features in OUR format,
# for cross-dataset validation. Same Zeek extraction + build_features.py as the testbed,
# so the feature columns match exactly.
#
# Labeling (first pass, binary): a window is "attack" if its source is the external
# attacker (185.175.0.7), else "benign" -- identical scheme to our own capture labeling.
#
# Uses the NETWORK-WIDE captures (whole-network view, like our Docker-bridge capture)
# to avoid double-counting the per-device veth files.
#
# Usage:
#   bash scripts/cic-process.sh "/mnt/c/Users/user/Desktop/IIoT Testbed/Modbus Dataset/Modbus Dataset"
set -uo pipefail
CIC="${1:-}"    # optional: root of the inner 'Modbus Dataset' folder (used only for
                # the default ATTACK_DIR/BENIGN_DIR paths below). If you point
                # ATTACK_DIR and BENIGN_DIR directly at the pcap folders, omit it.
OUT="${IIOT_CIC_DIR:-$HOME/cic-modbus}"
SESS="$OUT/sessions"; mkdir -p "$SESS"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

zeek_one() {                       # zeek_one <pcap> <session-name>
  local pcap="$1"
  local name="$2"
  local d="$SESS/$name"
  mkdir -p "$d"
  docker run --rm -v "$d:/logs" -v "$(dirname "$pcap"):/in:ro" -w /logs \
    zeek/zeek:latest zeek -C -r "/in/$(basename "$pcap")" 2>/dev/null \
    || echo "  [!] zeek failed on: $pcap"
}

process_group() {                  # process_group <find-root> <label-prefix>
  local root="$1" prefix="$2" i=0
  if [ ! -d "$root" ]; then echo "  [!] not found: $root"; return; fi
  while IFS= read -r p; do
    i=$((i+1)); zeek_one "$p" "${prefix}-$(printf '%03d' "$i")"
    echo "    [$prefix] $(basename "$p")"
  done < <(find "$root" -iname '*.pcap' | sort)
  echo "  [*] $prefix: $i pcaps"
}

# Override these to point straight at the pcap folders (recommended):
ATTACK_DIR="${ATTACK_DIR:-$CIC/attack/external/external-attacker/external-attacker-network-capture}"
BENIGN_DIR="${BENIGN_DIR:-$CIC/benign/network-wide-pcap-capture}"

echo "[*] Attack (external attacker's own capture, contains 185.175.0.7): $ATTACK_DIR"
process_group "$ATTACK_DIR" "attack"

echo "[*] Benign (network-wide capture): $BENIGN_DIR"
process_group "$BENIGN_DIR" "benign"

echo "[*] Building features (attacker IP 185.175.0.7)..."
IIOT_CAP_DIR="$OUT" ATTACKER_IP="185.175.0.7" python3 "$REPO/scripts/build_features.py" "${W:-3.0}"

echo
echo "[*] CIC features -> $OUT/features_windows.csv"
echo "[*] Next: python3 ml/validate_cic.py"
