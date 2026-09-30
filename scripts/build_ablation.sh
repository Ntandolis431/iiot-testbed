#!/usr/bin/env bash
# ============================================================================
#  build_ablation.sh  --  matched 1s vs 3s window ablation on the realistic set
# ============================================================================
# Rebuilds the SAME capture (iiot-dataset6/7/8/9) at two window lengths so the
# window-size ablation in the paper is apples-to-apples: identical traffic, only
# W differs. Concatenates the four per-dir builds exactly as the headline
# features_realistic_3s.csv was assembled, then trains/evaluates at each W.
#
# Usage:  bash scripts/build_ablation.sh
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

DIRS="6 7 8 9"
OUTDIR="/mnt/c/Users/user/Desktop/IIoT Testbed/iiot-testbed/data"
mkdir -p "$OUTDIR"

build_concat() {
  local W="$1" TAG="$2"
  local tmp first=1 f
  tmp="$(mktemp)"
  for d in $DIRS; do
    local CAP="$HOME/iiot-dataset$d"
    if [ ! -d "$CAP/sessions" ]; then echo "  [skip] $CAP (no sessions)"; continue; fi
    echo "  >> building iiot-dataset$d at W=${W}s ..."
    IIOT_CAP_DIR="$CAP" python3 ml/build_multilabel.py "$W" >/dev/null
    f="$CAP/features_multilabel.csv"
    if [ "$first" = 1 ]; then cat "$f" > "$tmp"; first=0
    else tail -n +2 "$f" >> "$tmp"; fi
  done
  local out="$OUTDIR/features_ablation_${TAG}.csv"
  mv "$tmp" "$out"
  local n; n=$(($(wc -l < "$out") - 1))
  echo "== wrote $out  (${n} windows)"
}

echo "==================== BUILD 3s ===================="
build_concat 3.0 3s
echo "==================== BUILD 1s ===================="
build_concat 1.0 1s

echo
echo "######################## TRAIN 3s ########################"
python3 ml/train_multilabel.py --multilabel "$OUTDIR/features_ablation_3s.csv"
echo
echo "######################## TRAIN 1s ########################"
python3 ml/train_multilabel.py --multilabel "$OUTDIR/features_ablation_1s.csv"
