#!/usr/bin/env bash
# One-command runner: install deps (first time) and run the ML pipeline.
# Usage:  bash ml/run.sh            # uses $IIOT_CAP_DIR/features_windows.csv
#         bash ml/run.sh --folds 5
set -uo pipefail
cd "$(dirname "$0")/.."
python3 -c "import sklearn,scipy,pandas,numpy" 2>/dev/null || \
  pip install --break-system-packages --default-timeout=120 --retries 10 scikit-learn joblib threadpoolctl || \
  sudo apt-get install -y python3-sklearn python3-sklearn-lib
python3 ml/train_evaluate.py "$@"
