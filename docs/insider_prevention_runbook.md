# Insider / Residual / Prevention — Reproducibility Runbook

End-to-end commands for the authenticated-insider detection (RQ3) and the
availability-preserving prevention (RQ2) experiments. Run everything from the repo
root in WSL:

```bash
cd "/mnt/c/Users/user/Desktop/IIoT Testbed/iiot-testbed"
```

Components added for this phase:

| File | Role |
|---|---|
| `plc/sensors.st` | PLC program: closed-loop tank level driven by a writable setpoint (HR10), with a safe envelope. `plc/sensors_openloop_backup.st` is the old open-loop version. |
| `attacker/operator_setpoint.py` | Legitimate operator: gentle, in-band setpoint writes (benign control). |
| `attacker/insider_write.py` | Authenticated insider: valid but harmful setpoint writes; logs `insider_ledger.csv`. |
| `attacker/process_logger.py` | Process historian: samples HR0–HR10 at 5 Hz into `process_telemetry.csv`. |
| `attacker/verify_control.py` | One-shot check that the control loop + writable setpoint work. |
| `ml/residual_detector.py` | Physical-process-residual detector (learned AR predictor + hard safe-envelope). Pure numpy. |
| `ml/prevent_fused.py` | Fused, criticality-prioritized IPS (network + residual), availability-first. |
| `scripts/collect-insider.sh` | Capture: benign + legit operator + N insider events → telemetry, ledger, Zeek. |
| `scripts/demo-prevent-insider.sh` | Live prevention demo (block the insider, watch the tank recover). |

---

## 0. Prerequisites

```bash
docker compose up -d                 # stack running
docker pull nicolaka/netshoot        # needed only for the live block (iptables)
```

## 1. Load the PLC program and verify the control loop

Load `plc/sensors.st` via the OpenPLC web UI (`http://127.0.0.1:8080`, login `openplc`/`openplc`):
**Programs → upload `plc/sensors.st` → Compile → Dashboard → Start PLC.**

Then confirm the loop and the writable setpoint:

```bash
docker run -i --rm --network iiot-testbed_iiot-net iiot-attacker python3 - < attacker/verify_control.py
```

Expect: setpoint reads back what is written; level chases it; setpoint 1500 drives level past
the 900 mm trip toward the 1200 mm brim.

## 2. Collect the detection dataset (3 insider events + normal operation)

```bash
rm -rf "data/insider"
IIOT_CAP_DIR="$PWD/data/insider" \
WARMUP=300 N_INSIDER=3 INSIDER_GAP=120 HOLD=25 COOLDOWN=60 NBENIGN=3 \
bash scripts/collect-insider.sh
```

Produces in `data/insider/`: `process_telemetry.csv`, `insider_ledger.csv`,
`features_multilabel.csv` (network features), and `sessions/collect-0001/` (Zeek + pcap).

## 3. Fit the residual model (benign telemetry only)

```bash
python3 ml/residual_detector.py train data/insider/process_telemetry.csv ml/models/residual_model.json
```

> Note: for a strictly benign fit, use a telemetry file with no insider events, or the
> `eval` mode below, which excludes the insider windows (+guard) from the fit automatically.

## 4. Evaluate detection

Residual channel (per-sample, vs the ledger):

```bash
python3 ml/residual_detector.py eval data/insider/process_telemetry.csv data/insider/insider_ledger.csv
```

Network channel — show the NIDS cannot separate the insider from the operator. First make
sure the 3 s headline model is loaded, then run detection:

```bash
python3 ml/train_multilabel.py --multilabel data/features_realistic_3s.csv --singlelabel /nonexistent
python3 ml/detect_multilabel.py data/insider/features_multilabel.csv --out data/insider/nids_preds.csv
```

Expected: insider host verdict = `write` in every window, identical to the operator host.

## 5. Live prevention demo (detect → prioritize → block → recover)

```bash
# safe dry-run first (no iptables): prove the decision logic
rm -rf "data/prevent"
DRYRUN=1 IIOT_CAP_DIR="$PWD/data/prevent" bash scripts/demo-prevent-insider.sh

# real block (drops the insider at the PLC; auto-unblocks on exit)
rm -rf "data/prevent"
IIOT_CAP_DIR="$PWD/data/prevent" bash scripts/demo-prevent-insider.sh
```

Outputs in `data/prevent/`: `prevention_fused_log.csv` (timeline of alarms/blocks) and
`process_telemetry.csv` (level recovering after the block). Confirm nothing is left blocked:

```bash
bash scripts/ipsblock.sh list
```

## 6. Cleanup

```bash
sudo rm -rf data/insider_smoke           # remove any smoke-test scratch (Docker-owned)
bash scripts/ipsblock.sh flush           # remove any stray DROP rules
```

---

### Key results (from real captures)

- Residual detector: 3/3 insider events, recall **0.980**, latency **< 0.2 s**, benign false-alarm **0.0017**.
- Network NIDS: identical `write` verdict for insider (29/29) and operator (85/85) → **cannot discriminate**.
- Live prevention: insider blocked **7 s** after the unsafe excursion; tank recovered **6 s** later; all allowlisted hosts untouched.
