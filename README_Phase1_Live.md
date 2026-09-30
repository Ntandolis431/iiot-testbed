# Phase 1 — Live Environment (continuous attacks + real-time detection)

This is the first phase of the live-environment roadmap: turn the batch testbed
into an always-on system where attacks are launched continuously and the model
scores the traffic in real time.

It uses the model you already trained. It does **not** yet do multi-label
detection (Phase 2) or automated blocking (Phase 3) — those come next.

## The three moving parts

They all share one capture directory, `IIOT_CAP_DIR` (default `~/iiot-live`):

| Part | Script | What it does |
|------|--------|--------------|
| Live capture | `scripts/start-live-capture.sh` (via `live-env.sh`) | Zeek sniffs the PLC and appends `live/conn.log` + `live/modbus.log`. |
| Attack bots | `scripts/attack-bots.sh` | Launches 1–3 randomised attacks **at once**, forever, and logs each to `attack_ledger.csv`. |
| Real-time detector | `ml/live_detect.py` | Every few seconds, windows the growing logs, scores new completed windows, streams verdicts, logs to `alerts.csv`. |

## Prerequisites

- The stack is up: `docker compose up -d` (needs `openplc` at least).
- OpenPLC is running the `plc/sensors.st` program (so there is benign traffic too).
- The attacker image is built: `docker build -t iiot-attacker attacker/`.
- The model is trained once:
  `python3 ml/train_model.py ~/iiot-captures/features_windows.csv`

## Run it

**Start the environment (sets up capture + attacker):**

```bash
bash scripts/live-env.sh up
```

It prints the two commands to run next. Open two terminals side by side:

**Terminal A — continuous attacks:**

```bash
IIOT_CAP_DIR=~/iiot-live bash scripts/attack-bots.sh
```

**Terminal B — real-time detection:**

```bash
IIOT_CAP_DIR=~/iiot-live python3 ml/live_detect.py
```

You'll see attacks launching on the left and detections appearing on the right,
a few seconds behind (one window + a completion margin).

**Check status / stop:**

```bash
bash scripts/live-env.sh status
bash scripts/live-env.sh down       # stops the live capture
```

## Tuning the attack load

```bash
# heavier: up to 4 at once, little or no gap between waves
MAX_CONC=4 MIN_GAP=0 MAX_GAP=3 IIOT_CAP_DIR=~/iiot-live bash scripts/attack-bots.sh

# bounded run (5 minutes) instead of forever
RUN_FOR=300 IIOT_CAP_DIR=~/iiot-live bash scripts/attack-bots.sh
```

## Outputs

Everything lands in `IIOT_CAP_DIR` (`~/iiot-live`):

- `live/conn.log`, `live/modbus.log` — the growing Zeek feature logs.
- `features_windows.csv` — the current windowed features (rebuilt each cycle).
- `alerts.csv` — every non-benign verdict: `wall_time, t_start, source, verdict, confidence`.
- `attack_ledger.csv` — ground truth of what was attacked and when:
  `start_ts, end_ts, attack, params, attacker_ip`.

## Why the ledger matters (the bridge to Phase 2)

`attack_ledger.csv` records the exact start/end of every attack. Because the
bots run several attacks **concurrently**, there are now time windows where two
or more attacks overlap. In Phase 2 we intersect each 1-second feature window
with the ledger to assign **all** the attack types active in that window — this
is the multi-label training data that a single-attack-at-a-time capture could
never produce. Generating the live load and generating the multi-label dataset
are the same step.

## Honest limits (Phase 1 only)

- The detector still outputs **one label per window** (the top class). Windows
  with two concurrent attacks are detected as an attack, but typed as one of
  them. Multi-label output is Phase 2.
- Detection is **passive** — it reports, it does not block. Blocking is Phase 3.
- Each cycle re-windows the whole live log, so over a very long run the cycle
  gets slower; fine for a demo of minutes to an hour. An incremental/tailing
  extractor is a later optimisation.
