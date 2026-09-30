#!/usr/bin/env python3
"""
============================================================================
 residual_detector.py -- physical-process-residual (consequence) detector
============================================================================
The SECOND detection channel. Network features cannot flag an authenticated
insider whose Modbus write is protocol-valid; only the physical CONSEQUENCE
gives it away. This detector watches the process historian (process_logger.py)
and fires on two layered signals:

  (1) LEARNED one-step predictor residual.
      A small linear auto-regressive model predicts the next tank level from the
      recent PHYSICAL state -- level, its rate of change, and the temp/press/flow
      context -- fitted on benign operation only. Crucially it is NOT given the
      setpoint, so when an insider drives the level off its normal trajectory the
      prediction error (residual) spikes. Threshold = a high quantile of the
      benign residual, so normal (gentle) operator setpoint changes stay silent.

  (2) HARD safe-envelope trip (guaranteed backstop).
      level must stay in [ENV_LO, ENV_HI]; setpoint in [SP_LO, SP_HI]. Any
      violation fires regardless of the learned model -- an interlock the ML
      layer can never suppress.

  consequence alarm = (|residual| > tau)  OR  (envelope violated)

Pure numpy/csv (no sklearn), so it runs anywhere.

Usage:
  # fit on a benign-only telemetry capture, save model
  python3 residual_detector.py train benign.csv model.json

  # score a telemetry capture with a saved model (optionally vs insider ledger)
  python3 residual_detector.py score telemetry.csv model.json [insider_ledger.csv]

  # one-shot: fit on the benign part of a capture, score the whole thing
  python3 residual_detector.py eval telemetry.csv [insider_ledger.csv]

Telemetry CSV columns: ts,temp,press,flow,level,setpoint
============================================================================
"""
import sys, os, csv, json
import numpy as np

# --- safe-envelope defaults (override via env) --------------------------------
ENV_LO = float(os.environ.get("ENV_LO", 50))
ENV_HI = float(os.environ.get("ENV_HI", 900))
SP_LO  = float(os.environ.get("SP_LO", 100))
SP_HI  = float(os.environ.get("SP_HI", 800))
QUANT  = float(os.environ.get("RESID_QUANT", 0.999))   # benign residual quantile for tau
MARGIN = float(os.environ.get("RESID_MARGIN", 1.5))    # multiply that quantile for headroom
TAU_FLOOR = float(os.environ.get("RESID_FLOOR", 8.0))  # min tau (units of level) to ignore quantisation noise


def load(path):
    ts, T = [], []
    with open(path) as f:
        for row in csv.DictReader(f):
            try:
                ts.append(float(row["ts"]))
                T.append([float(row["temp"]), float(row["press"]),
                          float(row["flow"]), float(row["level"]), float(row["setpoint"])])
            except (ValueError, KeyError):
                continue
    return np.array(ts), np.array(T, dtype=float)   # T columns: temp,press,flow,level,setpoint


def design(T):
    """features to predict level[t+1] from state at t (NO setpoint):
       [1, level, dlevel, temp, press, flow]"""
    temp, press, flow, level = T[:, 0], T[:, 1], T[:, 2], T[:, 3]
    dlevel = np.zeros_like(level); dlevel[1:] = level[1:] - level[:-1]
    X = np.column_stack([np.ones_like(level), level, dlevel, temp, press, flow])
    return X[:-1], level[1:]        # predict next level


def fit(T):
    X, y = design(T)
    beta, *_ = np.linalg.lstsq(X, y, rcond=None)
    resid = y - X @ beta
    tau = max(TAU_FLOOR, MARGIN * np.quantile(np.abs(resid), QUANT))
    return beta, tau


def score(T, beta, tau):
    """return per-sample alarm booleans + component signals (aligned to samples 1..N-1)."""
    X, y = design(T)
    pred = X @ beta
    resid = np.abs(y - pred)
    level_next = y
    setp_next = T[1:, 4]
    learned = resid > tau
    env = (level_next < ENV_LO) | (level_next > ENV_HI) | (setp_next < SP_LO) | (setp_next > SP_HI)
    alarm = learned | env
    return alarm, resid, learned, env


def truth_from_ledger(ts_next, ledger):
    """boolean insider-truth per scored sample, from insider_ledger.csv time spans."""
    truth = np.zeros(len(ts_next), dtype=bool)
    spans = []
    if ledger and os.path.exists(ledger):
        with open(ledger) as f:
            for row in csv.DictReader(f):
                if (row.get("attack") or "").strip() != "insider":
                    continue
                try:
                    spans.append((float(row["start_ts"]), float(row["end_ts"])))
                except (ValueError, KeyError):
                    pass
    for s, e in spans:
        truth |= (ts_next >= s) & (ts_next <= e)
    return truth, spans


def report(ts, T, beta, tau, ledger=None):
    alarm, resid, learned, env = score(T, beta, tau)
    ts_next = ts[1:]
    truth, spans = truth_from_ledger(ts_next, ledger)
    print(f"[*] samples scored: {len(alarm)}   tau(residual)={tau:.2f}   "
          f"envelope level[{ENV_LO:.0f},{ENV_HI:.0f}] setpoint[{SP_LO:.0f},{SP_HI:.0f}]")
    print(f"[*] max |residual| = {resid.max():.1f}   alarms: {int(alarm.sum())} "
          f"(learned {int(learned.sum())}, envelope {int(env.sum())})")
    if ledger and spans:
        tp = int((alarm & truth).sum()); fn = int((~alarm & truth).sum())
        fp = int((alarm & ~truth).sum()); tn = int((~alarm & ~truth).sum())
        rec = tp / (tp + fn) if (tp + fn) else float("nan")
        far = fp / (fp + tn) if (fp + tn) else float("nan")
        print(f"[*] insider windows: {len(spans)}   truth-positive samples: {int(truth.sum())}")
        print(f"[*] confusion  TP={tp} FN={fn} FP={fp} TN={tn}")
        print(f"[*] insider RECALL = {rec:.3f}   benign FALSE-ALARM = {far:.4f}")
        for k, (s, e) in enumerate(spans, 1):
            m = (ts_next >= s) & (ts_next <= e) & alarm
            if m.any():
                lat = ts_next[m][0] - s
                # which channel tripped first?
                first = np.argmax((ts_next >= s) & (ts_next <= e) & alarm)
                ch = "envelope" if env[first] else "learned-residual"
                print(f"    insider #{k}: DETECTED, latency {lat:.2f}s, first via {ch}")
            else:
                print(f"    insider #{k}: MISSED")
    return alarm, resid


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    mode = sys.argv[1]
    if mode == "train":
        ts, T = load(sys.argv[2])
        beta, tau = fit(T)
        json.dump({"beta": beta.tolist(), "tau": tau,
                   "env": [ENV_LO, ENV_HI, SP_LO, SP_HI]},
                  open(sys.argv[3], "w"), indent=2)
        print(f"[*] fitted on {len(T)} benign samples -> {sys.argv[3]}  (tau={tau:.2f})")
    elif mode == "score":
        ts, T = load(sys.argv[2])
        m = json.load(open(sys.argv[3]))
        ledger = sys.argv[4] if len(sys.argv) > 4 else None
        report(ts, T, np.array(m["beta"]), float(m["tau"]), ledger)
    elif mode == "eval":
        ts, T = load(sys.argv[2])
        ledger = sys.argv[3] if len(sys.argv) > 3 else None
        # fit on benign samples only (those OUTSIDE any insider window)
        _, spans = truth_from_ledger(ts, ledger)
        keep = np.ones(len(T), dtype=bool)
        for s, e in spans:
            keep &= ~((ts >= s - 2) & (ts <= e + 2))    # drop insider (+2s guard) from the fit
        beta, tau = fit(T[keep])
        print(f"[*] fitted on {int(keep.sum())} benign samples (excluded {int((~keep).sum())} insider+guard)")
        report(ts, T, beta, tau, ledger)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
