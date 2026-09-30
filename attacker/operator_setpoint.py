#!/usr/bin/env python3
"""
operator_setpoint.py  --  LEGITIMATE operator setpoint control (benign).

A real plant operator/SCADA periodically adjusts the tank level setpoint within
a safe operating band. This makes "a Modbus write to the setpoint register" a
NORMAL, authorised event -- which is exactly why the authenticated insider is
invisible to a network detector: the insider's write is, on the wire, identical
to one of these legitimate setpoint changes. Only the physical CONSEQUENCE
(level leaving the safe envelope) distinguishes them.

Runs from a benign (non-attacker) container, so its windows label benign. It
moves the setpoint in small steps (a gentle random walk) inside [LO, HI], so the
level always stays well within the safety band.

Usage (inside a container):
    python3 operator_setpoint.py [host] [port] [period_s] [lo] [hi]
    defaults: openplc 502 8.0 200 700
"""
import sys, time, random
from pymodbus.client import ModbusTcpClient

HOST   = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 502
PERIOD = float(sys.argv[3]) if len(sys.argv) > 3 else 8.0     # a setpoint change every ~8 s
LO     = int(sys.argv[4]) if len(sys.argv) > 4 else 200
HI     = int(sys.argv[5]) if len(sys.argv) > 5 else 700
SETPOINT_REG = 10
STEP_MAX = 120                                                # max change per adjustment (gentle)

sp = (LO + HI) // 2

def wr(c, addr, val):
    try:
        c.write_register(addr, val)
    except TypeError:
        c.write_register(addr, value=val)

print(f"[*] legitimate operator setpoint control -> {HOST}:{PORT}  "
      f"(band [{LO},{HI}], change every ~{PERIOD}s)")
while True:
    c = ModbusTcpClient(HOST, port=PORT)
    if not c.connect():
        time.sleep(2); continue
    try:
        while True:
            step = random.randint(-STEP_MAX, STEP_MAX)
            sp = max(LO, min(HI, sp + step))
            wr(c, SETPOINT_REG, sp)
            time.sleep(PERIOD)
    except Exception:
        try: c.close()
        except Exception: pass
        time.sleep(2)
