#!/usr/bin/env python3
"""
process_logger.py  --  the plant historian: samples physical telemetry.

Polls the PLC's process registers at a fixed rate and appends them to a CSV --
the data feed the physical-process-residual detector consumes (a stand-in for a
real process historian / OPC-DA tag logger). This is the SECOND observation
channel, parallel to the network capture: the network sees packets, the
historian sees physical state.

Columns: ts, temp, press, flow, level, setpoint
Registers: HR0 temp, HR1 press, HR2 flow, HR3 level, HR10 setpoint.

Usage (inside a container):
    python3 process_logger.py [host] [port] [period_s] [out_csv]
    defaults: openplc 502 0.2 /out/process_telemetry.csv
"""
import sys, os, time, csv
from pymodbus.client import ModbusTcpClient

HOST   = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 502
PERIOD = float(sys.argv[3]) if len(sys.argv) > 3 else 0.2
OUT    = sys.argv[4] if len(sys.argv) > 4 else (
    "/out/process_telemetry.csv" if os.path.isdir("/out") else "process_telemetry.csv")


def rd_block(c, addr, count):
    try:
        r = c.read_holding_registers(addr, count=count)
    except TypeError:
        r = c.read_holding_registers(addr, count)
    if r is None or r.isError():
        return None
    return r.registers


new = not os.path.exists(OUT)
f = open(OUT, "a", newline="")
w = csv.writer(f)
if new:
    w.writerow(["ts", "temp", "press", "flow", "level", "setpoint"])
    f.flush()

print(f"[*] process historian -> {OUT}  (every {PERIOD}s)")
while True:
    c = ModbusTcpClient(HOST, port=PORT)
    if not c.connect():
        time.sleep(2); continue
    try:
        while True:
            blk = rd_block(c, 0, 11)          # HR0..HR10 in one request
            ts = time.time()
            if blk is not None and len(blk) >= 11:
                w.writerow([f"{ts:.3f}", blk[0], blk[1], blk[2], blk[3], blk[10]])
                f.flush()
            time.sleep(PERIOD)
    except Exception:
        try: c.close()
        except Exception: pass
        time.sleep(2)
