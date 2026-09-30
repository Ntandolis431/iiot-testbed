#!/usr/bin/env python3
"""
verify_control.py  --  confirm the tank-level control loop on real OpenPLC.

Checks the one hardware assumption the insider/residual pillar rests on:
a Modbus master WRITE to holding register 10 (the setpoint, %QW10) must PERSIST
and be READ by the PLC program, so 'level' (HR3, %QW3) tracks it.

Run from a container on the testbed network, e.g.:
    docker run -i --rm --network iiot-testbed_iiot-net iiot-attacker \
        python3 - < attacker/verify_control.py
or, if the attacker image already has the file:
    docker exec -i wd-probe python3 /verify_control.py openplc

Expected output:
  * setpoint reads back exactly what we wrote (=> %QW10 is master-writable)
  * level moves toward the setpoint over a few seconds (=> program reads it)
  * setpoint 1500 drives level above the 900 mm trip toward the 1200 mm brim
If setpoint reads back 0 / resets, the write did NOT persist -> tell me and
we switch the setpoint to a %MW memory register instead.
"""
import sys, time
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502

c = ModbusTcpClient(HOST, port=PORT)
if not c.connect():
    sys.exit(f"[!] could not connect to {HOST}:{PORT}")


def rd(addr):
    try:
        r = c.read_holding_registers(addr, count=1)
    except TypeError:
        r = c.read_holding_registers(addr, 1)
    if r is None or r.isError():
        return None
    return r.registers[0]


def wr(addr, val):
    try:
        c.write_register(addr, val)
    except TypeError:
        c.write_register(addr, value=val)


print(f"[*] connected to {HOST}:{PORT}")
print(f"[*] initial   level(HR3)={rd(3)}   setpoint(HR10)={rd(10)}")

for sp in (700, 200, 1500):
    print(f"\n[*] writing setpoint HR10 = {sp}")
    wr(10, sp)
    for t in range(6):
        time.sleep(1.0)
        lv, spv = rd(3), rd(10)
        flag = "  <-- ABOVE 900 mm HIGH-LEVEL TRIP" if (lv is not None and lv > 900) else ""
        print(f"    t+{t+1}s   setpoint={spv}   level={lv}{flag}")

c.close()
print("\n[*] done. setpoint should persist at each written value; level should chase it.")
