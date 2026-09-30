#!/usr/bin/env python3
"""
Modbus device / point enumeration scan  (ICS-specific reconnaissance).

Distinct from the nmap port recon: this speaks Modbus and sweeps the protocol
address space to fingerprint the device -- which unit/slave IDs answer, which
function codes are supported, and which coil/register ranges exist. It is the
classic "map the PLC" step an attacker performs once port 502 is known open.

Produces many short probing connections with high diversity of unit IDs and
function codes -- the flow signature that separates a scan from normal SCADA
polling (which touches a small, fixed set).

For ISOLATED lab use only (see SECURITY.md).

Usage (inside the attacker container):
    python3 modbus_scan.py [host] [port] [max_unit]
    default host=openplc port=502 max_unit=20
"""
import sys
from pymodbus.client import ModbusTcpClient

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
MAXU = int(sys.argv[3]) if len(sys.argv) > 3 else 20


def read_regs(client, addr, count, unit):
    """read_holding_registers across pymodbus versions (slave/device_id kwarg)."""
    for kw in ("slave", "device_id", "unit"):
        try:
            return client.read_holding_registers(addr, count=count, **{kw: unit})
        except TypeError:
            continue
    return client.read_holding_registers(addr, count=count)


def read_coils(client, addr, count, unit):
    for kw in ("slave", "device_id", "unit"):
        try:
            return client.read_coils(addr, count=count, **{kw: unit})
        except TypeError:
            continue
    return client.read_coils(addr, count=count)


answered = []
print(f"[*] Modbus enumeration scan of {HOST}:{PORT}  units 0-{MAXU}")
for unit in range(0, MAXU + 1):
    c = ModbusTcpClient(HOST, port=PORT, timeout=1)
    if not c.connect():
        continue
    ok = False
    # probe a spread of addresses per unit to map the point space
    for addr in (0, 1, 10, 100, 1000, 40001 % 65536):
        try:
            rr = read_regs(c, addr, 4, unit)
            rc = read_coils(c, addr, 4, unit)
            if (rr is not None and not rr.isError()) or (rc is not None and not rc.isError()):
                ok = True
        except Exception:
            pass
    c.close()
    if ok:
        answered.append(unit)
        print(f"    unit {unit:3d}: responds")

print(f"[*] scan complete -- responding unit IDs: {answered or 'none'}")
