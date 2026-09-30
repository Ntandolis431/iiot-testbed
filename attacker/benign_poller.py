#!/usr/bin/env python3
"""
benign_poller.py  --  realistic legitimate SCADA baseline traffic (the 'benign' class).

A real SCADA/HMI does not read a single register with one function code; it polls
the device across SEVERAL Modbus function codes every cycle (coils, discrete
inputs, holding registers, input registers) over a few address blocks, at a steady
rate. The earlier poller used essentially one function code at a low rate, which
made the model equate "several function codes / steady polling" with an attack and
caused heavy false alarms on real benign traffic (e.g. CIC Modbus 2023). This
version reproduces realistic polling so the benign class matches real deployments.

It stays READ-ONLY on purpose: writes remain the signature of the (unauthorised)
write attack, so the benign baseline must never write.

Runs from a NON-attacker container, so build_features labels its windows 'benign'.

Usage (inside a container):  python3 benign_poller.py [host] [port] [period_s]
    defaults: openplc 502 0.6   (~4 requests / 0.6 s -> ~7 msg/s, ~20 per 3 s window,
    four distinct function codes -- matching real SCADA polling density)
"""
import sys, time
from pymodbus.client import ModbusTcpClient

HOST   = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 502
PERIOD = float(sys.argv[3]) if len(sys.argv) > 3 else 0.6

# a realistic HMI reads a handful of blocks across the four read function codes
BLOCKS = [
    ("read_coils", 0, 8),               # FC 0x01
    ("read_discrete_inputs", 0, 8),     # FC 0x02
    ("read_holding_registers", 0, 10),  # FC 0x03  (temp/pressure/flow/level + spares)
    ("read_input_registers", 0, 8),     # FC 0x04
]


def poll_once(c):
    for name, addr, count in BLOCKS:
        fn = getattr(c, name, None)
        if fn is None:
            continue
        try:
            fn(addr, count=count)
        except TypeError:
            try:
                fn(addr, count)          # older pymodbus positional signature
            except Exception:
                pass
        except Exception:
            pass


print(f"[*] realistic benign SCADA poller -> {HOST}:{PORT}  "
      f"({len(BLOCKS)} function codes every {PERIOD}s, read-only)")
while True:
    c = ModbusTcpClient(HOST, port=PORT)
    if not c.connect():
        time.sleep(2); continue
    try:
        while True:
            poll_once(c)
            time.sleep(PERIOD)
    except Exception:
        try: c.close()
        except Exception: pass
        time.sleep(2)                     # reconnect on any hiccup
