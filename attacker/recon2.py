#!/usr/bin/env python3
"""
Reconnaissance -- VARIANT implementation (for generalisation testing).

Different code from the nmap-based recon: a hand-written TCP port scanner that
connects to a range of ports on the target and records which are open. Same recon
behaviour (many short connections across many ports), completely different tool.

Usage:  python3 recon2.py [host] [start_port] [end_port]
        defaults: openplc 1 2000
"""
import sys, socket

HOST = sys.argv[1] if len(sys.argv) > 1 else "openplc"
START = int(sys.argv[2]) if len(sys.argv) > 2 else 1
END = int(sys.argv[3]) if len(sys.argv) > 3 else 2000

ip = socket.gethostbyname(HOST)
print(f"[*] VARIANT recon: scanning {HOST} ({ip}) ports {START}-{END} ...")
open_ports = []
for p in range(START, END + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        if s.connect_ex((ip, p)) == 0:
            open_ports.append(p)
    except Exception:
        pass
    finally:
        s.close()
print(f"[*] open ports found: {open_ports}")
print("[*] Done -- variant recon complete.")
