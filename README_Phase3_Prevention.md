# Phase 3 — Prevention (IDS → IPS)

The detector now *acts*. When it confirms an attacker, it blocks that source at
the PLC — the testbed realization of an SDN flow-rule / industrial-firewall
action (see the roadmap for the standards discussion). Detection is Phase 1–2;
this adds automated response, built to the availability-first doctrine of
NIST SP 800-82 / IEC 62443.

## Pieces

| Part | File | Role |
|------|------|------|
| Enforcement helper | `scripts/ipsblock.sh` | add/remove an iptables DROP for a source IP in openplc's netns; refuses allowlisted IPs |
| IPS loop | `ml/prevent.py` | detect with the multi-label model, confirm, block, auto-expire, unblock-all on exit |

## The four safeguards (this is where the rigor is)

1. **Allowlist** — the PLC, SCADA (FUXA) and gateway (Node-RED) container IPs are
   resolved at startup and can *never* be blocked. `ipsblock.sh` refuses them too
   (defense in depth).
2. **Confirmation** — a source must be flagged attack in `--confirm` *consecutive*
   completed windows (default 2) before it is blocked. One false window cannot cut
   off traffic.
3. **Auto-expiry** — every block is lifted after `--ttl` seconds (default 60).
4. **Clean exit** — Ctrl+C removes every block the process added, leaving the
   testbed normal.

## Run the demo

Prereqs: multi-label model trained, live capture up (`scripts/live-env.sh up`),
attacker container running.

**Safe first pass — dry run** (logs what it *would* block, touches nothing):

```bash
IIOT_CAP_DIR=/home/user/iiot-live python3 ml/prevent.py --dry-run --confirm 2 --ttl 60
```

**Live enforcement:**

```bash
IIOT_CAP_DIR=/home/user/iiot-live python3 ml/prevent.py --confirm 2 --ttl 60
```

In another terminal, run the bots (`scripts/attack-bots.sh`). You'll see:

```
>> attack from 172.19.0.8: flood+write  (strike 1/2)
>> attack from 172.19.0.8: flood+write  (strike 2/2)
[BLOCK] 172.19.0.8 -> iptables DROP on openplc, expires in 60s
...
[UNBLOCK] 172.19.0.8 (ttl expired)
```

**Prove the block actually stops the attack.** While `172.19.0.8` is blocked, its
Modbus writes can't reach the PLC:

```bash
docker exec kali python3 /modbus_write.py openplc 502     # times out / can't connect while blocked
bash scripts/ipsblock.sh list                              # shows the active DROP rule
```

## Honest caveat (state this in the review)

`zeek-live` taps the interface on RX **before** netfilter, so after a block you
still *see* the blocked host's connection attempts in the logs — libpcap captures
them before the kernel drops them. What the block stops is **delivery to OpenPLC**:
the malicious Modbus requests never reach the PLC application, so the attack is
neutralised even though the attacker keeps trying (its attempts now show up as
failed/half-open connections). Blocking at a bridge/SDN layer instead of the PLC's
INPUT chain would also remove them from capture — a documented design option.

## Safety

- Everything is local (containers on a bridge, host ports bound to 127.0.0.1).
- Blocks are host-scoped iptables rules in openplc's netns and are always removed
  on exit or by TTL; `bash scripts/ipsblock.sh flush` clears any that remain.
- `--dry-run` lets you validate the trigger logic before enabling enforcement.
