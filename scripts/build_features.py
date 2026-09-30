#!/usr/bin/env python3
"""
Task 4 -- Formalized feature extraction (windowed).

Turns the raw Zeek logs of every capture session into ONE machine-learning
feature table: each row = a fixed time window of traffic from one source host,
described by BOTH connection/flow features (from conn.log) and Modbus
application-layer features (from modbus.log), with a class label.

Why windows: a real-time IDS decides on a rolling window of traffic, not on a
single packet or a whole connection. Windowing also fixes the raw class
imbalance (a 20 s flood = one giant connection but ~20 one-second windows;
a 0.1 s port scan = thousands of connections but ~1 window with a huge
connection count) -- the model learns *rates and mixes*, not raw volume.

Label rule: a window is labeled with the session's attack type IF the source
host is the attacker; otherwise "benign" (legitimate SCADA<->PLC traffic seen
in the same session). Run-number suffixes collapse (flood-03 -> flood).

MITM note: MITM's signal is at the ARP/L2 layer, which is NOT in conn.log or
modbus.log. mitm* sessions are therefore EXCLUDED here and analysed separately
from the pcap (arp.opcode==2). This is a documented finding, not an omission.

Usage:
    python3 scripts/build_features.py [window_seconds]     # default 1.0
    IIOT_CAP_DIR=~/iiot-captures ATTACKER_IP=172.18.0.8 python3 scripts/build_features.py
Output:
    $IIOT_CAP_DIR/features_windows.csv
"""
import csv, os, sys, glob, math
from collections import defaultdict, Counter

CAP   = os.environ.get("IIOT_CAP_DIR", os.path.expanduser("~/iiot-captures"))
ATTACKER = os.environ.get("ATTACKER_IP", "172.18.0.8")
W     = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0
OUT   = os.path.join(CAP, "features_windows.csv")

READ_FUNCS  = ("READ",)          # func-name substrings -> read
WRITE_FUNCS = ("WRITE",)         # func-name substrings -> write


def read_zeek(path):
    if not os.path.exists(path):
        return
    fields = None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not line:
                continue
            elif fields:
                yield dict(zip(fields, line.split("\t")))


def num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def base_label(sess):
    import re
    return re.sub(r"[-_]\d+$", "", sess)


def entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    h = 0.0
    for c in counter.values():
        p = c / total
        h -= p * math.log2(p)
    return h


# window key = (session, orig_h, window_index).  Store raw aggregates first.
conn_agg = defaultdict(lambda: {
    "n": 0, "dports": set(), "dsts": set(), "opkts": 0.0, "rpkts": 0.0,
    "obytes": 0.0, "rbytes": 0.0, "dur": [], "rej": 0, "s0": 0, "sf": 0})
mb_agg = defaultdict(lambda: {
    "n": 0, "req": 0, "read": 0, "write": 0, "other": 0,
    "func": Counter(), "tid": set(), "unit": set(), "exc": 0})
# register-address coverage per window (from modbus_addr.log, produced by
# zeek/modbus-memmap.zeek). Separates an address-sweeping read enumeration
# (many distinct addresses) from benign polling (a few fixed ones).
addr_agg = defaultdict(lambda: {"addrs": set(), "amin": None, "amax": None})
win_meta = {}   # key -> (session, orig_h, label, t_start)

sessions = sorted(glob.glob(os.path.join(CAP, "sessions", "*")))
# include the passive benign baseline capture if present
if os.path.isdir(os.path.join(CAP, "live")):
    sessions.append(os.path.join(CAP, "live"))

t0_by_session = {}


def session_t0(sess_dir, sess):
    """earliest ts across both logs, to anchor window bins per session"""
    if sess in t0_by_session:
        return t0_by_session[sess]
    t0 = None
    for log in ("conn.log", "modbus.log"):
        for r in read_zeek(os.path.join(sess_dir, log)):
            t = num(r.get("ts"))
            if t and (t0 is None or t < t0):
                t0 = t
    t0_by_session[sess] = t0 or 0.0
    return t0_by_session[sess]


for d in sessions:
    sess = os.path.basename(d)
    if sess.startswith("mitm"):
        continue                       # ARP-layer attack -> analysed separately
    t0 = session_t0(d, sess)

    for r in read_zeek(os.path.join(d, "conn.log")):
        oh = r.get("id.orig_h", "")
        ts = num(r.get("ts"))
        wi = int((ts - t0) // W)
        key = (sess, oh, wi)
        lab = base_label(sess) if oh == ATTACKER else "benign"
        win_meta.setdefault(key, (sess, oh, lab, t0 + wi * W))
        a = conn_agg[key]
        a["n"] += 1
        a["dports"].add(r.get("id.resp_p", ""))
        a["dsts"].add(r.get("id.resp_h", ""))
        a["opkts"]  += num(r.get("orig_pkts"))
        a["rpkts"]  += num(r.get("resp_pkts"))
        a["obytes"] += num(r.get("orig_ip_bytes"))
        a["rbytes"] += num(r.get("resp_ip_bytes"))
        dur = num(r.get("duration"))
        if dur:
            a["dur"].append(dur)
        st = r.get("conn_state", "")
        if st == "REJ":
            a["rej"] += 1
        elif st == "S0":
            a["s0"] += 1
        elif st == "SF":
            a["sf"] += 1

    for r in read_zeek(os.path.join(d, "modbus.log")):
        oh = r.get("id.orig_h", "")
        ts = num(r.get("ts"))
        wi = int((ts - t0) // W)
        key = (sess, oh, wi)
        lab = base_label(sess) if oh == ATTACKER else "benign"
        win_meta.setdefault(key, (sess, oh, lab, t0 + wi * W))
        m = mb_agg[key]
        m["n"] += 1
        func = (r.get("func") or "").upper()
        pdu  = (r.get("pdu_type") or r.get("request_response") or "").lower()
        if pdu == "request" or pdu == "":
            m["req"] += 1
        if any(s in func for s in READ_FUNCS):
            m["read"] += 1
        elif any(s in func for s in WRITE_FUNCS):
            m["write"] += 1
        else:
            m["other"] += 1
        m["func"][func] += 1
        m["tid"].add(r.get("tid", ""))
        m["unit"].add(r.get("unit", ""))
        exc = (r.get("exception") or "").upper()
        if exc and exc not in ("-", "NONE", ""):
            m["exc"] += 1

    # register-address coverage (optional log from zeek/modbus-memmap.zeek)
    for r in read_zeek(os.path.join(d, "addr", "modbus_addr.log")):
        oh = r.get("orig_h", "")
        ts = num(r.get("ts"))
        wi = int((ts - t0) // W)
        key = (sess, oh, wi)
        lab = base_label(sess) if oh == ATTACKER else "benign"
        win_meta.setdefault(key, (sess, oh, lab, t0 + wi * W))
        try:
            adv = int(float(r.get("address")))
        except (TypeError, ValueError):
            continue
        a = addr_agg[key]
        a["addrs"].add(adv)
        a["amin"] = adv if a["amin"] is None else min(a["amin"], adv)
        a["amax"] = adv if a["amax"] is None else max(a["amax"], adv)

cols = ["session", "orig_h", "window", "t_start", "label",
        "cn_n_conns", "cn_uniq_dport", "cn_uniq_dst", "cn_orig_pkts",
        "cn_resp_pkts", "cn_orig_bytes", "cn_resp_bytes", "cn_dur_mean",
        "cn_dur_max", "cn_rej", "cn_s0", "cn_sf", "cn_rej_ratio",
        "cn_conn_rate",
        "mb_n", "mb_req", "mb_read", "mb_write", "mb_other", "mb_uniq_func",
        "mb_func_entropy", "mb_uniq_tid", "mb_uniq_unit", "mb_exc",
        "mb_write_ratio", "mb_rate", "mb_uniq_addr", "mb_addr_span"]

rows = []
for key in sorted(win_meta):
    sess, oh, lab, t_start = win_meta[key]
    c = conn_agg.get(key)
    m = mb_agg.get(key)
    row = {"session": sess, "orig_h": oh, "window": key[2],
           "t_start": f"{t_start:.3f}", "label": lab}
    if c:
        dur = c["dur"]
        row.update({
            "cn_n_conns": c["n"],
            "cn_uniq_dport": len(c["dports"]),
            "cn_uniq_dst": len(c["dsts"]),
            "cn_orig_pkts": int(c["opkts"]),
            "cn_resp_pkts": int(c["rpkts"]),
            "cn_orig_bytes": int(c["obytes"]),
            "cn_resp_bytes": int(c["rbytes"]),
            "cn_dur_mean": round(sum(dur) / len(dur), 4) if dur else 0,
            "cn_dur_max": round(max(dur), 4) if dur else 0,
            "cn_rej": c["rej"], "cn_s0": c["s0"], "cn_sf": c["sf"],
            "cn_rej_ratio": round(c["rej"] / c["n"], 4) if c["n"] else 0,
            "cn_conn_rate": round(c["n"] / W, 2),
        })
    else:
        for k in cols[5:19]:
            row[k] = 0
    if m:
        rw = m["read"] + m["write"]
        row.update({
            "mb_n": m["n"], "mb_req": m["req"], "mb_read": m["read"],
            "mb_write": m["write"], "mb_other": m["other"],
            "mb_uniq_func": len(m["func"]),
            "mb_func_entropy": round(entropy(m["func"]), 4),
            "mb_uniq_tid": len(m["tid"]), "mb_uniq_unit": len(m["unit"]),
            "mb_exc": m["exc"],
            "mb_write_ratio": round(m["write"] / rw, 4) if rw else 0,
            "mb_rate": round(m["n"] / W, 2),
        })
    else:
        for k in cols[19:]:
            row[k] = 0
    ad = addr_agg.get(key)
    if ad and ad["addrs"]:
        row["mb_uniq_addr"] = len(ad["addrs"])
        row["mb_addr_span"] = ad["amax"] - ad["amin"]
    else:
        row["mb_uniq_addr"] = 0
        row["mb_addr_span"] = 0
    rows.append(row)

with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

dist = Counter(r["label"] for r in rows)
print(f"[*] window = {W}s   attacker = {ATTACKER}")
print(f"[*] {OUT}")
print(f"[*] {len(rows)} feature windows  |  {len(cols)} columns")
print(f"[*] class balance: {dict(sorted(dist.items(), key=lambda x: -x[1]))}")
