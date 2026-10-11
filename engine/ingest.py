"""
One streaming pass over the raw log -> on-disk store (SQLite). O(n) time, bounded memory.

The file is cut into byte ranges at line boundaries (CHUNK_MB each). Worker processes read one range each, so the
whole log is never in memory: per line they parse the timestamp, build the message template, collect the MAC
addresses (postings: which block of 2048 lines mentions which MAC / template) and run the typed-event rules
chosen once per template. The parent merges the ranges in file order, gives every line its global number and
writes everything in batches. Finally rollups (per minute), sessions and graph edges are derived from the event
table with single SQL / streaming passes.

    python -m engine.ingest input_logs/big.log --test-id BIG      (or tools/ingest_logs.py)
"""
from __future__ import annotations

import json
import os
import zlib
from array import array
import sqlite3
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import ENGINE_VERSION  # noqa: E402
from engine import rules as R  # noqa: E402
from engine import textnorm as T  # noqa: E402

BLOCK = 2048                    # lines per random-access block
CHUNK_MB = int(os.environ.get("ENGINE_CHUNK_MB", "32"))
BUCKET = 60                     # seconds per rollup bucket
STORE_DIR = Path(__file__).resolve().parent.parent / "output" / "store"

SCHEMA = """
PRAGMA page_size=8192;
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE blocks(block INTEGER PRIMARY KEY, first_line INTEGER, byte_off INTEGER, byte_len INTEGER, n_lines INTEGER,
                    first_ts REAL, last_ts REAL, chunk INTEGER);
CREATE TABLE block_tpl(block INTEGER PRIMARY KEY, data BLOB);
CREATE TABLE chunk_tpl(chunk INTEGER, local INTEGER, tpl INTEGER, PRIMARY KEY(chunk, local)) WITHOUT ROWID;
CREATE TABLE templates(id INTEGER PRIMARY KEY, text TEXT, low TEXT, n INTEGER, first_line INTEGER, last_line INTEGER,
                       example TEXT, rules TEXT);
CREATE TABLE tpl_blocks(tpl INTEGER, block INTEGER, n INTEGER, PRIMARY KEY(tpl, block)) WITHOUT ROWID;
CREATE TABLE mac_blocks(mac TEXT, block INTEGER, n INTEGER, PRIMARY KEY(mac, block)) WITHOUT ROWID;
CREATE TABLE macs(mac TEXT PRIMARY KEY, n INTEGER, first_line INTEGER, last_line INTEGER) WITHOUT ROWID;
CREATE TABLE ent_tpl(mac TEXT, tpl INTEGER, n INTEGER, first_line INTEGER, last_line INTEGER,
                     PRIMARY KEY(mac, tpl)) WITHOUT ROWID;
CREATE TABLE events(line INTEGER PRIMARY KEY, ts REAL, hms TEXT, type TEXT, mac TEXT, peer TEXT, iface TEXT,
                    reason INTEGER, status INTEGER, detail TEXT, tpl INTEGER, seq INTEGER DEFAULT 0);
CREATE TABLE events_extra(line INTEGER, ts REAL, hms TEXT, type TEXT, mac TEXT, peer TEXT, iface TEXT,
                    reason INTEGER, status INTEGER, detail TEXT, tpl INTEGER);
CREATE TABLE attrs(line INTEGER, ts REAL, entity TEXT, key TEXT, value TEXT);
CREATE TABLE metrics(bucket INTEGER, entity TEXT, key TEXT, n INTEGER, mn REAL, mx REAL, sm REAL, first_line INTEGER,
                     PRIMARY KEY(bucket, entity, key)) WITHOUT ROWID;
CREATE TABLE tpl_roll(bucket INTEGER, tpl INTEGER, n INTEGER, first_line INTEGER, last_line INTEGER,
                      PRIMARY KEY(bucket, tpl)) WITHOUT ROWID;
"""
FINAL_SQL = """
CREATE INDEX ev_mac ON events(mac, line);
CREATE INDEX ev_type ON events(type, line);
CREATE INDEX ev_ts ON events(ts);
CREATE INDEX ev_iface ON events(iface, line);
CREATE INDEX ex_line ON events_extra(line);
CREATE INDEX ex_mac ON events_extra(mac, line);
CREATE INDEX at_ent ON attrs(entity, key, line);
CREATE INDEX at_key ON attrs(key, value);
CREATE INDEX et_tpl ON ent_tpl(tpl);
CREATE INDEX blk_first ON blocks(first_line);
CREATE TABLE rollup AS
  SELECT CAST(ts / 60 AS INTEGER) AS bucket, COALESCE(mac, iface, '*') AS entity, type, COUNT(*) AS n,
         MIN(line) AS first_line, MAX(line) AS last_line FROM all_events WHERE ts IS NOT NULL GROUP BY 1, 2, 3;
CREATE INDEX ru_ent ON rollup(entity, bucket);
CREATE INDEX ru_type ON rollup(type, bucket);
CREATE TABLE edges AS
  SELECT mac AS src, type AS rel, COALESCE(peer, iface, 'AP') AS dst, COUNT(*) AS n, MIN(line) AS first_line,
         MAX(line) AS last_line, MIN(ts) AS first_ts, MAX(ts) AS last_ts
  FROM all_events WHERE mac IS NOT NULL GROUP BY 1, 2, 3;
CREATE INDEX ed_src ON edges(src);
CREATE INDEX ed_dst ON edges(dst);
"""


def chunk_ranges(path: Path, chunk_bytes: int) -> list[tuple[int, int]]:
    size = path.stat().st_size
    out, start = [], 0
    with path.open("rb") as f:
        while start < size:
            end = min(size, start + chunk_bytes)
            if end < size:
                f.seek(end)
                f.readline()           # move to the next line boundary
                end = f.tell()
            out.append((start, end))
            start = end
    return out


def process_chunk(args):
    """Worker: one byte range -> local results (line numbers relative to the range)."""
    path, start, end, year = args[:4]
    with open(path, "rb") as f:
        f.seek(start)
        raw = f.read(end - start)
    lines = raw.splitlines(keepends=True)     # \r\n, \n and a lone \r end a line (like text editors)
    tpl: dict = {}
    mac: dict = {}
    ent_tpl: dict = {}
    metrics: dict = {}
    troll: dict = {}
    blocks = []
    ctx = R.Ctx()
    btpl = []                    # per block: the template id of every line (zlib-compressed uint32 array)
    prefixes = set()             # shapes of the text before the message (timestamp, facility) - not in templates
    cur = array("I")
    last_ep, last_hms = None, None
    off = start
    last_attr = {}
    attrs_out = []
    b_first_ep = b_last_ep = None
    b_off, b_first = start, 0
    ts_lines = 0
    first_ep = None
    mac_rx_findall = T.MAC_RX.findall
    template, parse_prefix, body_of = T.template, T.parse_prefix, T.body_of
    for i, lb in enumerate(lines):
        if i - b_first == BLOCK:
            blocks.append((b_first, b_off, off - b_off, BLOCK, b_first_ep, b_last_ep))
            btpl.append(zlib.compress(cur.tobytes(), 1))
            cur = array("I")
            b_first, b_off, b_first_ep, b_last_ep = i, off, None, None
        off += len(lb)
        lb = lb.rstrip(b"\r\n")
        if not lb:
            cur.append(0)
            continue
        s = lb.decode("utf-8", "replace")
        if "\x1b" in s:
            s = T.ANSI_RX.sub("", s)
        if s.endswith("\r"):
            s = s[:-1]
        ep, hms, st = parse_prefix(s, year)
        if ep is not None:
            last_ep, last_hms = ep, hms
            ts_lines += 1
            if first_ep is None:
                first_ep = ep
            if b_first_ep is None:
                b_first_ep = ep
            b_last_ep = ep
        body = body_of(s, st)
        if len(prefixes) < 400:
            pre = s[:len(s) - len(body)]
            if pre:
                prefixes.add(T.NUM_RX.sub("#", pre).lower())
        key = template(body)
        info = tpl.get(key)
        blk = i // BLOCK
        if info is None:
            low_t = key.lower()
            info = tpl[key] = [0, i, i, {}, s[:300], R.rules_for_template(low_t), "<M>" in key,
                               ("sta=" in low_t or "wpa: " in low_t), len(tpl) + 1]
        cur.append(info[8])
        info[0] += 1
        info[2] = i
        bd = info[3]
        bd[blk] = bd.get(blk, 0) + 1
        if last_ep is not None:
            bk = (int(last_ep // BUCKET), key)
            tr = troll.get(bk)
            if tr is None:
                troll[bk] = [1, i, i]
            else:
                tr[0] += 1
                tr[2] = i
        if info[6]:
            for m in set(mac_rx_findall(s)):
                m = m.upper()
                d = mac.get(m)
                if d is None:
                    d = mac[m] = [0, i, i, {}]
                d[0] += 1
                d[2] = i
                d[3][blk] = d[3].get(blk, 0) + 1
                ek = (m, key)
                e = ent_tpl.get(ek)
                if e is None:
                    ent_tpl[ek] = [1, i, i]
                else:
                    e[0] += 1
                    e[2] = i
            if info[7]:
                sm = R.STA_RX.search(s) or R.CONTEXT_STA_RX.search(s)
                if sm:
                    ctx.last_sta, ctx.last_sta_line = sm.group(1).upper(), i
        if info[5]:
            low = s.lower()
            ctx.line, ctx.ep, ctx.hms, ctx.tpl = i, last_ep, last_hms, key
            na = len(ctx.attrs)
            iface = R.iface_of(body)
            for fn in info[5]:
                fn(s, low, body, iface, ctx)
            if len(ctx.attrs) > na:
                for a in ctx.attrs[na:]:
                    _, aep, ent, k, v = a
                    if k == "signal":
                        try:
                            x = float(v)
                        except ValueError:
                            continue
                        mk = (int((aep or 0) // BUCKET), ent, k)
                        mm = metrics.get(mk)
                        if mm is None:
                            metrics[mk] = [1, x, x, x, i]
                        else:
                            mm[0] += 1
                            mm[1] = min(mm[1], x)
                            mm[2] = max(mm[2], x)
                            mm[3] += x
                    elif last_attr.get((ent, k)) != v:
                        last_attr[(ent, k)] = v
                        attrs_out.append(a)
                del ctx.attrs[na:]
    n = len(lines)
    if n > b_first:
        blocks.append((b_first, b_off, off - b_off, n - b_first, b_first_ep, b_last_ep))
        btpl.append(zlib.compress(cur.tobytes(), 1))
    return {"start": start, "n_lines": n, "blocks": blocks, "btpl": btpl, "prefixes": prefixes, "tpl": tpl, "mac": mac, "ent_tpl": ent_tpl,
            "events": ctx.events, "attrs": attrs_out, "metrics": metrics, "troll": troll, "ts_lines": ts_lines,
            "first_ep": first_ep, "last_ep": last_ep}


def _connect(db: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(db))
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("PRAGMA temp_store=MEMORY")
    con.execute("PRAGMA cache_size=-65536")
    return con


def ingest(path: str | Path, test_id: str, out_dir: Path | None = None, workers: int | None = None,
           year: int | None = None, progress=None, chunk_bytes: int | None = None) -> Path:
    path = Path(path)
    out_dir = Path(out_dir or STORE_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    db = out_dir / f"{test_id}.sqlite"
    tmp = db.with_suffix(".building")
    if tmp.exists():
        tmp.unlink()
    t0 = time.time()
    st = path.stat()
    year = year or time.gmtime(st.st_mtime).tm_year
    ranges = chunk_ranges(path, chunk_bytes or CHUNK_MB * 1024 * 1024)
    workers = workers or max(1, min(len(ranges), (os.cpu_count() or 2), int(os.environ.get("ENGINE_WORKERS", "8"))))
    con = _connect(tmp)
    con.executescript(SCHEMA)
    tid_of: dict = {}
    tstat: dict = {}
    macs: dict = {}
    ent_tpl: dict = {}
    metrics: dict = {}
    troll: dict = {}
    base_line = base_block = 0
    chunk_no = 0
    prefixes: set = set()
    n_events = 0
    first_ep = last_ep = None
    ts_lines = 0

    def gid(key, info):
        g = tid_of.get(key)
        if g is None:
            g = tid_of[key] = len(tid_of) + 1
            tstat[g] = [key, 0, None, None, info[4], ",".join(f.__name__[2:] for f in info[5])]
        return g

    args = [(str(path), a, b, year) for a, b in ranges]
    done_bytes = 0

    def ordered_results(pool):
        """Results in file order with at most 2 x workers ranges in flight (bounded memory)."""
        from collections import deque
        q = deque()
        it = iter(args)
        for a in it:
            q.append(pool.submit(process_chunk, a))
            if len(q) >= 2 * workers:
                break
        while q:
            res = q.popleft().result()
            nxt = next(it, None)
            if nxt is not None:
                q.append(pool.submit(process_chunk, nxt))
            yield res

    def inline_results():
        for a in args:
            yield process_chunk(a)

    pool = ProcessPoolExecutor(max_workers=workers) if len(args) > 1 and workers > 1 else None
    try:
        for res in (ordered_results(pool) if pool else inline_results()):
            # ---- templates and their block postings
            lmap = {}
            tb_rows = []
            for key, info in res["tpl"].items():
                g = gid(key, info)
                lmap[key] = g
                ts_ = tstat[g]
                ts_[1] += info[0]
                if ts_[2] is None:
                    ts_[2] = base_line + info[1] + 1
                ts_[3] = base_line + info[2] + 1
                tb_rows.extend((g, base_block + b, c) for b, c in info[3].items())
            con.executemany("INSERT INTO tpl_blocks VALUES (?,?,?)", tb_rows)
            mb_rows = []
            for m, (n, f, l, bd) in res["mac"].items():
                d = macs.get(m)
                if d is None:
                    macs[m] = [n, base_line + f + 1, base_line + l + 1]
                else:
                    d[0] += n
                    d[2] = base_line + l + 1
                mb_rows.extend((m, base_block + b, c) for b, c in bd.items())
            con.executemany("INSERT INTO mac_blocks VALUES (?,?,?)", mb_rows)
            for (m, key), (n, f, l) in res["ent_tpl"].items():
                k = (m, lmap[key])
                e = ent_tpl.get(k)
                if e is None:
                    ent_tpl[k] = [n, base_line + f + 1, base_line + l + 1]
                else:
                    e[0] += n
                    e[2] = base_line + l + 1
            for k, v in res["metrics"].items():
                mm = metrics.get(k)
                if mm is None:
                    metrics[k] = [v[0], v[1], v[2], v[3], base_line + v[4] + 1]
                else:
                    mm[0] += v[0]
                    mm[1] = min(mm[1], v[1])
                    mm[2] = max(mm[2], v[2])
                    mm[3] += v[3]
            for (bk, key), (n, f, l) in res["troll"].items():
                k = (bk, lmap[key])
                tr = troll.get(k)
                if tr is None:
                    troll[k] = [n, base_line + f + 1, base_line + l + 1]
                else:
                    tr[0] += n
                    tr[2] = base_line + l + 1
            # ---- events: one row per line in `events`, further events of the same line in `events_extra`
            rows, extra, seen = [], [], set()
            for (ln, ep, hms, typ, m, peer, iface, reason, status, detail, key) in res["events"]:
                gl = base_line + ln + 1
                row = (gl, ep, hms, typ, m, peer, iface, reason, status, detail, lmap.get(key))
                if gl in seen:
                    extra.append(row)
                else:
                    seen.add(gl)
                    rows.append(row)
            con.executemany("INSERT INTO events(line, ts, hms, type, mac, peer, iface, reason, status, detail, tpl) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            if extra:
                con.executemany("INSERT INTO events_extra VALUES (?,?,?,?,?,?,?,?,?,?,?)", extra)
            n_events += len(rows) + len(extra)
            con.executemany("INSERT INTO attrs VALUES (?,?,?,?,?)",
                            [(base_line + ln + 1, ep, e, k, v) for (ln, ep, e, k, v) in res["attrs"]])
            con.executemany("INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?)",
                            [(base_block + j, base_line + bf + 1, bo, bl, bn, e0, e1, chunk_no)
                             for j, (bf, bo, bl, bn, e0, e1) in enumerate(res["blocks"])])
            con.executemany("INSERT INTO block_tpl VALUES (?,?)",
                            [(base_block + j, d) for j, d in enumerate(res["btpl"])])
            con.executemany("INSERT INTO chunk_tpl VALUES (?,?,?)",
                            [(chunk_no, info[8], lmap[key]) for key, info in res["tpl"].items()])
            chunk_no += 1
            if len(prefixes) < 2000:
                prefixes |= res["prefixes"]
            base_block += len(res["blocks"])
            base_line += res["n_lines"]
            ts_lines += res["ts_lines"]
            if res["first_ep"] is not None and first_ep is None:
                first_ep = res["first_ep"]
            if res["last_ep"] is not None:
                last_ep = res["last_ep"]
            done_bytes = res["start"] + sum(b[2] for b in res["blocks"])
            if progress:
                progress(done_bytes, st.st_size, base_line)
    finally:
        if pool:
            pool.shutdown()
    # ---- dimension tables
    con.executemany("INSERT INTO templates VALUES (?,?,?,?,?,?,?,?)",
                    [(g, k, k.lower(), n, f, l, ex, rl) for g, (k, n, f, l, ex, rl) in tstat.items()])
    con.executemany("INSERT INTO macs VALUES (?,?,?,?)", [(m, *v) for m, v in macs.items()])
    con.executemany("INSERT INTO ent_tpl VALUES (?,?,?,?,?)", [(m, g, *v) for (m, g), v in ent_tpl.items()])
    con.executemany("INSERT INTO metrics VALUES (?,?,?,?,?,?,?,?)", [(*k, *v) for k, v in metrics.items()])
    con.executemany("INSERT INTO tpl_roll VALUES (?,?,?,?,?)", [(*k, *v) for k, v in troll.items()])
    con.execute("CREATE VIEW all_events AS SELECT line, ts, hms, type, mac, peer, iface, reason, status, detail, tpl "
                "FROM events UNION ALL SELECT * FROM events_extra")
    con.executescript(FINAL_SQL)
    build_sessions(con)
    elapsed = time.time() - t0
    meta = {"engine_version": ENGINE_VERSION, "test_id": test_id, "source": str(path), "source_size": st.st_size,
            "source_mtime": int(st.st_mtime), "total_lines": base_line, "lines_with_timestamp": ts_lines,
            "blocks": base_block, "block_lines": BLOCK, "chunks": len(ranges), "workers": workers,
            "templates": len(tid_of), "macs": len(macs), "events": n_events, "first_ts": first_ep, "last_ts": last_ep,
            "bucket_s": BUCKET, "ingest_seconds": round(elapsed, 2), "year": year,
            "coverage": f"all {base_line} lines in {len(ranges)} byte ranges were read (100%)",
            "prefix_shapes": sorted(prefixes)[:2000]}
    con.executemany("INSERT INTO meta VALUES (?,?)", [(k, json.dumps(v)) for k, v in meta.items()])
    con.commit()
    con.execute("ANALYZE")
    con.close()
    if db.exists():
        db.unlink()
    tmp.replace(db)
    return db


CAUSE = {"deauth_rx": "station_left", "disassoc_rx": "station_left", "unprot": "station_left",
         "missing_acks": "dut_kickout", "inactivity": "dut_kickout", "deauth_local": "dut_kickout",
         "disconnect_req": "dut_kickout", "deauth_tx": "dut_kickout", "disassoc_tx": "dut_kickout",
         "fourway_fail": "handshake_failed", "disconnected": "unknown", "silent": "silent_reconnect", "open": "open"}
TEARDOWN = ("ap_disabled", "iface_removed", "bss_terminating")


def build_sessions(con: sqlite3.Connection):
    """Per client: AP-STA-CONNECTED -> the first disconnect-class event before the next connection. One ordered
    pass over the client's events (index ev_mac), linear in the number of events. A session that ends within
    10 s after an AP teardown (AP-DISABLED / interface removed / BSS terminating) is attributed to the restart."""
    import bisect
    con.execute("CREATE TABLE sessions(client TEXT, iface TEXT, start_line INTEGER, start_ts REAL, start_hms TEXT, "
                "end_line INTEGER, end_ts REAL, end_hms TEXT, end_type TEXT, reason INTEGER, end_detail TEXT, "
                "cause TEXT, restart_line INTEGER)")
    td = con.execute("SELECT ts, line FROM all_events WHERE type IN (?,?,?) AND ts IS NOT NULL ORDER BY ts",
                     TEARDOWN).fetchall()
    td_ts = [t for t, _ in td]
    caps = [r[0] for r in con.execute("SELECT line FROM all_events WHERE type = 'capture' ORDER BY line")]
    disc = R.DISCONNECT_TYPES
    rows = []

    def close(p, e):
        if e is not None and caps:
            j = bisect.bisect_right(caps, p[2])
            if j < len(caps) and caps[j] < e[0]:     # a new console capture started before the end was logged
                e = None
        if e is None:
            e = (None, None, None, "open", None, None)
        cause, rl = CAUSE.get(e[3], "unknown"), None
        if e[1] is not None and e[3] != "open":
            j = bisect.bisect_right(td_ts, e[1]) - 1
            if j >= 0 and e[1] - td_ts[j] <= 10 and td_ts[j] >= (p[3] or 0):
                cause, rl = "ap_restart", td[j][1]
        rows.append((p[0], p[1], p[2], p[3], p[4], e[0], e[1], e[2], e[3], e[4], e[5], cause, rl))

    cur = pend = end_ev = None
    q = ("SELECT mac, line, ts, hms, type, iface, reason, detail FROM all_events WHERE mac IS NOT NULL "
         "AND (type = 'connected' OR type IN (%s)) ORDER BY mac, line" % ",".join("?" * len(disc)))
    for mac, line, ts, hms, typ, iface, reason, detail in con.execute(q, sorted(disc)):
        if mac != cur:
            if pend:
                close(pend, end_ev)
            cur, pend, end_ev = mac, None, None
        if typ == "connected":
            if pend:
                close(pend, end_ev or (line, ts, hms, "silent", None, "connected again without a logged disconnect"))
            pend, end_ev = (mac, iface, line, ts, hms), None
        elif pend and end_ev is None:
            end_ev = (line, ts, hms, typ, reason, detail)
        elif pend and end_ev and reason is not None and end_ev[4] is None and line - end_ev[0] <= 40:
            end_ev = (end_ev[0], end_ev[1], end_ev[2], end_ev[3], reason, end_ev[5])
        if len(rows) > 50000:
            con.executemany("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            rows.clear()
    if pend:
        close(pend, end_ev)
    con.executemany("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.execute("CREATE INDEX se_client ON sessions(client, start_line)")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--test-id", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--workers", type=int, default=None)
    a = ap.parse_args()

    def prog(done, total, lines):
        print(f"\r  {done / max(total, 1) * 100:5.1f}%  {lines:,} lines", end="", flush=True)
    db = ingest(a.path, a.test_id, Path(a.out) if a.out else None, a.workers, progress=prog)
    print(f"\n  store: {db}")


if __name__ == "__main__":
    main()
