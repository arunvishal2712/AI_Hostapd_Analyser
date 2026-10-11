"""
The on-disk store of one log (output/store/<TEST_ID>.sqlite) and random access to the raw log.

Raw lines are never copied into the store: the store keeps the byte offset of every block of 2048 lines, so any
line is one seek + one small read away. `StoreIndex` gives the legacy analysis code the same interface as the old
in-memory LogIndex (lines[i], low[i], candidates(needles)) without loading the file: candidates() first selects the
message templates that can contain the needle, then reads only the blocks those templates occur in.
"""
from __future__ import annotations

import bisect
import json
import re
import sqlite3
import threading
from collections import OrderedDict
from pathlib import Path

from engine import textnorm as T

ROOT = Path(__file__).resolve().parent.parent
STORE_DIR = ROOT / "output" / "store"
_OPEN: dict = {}
_LOCK = threading.Lock()


class StoreMissing(Exception):
    pass


def store_path(test_id: str, store_dir: Path | None = None) -> Path:
    return Path(store_dir or STORE_DIR) / f"{test_id}.sqlite"


def open_store(test_id: str, store_dir: Path | None = None, source: Path | None = None) -> "Store":
    p = store_path(test_id, store_dir)
    if not p.is_file():
        raise StoreMissing(f"no engine store for {test_id}")
    key = (str(p), p.stat().st_mtime)
    with _LOCK:
        st = _OPEN.get(key)
        if st is None:
            for k in [k for k in _OPEN if k[0] == str(p)]:
                _OPEN.pop(k).close()
            st = _OPEN[key] = Store(p, source)
    return st


class Store:
    def __init__(self, db: Path, source: Path | None = None):
        self.db = Path(db)
        self.con = sqlite3.connect(str(db), check_same_thread=False)
        self.con.execute("PRAGMA query_only=1")
        self.meta = {k: json.loads(v) for k, v in self.con.execute("SELECT key, value FROM meta")}
        src = Path(source) if source else Path(self.meta["source"])
        if not src.is_absolute():
            src = ROOT / src
        self.source = src
        self.total_lines = int(self.meta["total_lines"])
        rows = self.con.execute("SELECT first_line, byte_off, byte_len, n_lines, chunk FROM blocks ORDER BY block").fetchall()
        self._bfirst = [r[0] for r in rows]
        self._binfo = [r[:4] for r in rows]
        self._bchunk = [r[4] for r in rows]
        self._local: dict = {}
        self.prefixes = [p for p in self.meta.get("prefix_shapes") or []]
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._qlock = threading.RLock()
        self._tpl_low = None

    def close(self):
        self.con.close()

    # ------------------------------------------------------------------ raw lines
    def check_source(self) -> bool:
        try:
            s = self.source.stat()
        except OSError:
            return False
        return s.st_size == int(self.meta["source_size"])

    def block_of(self, line: int) -> int:
        return bisect.bisect_right(self._bfirst, line) - 1

    def _raw_block(self, b: int) -> list[bytes]:
        """The block's lines as raw bytes (split in C, decoded only when a line is used); LRU of 256 blocks."""
        with self._lock:
            hit = self._cache.get(b)
            if hit is not None:
                self._cache.move_to_end(b)
                return hit
        first, off, ln, n = self._binfo[b]
        with self.source.open("rb") as f:
            f.seek(off)
            raw = f.read(ln).splitlines()
        while len(raw) < n:
            raw.append(b"")
        with self._lock:
            self._cache[b] = raw
            if len(self._cache) > 256:
                self._cache.popitem(last=False)
        return raw

    @staticmethod
    def _dec(x: bytes) -> str:
        s = x.decode("utf-8", "replace")
        return T.ANSI_RX.sub("", s) if "\x1b" in s else s

    def block_lines(self, b: int) -> list[str]:
        return [self._dec(x) for x in self._raw_block(b)]

    def block_template_ids(self, b: int):
        """Template id (chunk-local) of every line of block b; 0 = empty line."""
        import zlib
        from array import array
        rows = self.q("SELECT data FROM block_tpl WHERE block = ?", (b,))
        row = rows[0] if rows else None
        a = array("I")
        if row:
            a.frombytes(zlib.decompress(row[0]))
        return a

    def positions(self, b: int, local_ids) -> list[int]:
        """0-based positions in block b of the lines whose template is one of local_ids. array.index() runs in C,
        so the cost is the number of matching lines, not the block size."""
        if not local_ids:
            return []
        ids = self.block_template_ids(b)
        out = []
        for x in local_ids:
            p = -1
            while True:
                try:
                    p = ids.index(x, p + 1)
                except ValueError:
                    break
                out.append(p)
        out.sort()
        return out

    def lines_of_templates(self, gids, blocks=None) -> list[int]:
        """1-based line numbers of every line with one of the given (global) templates, optionally only in blocks."""
        gids = set(gids)
        bl = self.blocks_for_templates(gids) if blocks is None else sorted(set(blocks) & set(self.blocks_for_templates(gids)))
        out = []
        for b in bl:
            out.extend(self._bfirst[b] + j for j in self.positions(b, self.local_ids(self._bchunk[b], gids)))
        return out

    def local_ids(self, chunk: int, gids) -> set:
        """Global template ids -> the chunk-local ids used in block_tpl (cached per chunk)."""
        m = self._local.get(chunk)
        if m is None:
            if len(self._local) > 64:
                self._local.clear()
            m = self._local[chunk] = {g: l for l, g in self.q(
                "SELECT local, tpl FROM chunk_tpl WHERE chunk = ?", (chunk,))}
        return {m[g] for g in gids if g in m}

    def line(self, n: int) -> str:
        """1-based line number -> text ('' when out of range)."""
        if n < 1 or n > self.total_lines:
            return ""
        b = self.block_of(n)
        return self._dec(self._raw_block(b)[n - self._bfirst[b]])

    def lines(self, a: int, b: int) -> list[tuple[int, str]]:
        a, b = max(1, a), min(self.total_lines, b)
        out = []
        n = a
        while n <= b:
            blk = self.block_of(n)
            ls = self.block_lines(blk)
            first = self._bfirst[blk]
            while n <= b and n - first < len(ls):
                out.append((n, ls[n - first]))
                n += 1
            if n - first >= len(ls):
                continue
        return out

    # ------------------------------------------------------------------ postings
    def templates_with(self, anchor: str) -> list[int]:
        a = anchor.lower()
        return [r[0] for r in self.q(
            "SELECT id FROM templates WHERE instr(low, ?) > 0 OR substr(low, -1) = '~'", (a,))]

    def blocks_for_templates(self, tids) -> list[int]:
        tids = list(tids)
        out = set()
        for i in range(0, len(tids), 500):
            part = tids[i:i + 500]
            out.update(r[0] for r in self.q(
                f"SELECT DISTINCT block FROM tpl_blocks WHERE tpl IN ({','.join('?' * len(part))})", part))
        return sorted(out)

    def blocks_for_mac(self, mac: str) -> list[int]:
        return [r[0] for r in self.q("SELECT block FROM mac_blocks WHERE mac = ? ORDER BY block",
                                               (mac.upper(),))]

    def has_mac(self, mac: str) -> bool:
        return bool(self.q("SELECT 1 FROM macs WHERE mac = ?", (mac.upper(),)))

    def scan_blocks(self, blocks, test) -> list[int]:
        """1-based line numbers in the given blocks for which test(line) is true."""
        out = []
        for b in blocks:
            first = self._bfirst[b]
            for j, l in enumerate(self.block_lines(b)):
                if test(l):
                    out.append(first + j)
        return out

    def q(self, sql: str, args=()) -> list[tuple]:
        with self._qlock:              # one connection shared by the bridge's worker threads
            return self.con.execute(sql, args).fetchall()


PREFIX_WORDS = set("""mon tue wed thu fri sat sun jan feb mar apr may jun jul aug sep oct nov dec daemon daemon.
daemon.debug daemon.info daemon.notice daemon.warn daemon.err debug info notice warn err hostapd hostapd: hostapd[
.debug .info .notice .warn .err""".split())
MAC_ANY = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){1,5}", re.I)


HEXISH = re.compile(r"[0-9a-f:]*[0-9:][0-9a-f:]*")


def anchor_of(needle: str) -> str:
    """Longest piece of a needle that survives template masking unchanged. Every run of hex digits / colons that
    contains a digit or a colon (numbers, MACs, partial MACs, hex) is cut out, and so is a '-' / '.' that may belong
    to a masked number. Any substring of the needle is a valid (weaker) anchor, so cutting more is always safe."""
    s = HEXISH.sub("\x00", needle.lower())
    parts = [p.strip("-.") if p.strip() else p for p in s.split("\x00")]
    return max(parts, key=len) if parts else ""


class _Lines:
    def __init__(self, store: Store, lower: bool):
        self.s, self.lower = store, lower

    def __len__(self):
        return self.s.total_lines

    def __getitem__(self, i):
        if isinstance(i, slice):
            raise TypeError("slicing a disk-backed log is not supported - use Store.lines(a, b)")
        if i < 0:
            i += self.s.total_lines
        t = self.s.line(i + 1)
        if self.lower:
            return "" if "hexdump" in t.lower() else t.lower()
        return t

    def __iter__(self):
        for b in range(len(self.s._bfirst)):
            for t in self.s.block_lines(b):
                yield ("" if "hexdump" in t.lower() else t.lower()) if self.lower else t


class StoreIndex:
    """Drop-in replacement for log_search.LogIndex backed by the store (0-based line indexes)."""

    def __init__(self, store: Store):
        self.store = store
        self.lines = _Lines(store, False)
        self.low = _Lines(store, True)
        self._cand: dict = {}

    def _select(self, needles, case_sensitive: bool):
        """-> (templates whose text contains a needle, templates that may contain it) or None when a needle cannot
        be located through templates (it is too short, or may sit in the syslog prefix) - then every line is read."""
        full, part = set(), set()
        for nd in needles:
            al = anchor_of(nd)
            if any(al in p for p in self.store.prefixes) or (not self.store.prefixes and al.strip() in PREFIX_WORDS):
                return None              # the text may sit in the timestamp / facility prefix: read every line
            cut = max((k for p in self.store.prefixes for k in range(1, min(len(al), len(p)) + 1) if p.endswith(al[:k])),
                      default=0)
            a = al[cut:].strip()         # the part that may overlap the prefix is not used for template selection
            if len(a) < 3:
                return None
            rows = self.store.q("SELECT id, text, low FROM templates WHERE instr(low, ?) > 0 OR substr(low, -1) = '~'",
                                (a.lower(),))
            if case_sensitive and (re.fullmatch(r"[0-9a-fA-F \t]+", nd) or "(len=" in nd or "): " in nd
                                   or nd.strip().endswith(("hexdump(", "hexdump(l", "hexdump(le"))):
                # the hex payload of hexdump lines is not part of their template: those templates may match too
                rows = rows + self.store.q("SELECT id, text, low FROM templates WHERE instr(low, 'hexdump') > 0")
            for tid, text, low in rows:
                if not case_sensitive and "hexdump" in low:
                    continue                       # LogIndex.low blanks hexdump lines
                if (nd in text) if case_sensitive else (nd in low):
                    full.add(tid)
                else:
                    part.add(tid)
        return full, part - full

    def _lines_for(self, needles, case_sensitive: bool, test) -> list[int]:
        sel = self._select(needles, case_sensitive)
        st = self.store
        if sel is None:
            return [n - 1 for n in st.scan_blocks(range(len(st._bfirst)), test)]
        full, part = sel
        out = []
        for b in st.blocks_for_templates(full | part):
            ch = st._bchunk[b]
            first = st._bfirst[b]
            lf, lp = st.local_ids(ch, full), st.local_ids(ch, part)
            pos_full, need = st.positions(b, lf), st.positions(b, lp)
            out.extend(first + j - 1 for j in pos_full)
            if need:
                raw = st._raw_block(b)
                out.extend(first + j - 1 for j in need if test(st._dec(raw[j])))
        out.sort()
        return out

    def candidates(self, needles) -> list[int]:
        key = ("low", tuple(needles))
        if key in self._cand:
            return self._cand[key]
        nds = [n.lower() for n in needles]

        def test(l):
            low = l.lower()
            return "hexdump" not in low and any(n in low for n in nds)
        out = self._lines_for(nds, False, test)
        if len(self._cand) > 256:
            self._cand.clear()
        self._cand[key] = out
        return out

    def raw_candidates(self, needles) -> list[int]:
        """Case-sensitive search on raw lines, hexdumps included."""
        key = ("raw", tuple(needles))
        if key in self._cand:
            return self._cand[key]
        nds = list(needles)
        out = self._lines_for(nds, True, lambda l: any(n in l for n in nds))
        self._cand[key] = out
        return out

    def contains(self, s: str) -> bool:
        if re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", s.strip()):
            return self.store.has_mac(s.strip())
        return bool(self.candidates([s.lower()]))


def mask(text: str) -> str:
    return T.template(text)
