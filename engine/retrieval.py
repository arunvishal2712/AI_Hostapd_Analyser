"""
Context retrieval (exact values, lines, counts) and Wide retrieval (top-to-bottom summary of one subject).

Both work on the store only. Every number comes from an exact count over the events / postings written at ingest
(which read 100 % of the lines); every evidence item carries the hostapd time and the line number, and its text is
read back from the raw log at query time, so nothing is paraphrased or invented.

Cost: context = index lookups + reading a few blocks (O(log n + k)); wide = one pass over the subject's rollup rows
(O(number of minutes the subject is active)) plus its template inventory - both at most linear in the log size.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from common.reason_codes import REASON_CODE_MEANINGS
from engine import rules as R

PREFIX_RX = re.compile(r"^.*?hostapd(?:\[\d+\])?:\s*")
LINE_Q_RX = re.compile(r"\blines?\s+(\d{1,9})(?:\s*(?:-|to|\.\.)\s*(\d{1,9}))?", re.I)
QUOTED_RX = re.compile(r"[\"“']([^\"”']{4,120})[\"”']")
REASON_Q_RX = re.compile(r"reason(?:\s*code)?\s*(\d{1,3})", re.I)
STATUS_Q_RX = re.compile(r"status(?:\s*code)?\s*(\d{1,3})", re.I)

TYPE_WORDS = [
    (r"deauth", {"deauth_rx", "deauth_tx", "deauth_local", "unprot"}),
    (r"disassoc", {"disassoc_rx", "disassoc_tx", "inactivity"}),
    (r"disconnect|drop|kick|left|leave|lost connection", R.DISCONNECT_TYPES | {"disconnected"}),
    (r"4-?way|handshake|eapol|ptk|key exchange|reason ?15", {"fourway_fail", "fourway_ok", "eapol_start", "eapol_rx",
                                                             "disconnect_req", "eapol_noack"}),
    (r"\bsae\b|password|psk", {"sae_commit", "sae_fail"}),
    (r"\bauth", {"auth_req", "auth_ok", "auth_no_ack", "sae_commit", "sae_fail"}),
    (r"\bassoc|\bjoin", {"assoc_req", "assoc_ok", "assoc_no_ack", "reassoc_req"}),
    (r"roam|reassoc|current.?ap|bss.?t", {"reassoc_req", "btm"}),
    (r"\bmlo\b|multi-?link|status ?43|akm|key mgmt", {"mlo_reject", "akm_invalid"}),
    (r"\bdfs\b|radar|\bcac\b", {"dfs_cac_start", "dfs_cac_done", "radar"}),
    (r"restart|reload|reboot|went down|teardown|ap-disabled|ap-enabled|interface state|reconfig",
     {"ap_disabled", "ap_enabled", "iface_removed", "bss_terminating", "iface_state", "config_load"}),
    (r"driver|nl80211|\bnft\b|severed|resource busy|platform", {"drv_busy", "drv_severed", "nft_error", "nl80211_error"}),
    (r"\bconnect(?:ed|ion)?s?\b|session", {"connected", "disconnected"}),
    (r"\back\b|acknowledg|missing ack", {"missing_acks", "auth_no_ack", "assoc_no_ack", "eapol_noack"}),
    (r"inactiv|idle", {"inactivity"}),
    (r"firmware|version|openwrt", {"firmware"}),
    (r"channel switch|\bcsa\b", {"chan_switch"}),
    (r"radius|\beap\b|802\.1x", {"eap_fail"}),
]
ATTR_WORDS = [
    (r"\bchannel|\bchan\b", "channel"), (r"freq", "freq"), (r"signal|rssi|dbm", "signal"), (r"\baid\b", "aid"),
    (r"\bssid", "ssid"), (r"bssid|hwaddr|mac of the ap|ap mac", "bssid"), (r"cac|dfs wait", "cac_time"),
    (r"firmware|version", "firmware"), (r"auth.?alg", "auth_alg"), (r"\bstate\b", "state"),
    (r"current.?ap|roam", "current_ap"), (r"interface|iface", "iface"),
]


def is_group(mac: str) -> bool:
    """Broadcast / multicast address (never a client)."""
    try:
        return bool(int(mac[:2], 16) & 1)
    except (ValueError, TypeError):
        return False


def ref(store, line: int, why: str = "") -> dict:
    raw = store.line(line)
    from engine.textnorm import parse_prefix
    _, hms, _ = parse_prefix(raw)
    return {"line": line, "time": hms or "", "text": PREFIX_RX.sub("", raw).strip()[:220], "why": why}


def hms_of(ts) -> str:
    if ts is None:
        return ""
    s = int(ts) % 86400
    return f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


INFO_TYPES = {"eapol_start", "eapol_rx", "eapol_noack", "fourway_ok", "auth_req", "sae_commit", "auth_ok", "assoc_req",
              "assoc_ok", "connected", "mlo_link_ok"}


def types_in(question: str) -> set:
    """Event types a question is about. When it asks about failures / problems, the informational events of the same
    family (handshake started / completed, EAPOL frames, requests) are left out - they are context, not the subject."""
    ql = question.lower()
    out = set()
    for rx, ts in TYPE_WORDS:
        if re.search(rx, ql):
            out |= ts
    if out and re.search(r"fail|timeout|timed out|reject|error|problem|issue|mismatch|wrong", ql):
        focus = out - INFO_TYPES
        if "ack" in ql and "eapol_noack" in out:
            focus.add("eapol_noack")
        out = focus or out
    return out


ATTR_LABEL = {"connect_channel": "channel used by client connections on", "cac_time": "DFS wait (CAC) time of",
              "current_ap": "AP the client reported as current (roaming) for"}


def attr_keys_in(question: str) -> list[str]:
    ql = question.lower()
    keys = [k for rx, k in ATTR_WORDS if re.search(rx, ql)]
    if "channel" in keys:
        keys.insert(keys.index("channel") + 1, "connect_channel")
    return keys


def resolve(store, u: dict, analysis: dict | None = None) -> dict:
    """Question entities -> MACs (with Wi-Fi 7 link addresses), interfaces, SSIDs, BSSIDs known to the store."""
    macs = [m.upper() for m in u.get("macs") or []]
    links, owner = {}, {}
    for c in ((analysis or {}).get("mac_roles") or {}).get("clients") or []:
        links[c["mac"]] = [l.upper() for l in c.get("link_addresses") or []]
        for l in links[c["mac"]]:
            owner[l] = c["mac"]
    macs = list(dict.fromkeys(owner.get(m, m) for m in macs))
    allm = list(dict.fromkeys(macs + [l for m in macs for l in links.get(m, [])]))
    ssids = list(u.get("ssids") or [])
    ifaces, bssids = [], []
    if ssids:
        for ent, val in store.q("SELECT DISTINCT entity, value FROM attrs WHERE key = 'ssid'"):
            if val in ssids:
                (bssids if ":" in ent else ifaces).append(ent)
    for m in macs:
        if store.q("SELECT 1 FROM attrs WHERE entity = ? AND key = 'iface' LIMIT 1", (m,)):
            bssids.append(m)
    q = u.get("original") or u.get("question") or ""
    for tok in set(re.findall(r"\b(?:phy|wlan|ath|wl)[\w.\-]*\w", q, re.I)):
        if store.q("SELECT 1 FROM events WHERE iface = ? LIMIT 1", (tok,)):
            ifaces.append(tok)
    return {"macs": macs, "all_macs": allm, "links": {m: links.get(m, []) for m in macs}, "ssids": ssids,
            "ifaces": list(dict.fromkeys(ifaces)), "bssids": list(dict.fromkeys(bssids))}


def _window_sql(u: dict):
    w = u.get("window")
    return (" AND hms BETWEEN ? AND ?", [w[0], w[1]]) if w else ("", [])


def events(store, types=None, macs=None, ifaces=None, u=None, limit=200, order="line", extra="", args=()):
    sql = "SELECT line, ts, hms, type, mac, peer, iface, reason, status, detail FROM all_events WHERE 1=1"
    a: list = []
    if types:
        sql += f" AND type IN ({','.join('?' * len(types))})"
        a += sorted(types)
    if macs:
        sql += f" AND mac IN ({','.join('?' * len(macs))})"
        a += list(macs)
    if ifaces:
        sql += f" AND iface IN ({','.join('?' * len(ifaces))})"
        a += list(ifaces)
    if u:
        w, wa = _window_sql(u)
        sql += w
        a += wa
    sql += extra
    a += list(args)
    sql += f" ORDER BY {order} LIMIT {int(limit)}"
    cols = ("line", "ts", "hms", "type", "mac", "peer", "iface", "reason", "status", "detail")
    return [dict(zip(cols, r)) for r in store.q(sql, a)]


def count_events(store, types=None, macs=None, ifaces=None, u=None, extra="", args=()) -> dict:
    sql = "SELECT type, COUNT(*), MIN(line), MAX(line) FROM all_events WHERE 1=1"
    a: list = []
    if types:
        sql += f" AND type IN ({','.join('?' * len(types))})"
        a += sorted(types)
    if macs:
        sql += f" AND mac IN ({','.join('?' * len(macs))})"
        a += list(macs)
    if ifaces:
        sql += f" AND iface IN ({','.join('?' * len(ifaces))})"
        a += list(ifaces)
    if u:
        w, wa = _window_sql(u)
        sql += w
        a += wa
    sql += extra
    a += list(args)
    return {t: {"n": n, "first_line": f, "last_line": l} for t, n, f, l in store.q(sql + " GROUP BY type ORDER BY 2 DESC", a)}


def owner_of(mac: str, ents: dict) -> str:
    for m, ls in ents.get("links", {}).items():
        if mac == m or mac in ls:
            return m
    return mac


def ev_line(e: dict, with_mac=True) -> str:
    bits = [R.LABELS.get(e["type"], e["type"])]
    if with_mac and e.get("mac"):
        bits.append(e["mac"])
    if e.get("reason") is not None:
        bits.append(f"reason {e['reason']} ({REASON_CODE_MEANINGS.get(e['reason'], 'reserved')})")
    if e.get("status") is not None:
        bits.append(f"status {e['status']}")
    if e.get("iface"):
        bits.append(f"on {e['iface']}")
    if e.get("detail"):
        bits.append(str(e["detail"])[:90])
    return ", ".join(bits)


# ------------------------------------------------------------------------------------------------ CONTEXT
def context(store, question: str, u: dict, ents: dict) -> dict:
    """Specific values: line lookups, attribute values, events of an entity at a time, exact counts, phrases."""
    res = {"mode": "context", "title": "Context retrieval (exact values from the log)", "answer": [], "evidence": [],
           "tables": [], "coverage": store.meta.get("coverage", ""), "trace": []}
    q = question
    # 1) explicit line numbers
    for m in LINE_Q_RX.finditer(q):
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        a, b = (a - 3, b + 3) if a == b else (a, min(b, a + 60))
        rows = [ref(store, n, "requested line" if n == int(m.group(1)) else "context") for n in range(a, b + 1)]
        res["evidence"] += rows
        res["answer"].append(f"Lines {a}-{b} of {store.total_lines} read directly from the raw log.")
        res["trace"].append({"tool": "read_lines", "args": f"{a}-{b}", "found": f"{len(rows)} lines"})
    macs, ifaces = ents["all_macs"], ents["ifaces"] + ents["bssids"]
    keys = attr_keys_in(q)
    # 2) attribute values for the entities in the question (or for every interface when none was named)
    if keys:
        targets = ents["macs"] + ents["ifaces"] + ents["bssids"] or [None]
        for k in keys:
            if k == "signal":
                for m in (ents["all_macs"] or []):
                    w = u.get("window")
                    rows = store.q("SELECT SUM(n), MIN(mn), MAX(mx), SUM(sm), MIN(first_line) FROM metrics WHERE entity = ?"
                                   " AND key = 'signal'", (m,))
                    n, mn, mx, sm, fl = rows[0]
                    if n:
                        res["answer"].append(f"Signal of {owner_of(m, ents)}"
                                             + (f" (link {m})" if owner_of(m, ents) != m else "")
                                             + f" in {n} received frames: min {mn:.0f} dBm, max {mx:.0f} dBm, "
                                             f"average {sm / n:.1f} dBm (whole log{'' if not w else ', window ignored for signal'}).")
                        res["evidence"].append(ref(store, fl, "first frame with ssi_signal from this client"))
                continue
            sql = "SELECT entity, value, MIN(line), MAX(line), COUNT(*) FROM attrs WHERE key = ?"
            a = [k]
            tg = [t for t in targets if t]
            if tg:
                allt = tg + [l for t in tg for l in ents["links"].get(t, [])]
                sql += f" AND entity IN ({','.join('?' * len(allt))})"
                a += allt
            rows = store.q(sql + " GROUP BY entity, value ORDER BY MIN(line) LIMIT 40", a)
            for ent, val, f, l, n in rows:
                res["answer"].append(f"{ATTR_LABEL.get(k, k + ' of')} {ent} = {val} (first logged at line {f}"
                                     + (f", last at line {l}" if l != f else "") + ")")
                res["evidence"].append(ref(store, f, f"{k} of {ent}"))
            res["trace"].append({"tool": "attribute_lookup", "args": f"{k} for {', '.join(tg) or 'all'}",
                                 "found": f"{len(rows)} value(s)"})
            if not rows and k == "connect_channel":
                continue
                res["answer"].append(f"No {k} value for {', '.join(tg) or 'any entity'} was logged.")
    # 3) events of the requested types / entity / time
    types = types_in(q)
    rm, sm = REASON_Q_RX.search(q), STATUS_Q_RX.search(q)
    extra, eargs = "", []
    if rm:
        extra += " AND reason = ?"
        eargs.append(int(rm.group(1)))
    if sm:
        extra += " AND status = ?"
        eargs.append(int(sm.group(1)))
    if types or macs or u.get("window") or extra:
        cnt = count_events(store, types or None, macs or None, None, u) if not extra else None
        rows = events(store, types or None, macs or None, None, u, limit=60, extra=extra, args=eargs)
        if cnt is not None:
            total = sum(v["n"] for v in cnt.values())
            res["answer"].append(
                f"Exact count{' in ' + u['window'][0] + '-' + u['window'][1] if u.get('window') else ''}"
                f"{' for ' + ', '.join(ents['macs']) if ents['macs'] else ''}: {total} event(s) - "
                + "; ".join(f"{R.LABELS.get(t, t)} x{v['n']} (first line {v['first_line']}, last line {v['last_line']})"
                            for t, v in list(cnt.items())[:12]))
        else:
            res["answer"].append(f"{len(rows)} event(s) match" + (f" reason {rm.group(1)}" if rm else "")
                                 + (f" status {sm.group(1)}" if sm else "") + (" (first 60 shown)" if len(rows) == 60 else ""))
        res["tables"].append({"title": "Matching events", "columns": ["time", "line", "event"],
                              "rows": [{"time": e["hms"] or "", "line": e["line"], "event": ev_line(e)} for e in rows]})
        res["evidence"] += [ref(store, e["line"], R.LABELS.get(e["type"], e["type"])) for e in rows[:8]]
        res["trace"].append({"tool": "find_events", "args": ", ".join(filter(None, [",".join(sorted(types))[:80],
                             ",".join(macs), str(u.get("window") or ""), extra])), "found": f"{len(rows)} rows"})
    # 4) quoted phrase -> every line of that message shape
    for m in QUOTED_RX.finditer(q):
        res["tables"].append(phrase_table(store, m.group(1), macs, res))
    if not res["answer"] and not res["evidence"]:
        res["answer"].append("No exact value, line or event matched the question; see the other retrieval results.")
    return res


def phrase_table(store, phrase: str, macs: list, res: dict) -> dict:
    from engine.store import StoreIndex
    si = StoreIndex(store)
    hits = si.raw_candidates([phrase]) or si.candidates([phrase.lower()])
    if macs:
        hits = [i for i in hits if any(m.lower() in si.low[i] for m in macs)]
    res["answer"].append(f'The text "{phrase}" occurs in {len(hits)} line(s)'
                         + (f" (first line {hits[0] + 1}, last line {hits[-1] + 1})" if hits else ""))
    res["trace"].append({"tool": "phrase_search", "args": phrase, "found": f"{len(hits)} lines"})
    rows = [ref(store, i + 1, "phrase") for i in hits[:40]]
    res["evidence"] += rows[:6]
    return {"title": f'Lines containing "{phrase}"', "columns": ["time", "line", "text"], "rows": rows}


# ------------------------------------------------------------------------------------------------ WIDE
def subject_of(store, question: str, u: dict, ents: dict) -> dict:
    if ents["macs"]:
        return {"kind": "client", "name": ", ".join(ents["macs"]), "macs": ents["all_macs"]}
    if ents["ifaces"] or ents["bssids"]:
        return {"kind": "ssid" if ents["ssids"] else "interface", "name": ", ".join(ents["ssids"] or ents["ifaces"]),
                "ifaces": ents["ifaces"], "bssids": ents["bssids"]}
    t = types_in(question)
    if t:
        return {"kind": "event", "name": ", ".join(sorted(R.LABELS.get(x, x) for x in t))[:120], "types": t}
    m = QUOTED_RX.search(question)
    if m:
        return {"kind": "phrase", "name": m.group(1), "phrase": m.group(1)}
    return {"kind": "log", "name": "the whole log"}


def wide(store, question: str, u: dict, ents: dict, gap_s: int = 300) -> dict:
    """Map-reduce over the whole log for one subject: per-minute rollups -> phases (activity separated by quiet
    gaps), totals per event type, peaks, first/last occurrence, and the complete inventory of message shapes."""
    subj = subject_of(store, question, u, ents)
    res = {"mode": "wide", "title": f"Wide retrieval - {subj['name']} from the first to the last line",
           "answer": [], "evidence": [], "tables": [], "trace": [], "subject": subj}
    # ---- map: rows (bucket, type, n, first_line, last_line) for the subject
    if subj["kind"] == "client":
        rows = store.q(f"SELECT bucket, type, SUM(n), MIN(first_line), MAX(last_line) FROM rollup WHERE entity IN "
                       f"({','.join('?' * len(subj['macs']))}) GROUP BY 1, 2 ORDER BY 1", subj["macs"])
    elif subj["kind"] in ("ssid", "interface"):
        ents_ = subj["ifaces"] + subj["bssids"]
        cl = [r[0] for r in store.q(f"SELECT DISTINCT src FROM edges WHERE dst IN ({','.join('?' * len(ents_))})", ents_)
              if not is_group(r[0])]
        allx = ents_ + cl
        rows = store.q(f"SELECT bucket, type, SUM(n), MIN(first_line), MAX(last_line) FROM rollup WHERE entity IN "
                       f"({','.join('?' * len(allx))}) GROUP BY 1, 2 ORDER BY 1", allx)
        subj["clients"] = cl
    elif subj["kind"] == "event":
        ts = sorted(subj["types"])
        rows = store.q(f"SELECT bucket, type, SUM(n), MIN(first_line), MAX(last_line) FROM rollup WHERE type IN "
                       f"({','.join('?' * len(ts))}) GROUP BY 1, 2 ORDER BY 1", ts)
    elif subj["kind"] == "phrase":
        from engine.store import anchor_of
        tids = store.templates_with(anchor_of(subj["phrase"]))
        tids = [t for t, low in store.q(f"SELECT id, low FROM templates WHERE id IN ({','.join('?' * len(tids))})", tids)
                if subj["phrase"].lower() in low or anchor_of(subj["phrase"]).strip() in low] if tids else []
        rows = store.q(f"SELECT bucket, 'phrase', SUM(n), MIN(first_line), MAX(last_line) FROM tpl_roll WHERE tpl IN "
                       f"({','.join('?' * len(tids))}) GROUP BY 1 ORDER BY 1", tids) if tids else []
    else:
        rows = store.q("SELECT bucket, type, SUM(n), MIN(first_line), MAX(last_line) FROM rollup GROUP BY 1, 2 ORDER BY 1")
    res["trace"].append({"tool": "map_rollups", "args": subj["kind"], "found": f"{len(rows)} (minute, event type) rows"})
    if u.get("window"):
        lo, hi = u["window"]
        rows = [r for r in rows if lo <= hms_of(r[0] * 60) <= hi or lo <= hms_of(r[0] * 60 + 59) <= hi]
    if not rows:
        res["answer"].append(f"Nothing about {subj['name']} was found in any of the {store.total_lines} lines.")
        res["coverage"] = store.meta.get("coverage", "")
        return res
    # ---- reduce: totals, phases, peaks
    tot, first, last = Counter(), {}, {}
    per_bucket = defaultdict(Counter)
    for b, t, n, f, l in rows:
        tot[t] += n
        first[t] = min(first.get(t, f), f)
        last[t] = max(last.get(t, l), l)
        per_bucket[b][t] += n
    buckets = sorted(per_bucket)
    phases, cur = [], [buckets[0]]
    for b in buckets[1:]:
        if (b - cur[-1]) * 60 > gap_s:
            phases.append(cur)
            cur = [b]
        else:
            cur.append(b)
    phases.append(cur)
    ptab = []
    for i, ph in enumerate(phases, 1):
        c = Counter()
        for b in ph:
            c.update(per_bucket[b])
        lines_ = [r for r in rows if ph[0] <= r[0] <= ph[-1]]
        fl, ll = min(r[3] for r in lines_), max(r[4] for r in lines_)
        notable = [R.LABELS.get(t, t) for t in c if t in R.FAILURE_TYPES or t in R.DISCONNECT_TYPES or t in R.AP_TYPES]
        t_first, t_last = ref(store, fl)["time"], ref(store, ll)["time"]
        ptab.append({"phase": i, "time": t_first, "end": t_last,
                     "line": fl, "last_line": ll,
                     "events": sum(c.values()),
                     "what": "; ".join(f"{R.LABELS.get(t, t)} x{n}" for t, n in c.most_common(6)),
                     "notable": ", ".join(dict.fromkeys(notable))[:160]})
    peaks = sorted(per_bucket.items(), key=lambda kv: -sum(kv[1].values()))[:3]
    res["answer"].append(
        f"{subj['name']}: {sum(tot.values())} events in {len(buckets)} active minute(s), first at line {min(first.values())}"
        f" and last at line {max(last.values())}; grouped into {len(phases)} phase(s) separated by more than "
        f"{gap_s // 60} quiet minutes.")
    res["answer"].append("Totals: " + "; ".join(f"{R.LABELS.get(t, t)} x{n} (lines {first[t]}-{last[t]})"
                                               for t, n in tot.most_common(14)))
    res["answer"].append("Busiest minutes: " + "; ".join(
        f"{hms_of(b * 60)[:5]} ({sum(c.values())} events: " + ", ".join(f"{R.LABELS.get(t, t)} x{n}" for t, n in
                                                                    c.most_common(3)) + ")" for b, c in peaks))
    res["tables"].append({"title": "Phases (top to bottom)", "columns": ["phase", "time", "end", "line", "last_line",
                                                                         "events", "what", "notable"], "rows": ptab})
    res["evidence"] += [ref(store, p["line"], f"start of phase {p['phase']}") for p in ptab[:6]]
    if ptab[-1]["last_line"] != ptab[-1]["line"]:
        res["evidence"].append(ref(store, ptab[-1]["last_line"], "last occurrence"))
    # ---- complete inventory of message shapes for a client (every kind of line that mentions it)
    if subj["kind"] == "client":
        inv = store.q(f"SELECT t.text, SUM(e.n), MIN(e.first_line), MAX(e.last_line) FROM ent_tpl e JOIN templates t "
                      f"ON t.id = e.tpl WHERE e.mac IN ({','.join('?' * len(subj['macs']))}) GROUP BY t.id "
                      f"ORDER BY MIN(e.first_line)", subj["macs"])
        res["tables"].append({"title": f"Every kind of log line that mentions {subj['name']} ({len(inv)} shapes)",
                              "columns": ["line", "last_line", "n", "shape"],
                              "rows": [{"line": f, "last_line": l, "n": n, "shape": t[:160]} for t, n, f, l in inv]})
        res["answer"].append(f"{sum(r[1] for r in inv)} log lines mention {subj['name']} ({len(inv)} different message "
                             f"shapes); all of them were counted.")
        res["trace"].append({"tool": "entity_inventory", "args": subj["name"], "found": f"{len(inv)} message shapes"})
    res["coverage"] = (f"{store.meta.get('coverage', '')}; the subject's rollups cover every minute from "
                       f"{hms_of(buckets[0] * 60)} to {hms_of(buckets[-1] * 60 + 59)} ({len(buckets)} active minutes).")
    return res
