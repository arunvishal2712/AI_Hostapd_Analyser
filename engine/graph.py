"""
Graph RAG: the whole story of one thing.

The store already holds an event-level property graph: every typed event is an edge client -> interface / BSSID with
a time and a line number (table `edges` aggregates them per relation). This module adds the structure around it -
interface -> BSSID -> SSID, BSSID -> AP MLD, client -> Wi-Fi 7 link addresses, client -> sessions, session -> AP
restart, and client ~ client "shared fate" (sessions that ended within a few seconds of each other) - and answers
with a traversal instead of a text search:

    story(client)        identity, links, where it connected, lifecycle funnel, every session and how it ended,
                         restarts that dropped it, clients that dropped together with it
    story(ssid / iface)  BSSIDs, clients served, session outcomes, AP-side events
    story(event types)   who, where, when - the subgraph of all occurrences
    path(a, b)           how two entities are connected

Cost: one pass over the subject's edges / sessions (index lookups), i.e. linear in the subject's size.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque

from engine import rules as R
from engine.retrieval import ev_line, hms_of, is_group, ref, types_in

FUNNEL = [("auth_req", "auth requests"), ("sae_commit", "SAE commits"), ("auth_ok", "authenticated"),
          ("auth_no_ack", "auth response not ACKed"), ("assoc_req", "assoc requests"),
          ("reassoc_req", "reassoc requests"), ("assoc_ok", "associated"), ("eapol_start", "4-way started"),
          ("eapol_rx", "EAPOL replies from client"), ("fourway_ok", "4-way completed"), ("connected", "connected"),
          ("fourway_fail", "4-way failed"), ("mlo_reject", "MLO link rejected"), ("sae_fail", "SAE failed")]
CAUSE_LABEL = {"station_left": "station left", "dut_kickout": "DUT kickout", "ap_restart": "Wi-Fi reload / AP restart",
               "silent_reconnect": "silent reconnect", "handshake_failed": "handshake failed", "unknown": "not logged",
               "open": "still connected"}


class Graph:
    def __init__(self, store, analysis: dict | None = None):
        self.s = store
        self.adj = defaultdict(set)
        self.kind = {}
        self.bss_iface, self.iface_ssid, self.bss_ssid, self.bss_mld = {}, {}, {}, {}
        for ent, key, val in store.q("SELECT DISTINCT entity, key, value FROM attrs WHERE key IN ('bssid','ssid','iface')"):
            if key == "bssid":
                self.bss_iface[val] = ent
                self._link(("iface", ent), ("bssid", val))
            elif key == "ssid" and ":" not in ent:
                self.iface_ssid[ent] = val
                self._link(("iface", ent), ("ssid", val))
            elif key == "ssid":
                self.bss_ssid[ent] = val
                self._link(("bssid", ent), ("ssid", val))
        roles = (analysis or {}).get("mac_roles") or {}
        self.links, self.owner = {}, {}
        for c in roles.get("clients") or []:
            self.links[c["mac"]] = [l.upper() for l in c.get("link_addresses") or []]
            self.kind[c["mac"]] = "client"
            for l in self.links[c["mac"]]:
                self.owner[l] = c["mac"]
                self._link(("client", c["mac"]), ("link", l))
            for s in c.get("ssids") or []:
                self._link(("client", c["mac"]), ("ssid", s))
        for b in ((analysis or {}).get("metadata") or {}).get("ap_bss") or []:
            for m in b.get("mld_addrs") or []:
                if m != b["mac"]:
                    self.bss_mld[b["mac"]] = m
                    self._link(("bssid", b["mac"]), ("ap_mld", m))
            if b.get("ssid"):
                self.bss_ssid.setdefault(b["mac"], b["ssid"])
                self._link(("bssid", b["mac"]), ("ssid", b["ssid"]))
            if b.get("interface"):
                self._link(("bssid", b["mac"]), ("iface", b["interface"]))
        for src, rel, dst, n in store.q("SELECT src, rel, dst, SUM(n) FROM edges GROUP BY 1, 2, 3"):
            if is_group(src):
                continue
            o = self.owner.get(src, src)
            dk = "bssid" if ":" in dst else ("iface" if dst != "AP" else "ap")
            self._link(("client", o), (dk, dst))

    def _link(self, a, b):
        self.adj[a].add(b)
        self.adj[b].add(a)

    def macs_of(self, mac):
        mac = self.owner.get(mac, mac)
        return [mac] + self.links.get(mac, [])

    def ssid_of(self, dst):
        return self.iface_ssid.get(dst) or self.bss_ssid.get(dst) or self.iface_ssid.get(self.bss_iface.get(dst, ""))

    # ------------------------------------------------------------------ stories
    def story_client(self, mac: str, devices: dict | None = None) -> dict:
        s = self.s
        mac = self.owner.get(mac, mac)
        ms = self.macs_of(mac)
        ph = ",".join("?" * len(ms))
        res = {"mode": "graph", "title": f"Graph RAG - the whole story of client {mac}", "answer": [], "evidence": [],
               "tables": [], "trace": [], "nodes": [], "edges": []}
        rels = s.q(f"SELECT rel, dst, SUM(n), MIN(first_line), MAX(last_line), MIN(first_ts), MAX(last_ts) FROM edges "
                   f"WHERE src IN ({ph}) GROUP BY rel, dst", ms)
        if not rels:
            res["answer"].append(f"{mac} does not appear in any typed event of the log.")
            return res
        tot = Counter()
        where = Counter()
        first = min(r[3] for r in rels)
        last = max(r[4] for r in rels)
        for rel, dst, n, f, l, t0, t1 in rels:
            tot[rel] += n
            if dst not in ("AP", "?"):
                where[dst] += n
        dev = (devices or {}).get(mac, {}).get("label")
        ssids = sorted({self.ssid_of(d) for d in where if self.ssid_of(d)})
        res["answer"].append(
            f"{mac}" + (f" ({dev})" if dev else "") + (f" with Wi-Fi 7 link address(es) {', '.join(self.links[mac])}"
                                                       if self.links.get(mac) else "")
            + f" appears from line {first} to line {last}; SSID(s): {', '.join(ssids) or 'not logged'}; "
            + (f"talked to {len(where)} interface/BSSID node(s): " + ", ".join(
                f"{d}" + (f" ({self.ssid_of(d)})" if self.ssid_of(d) else "") + f" x{n}" for d, n in where.most_common(6))
               if where else "no interface or BSSID is named in its events") + ".")
        funnel = [(lbl, tot[k]) for k, lbl in FUNNEL if tot.get(k)]
        res["answer"].append("Join funnel (exact counts): " + " -> ".join(f"{lbl} {n}" for lbl, n in funnel) + ".")
        sess = s.q(f"SELECT start_line, start_hms, end_line, end_hms, cause, end_type, reason, iface, restart_line, "
                   f"start_ts, end_ts FROM sessions WHERE client IN ({ph}) ORDER BY start_line", ms)
        cc = Counter(r[4] for r in sess)
        res["answer"].append(f"{len(sess)} session(s): " + ", ".join(f"{CAUSE_LABEL.get(c, c)} x{n}" for c, n in cc.most_common())
                             + "." if sess else "It never connected: there is no AP-STA-CONNECTED for it in the whole log"
                             + (f" although it tried ({', '.join(f'{lbl} {n}' for lbl, n in funnel[:3])})." if funnel else "."))
        rows = []
        shared = Counter()
        for sl, sh, el, eh, cause, et, reason, iface, rl, st, et_ in sess:
            dur = f"{int(et_ - st)} s" if et_ and st else "-"
            rows.append({"time": sh or "", "line": sl, "end": eh or "", "end_line": el or "", "length": dur,
                         "iface": iface or "", "ssid": self.ssid_of(iface or "") or "",
                         "ended": CAUSE_LABEL.get(cause, cause) + (f" (reason {reason})" if reason is not None else ""),
                         "restart_line": rl or ""})
            if et_ and cause not in ("open",):
                for (oc,) in s.q("SELECT DISTINCT client FROM sessions WHERE end_ts BETWEEN ? AND ? AND client NOT IN "
                                 f"({ph})", (et_ - 5, et_ + 5, *ms)):
                    shared[oc] += 1
        res["tables"].append({"title": f"Sessions of {mac}", "columns": ["time", "line", "end", "end_line", "length",
                                                                     "iface", "ssid", "ended", "restart_line"],
                              "rows": rows})
        if shared:
            res["answer"].append("Shared fate (other clients whose session ended within 5 s of this client's): "
                                 + ", ".join(f"{m} x{n}" for m, n in shared.most_common(8)) + ".")
        rst = sorted({r["restart_line"] for r in rows if r["restart_line"]})
        if rst:
            res["answer"].append(f"{len(rst)} AP restart(s) dropped this client (restart lines {', '.join(map(str, rst[:6]))}).")
            res["evidence"] += [ref(s, l, "AP restart that ended a session") for l in rst[:3]]
        ft = sorted(R.FAILURE_TYPES - {"eapol_noack"})
        fails = s.q(f"SELECT line FROM all_events WHERE mac IN ({ph}) AND type IN "
                    f"({','.join('?' * len(ft))}) ORDER BY line LIMIT 4", (*ms, *ft))
        res["evidence"] += [ref(s, sess[0][0], "first connection")] if sess else []
        res["evidence"] += [ref(s, l, "failure") for (l,) in fails]
        res["evidence"] += [ref(s, r["end_line"], "session end") for r in rows if r["end_line"]][:4]
        res["nodes"] = [{"id": mac, "kind": "client"}] + [{"id": d, "kind": "bssid" if ":" in d else "iface"} for d in where] \
            + [{"id": x, "kind": "ssid"} for x in ssids] + [{"id": m, "kind": "client"} for m in shared]
        res["edges"] = [{"src": mac, "dst": d, "n": n} for d, n in where.items()] \
            + [{"src": d, "dst": self.ssid_of(d), "n": 0} for d in where if self.ssid_of(d)] \
            + [{"src": mac, "dst": m, "n": n, "rel": "dropped together"} for m, n in shared.items()]
        res["trace"].append({"tool": "graph_traverse", "args": mac,
                             "found": f"{len(where)} AP nodes, {len(sess)} sessions, {len(shared)} shared-fate clients"})
        res["coverage"] = "all typed events of the client and its link addresses (exact counts from the whole log)"
        return res

    def story_ap(self, ifaces: list, bssids: list, ssids: list) -> dict:
        s = self.s
        nodes = list(dict.fromkeys(ifaces + bssids))
        label = ", ".join(ssids or nodes)
        res = {"mode": "graph", "title": f"Graph RAG - everything connected to {label}", "answer": [], "evidence": [],
               "tables": [], "trace": []}
        ph = ",".join("?" * len(nodes))
        cl = s.q(f"SELECT src, SUM(n), MIN(first_line), MAX(last_line) FROM edges WHERE dst IN ({ph}) GROUP BY src "
                 f"ORDER BY 2 DESC", nodes)
        owners = Counter()
        for m, n, f, l in cl:
            if not is_group(m):
                owners[self.owner.get(m, m)] += n
        sess = s.q(f"SELECT client, cause, COUNT(*), MIN(start_line) FROM sessions WHERE iface IN ({ph}) GROUP BY 1, 2", nodes)
        per = defaultdict(Counter)
        for c, cause, n, f in sess:
            per[self.owner.get(c, c)][cause] += n
        aps = s.q(f"SELECT type, COUNT(*), MIN(line), MAX(line) FROM all_events WHERE iface IN ({ph}) AND type IN "
                  f"({','.join('?' * len(R.AP_TYPES))}) GROUP BY type ORDER BY 2 DESC", (*nodes, *sorted(R.AP_TYPES)))
        res["answer"].append(f"{label}: interfaces/BSSIDs {', '.join(nodes)}; {len(owners)} client(s) interacted with them; "
                             f"{sum(n for _, _, n, _ in sess)} session(s) on them.")
        if aps:
            res["answer"].append("AP-side events: " + "; ".join(f"{R.LABELS.get(t, t)} x{n} (lines {f}-{l})" for t, n, f, l in aps))
            res["evidence"] += [ref(s, f, R.LABELS.get(t, t)) for t, n, f, l in aps[:4]]
        res["tables"].append({"title": f"Clients of {label}", "columns": ["line", "client", "events"] +
                              list(CAUSE_LABEL.values()),
                              "rows": [{"line": next((f for m2, _, f, _ in cl if self.owner.get(m2, m2) == m), ""),
                                        "client": m, "events": n,
                                        **{CAUSE_LABEL[k]: per[m].get(k, 0) for k in CAUSE_LABEL}}
                                       for m, n in owners.most_common(40)]})
        res["trace"].append({"tool": "graph_neighbourhood", "args": label, "found": f"{len(owners)} clients"})
        res["coverage"] = "all typed events on these interfaces / BSSIDs (whole log)"
        return res

    def story_events(self, types: set, u: dict | None = None) -> dict:
        s = self.s
        ts = sorted(types)
        ph = ",".join("?" * len(ts))
        res = {"mode": "graph", "title": "Graph RAG - who, where and when for " +
               ", ".join(R.LABELS.get(t, t) for t in ts)[:100], "answer": [], "evidence": [], "tables": [], "trace": []}
        who = s.q(f"SELECT mac, COUNT(*), MIN(line), MAX(line) FROM all_events WHERE type IN ({ph}) AND mac IS NOT NULL "
                  f"GROUP BY mac ORDER BY 2 DESC", ts)
        where = s.q(f"SELECT COALESCE(iface, peer, '?'), COUNT(*) FROM all_events WHERE type IN ({ph}) GROUP BY 1 ORDER BY 2 DESC", ts)
        tot = s.q(f"SELECT type, COUNT(*), MIN(line), MAX(line), MIN(ts), MAX(ts) FROM all_events WHERE type IN ({ph}) "
                  f"GROUP BY type ORDER BY 2 DESC", ts)
        if not tot:
            res["answer"].append("None of these events occur anywhere in the log.")
            return res
        owners = Counter()
        firstl = {}
        for m, n, f, l in who:
            if is_group(m):
                continue
            o = self.owner.get(m, m)
            owners[o] += n
            firstl[o] = min(firstl.get(o, f), f)
        res["answer"].append("Totals: " + "; ".join(f"{R.LABELS.get(t, t)} x{n} ({hms_of(t0)} line {f} -> {hms_of(t1)} line {l})"
                                                    for t, n, f, l, t0, t1 in tot) + ".")
        res["answer"].append("Who: " + ", ".join(f"{m} x{n}" for m, n in owners.most_common(10)) +
                             (f" ({len(owners)} clients)" if len(owners) > 10 else "") + ".")
        res["answer"].append("Where: " + ", ".join(f"{d}" + (f" ({self.ssid_of(d)})" if self.ssid_of(d) else "") + f" x{n}"
                                                   for d, n in where[:8]) + ".")
        res["tables"].append({"title": "Who", "columns": ["line", "client", "n"],
                              "rows": [{"line": firstl[m], "client": m, "n": n} for m, n in owners.most_common(40)]})
        res["evidence"] += [ref(s, f, f"first {R.LABELS.get(t, t)}") for t, n, f, l, _, _ in tot[:4]]
        res["evidence"] += [ref(s, l, f"last {R.LABELS.get(t, t)}") for t, n, f, l, _, _ in tot[:2]]
        res["trace"].append({"tool": "graph_event_subgraph", "args": ",".join(ts)[:80],
                             "found": f"{len(owners)} clients, {len(where)} places"})
        res["coverage"] = "every occurrence of these event types in the whole log"
        return res

    def path(self, a, b, limit: int = 6):
        """Shortest relation path between two nodes (BFS over the entity graph)."""
        start = next((k for k in self.adj if k[1] == a), None)
        goal = next((k for k in self.adj if k[1] == b), None)
        if not start or not goal:
            return None
        prev, q = {start: None}, deque([start])
        while q:
            x = q.popleft()
            if x == goal:
                out = []
                while x:
                    out.append(x)
                    x = prev[x]
                return list(reversed(out))
            for y in self.adj[x]:
                if y not in prev:
                    prev[y] = x
                    q.append(y)
        return None


_G: dict = {}


def graph_for(store, analysis: dict | None = None) -> Graph:
    key = (str(store.db), store.db.stat().st_mtime, id(analysis) if analysis is not None else 0)
    g = _G.get(key)
    if g is None:
        _G.clear()
        g = _G[key] = Graph(store, analysis)
    return g


def story(store, question: str, u: dict, ents: dict, analysis: dict | None = None, devices: dict | None = None) -> dict:
    g = graph_for(store, analysis)
    if ents["macs"]:
        rs = [g.story_client(m, devices) for m in ents["macs"][:2]]
        if len(rs) == 2:
            p = g.path(ents["macs"][0], ents["macs"][1])
            if p:
                rs[0]["answer"].append("Relation path: " + " -> ".join(f"{k}:{v}" for k, v in p) + ".")
        r = rs[0]
        for x in rs[1:]:
            r["answer"] += x["answer"]
            r["tables"] += x["tables"]
            r["evidence"] += x["evidence"]
        return r
    if ents["ifaces"] or ents["bssids"]:
        return g.story_ap(ents["ifaces"], ents["bssids"], ents["ssids"])
    t = types_in(question)
    if t:
        return g.story_events(t, u)
    return g.story_events(R.FAILURE_TYPES | R.DISCONNECT_TYPES, u)
