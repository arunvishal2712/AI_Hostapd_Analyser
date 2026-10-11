"""
Question -> visual view (v3.5).

The Workbench output panel does not show a wall of text: every question is turned into a list of blocks
(KPI tiles, findings cards, bar / stacked charts, a connection timeline, comparison tables, data tables) that
the browser renders. Everything here is deterministic - it comes from insights.build() and the event table -
so the picture is always correct; the language model adds the explanation next to it.

Every table row carries the hostapd timestamp ("time") and the log line number ("line"); the UI makes the
line clickable and shows the raw log around it.
"""
from __future__ import annotations

import re
from collections import Counter

KIND_ORDER = [("dut", "DUT kickout"), ("sta", "Station left"), ("reload", "Wi-Fi reload"),
              ("silent", "Silent reconnect"), ("handshake", "Handshake failed")]

RX = {
    "compare": r"compar|\bvs\.?\b|versus|differen|capture ?[12]\b|before and after|first .*second|both captures",
    "disconnects": r"disconnect|\bdrop|kicked|kickout|\bleft\b|\bleave|lost connection|fell off",
    "devices": r"what devices|devices are|device types?|\bdevices?\b.*\b(type|kind|model|vendor|identif|which)|\bphones?\b|\bmodel\b|vendor|manufactur|identif"
               r"|what (kind|type) of|\bdevice list\b|which devices",
    "restarts": r"restart|reload|reboot|\bdfs\b|\bcac\b|radar|went down|teardown|interface down",
    "driver": r"driver|warning|platform|\bnft\b|severed|resource busy|ack=0|eapol tx",
    "failures": r"\bjoin|fail|could ?n.t connect|cannot connect|unable to connect|\bmlo\b|multi-?link|\bsae\b|handshake"
                r"|auth\w* (issue|problem|error)|status ?43|reason ?15",
    "timeline": r"timeline|session|sequence|history|over time|when did|connection time",
    "events": r"deauth|disassoc|reassoc|roam|4-way|four-way",
    "clients": r"\bclients?\b.*\b(table|list|all|each|every|summary|overview)|per[- ]client|which clients|client table",
    "report": r"report|overall|summary|summari[sz]e|overview|analy[sz]|dashboard|everything|status of",
}


def _hms(t: str | None) -> str:
    return (t or "")[:8]


def _in_window(t: str, window) -> bool:
    return not window or not t or window[0] <= t <= window[1]


def table(title, columns, rows, note=None, limit=400, key=None):
    """columns: [(key, label)]. 'time' and 'line' columns are always present and come first."""
    keys = [c[0] for c in columns]
    cols = [("time", "Time"), ("line", "Line")] + [c for c in columns if c[0] not in ("time", "line")]
    if "time" not in keys or "line" not in keys:
        pass
    rows = list(rows)
    return {"type": "table", "title": title, "columns": [{"key": k, "label": l} for k, l in cols],
            "rows": rows[:limit], "total": len(rows), "note": note, "id": key or re.sub(r"\W+", "-", title.lower())}


def bar(title, data, unit="", note=None, refs=None):
    return {"type": "bar", "title": title, "data": [{"label": k, "value": v} for k, v in data if v], "unit": unit,
            "note": note}


def stacked(title, categories, series, note=None):
    return {"type": "stacked", "title": title, "categories": categories,
            "series": [s for s in series if any(s["values"])], "note": note}


def kpis(items):
    return {"type": "kpis", "items": items}


def md(text):
    return {"type": "markdown", "text": text}


# ------------------------------------------------------------------ building blocks
def _client_table(model, clients):
    rows = []
    sess = model["sessions"]
    for c in clients:
        first = next((s for s in sess if s["client"] == c["client"]), None)
        rows.append({"time": first["start"] if first else c.get("first_seen_time", ""),
                     "line": first["start_line"] if first else c["first_seen_line"],
                     "client": c["client"], "device": c["device"], "ssid": c["ssid"], "bands": ", ".join(c["bands"]) or "-",
                     "mlo": "yes" if c["mlo"] else "no", "sessions": c["sessions"], "dut_kickouts": c["dut_kickouts"],
                     "sta_left": c["sta_left"], "reload_drops": c["reload_drops"], "silent": c["silent"],
                     "mlo_rejected": c["mlo_rejected"], "handshake_failed": c["handshake_failed"],
                     "sae_commits": c["sae_commits"], "eapol_retries": c["eapol_retries"],
                     "final": c["final_state"] + (f" (line {c['final_line']})" if c.get("final_line") else "")})
    return table("Clients", [("client", "Client"), ("device", "Device"), ("ssid", "SSID"), ("bands", "Bands"),
                             ("mlo", "MLO"), ("sessions", "Sessions"), ("dut_kickouts", "DUT kickouts"),
                             ("sta_left", "Station left"), ("reload_drops", "Reload drops"), ("silent", "Silent reconnects"),
                             ("mlo_rejected", "MLO link rejected"), ("handshake_failed", "Handshake failed"),
                             ("sae_commits", "SAE commits"), ("eapol_retries", "EAPOL retries"), ("final", "Final state")],
                 rows, note="Time / Line = first connection in the log (or first time the client was seen).", key="clients")


def _disc_table(rows, title="Disconnects"):
    return table(title, [("capture", "Capture"), ("client", "Client"), ("device", "Device"), ("ssid", "SSID"),
                         ("band", "Band"), ("initiator", "Initiator"), ("reason", "Reason"), ("cause", "What the log shows"),
                         ("duration", "Session length")],
                 [{**d, "duration": f"{d['duration_s']} s" if d.get("duration_s") is not None else "-"} for d in rows],
                 key="disconnects")


def _join_table(rows, title="Join failures"):
    return table(title, [("capture", "Capture"), ("client", "Client"), ("kind", "Failure"), ("detail", "Detail"),
                         ("text", "Log line")], rows, key="join-failures")


def _session_table(rows):
    return table("Sessions", [("client", "Client"), ("capture", "Capture"), ("band", "Band"), ("iface", "Interface"),
                              ("end", "Ended"), ("end_line", "End line"), ("end_by", "Ended by"), ("reason", "Reason"),
                              ("cause", "What the log shows")],
                 [{**s, "time": s["start"], "line": s["start_line"],
                   "end_by": dict(KIND_ORDER).get(s["end_by"], "still connected" if s["end_by"] == "open" else s["end_by"]),
                   "reason": s["reason"] or "-"} for s in rows], key="sessions",
                 note="Time / Line = start of the session (AP-STA-CONNECTED); End line = where it ended.")


def _timeline(model, clients=None, title="Connection timeline", window=None):
    out = []
    want = set(clients) if clients is not None else None
    for cap in model["captures"]:
        if window and (cap["end"] < window[0] or cap["start"] > window[1]):
            continue
        ss = [s for s in model["sessions"] if s["capture"] == cap["n"] and (want is None or s["client"] in want)]
        jf = [j for j in model["join_failures"] if j["capture"] == cap["n"] and (want is None or j["client"] in want)]
        if not ss and not jf:
            continue
        lanes = []
        order = []
        for s in ss:
            if s["client"] not in order:
                order.append(s["client"])
        for j in jf:
            if j["client"] and j["client"] not in order:
                order.append(j["client"])
        dev = {c["client"]: c["device"] for c in model["clients"]}
        base = cap["start_epoch"]
        hms0 = cap["start"]

        def rel(hms):  # hh:mm:ss -> seconds from capture start (captures stay inside one day)
            if not hms:
                return None
            h, m, s = map(int, hms.split(":"))
            h0, m0, s0 = map(int, hms0.split(":"))
            return (h * 3600 + m * 60 + s) - (h0 * 3600 + m0 * 60 + s0)
        for cl in order[:40]:
            segs = [{"x0": (s["start_epoch"] or base) - base, "x1": (s["end_epoch"] or base) - base, "band": s["band"],
                     "end_by": s["end_by"], "start": s["start"], "end": s["end"], "line": s["start_line"],
                     "end_line": s["end_line"], "reason": s["reason"], "cause": s["cause"]}
                    for s in ss if s["client"] == cl]
            marks = [{"x": rel(j["time"]), "time": j["time"], "line": j["line"], "kind": j["kind"]}
                     for j in jf if j["client"] == cl and rel(j["time"]) is not None]
            lanes.append({"label": cl, "sub": dev.get(cl, ""), "segments": segs, "marks": marks})
        rl = []
        for r in model["restarts"]:
            t = (r.get("start_time") or "").split()
            if len(t) >= 4 and cap["first_line"] <= r["start_line"] <= cap["last_line"]:
                rl.append({"x": rel(t[3]), "time": t[3], "line": r["start_line"], "label": "Wi-Fi reload"})
        for c in model.get("dfs") or []:
            if c["kind"] == "start" and cap["first_line"] <= c["line"] <= cap["last_line"]:
                rl.append({"x": rel(c["time"]), "x1": rel(c["time"]) + (c.get("cac_s") or 60), "time": c["time"],
                           "line": c["line"], "label": f"DFS wait {c.get('cac_s') or 60} s"})
        out.append({"type": "timeline", "title": f"{title} - capture {cap['n']} ({cap['start']} - {cap['end']})",
                    "start": cap["start"], "duration": (cap["end_epoch"] or base) - base, "lanes": lanes, "events": rl,
                    "note": "One row per client. Bar colour = band; the mark at the end of a bar says who ended the "
                            "session; x = a failed join attempt. Hover a bar for time and line numbers."})
    return out


def _initiator_bar(disc, title="Why clients disconnected"):
    c = Counter(d["initiator"] for d in disc)
    return bar(title, [(lbl, c.get(lbl, 0)) for _, lbl in KIND_ORDER], unit="disconnects")


def _per_client_stacked(disc, top=12, title="Disconnects per client, by who ended the session"):
    per = Counter(d["client"] for d in disc)
    cats = [m for m, _ in per.most_common(top)]
    series = [{"name": lbl, "values": [sum(1 for d in disc if d["client"] == m and d["kind"] == k) for m in cats]}
              for k, lbl in KIND_ORDER]
    return stacked(title, cats, series)


def _findings(model, keep=None):
    items = [f for f in model["findings"] if keep is None or keep(f)]
    return {"type": "findings", "items": items} if items else None


def _filter(model, macs=None, ssids=None, band=None, window=None):
    def ok_c(m, ssid=None):
        return (not macs or m in macs) and (not ssids or (ssid or "") in ssids)
    ssid_of = {c["client"]: c["ssid"] for c in model["clients"]}
    bnorm = band.replace("GHz", " GHz") if band else None
    disc = [d for d in model["disconnects"] if ok_c(d["client"], d["ssid"]) and (not bnorm or d["band"] == bnorm)
            and _in_window(d["time"], window)]
    joinf = [j for j in model["join_failures"] if ok_c(j["client"], ssid_of.get(j["client"]))
             and _in_window(j["time"], window)]
    sess = [s for s in model["sessions"] if ok_c(s["client"], ssid_of.get(s["client"])) and (not bnorm or s["band"] == bnorm)
            and _in_window(s["start"], window)]
    cl = [c for c in model["clients"] if ok_c(c["client"], c["ssid"])]
    return disc, joinf, sess, cl


# ------------------------------------------------------------------ views
def report_view(model, full):
    md_ = full.get("metadata") or {}
    k = model["kpis"]
    caps = model["captures"]
    blocks = [kpis([
        {"label": "Clients connected", "value": k["clients_connected"],
         "note": f"{len(model['clients'])} clients seen on {len(model['ssids'])} SSIDs"},
        {"label": "Disconnects", "value": k["disconnects"],
         "note": f"{k['dut']} DUT kickouts · {k['sta']} station left · {k['reload']} Wi-Fi reload · {k['silent']} silent"},
        {"label": "Join failures", "value": k["join_failures"],
         "note": " · ".join(f"{n} {t}" for t, n in model["join_kinds"].items()) or "none"},
        {"label": "Wi-Fi reloads", "value": len(model["restarts"]),
         "note": f"{sum(1 for c in model.get('dfs') or [] if c['kind'] == 'start')} DFS radar waits"},
        {"label": "Captures", "value": len(caps),
         "note": " · ".join(f"#{c['n']} {c['start']}-{c['end']} ({(c['firmware'] or '').replace('OpenWrt ', '')})" for c in caps)},
    ])]
    f = _findings(model)
    if f:
        blocks.append(f)
    blocks += [_initiator_bar(model["disconnects"]),
               bar("Join failures by type", list(model["join_kinds"].items()), unit="attempts")]
    blocks += _timeline(model)
    blocks.append(_per_client_stacked(model["disconnects"]))
    blocks.append(_client_table(model, model["clients"]))
    blocks.append(_disc_table(model["disconnects"]))
    if model["join_failures"]:
        blocks.append(_join_table(model["join_failures"]))
    blocks.append(_device_table(model))
    if len(caps) > 1:
        blocks += compare_captures(model)
    title = f"Hostapd analysis - {md_.get('test_id')}"
    sub = f"{md_.get('source_file', '')} · SSIDs: {', '.join(model['ssids'])} · bands: {', '.join(model['bands'])}"
    return title, sub, blocks


def _device_table(model):
    rows = []
    sess = model["sessions"]
    for c in model["clients"]:
        first = next((s for s in sess if s["client"] == c["client"]), None)
        rows.append({"time": first["start"] if first else c.get("first_seen_time", ""),
                     "line": first["start_line"] if first else c["first_seen_line"],
                     "client": c["client"], "device": c["device"],
                     "mac_type": "private (randomised)" if c["private_mac"] else "global (vendor OUI)",
                     "wifi7": "yes" if c["mlo"] else "no", "evidence": "; ".join(c["device_evidence"][:3])})
    return table("Device identification", [("client", "Client"), ("device", "Likely device"), ("mac_type", "MAC type"),
                                           ("wifi7", "Wi-Fi 7 / MLO"), ("evidence", "Evidence")], rows, key="devices",
                 note="Best guess from WPS / vendor elements in the client's own request frames and the MAC vendor prefix. "
                      "The exact phone model is not in hostapd logs.")


def compare_captures(model):
    caps = model["captures"]
    if len(caps) < 2:
        return [md("Only one capture is in this log - nothing to compare inside the file. Ask to compare two tests "
                   "(e.g. 'compare TEST_001 with TEST_002') to compare uploaded logs.")]
    a, b = caps[0], caps[1]

    def stat(c):
        n = c["n"]
        d = [x for x in model["disconnects"] if x["capture"] == n]
        j = [x for x in model["join_failures"] if x["capture"] == n]
        s = [x for x in model["sessions"] if x["capture"] == n]
        kc = Counter(x["kind"] for x in d)
        jc = Counter(x["kind"] for x in j)
        return {"Time": f"{c['start']} - {c['end']}", "Log lines": f"{c['first_line']} - {c['last_line']}",
                "Firmware": c["firmware"] or "-", "Operator actions": ", ".join(c["actions"]) or "-",
                "Clients connected": len({x["client"] for x in s}), "Sessions": len(s), "Disconnects": len(d),
                **{lbl: kc.get(k, 0) for k, lbl in KIND_ORDER},
                "Join failures": len(j), **{f"  {t}": jc.get(t, 0) for t in sorted({x["kind"] for x in model["join_failures"]})},
                "Wi-Fi reloads": sum(1 for r in model["restarts"] if c["first_line"] <= r["start_line"] <= c["last_line"])}
    sa, sb = stat(a), stat(b)
    rows = []
    for key in sa:
        va, vb = sa[key], sb[key]
        ch = ""
        if isinstance(va, int) and isinstance(vb, int):
            ch = "same" if va == vb else (f"+{vb - va}" if vb > va else f"{vb - va}")
        rows.append({"metric": key, "a": va, "b": vb, "change": ch})
    cmp_ = {"type": "compare", "title": f"Capture {a['n']} vs capture {b['n']}",
            "left": f"Capture {a['n']} (line {a['first_line']}, {a['start']})",
            "right": f"Capture {b['n']} (line {b['first_line']}, {b['start']})", "rows": rows}
    cats = [lbl for _, lbl in KIND_ORDER] + sorted({x["kind"] for x in model["join_failures"]})
    vals = lambda st: [st.get(c, st.get(f"  {c}", 0)) for c in cats]
    grouped = {"type": "grouped", "title": "Disconnects and join failures per capture", "categories": cats,
               "series": [{"name": f"Capture {a['n']}", "values": vals(sa)}, {"name": f"Capture {b['n']}", "values": vals(sb)}]}
    return [cmp_, grouped]


def compare_tests(sa: dict, sb: dict):
    """sa / sb: summary() of two tests."""
    keys = list(dict.fromkeys(list(sa["metrics"]) + list(sb["metrics"])))
    rows = []
    for k in keys:
        va, vb = sa["metrics"].get(k, 0), sb["metrics"].get(k, 0)
        ch = ("same" if va == vb else (f"+{vb - va}" if vb > va else f"{vb - va}")) if isinstance(va, int) and isinstance(vb, int) else ""
        rows.append({"metric": k, "a": va, "b": vb, "change": ch})
    cats = [lbl for _, lbl in KIND_ORDER]
    return [{"type": "compare", "title": f"{sa['test_id']} vs {sb['test_id']}", "left": sa["test_id"], "right": sb["test_id"],
             "rows": rows},
            {"type": "grouped", "title": "Disconnects by initiator per test", "categories": cats,
             "series": [{"name": sa["test_id"], "values": [sa["metrics"].get(c, 0) for c in cats]},
                        {"name": sb["test_id"], "values": [sb["metrics"].get(c, 0) for c in cats]}]}]


def summary(model) -> dict:
    k = model["kpis"]
    m = {"Clients seen": len(model["clients"]), "Clients connected": k["clients_connected"],
         "Sessions": len(model["sessions"]), "Disconnects": k["disconnects"],
         **{lbl: k.get(key, 0) for key, lbl in KIND_ORDER}, "Join failures": k["join_failures"],
         **{f"  {t}": n for t, n in model["join_kinds"].items()}, "Wi-Fi reloads": len(model["restarts"]),
         "Captures": len(model["captures"]), "Findings": len(model["findings"])}
    return {"test_id": model["test_id"], "metrics": m,
            "findings": [f["title"] for f in model["findings"]],
            "firmware": [c["firmware"] for c in model["captures"]]}


def client_view(model, macs, ev_rows, window=None):
    disc, joinf, sess, cl = _filter(model, macs=set(macs), window=window)
    blocks = []
    for c in cl:
        blocks.append(kpis([
            {"label": c["client"], "value": c["device"], "note": f"{c['ssid']} · {', '.join(c['bands']) or 'never connected'}"
                                                              f" · {'Wi-Fi 7 / MLO' if c['mlo'] else 'single link'}"},
            {"label": "Sessions", "value": c["sessions"], "note": f"final state {c['final_state']} (line {c['final_line']})"},
            {"label": "Disconnects", "value": c["dut_kickouts"] + c["sta_left"] + c["reload_drops"] + c["silent"],
             "note": f"{c['dut_kickouts']} DUT kickout · {c['sta_left']} station left · {c['reload_drops']} reload · {c['silent']} silent"},
            {"label": "Join failures", "value": c["mlo_rejected"] + c["handshake_failed"] + c["auth_not_acked"],
             "note": f"{c['mlo_rejected']} MLO link rejected · {c['handshake_failed']} handshake · {c['auth_not_acked']} auth not ACKed"},
            {"label": "SAE commits / EAPOL retries", "value": f"{c['sae_commits']} / {c['eapol_retries']}",
             "note": "how hard the client had to try to join"},
        ]))
        blocks.append(md("**Device evidence for " + c["client"] + ":** " + "; ".join(c["device_evidence"])))
    f = _findings(model, keep=lambda f: any(m in f["text"] or m in f["title"] for m in macs))
    if f:
        blocks.append(f)
    blocks += _timeline(model, clients=macs, title="Sessions")
    if sess:
        blocks.append(_session_table(sess))
    if disc:
        blocks.append(_disc_table(disc))
    if joinf:
        blocks.append(_join_table(joinf))
    if ev_rows:
        blocks.append(_event_table(ev_rows, "Deauth / disassoc / reassoc / 4-way events"))
    return f"Client {', '.join(macs)}", "Everything the log shows for this client", blocks


def _event_table(rows, title):
    return table(title, [("event", "Event"), ("mac", "Client"), ("ssid", "SSID"), ("sender", "Sent by"),
                         ("reason", "Reason"), ("meaning", "Meaning"), ("detail", "Detail")],
                 [{**r, "time": r.get("hms") or _hms(r.get("time")), "reason": r.get("reason") if r.get("reason") is not None else "-"}
                  for r in rows], key="events")


def events_view(model, ev_rows, types):
    c = Counter(r["event"] for r in ev_rows)
    per = Counter(r["mac"] for r in ev_rows)
    blocks = [kpis([{"label": k, "value": v, "note": ""} for k, v in c.most_common()] or
                   [{"label": "Events", "value": 0, "note": "none of the requested type in the log"}])]
    if ev_rows:
        blocks.append(bar("Events per client", per.most_common(15), unit="events"))
        blocks.append(_event_table(ev_rows, "Events"))
    return "Events: " + (", ".join(types) if types else "deauth / disassoc / reassoc / 4-way"), \
        f"{len(ev_rows)} matching events, de-duplicated (one row per event, not per log line)", blocks


def disconnects_view(model, disc, joinf, window=None, ssids=None):
    k = Counter(d["kind"] for d in disc)
    blocks = [kpis([{"label": "Disconnects", "value": len(disc), "note": f"{len({d['client'] for d in disc})} clients"}]
                   + [{"label": lbl, "value": k.get(key, 0), "note": NOTE[key]} for key, lbl in KIND_ORDER if key in k])]
    f = _findings(model, keep=lambda f: not re.search(r"MLO security|Driver", f["title"]))
    if f:
        blocks.append(f)
    blocks += [_initiator_bar(disc), _per_client_stacked(disc)]
    blocks += _timeline(model, clients=sorted({d["client"] for d in disc}), window=window)
    blocks.append(_disc_table(disc))
    return "Why clients disconnected" + (f" ({', '.join(ssids)})" if ssids else ""), \
        "Every ended session, with who ended it and the log line that proves it", blocks


NOTE = {"dut": "the AP removed the client (no ACKs / inactivity / handshake timeout)",
        "sta": "the client sent deauth / disassoc itself", "reload": "AP interfaces torn down (wifi reload / reconfig)",
        "silent": "client re-joined without a logged disconnect", "handshake": "4-way handshake failed"}


def failures_view(model, joinf):
    blocks = [kpis([{"label": t, "value": n, "note": ""} for t, n in Counter(j["kind"] for j in joinf).most_common()]
                   or [{"label": "Join failures", "value": 0, "note": "none found"}])]
    f = _findings(model, keep=lambda f: re.search(r"MLO|handshake|SAE|auth", f["title"], re.I))
    if f:
        blocks.append(f)
    if joinf:
        blocks.append(bar("Join failures per client", Counter(j["client"] for j in joinf).most_common(15), unit="attempts"))
        blocks.append(_join_table(joinf))
    return "Join failures", "Clients that tried to join and did not get through", blocks


def restarts_view(model):
    rows = []
    for r in model["restarts"]:
        t = (r.get("start_time") or "").split()
        rows.append({"time": t[3] if len(t) >= 4 else "", "line": r["start_line"], "end_line": r["end_line"],
                     "trigger": r["trigger_text"], "events": ", ".join(f"{k} x{v}" for k, v in r["events"].items()),
                     "enabled": r.get("enabled_after") or "no AP-ENABLED afterwards"})
    dfs = [{"time": c["time"], "line": c["line"], "kind": "DFS wait started" if c["kind"] == "start" else "DFS wait finished",
            "text": c["text"]} for c in model.get("dfs") or []]
    blocks = [kpis([{"label": "Wi-Fi reload / restart cycles", "value": len(rows), "note": ""},
                    {"label": "Clients dropped by reloads", "value": model["kpis"]["reload"], "note": ""},
                    {"label": "DFS radar waits", "value": sum(1 for c in dfs if c["kind"].endswith("started")), "note": ""}])]
    f = _findings(model, keep=lambda f: f["side"] == "Expected")
    if f:
        blocks.append(f)
    blocks.append(table("Restart / reconfiguration cycles", [("end_line", "Last line"), ("trigger", "Started with"),
                                                             ("events", "Events"), ("enabled", "AP-ENABLED again at line")],
                        rows, key="restarts"))
    if dfs:
        blocks.append(table("DFS (radar check) events", [("kind", "Event"), ("text", "Log line")], dfs, key="dfs"))
    return "AP restarts and Wi-Fi reloads", "", blocks


VISUAL_RX = (r"\btab(le|les|ular)\b|\bcolumns?\b|\bcharts?\b|\bgraph(s|ical)?\b|\bplot\b|\bvisual|\bpictur|"
             r"\bpictorial|\bpictograph|\bdiagram|\btimeline|\bdetail|\bin depth\b|\bdeep dive|\belaborat|"
             r"\bbreak ?down|\breport\b|\bsummar|\boverview|\bcompar|\bversus\b|\bvs\.?\s|\bstatistic|\bstats\b|"
             r"\bdashboard|\bstep by step\b|\bwhole story\b")


def wants_visual(question: str, u: dict | None = None) -> bool:
    """True when the user asked for a table / detailed explanation / chart / timeline / report: the Workbench then
    shows the answer as a pictographic view (KPI tiles, charts, timeline, tables with event icons). Plain questions
    get only the short answer."""
    u = u or {}
    if set(u.get("shape") or []) & {"table", "timeline", "detailed"}:
        return True
    return any(re.search(VISUAL_RX, (x or "").lower()) for x in (question, u.get("question")))


def build(question: str, u: dict, model: dict, full: dict, ev_rows: list | None, event_select=None,
          other_summaries: list | None = None) -> dict:
    ql = (u.get("question") or question or "").lower()
    macs = [m for m in u.get("macs") or [] if any(c["client"] == m for c in model["clients"])]
    ssids = u.get("ssids") or []
    window = u.get("window")
    hit = {k: bool(re.search(rx, ql)) for k, rx in RX.items()}
    blocks, title, sub = [], "", ""
    if hit["compare"] and other_summaries and len(other_summaries) >= 2:
        title, sub = f"Comparison: {other_summaries[0]['test_id']} vs {other_summaries[1]['test_id']}", ""
        blocks = compare_tests(other_summaries[0], other_summaries[1])
    elif hit["compare"]:
        title, sub, blocks = "Capture comparison", "Same file, two console captures", compare_captures(model)
        f = _findings(model, keep=lambda f: "capture" in f["title"])
        if f:
            blocks.append(f)
    elif macs:
        rows = event_select(ev_rows, macs=macs, window=window) if ev_rows is not None and event_select else []
        title, sub, blocks = client_view(model, macs, rows, window)
    elif hit["events"] and ev_rows is not None and event_select:
        types = [t for t in u.get("events") or [] if t != "auth_fail"]
        rows = event_select(ev_rows, types=types or None, ssids=ssids or None, window=window)
        title, sub, blocks = events_view(model, rows, types)
    elif hit["disconnects"] and not hit["failures"]:
        disc, joinf, sess, cl = _filter(model, ssids=set(ssids) or None, band=u.get("band"), window=window)
        title, sub, blocks = disconnects_view(model, disc, joinf, window, ssids)
    elif hit["restarts"]:
        title, sub, blocks = restarts_view(model)
    elif hit["failures"]:
        disc, joinf, sess, cl = _filter(model, ssids=set(ssids) or None, window=window)
        title, sub, blocks = failures_view(model, joinf)
    elif hit["devices"]:
        title, sub, blocks = "Devices", "", [_device_table(model)]
    elif hit["driver"]:
        title, sub = "Driver / platform warnings", ""
        blocks = [x for x in [_findings(model, keep=lambda f: "Driver" in f["title"])] if x] or [
            md("No driver / platform warning was found.")]
    elif ssids or u.get("band") or window or hit["timeline"] or hit["clients"]:
        disc, joinf, sess, cl = _filter(model, ssids=set(ssids) or None, band=u.get("band"), window=window)
        title = "Clients" + (f" on {', '.join(ssids)}" if ssids else "") + (f" on {u['band']}" if u.get("band") else "") + \
                (f" between {window[0]} and {window[1]}" if window else "")
        sub = f"{len(cl)} clients, {len(sess)} sessions, {len(disc)} disconnects, {len(joinf)} join failures"
        blocks = [_initiator_bar(disc), _per_client_stacked(disc)]
        active = {x["client"] for x in sess} | {x["client"] for x in disc} | {x["client"] for x in joinf}
        if window:
            cl = [c for c in cl if c["client"] in active]
        blocks += _timeline(model, clients=[c["client"] for c in cl], window=window)
        blocks += [_client_table(model, cl), _disc_table(disc)]
        if hit["timeline"]:
            blocks.insert(0, _session_table(sess))
        if joinf:
            blocks.append(_join_table(joinf))
    else:
        title, sub, blocks = report_view(model, full)
    blocks = [b for b in blocks if b and not (b.get("type") in ("bar",) and not b.get("data"))
              and not (b.get("type") == "stacked" and not b.get("series"))]
    return {"title": title, "subtitle": sub, "blocks": blocks, "refs": refs(blocks), "understood": u.get("summary", "")}


def refs(blocks, limit=12) -> list[dict]:
    """(time, line) pairs the answer can cite - findings evidence first, then table rows."""
    out, seen = [], set()
    for b in blocks:
        items = []
        if b["type"] == "findings":
            for f in b["items"]:
                items += [{**e, "about": f["title"]} for e in f["evidence"][:2]]
        elif b["type"] == "table":
            items = [{"time": r.get("time"), "line": r.get("line"), "text": " ".join(str(x) for x in (
                      r.get("client") or r.get("mac"), r.get("text") or r.get("cause") or r.get("detail") or r.get("event")) if x),
                      "about": b["title"]} for r in b["rows"][:4]]
        for e in items:
            if e.get("line") and e["line"] not in seen and e.get("time"):
                seen.add(e["line"])
                out.append({"time": e["time"], "line": e["line"], "text": (e.get("text") or "")[:140], "about": e["about"]})
    return out[:limit]
