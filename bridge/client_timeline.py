"""
Per-client timeline - the data behind the Workbench "Timeline" button.

For every client MAC: connections, reconnections (with the time it was offline), disconnections (with how long it
was connected and why the session ended), deauthentication / disassociation (who sent it, the reason code, its
IEEE meaning and a plain-language explanation), join failures, link loss, roaming and the AP restarts that hit it.
Every item carries the hostapd time and the log line.

Built from the v4 engine store only: indexed SQL per client (index ev_mac), so a page costs time linear in that
client's own events, independent of the log size. Nothing here comes from the language model.
"""
from __future__ import annotations

import datetime as _dt
import threading
from collections import OrderedDict

from common.reason_codes import explain_reason, status_meaning

BCAST = "FF:FF:FF:FF:FF:FF"

KIND_OF = {
    "connected": "connect",
    "disconnected": "disconnect",
    "deauth_rx": "deauth", "deauth_tx": "deauth", "deauth_local": "deauth", "disassoc_rx": "deauth",
    "disassoc_tx": "deauth", "unprot": "deauth", "disconnect_req": "deauth",
    "inactivity": "linkloss", "missing_acks": "linkloss",
    "auth_no_ack": "failure", "assoc_no_ack": "failure", "fourway_fail": "failure", "sae_fail": "failure",
    "mlo_reject": "failure", "akm_invalid": "failure", "eap_fail": "failure", "status_fail": "failure",
    "eapol_noack": "failure",
    "reassoc_req": "roam", "btm": "roam",
    "auth_req": "join", "sae_commit": "join", "auth_ok": "join", "assoc_req": "join", "assoc_ok": "join",
    "eapol_start": "join", "eapol_rx": "join", "fourway_ok": "join", "mlo_link_ok": "join",
}
KINDS = ["connect", "disconnect", "deauth", "linkloss", "failure", "roam", "join", "ap"]
KIND_LABEL = {"connect": "Connections", "disconnect": "Disconnections", "deauth": "Deauth / disassoc",
              "linkloss": "Link loss", "failure": "Failures", "roam": "Roaming", "join": "Join steps",
              "ap": "AP events"}
DEFAULT_KINDS = ["connect", "disconnect", "deauth", "linkloss", "failure", "roam", "ap"]

AP_TYPES = ("ap_disabled", "ap_enabled", "bss_terminating", "iface_removed", "config_load", "dfs_cac_start",
            "dfs_cac_done", "radar", "chan_switch")
RESTART = {"ap_disabled", "bss_terminating", "iface_removed", "config_load", "ap_enabled"}
TEARDOWN = ("ap_disabled", "bss_terminating", "iface_removed")

TITLE = {  # type -> (title, sent by)
    "disconnected": ("Disconnected", ""),
    "deauth_tx": ("Deauthentication sent by the AP", "AP"),
    "deauth_rx": ("Deauthentication sent by the client", "Client"),
    "deauth_local": ("AP removed the client (local deauthentication)", "AP"),
    "disassoc_tx": ("Disassociation sent by the AP", "AP"),
    "disassoc_rx": ("Disassociation sent by the client", "Client"),
    "unprot": ("Unprotected deauth / disassoc received", ""),
    "disconnect_req": ("AP security layer requested a disconnect", "AP"),
    "inactivity": ("Inactivity timeout - the client stopped responding", "AP"),
    "missing_acks": ("Link loss - too many missing ACKs", "AP"),
    "auth_no_ack": ("Authentication response not acknowledged by the client", ""),
    "assoc_no_ack": ("Association response not acknowledged by the client", ""),
    "fourway_fail": ("4-way handshake failed", ""),
    "sae_fail": ("WPA3-SAE authentication failed", ""),
    "mlo_reject": ("MLO link rejected", "AP"),
    "akm_invalid": ("Client offered a key management the AP does not accept", ""),
    "eap_fail": ("EAP / RADIUS authentication failed", ""),
    "status_fail": ("Request rejected with a status code", "AP"),
    "eapol_noack": ("EAPOL key frame not acknowledged by the client", ""),
    "reassoc_req": ("Reassociation request (roam / rejoin)", "Client"),
    "btm": ("BSS transition management (steering)", "AP"),
    "auth_req": ("Authentication request", "Client"),
    "sae_commit": ("SAE commit", "Client"),
    "auth_ok": ("Authenticated", ""),
    "assoc_req": ("Association request", "Client"),
    "assoc_ok": ("Associated", ""),
    "eapol_start": ("4-way handshake started", "AP"),
    "eapol_rx": ("EAPOL key frame received from the client", "Client"),
    "fourway_ok": ("4-way handshake completed - keys installed", ""),
    "mlo_link_ok": ("MLO link accepted", ""),
}
EXPLAIN_TYPE = {
    "deauth_local": "hostapd removed the station itself (failed inactivity poll, a disconnect request from the "
                    "security layer, or an AP reconfiguration).",
    "inactivity": "After the inactivity time the AP polled the client, got no answer and disconnected it.",
    "missing_acks": "The driver sent frames to this client without getting ACKs - out of range, radio switched "
                    "off, or heavy interference.",
    "unprot": "With Protected Management Frames (PMF) an unprotected deauth / disassoc is ignored; it can be a "
              "spoofed frame or a client that lost its keys.",
    "auth_no_ack": "The AP answered the authentication request but the client never acknowledged it - weak signal "
                   "or the client already moved on.",
    "assoc_no_ack": "The AP answered the association request but the client never acknowledged it - weak signal "
                    "or the client already moved on.",
    "eapol_noack": "Repeated misses of EAPOL-Key frames end in a 4-way handshake timeout (reason 15).",
    "fourway_fail": "The key exchange did not finish - usually a wrong passphrase or a client that stopped "
                    "answering.",
    "akm_invalid": "The client asked for a key management (e.g. SAE-EXT-KEY or FT) that is not enabled in the AP "
                   "configuration.",
    "sae_fail": "WPA3-SAE failed - wrong password, an unsupported group or an anti-clogging problem.",
    "mlo_reject": "One link of a Wi-Fi 7 multi-link association was refused; the client may stay connected on "
                  "the remaining links.",
    "eap_fail": "Enterprise (802.1X) authentication failed - credentials or the RADIUS server.",
    "disconnect_req": "The WPA authenticator gave up on the client (for example after the 4-way handshake timed "
                      "out) and asked hostapd to disconnect it.",
    "reassoc_req": "The client asked to rejoin / roam onto this BSS.",
}
CAUSE_LABEL = {"station_left": "the client left", "dut_kickout": "the AP disconnected the client",
               "ap_restart": "AP restart / Wi-Fi reload", "silent_reconnect": "it reconnected without a logged "
               "disconnect", "handshake_failed": "the 4-way handshake failed", "unknown": "cause not logged",
               "open": "still connected at the end of the log"}
SEL = "line, ts, hms, type, mac, peer, iface, reason, status, detail"

_LOCK = threading.Lock()
_OVERVIEW: dict = {}
_CLIENT: "OrderedDict" = OrderedDict()


# ---------------------------------------------------------------------------- helpers
def dur(sec) -> str:
    if sec is None:
        return ""
    sec = int(round(max(0, sec)))
    if sec < 60:
        return f"{sec} s"
    if sec < 3600:
        return f"{sec // 60} min {sec % 60:02d} s"
    if sec < 86400:
        return f"{sec // 3600} h {sec % 3600 // 60:02d} min"
    return f"{sec // 86400} d {sec % 86400 // 3600} h"


def _date(ts):
    if ts is None:
        return ""
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return ""


def _key(store):
    return (str(store.db), store.db.stat().st_mtime)


def groups(full: dict) -> tuple[dict, dict]:
    """(alias: any MAC of a client -> client MAC, info: client MAC -> roles info) from the parser's MAC roles."""
    roles = full.get("mac_roles") or {}
    alias, info = {}, {}
    for c in roles.get("clients") or []:
        m = c["mac"].upper()
        alias[m] = m
        for l in c.get("link_addresses") or []:
            alias[l.upper()] = m
        info[m] = c
    for c in full.get("clients") or []:
        m = (c.get("client_mac") or "").upper()
        if m and m not in alias:
            alias[m] = m
            info[m] = {"mac": m, "interfaces": {i: 0 for i in c.get("interfaces") or []}}
    return alias, info


def _ap_macs(full: dict) -> set:
    md = full.get("metadata") or {}
    roles = full.get("mac_roles") or {}
    out = {BCAST}
    for b in (md.get("ap_bss") or []) + (roles.get("ap_bss") or []):
        if isinstance(b, dict) and b.get("mac"):
            out.add(b["mac"].upper())
            out.update(m.upper() for m in b.get("mld_addrs") or [])
    return out


def _bands(full: dict) -> dict:
    md = full.get("metadata") or {}
    out = {}
    for b in md.get("ap_bss") or []:
        f = b.get("freq_mhz")
        if b.get("mac") and f:
            out[b["mac"].upper()] = "2.4 GHz" if f < 3000 else "5 GHz" if f < 5925 else "6 GHz"
    return out


# ---------------------------------------------------------------------------- overview (all clients)
def overview(store, full: dict, devices: dict | None = None) -> dict:
    """Client list with counters + every session (for the swimlane) + AP restart markers. Cached per store."""
    k = _key(store) + (id(full),)
    with _LOCK:
        hit = _OVERVIEW.get(k)
    if hit is not None:
        return _with_devices(hit, devices)
    alias, info = groups(full)
    apm = _ap_macs(full)
    # AP-STA-CONNECTED is definitive: such a MAC is a client even if another rule listed it as an AP address
    apm -= {(r[0] or "").upper() for r in store.q("SELECT DISTINCT mac FROM events WHERE type = 'connected'")}
    counts: dict = {}
    span: dict = {}
    # one grouped pass over the event table (index ev_mac); same-second duplicates of one frame count once
    for tbl in ("events", "events_extra"):
        for mac, typ, n, nd, f, l in store.q(
                f"SELECT mac, type, COUNT(*), COUNT(DISTINCT COALESCE(CAST(ts AS INTEGER), line)), MIN(line), MAX(line) "
                f"FROM {tbl} WHERE mac IS NOT NULL GROUP BY mac, type"):
            m = mac.upper()
            if m in apm:
                continue
            c = alias.get(m)
            if c is None:
                if typ != "connected":
                    continue
                c = alias[m] = m
                info[m] = {"mac": m}
            kind = KIND_OF.get(typ)
            if kind:
                d = counts.setdefault(c, {})
                d[typ] = d.get(typ, 0) + (n if typ in ("connected", "disconnected") else nd)
            s = span.setdefault(c, [f, l])
            s[0], s[1] = min(s[0], f), max(s[1], l)
    t0, t1 = store.meta.get("first_ts"), store.meta.get("last_ts")
    sessions: dict = {}
    for row in store.q("SELECT client, start_line, start_ts, start_hms, end_line, end_ts, end_hms, end_type, reason, "
                       "cause, restart_line FROM sessions ORDER BY start_line"):
        c = alias.get((row[0] or "").upper())
        if c is None:
            continue
        sessions.setdefault(c, []).append({
            "line": row[1], "ts": row[2], "start": row[3] or "", "end_line": row[4], "end_ts": row[5],
            "end": row[6] or "", "end_type": row[7], "reason": row[8], "cause": row[9],
            "cause_text": CAUSE_LABEL.get(row[9], row[9] or ""), "restart_line": row[10]})
    bands = _bands(full)
    clients = []
    for c in sorted(info, key=lambda m: (span.get(m, [10 ** 12])[0], m)):
        if c not in span and c not in sessions:
            continue
        n = counts.get(c, {})
        ss = sessions.get(c, [])
        conn = n.get("connected", 0)
        sec = 0.0
        for s in ss:
            if s["ts"] is not None:
                end = s["end_ts"] if s["end_ts"] is not None else (t1 if s["end_type"] == "open" else None)
                if end is not None:
                    sec += max(0.0, end - s["ts"])
        ri = info.get(c) or {}
        cl = {
            "mac": c, "links": sorted(m for m, v in alias.items() if v == c and m != c),
            "ssids": ri.get("ssids") or [], "interfaces": sorted((ri.get("interfaces") or {}).keys()),
            "bands": sorted({bands[b.upper()] for b in (ri.get("bssids") or []) if b.upper() in bands}),
            "first_line": span.get(c, [None])[0], "last_line": span.get(c, [None, None])[1],
            "n": {"connect": conn, "reconnect": max(0, conn - 1),
                  "disconnect": n.get("disconnected", 0),
                  "deauth": sum(v for t, v in n.items() if KIND_OF.get(t) == "deauth" and t != "unprot"),
                  "failure": sum(v for t, v in n.items() if KIND_OF.get(t) == "failure"),
                  "linkloss": sum(v for t, v in n.items() if KIND_OF.get(t) == "linkloss")},
            "connected_s": round(sec), "connected_time": dur(sec) if ss else "",
            "state": ("connected" if ss and ss[-1]["end_type"] == "open" else
                      "disconnected" if ss else "never connected"),
            "sessions": ss[:400], "sessions_total": len(ss),
        }
        clients.append(cl)
    markers = _restart_markers(store, 0, store.total_lines)
    first_date, last_date = _date(t0), _date(t1)
    res = {"start_ts": t0, "end_ts": t1, "duration": (t1 - t0) if t0 is not None and t1 is not None else None,
           "first_date": first_date, "last_date": last_date, "multi_day": bool(first_date and first_date != last_date),
           "total_lines": store.total_lines, "clients": clients, "ap_restarts": markers[:500]}
    with _LOCK:
        for kk in [kk for kk in _OVERVIEW if kk[0] == k[0]]:
            del _OVERVIEW[kk]
        _OVERVIEW[k] = res
    return _with_devices(res, devices)


def _with_devices(res: dict, devices: dict | None) -> dict:
    devices = devices or {}
    out = dict(res)
    out["clients"] = [dict(c, device=(devices.get(c["mac"]) or {}).get("label") or "") for c in res["clients"]]
    return out


def _restart_markers(store, a: int, b: int, ifaces=None) -> list:
    """AP teardown lines (AP-DISABLED / BSS terminating / interface removed) clustered into restart markers."""
    rows = store.q(f"SELECT {SEL} FROM all_events WHERE type IN ({','.join('?' * len(TEARDOWN))}) "
                   f"AND line BETWEEN ? AND ? ORDER BY line LIMIT 20000", (*TEARDOWN, a, b))
    out = []
    for r in rows:
        if ifaces and r[6] and r[6] not in ifaces:
            continue
        last = out[-1] if out else None
        if last and (r[0] - last["end_line"] <= 400 or (r[1] is not None and last["ts_end"] is not None
                                                          and r[1] - last["ts_end"] <= 15)):
            last["end_line"], last["ts_end"] = r[0], r[1] if r[1] is not None else last["ts_end"]
            if r[6]:
                last["ifaces"].add(r[6])
            continue
        out.append({"line": r[0], "ts": r[1], "ts_end": r[1], "time": r[2] or "", "end_line": r[0],
                    "ifaces": {r[6]} if r[6] else set()})
    for m in out:
        m["ifaces"] = sorted(m["ifaces"])
        m["label"] = "AP restart / Wi-Fi reload"
    return out


# ---------------------------------------------------------------------------- one client
def _merge(rows):
    """Collapse the 2-3 log lines hostapd writes for one frame (e.g. 'RX frame' + 'disassociated') into one item."""
    out = []
    for r in rows:
        line, ts, hms, typ = r[0], r[1], r[2], r[3]
        last = out[-1] if out else None
        if (last and typ == last["type"] and typ not in ("connected", "disconnected")
                and line - last["lines"][-1] <= 60 and (ts is None or last["ts"] is None or abs(ts - last["ts"]) <= 1)):
            last["count"] += 1
            if len(last["lines"]) < 8:
                last["lines"].append(line)
            for i, f in ((5, "peer"), (6, "iface"), (7, "reason"), (8, "status")):
                if last[f] is None and r[i] is not None:
                    last[f] = r[i]
            if r[9] and (not last["detail"] or len(r[9]) > len(last["detail"])):
                last["detail"] = r[9]
            continue
        out.append({"line": line, "ts": ts, "hms": hms or "", "type": typ, "mac": r[4], "peer": r[5], "iface": r[6],
                    "reason": r[7], "status": r[8], "detail": r[9], "count": 1, "lines": [line]})
    return out


def _client_items(store, full: dict, mac: str):
    """All timeline items of one client (every kind), in log order, plus its summary. Cached (small LRU)."""
    k = _key(store) + (mac,)
    with _LOCK:
        hit = _CLIENT.get(k)
        if hit is not None:
            _CLIENT.move_to_end(k)
            return hit
    alias, info = groups(full)
    macs = sorted({m for m, c in alias.items() if c == mac} | {mac})
    ph = ",".join("?" * len(macs))
    rows = store.q(f"SELECT {SEL} FROM events WHERE mac IN ({ph}) UNION ALL "
                   f"SELECT {SEL} FROM events_extra WHERE mac IN ({ph}) ORDER BY line", (*macs, *macs))
    rows = [r for r in rows if r[3] in KIND_OF]
    sess = {r[0]: r for r in store.q(
        f"SELECT start_line, end_line, end_type, reason, cause, restart_line, start_ts, end_ts FROM sessions "
        f"WHERE client IN ({ph}) ORDER BY start_line", tuple(macs))}
    multi = _date(store.meta.get("first_ts")) != _date(store.meta.get("last_ts"))
    items = []
    state, conn_ts, conn_line, last_off_ts, cur_sess = None, None, None, None, None
    n_conn = 0
    for e in _merge(rows):
        typ = e["type"]
        it = {"line": e["line"], "lines": e["lines"], "count": e["count"], "time": e["hms"], "ts": e["ts"],
              "date": _date(e["ts"]) if multi else "", "type": typ, "kind": KIND_OF[typ], "iface": e["iface"] or "",
              "bssid": e["peer"] or "", "detail": e["detail"] or "", "by": TITLE.get(typ, ("", ""))[1],
              "title": TITLE.get(typ, (typ, ""))[0], "explain": EXPLAIN_TYPE.get(typ, ""), "note": "",
              "reason": explain_reason(e["reason"]),
              "status": {"code": int(e["status"]), "meaning": status_meaning(e["status"])} if e["status"] is not None
              else None, "mac": e["mac"] if e["mac"] and e["mac"].upper() != mac else ""}
        if typ == "connected":
            if n_conn == 0:
                it["title"] = "Connected"
            elif state == "connected":
                it["title"] = "Reconnected"
                it["note"] = "connected again although no disconnect was logged for the previous session"
                it["silent"] = True
            else:
                it["title"] = "Reconnected"
                if last_off_ts is not None and e["ts"] is not None:
                    it["note"] = f"after {dur(e['ts'] - last_off_ts)} offline"
                    it["gap_s"] = round(e["ts"] - last_off_ts)
            n_conn += 1
            state, conn_ts, conn_line, cur_sess = "connected", e["ts"], e["line"], sess.get(e["line"])
            it["kind"] = "connect"
            it["n"] = n_conn
            if e["detail"]:
                it["explain"] = e["detail"].replace("auth_alg=", "auth: ").replace("aid=", "AID ")
        elif typ == "disconnected":
            parts = []
            if conn_ts is not None and e["ts"] is not None:
                parts.append(f"was connected {dur(e['ts'] - conn_ts)}")
                it["session_s"] = round(e["ts"] - conn_ts)
            if cur_sess is not None and cur_sess[4]:
                parts.append("ended because " + CAUSE_LABEL.get(cur_sess[4], cur_sess[4]))
                it["cause"] = cur_sess[4]
                if cur_sess[3] is not None and it["reason"] is None:
                    it["reason"] = explain_reason(cur_sess[3])
                if cur_sess[5]:
                    it["restart_line"] = cur_sess[5]
            it["note"] = ", ".join(parts)
            state, last_off_ts, cur_sess = "disconnected", e["ts"], None
        elif KIND_OF[typ] in ("deauth", "linkloss") and state == "connected" and e["ts"] is not None:
            last_off_ts = e["ts"]
        if typ == "mlo_reject" and it["status"] is None:
            it["status"] = {"code": 43, "meaning": status_meaning(43)}
        items.append(it)
    items = _fold(items)
    # AP restarts / DFS on this client's interfaces while it was around
    ifaces = sorted({i["iface"] for i in items if i["iface"]})
    if items:
        a, b = items[0]["line"], items[-1]["line"]
        for m in _restart_markers(store, a, b, set(ifaces) or None):
            items.append({"line": m["line"], "lines": [m["line"], m["end_line"]], "count": 1, "time": m["time"],
                          "ts": m["ts"], "date": _date(m["ts"]) if multi else "", "type": "ap_restart", "kind": "ap",
                          "iface": ", ".join(m["ifaces"]), "bssid": "", "detail": "", "by": "AP", "reason": None,
                          "status": None, "mac": "", "title": "AP restart / Wi-Fi reload",
                          "explain": "The AP took its interfaces down and up again (AP-DISABLED / BSS terminating); "
                                     "every client on them is dropped and must rejoin.",
                          "note": f"lines {m['line']}-{m['end_line']}"})
        for r in store.q(f"SELECT {SEL} FROM all_events WHERE type IN ('dfs_cac_start','dfs_cac_done','radar',"
                         f"'chan_switch') AND line BETWEEN ? AND ? ORDER BY line LIMIT 2000", (a, b)):
            if ifaces and r[6] and r[6] not in ifaces:
                continue
            t = {"dfs_cac_start": "DFS channel check started - 5 GHz off air",
                 "dfs_cac_done": "DFS channel check completed - 5 GHz back on air",
                 "radar": "Radar detected - channel must change", "chan_switch": "Channel switch"}[r[3]]
            items.append({"line": r[0], "lines": [r[0]], "count": 1, "time": r[2] or "", "ts": r[1],
                          "date": _date(r[1]) if multi else "", "type": r[3], "kind": "ap", "iface": r[6] or "",
                          "bssid": "", "detail": r[9] or "", "by": "AP", "reason": None, "status": None, "mac": "",
                          "title": t, "explain": "", "note": ""})
        # broadcast deauth only matters while the client was connected; one item per burst (<= 10 s)
        up, start = [], None
        for i in items:
            if i["type"] == "connected" and start is None:
                start = i["line"]
            elif i["type"] == "disconnected" and start is not None:
                up.append((start, i["line"]))
                start = None
        if start is not None:
            up.append((start, b + 1))
        burst = None
        for r in store.q(f"SELECT {SEL} FROM events WHERE type = 'deauth_tx' AND mac = ? AND line BETWEEN ? AND ? "
                         f"ORDER BY line LIMIT 5000", (BCAST, a, b)):
            if not any(x <= r[0] <= y for x, y in up):
                continue
            if burst and (r[0] - burst["lines"][-1] <= 400 or (r[1] is not None and burst["ts"] is not None
                                                               and r[1] - burst["ts"] <= 10)):
                burst["count"] += 1
                if len(burst["lines"]) < 8:
                    burst["lines"].append(r[0])
                burst["note"] = f"{burst['count']} broadcast deauth frames"
                continue
            burst = {"line": r[0], "lines": [r[0]], "count": 1, "time": r[2] or "", "ts": r[1],
                     "date": _date(r[1]) if multi else "", "type": "bcast_deauth", "kind": "ap",
                     "iface": r[6] or "", "bssid": r[5] or "", "detail": "", "by": "AP", "reason": None,
                     "status": None, "mac": "", "title": "Broadcast deauthentication from the AP",
                     "explain": "The AP told every client on this BSS to leave (sent when a BSS is stopped or "
                                "restarted) while this client was connected.", "note": ""}
            items.append(burst)
        items.sort(key=lambda x: x["line"])
    summary = _summary(items, sess, store.meta.get("last_ts"))
    res = (items, summary, macs)
    with _LOCK:
        _CLIENT[k] = res
        while len(_CLIENT) > 24:
            _CLIENT.popitem(last=False)
    return res


PRIORITY = {"connect": 0, "disconnect": 1, "deauth": 2, "failure": 3, "linkloss": 4, "roam": 5, "join": 6}


def _fold(items):
    """One log line can yield two events (e.g. '4-way handshake failed' + 'disconnect request, reason 15'): keep
    one item and list the other under 'also'. A deauth frame that follows within a few lines without its own
    reason code inherits the reason of the request that caused it."""
    out = []
    for it in items:
        last = out[-1] if out else None
        if last and it["line"] == last["line"]:
            a, b = (last, it) if PRIORITY[last["kind"]] <= PRIORITY[it["kind"]] else (it, last)
            a.setdefault("also", []).append(b["title"])
            for f in ("reason", "status"):
                if a[f] is None and b[f] is not None:
                    a[f] = b[f]
            if a is it:
                it["also"] = it.get("also", []) + last.get("also", [])
                out[-1] = it
            continue
        if (last and it["kind"] == "deauth" and it["reason"] is None and last["reason"] is not None
                and last["kind"] in ("deauth", "failure", "linkloss") and 0 < it["line"] - last["line"] <= 12):
            it["reason"], it["reason_inherited"] = last["reason"], True
            it["note"] = (it["note"] + "; " if it["note"] else "") + f"reason from line {last['line']}"
        out.append(it)
    return out


def _summary(items, sess, last_ts) -> dict:
    n = {k: 0 for k in KINDS}
    reasons: dict = {}
    by = {"AP": 0, "Client": 0}
    for it in items:
        n[it["kind"]] += 1
        if it["kind"] == "deauth" and it["type"] != "unprot":
            if it["by"] in by:
                by[it["by"]] += 1
            if it["reason"] and not it.get("reason_inherited"):
                r = reasons.setdefault(it["reason"]["code"], dict(it["reason"], count=0, by_ap=0, by_client=0,
                                                                  first_line=it["line"], first_time=it["time"]))
                r["count"] += 1
                r["by_ap"] += it["by"] == "AP"
                r["by_client"] += it["by"] == "Client"
    conn = [i for i in items if i["type"] == "connected"]
    gaps = [i.get("gap_s") for i in conn if i.get("gap_s") is not None]
    sec = 0.0
    causes: dict = {}
    for s in sess.values():
        if s[6] is not None:
            end = s[7] if s[7] is not None else (last_ts if s[2] == "open" else None)
            if end is not None:
                sec += max(0.0, end - s[6])
        causes[s[4]] = causes.get(s[4], 0) + 1
    worst = max(gaps) if gaps else None
    return {"connections": len(conn), "reconnections": max(0, len(conn) - 1),
            "silent_reconnects": sum(1 for i in conn if i.get("silent")),
            "disconnections": n["disconnect"], "deauth": n["deauth"], "deauth_by_ap": by["AP"],
            "deauth_by_client": by["Client"], "failures": n["failure"], "linkloss": n["linkloss"], "roams": n["roam"],
            "ap_events": n["ap"], "connected_time": dur(sec) if sess else "", "connected_s": round(sec),
            "longest_offline": dur(worst) if worst is not None else "", "longest_offline_s": worst,
            "reasons": sorted(reasons.values(), key=lambda r: -r["count"]),
            "causes": [{"cause": c, "text": CAUSE_LABEL.get(c, c or ""), "count": v}
                       for c, v in sorted(causes.items(), key=lambda kv: -kv[1])],
            "kinds": {k: n[k] for k in KINDS},
            "state": ("connected" if conn and any(s[2] == "open" for s in sess.values())
                      else "disconnected" if conn else "never connected")}


def client(store, full: dict, mac: str, kinds=None, offset: int = 0, limit: int = 300, raw: bool = True) -> dict:
    """One client's timeline page: items of the selected kinds (offset / limit) with the raw log line of each."""
    mac = mac.upper()
    alias, _ = groups(full)
    mac = alias.get(mac, mac)
    items, summary, macs = _client_items(store, full, mac)
    kinds = [k for k in (kinds or DEFAULT_KINDS) if k in KINDS]
    sel = [i for i in items if i["kind"] in kinds]
    page = [dict(i) for i in sel[max(0, offset):max(0, offset) + max(1, min(limit, 2000))]]
    if raw:
        for i in page:
            i["raw"] = store.line(i["line"]).strip()[:400]
    return {"mac": mac, "macs": macs, "kinds": kinds, "kind_labels": KIND_LABEL, "all_kinds": KINDS,
            "total": len(sel), "total_all": len(items), "offset": offset, "items": page, "summary": summary}


def to_csv_rows(items) -> list[list]:
    out = [["date", "time", "line", "event", "kind", "sent_by", "interface", "bssid", "reason", "reason_meaning",
            "status", "status_meaning", "note", "log_line"]]
    for i in items:
        out.append([i.get("date", ""), i["time"], i["line"], i["title"], KIND_LABEL.get(i["kind"], i["kind"]), i["by"],
                    i["iface"], i["bssid"], (i["reason"] or {}).get("code", ""), (i["reason"] or {}).get("meaning", ""),
                    (i["status"] or {}).get("code", ""), (i["status"] or {}).get("meaning", ""), i["note"],
                    i.get("raw", "")])
    return out
