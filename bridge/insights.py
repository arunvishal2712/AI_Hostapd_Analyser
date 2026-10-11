"""
Insights model (v3.5) - everything the visual output area shows, computed deterministically from the raw log.

    captures      PuTTY / console sessions in one file (start, end, firmware, operator actions)
    sessions      per client: connected intervals with band, who ended them (DUT / STA / Wi-Fi reload /
                  silent reconnect) and the reason - drawn as the connection timeline
    disconnects   one row per ended session (time, line, capture, client, device, SSID, band, initiator, reason)
    join_failures MLO link rejected (status 43), 4-way handshake failed (reason 15), auth not ACKed, SAE mismatch
    clients       per client: device, SSID, bands, MLO, sessions, SAE commits, EAPOL retries, problems
    findings      ranked, each with side (DUT / STA / Expected), confidence, next step and log evidence
    kpis          headline numbers

Every item carries the hostapd timestamp and the log line number so the answer can be checked in the raw log.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime

import devices
import episodes as ep_mod

MAC = r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}"
TS_RX = re.compile(r"^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})")
HMS_RX = re.compile(r"(\d{2}:\d{2}:\d{2})")
PREFIX_RX = re.compile(r"^.*?hostapd(?:\[\d+\])?:\s*")
CONNECTED_RX = re.compile(rf"(\S+): AP-STA-CONNECTED ({MAC})", re.I)
ASSOC_RX = re.compile(rf"RX frame da=\S+ sa=({MAC}) bssid=({MAC}) freq=(\d+).*STYPE_(?:RE)?ASSOC_REQ", re.I)
SAE_COMMIT_RX = re.compile(rf"authentication: STA=({MAC}) auth_alg=3 auth_transaction=1", re.I)
PTK_RX = re.compile(rf"WPA: ({MAC}) WPA_PTK entering state (PTKSTART|AUTHENTICATION2)", re.I)
AKM_RX = re.compile(rf"Invalid WPA key mgmt \((0x[0-9a-f]+)\) from ({MAC})", re.I)
REASSOC_AP_RX = re.compile(rf"reassociation request: STA=({MAC}).*?current_ap=({MAC})", re.I)
FW_RX = re.compile(r"OpenWrt\s+([\w.\-]+),\s*([\d.]+)")
AKM_NAMES = {0x4000000: "SAE-EXT-KEY (AKM 24)", 0x400: "SAE (AKM 8)", 0x2: "PSK (AKM 2)", 0x100: "PSK-SHA256 (AKM 6)",
             0x10000: "OWE (AKM 18)", 0x1: "802.1X (AKM 1)"}
BAND = lambda f: "2.4 GHz" if f and f < 3000 else "5 GHz" if f and f < 5925 else "6 GHz" if f else None
INITIATOR = {"reload": "Wi-Fi reload", "sta": "Station left", "dut": "DUT kickout", "silent": "Silent reconnect",
             "handshake": "Handshake failed"}
_CACHE: dict = {}


def ts_of(line: str):
    m = TS_RX.match(line)
    if not m:
        return None, None
    try:
        dt = datetime.strptime(f"{m.group(2)} {m.group(3)} {m.group(7)} {m.group(4)}:{m.group(5)}:{m.group(6)}",
                               "%b %d %Y %H:%M:%S")
        return dt.timestamp(), f"{m.group(4)}:{m.group(5)}:{m.group(6)}"
    except ValueError:
        return None, None


def _ref(index, i: int) -> dict:
    """Evidence reference: hostapd time + 1-based line number + the message text."""
    raw = index.lines[i]
    _, hms = ts_of(raw)
    return {"time": hms or "", "line": i + 1, "text": PREFIX_RX.sub("", raw).strip()[:200]}


def _cause_kind(cause: str) -> str:
    c = cause.lower()
    if "teardown" in c:
        return "reload"
    if "4-way" in c:
        return "handshake"
    if "client left" in c or "unprotected" in c:
        return "sta"
    return "dut"


def captures(index) -> list[dict]:
    starts = [i for i in index.raw_candidates(["PuTTY log", "login as:"])
              if "PuTTY log" in index.lines[i] or index.lines[i].startswith("login as:")]
    # merge a "PuTTY log" header and the "login as:" right after it
    marks = []
    for i in starts:
        if not marks or i - marks[-1] > 50:
            marks.append(i)
    if not marks or marks[0] > 0:
        marks = [0] + marks
    bounds = marks + [len(index.lines)]
    out = []
    for n in range(len(bounds) - 1):
        a, b = bounds[n], bounds[n + 1]
        first = last = None
        for i in range(a, b):
            if TS_RX.match(index.lines[i]):
                first = i
                break
        for i in range(b - 1, a - 1, -1):
            if TS_RX.match(index.lines[i]):
                last = i
                break
        if first is None:
            continue
        fw, actions = None, []
        for i in range(a, min(b, first + 400)):
            l = index.lines[i]
            m = FW_RX.search(l)
            if m and not fw:
                fw = f"OpenWrt {m.group(1)}, {m.group(2)}"
            if "root@" in l:
                for cmd, label in (("vi /etc/config/wireless", "/etc/config/wireless edited"), ("wifi", "wifi reload"),
                                   ("reboot", "reboot"), ("sysupgrade", "sysupgrade (reflash)")):
                    if cmd in l and label not in actions:
                        actions.append(label)
        e0, t0 = ts_of(index.lines[first])
        e1, t1 = ts_of(index.lines[last])
        out.append({"n": len(out) + 1, "first_line": first + 1, "last_line": last + 1, "start": t0, "end": t1,
                    "start_epoch": e0, "end_epoch": e1, "firmware": fw, "actions": actions})
    return out


def build(index, analysis: dict, eps: dict, restarts: list) -> dict:
    key = (id(index), len(index.low), (analysis.get("metadata") or {}).get("test_id"))
    if key in _CACHE:
        return _CACHE[key]
    md = analysis.get("metadata") or {}
    roles = analysis.get("mac_roles") or {}
    rclients = roles.get("clients") or []
    alias, links_of = {}, {}
    for c in rclients:
        alias[c["mac"].lower()] = c["mac"]
        links_of[c["mac"]] = c.get("link_addresses") or []
        for l in c.get("link_addresses") or []:
            alias[l.lower()] = c["mac"]
    ssid_of = {c["mac"]: ", ".join(c.get("ssids") or []) for c in rclients}
    band_of_bss = {b["mac"].lower(): b.get("band") for b in md.get("ap_bss") or []}
    for b in md.get("ap_bss") or []:
        if b.get("freq_mhz"):
            band_of_bss[b["mac"].lower()] = BAND(b["freq_mhz"])
    ap_macs = {b["mac"].lower() for b in md.get("ap_bss") or []} | {
        m.lower() for b in md.get("ap_bss") or [] for m in b.get("mld_addrs") or []}
    caps = captures(index)

    def cap_of(i):
        for c in caps:
            if c["first_line"] - 1 <= i <= c["last_line"] - 1:
                return c["n"]
        return caps[-1]["n"] if caps else 1

    devs = devices.identify(index, links_of)

    # ---------------------------------------------------------------- one pass over the relevant lines
    needles = ["ap-sta-connected", "stype_assoc_req", "stype_reassoc_req", "auth_alg=3 auth_transaction=1",
               "wpa_ptk entering state", "invalid wpa key mgmt", "mld: link: status=43", "reassociation request: sta=",
               "dfs-cac-start", "dfs-cac-completed", "resource busy", "link has been severed", "nft:",
               "eapol-key tx status for sta"]
    conn, last_band, sae, ptk, auth2 = [], {}, Counter(), Counter(), Counter()
    mlo_rej, roam_aps, cac, drv = [], defaultdict(list), [], defaultdict(list)
    eapol_ack0 = set()
    for i in index.candidates(needles):
        line, low = index.lines[i], index.low[i]
        if "ap-sta-connected" in low:
            m = CONNECTED_RX.search(line)
            if m:
                cl = alias.get(m.group(2).lower(), m.group(2).upper())
                conn.append((i, cl, m.group(1), last_band.get(cl)))
            continue
        if "assoc_req" in low:
            m = ASSOC_RX.search(line)
            if m and m.group(2).lower() not in ("ff:ff:ff:ff:ff:ff",):
                cl = alias.get(m.group(1).lower())
                if cl:
                    last_band[cl] = band_of_bss.get(m.group(2).lower()) or BAND(int(m.group(3)))
            continue
        if "auth_transaction=1" in low:
            m = SAE_COMMIT_RX.search(line)
            if m and alias.get(m.group(1).lower()):
                sae[alias[m.group(1).lower()]] += 1
            continue
        if "wpa_ptk entering state" in low:
            m = PTK_RX.search(line)
            if m and alias.get(m.group(1).lower()):
                (ptk if m.group(2).upper() == "PTKSTART" else auth2)[alias[m.group(1).lower()]] += 1
            continue
        if "invalid wpa key mgmt" in low:
            m = AKM_RX.search(line)
            if m:
                ok = any("status=43" in index.low[j] for j in range(i + 1, min(i + 4, len(index.low))))
                if ok:
                    cl = alias.get(m.group(2).lower(), m.group(2).upper())
                    mlo_rej.append({**_ref(index, i), "mac": cl, "akm": AKM_NAMES.get(int(m.group(1), 16), m.group(1)),
                                    "capture": cap_of(i)})
            continue
        if "reassociation request: sta=" in low:
            m = REASSOC_AP_RX.search(line)
            if m and m.group(2).lower() not in ap_macs:
                roam_aps[alias.get(m.group(1).lower(), m.group(1).upper())].append(
                    {**_ref(index, i), "current_ap": m.group(2).upper()})
            continue
        if "dfs-cac" in low:
            cm = re.search(r"cac_time=(\d+)", low)
            cac.append({**_ref(index, i), "kind": "start" if "start" in low else "done",
                        "cac_s": int(cm.group(1)) if cm else None})
            continue
        if "eapol-key tx status for sta" in low and "ack=0" in low:
            mm = re.search(rf"STA ({MAC})", line, re.I)
            if mm:
                eapol_ack0.add(alias.get(mm.group(1).lower(), mm.group(1).upper()))
            if len(drv["eapol_ack0"]) < 3:
                drv["eapol_ack0"].append(_ref(index, i))
            continue
        for k, nd in (("resource_busy", "resource busy"), ("link_severed", "link has been severed"), ("nft", "nft:")):
            if nd in low and (k != "nft" or re.search(r"fail|error|unable|could not", low)):
                drv[k].append(_ref(index, i)) if len(drv[k]) < 3 else None
                drv[k + "_n"] = drv.get(k + "_n", [0]) if isinstance(drv.get(k + "_n"), list) else [0]
                drv[k + "_n"][0] += 1

    # ---------------------------------------------------------------- sessions
    ep_rows = {m: (v.get("episodes") or []) for m, v in (eps or {}).items()}
    sessions, disconnects = [], []
    by_client = defaultdict(list)
    for i, cl, iface, band in conn:
        by_client[cl].append((i, iface, band))
    for cl, cons in by_client.items():
        evs = sorted(ep_rows.get(cl, []), key=lambda r: r["line"])
        for k, (i, iface, band) in enumerate(cons):
            start_line = i + 1
            nxt = cons[k + 1][0] + 1 if k + 1 < len(cons) else None
            cap = cap_of(i)
            cap_end = next((c["last_line"] for c in caps if c["n"] == cap), None)
            end_ev = next((e for e in evs if e["line"] > start_line and (nxt is None or e["line"] < nxt)
                           and (cap_end is None or e["line"] <= cap_end)), None)
            e_start, t_start = ts_of(index.lines[i])
            if end_ev:
                kind = _cause_kind(end_ev["cause"])
                end_line = end_ev["line"]
                reason = ", ".join(map(str, end_ev.get("reasons") or [])) or None
            elif nxt is not None and (cap_end is None or nxt <= cap_end):
                kind, end_line, reason = "silent", nxt, None
            else:
                kind, end_line, reason = "open", cap_end or start_line, None
            e_end, t_end = ts_of(index.lines[end_line - 1])
            s = {"client": cl, "capture": cap, "band": band or "-", "iface": iface, "start": t_start,
                 "start_epoch": e_start, "start_line": start_line, "end": t_end, "end_epoch": e_end,
                 "end_line": end_line, "end_by": kind, "reason": reason,
                 "cause": end_ev["cause"] if end_ev else ("connected until the end of the capture" if kind == "open"
                                                          else "new connection without a disconnect (silent reconnect)")}
            sessions.append(s)
            if kind != "open":
                disconnects.append({"time": t_end or "", "line": end_line, "capture": cap, "client": cl,
                                    "device": devs.get(cl, {}).get("label", "Unknown"), "ssid": ssid_of.get(cl, ""),
                                    "band": band or "-", "initiator": INITIATOR[kind], "kind": kind,
                                    "reason": reason or "-", "cause": s["cause"],
                                    "duration_s": round(e_end - e_start) if e_end and e_start else None})
    sessions.sort(key=lambda s: s["start_line"])
    disconnects.sort(key=lambda d: d["line"])

    # ---------------------------------------------------------------- join failures
    joinf = [{"time": r["time"], "line": r["line"], "capture": r["capture"], "client": r["mac"],
              "kind": "MLO link rejected", "detail": f"status 43 - client offered {r['akm']}, the affiliated link rejected it",
              "text": r["text"]} for r in mlo_rej]
    for e in analysis.get("events") or []:
        if e["event"] == "DISCONNECT_REQUEST" and e.get("reason_code") in (15, 16):
            joinf.append({"time": (HMS_RX.search(e.get("timestamp") or "") or [""])[0] if e.get("timestamp") else "",
                          "line": e["line_no"], "capture": cap_of(e["line_no"] - 1), "client": e.get("client_mac"),
                          "kind": "Handshake failed", "detail": f"4-way handshake timeout, reason {e['reason_code']}",
                          "text": PREFIX_RX.sub("", e.get("message") or "")[:200]})
        elif e["event"] == "AUTH_FAILURE" and e.get("subtype") == "auth_resp_no_ack":
            joinf.append({"time": (HMS_RX.search(e.get("timestamp") or "") or [""])[0] if e.get("timestamp") else "",
                          "line": e["line_no"], "capture": cap_of(e["line_no"] - 1), "client": e.get("client_mac"),
                          "kind": "Auth not ACKed", "detail": "client did not acknowledge the authentication response",
                          "text": PREFIX_RX.sub("", e.get("message") or "")[:200]})
        elif e["event"] == "SAE_FAILURE":
            joinf.append({"time": (HMS_RX.search(e.get("timestamp") or "") or [""])[0] if e.get("timestamp") else "",
                          "line": e["line_no"], "capture": cap_of(e["line_no"] - 1), "client": e.get("client_mac"),
                          "kind": "SAE mismatch", "detail": "SAE confirm mismatch (password / PMK mismatch suspected)",
                          "text": PREFIX_RX.sub("", e.get("message") or "")[:200]})
    joinf.sort(key=lambda j: j["line"])

    # ---------------------------------------------------------------- per-client table
    clients = []
    for c in rclients:
        m = c["mac"]
        ss = [s for s in sessions if s["client"] == m]
        dd = [d for d in disconnects if d["client"] == m]
        jj = [j for j in joinf if j["client"] == m]
        k = Counter(d["kind"] for d in dd)
        clients.append({
            "client": m, "device": devs.get(m, {}).get("label", "Unknown"),
            "device_evidence": devs.get(m, {}).get("evidence", []), "private_mac": devs.get(m, {}).get("private_mac"),
            "ssid": ssid_of.get(m, ""), "bands": sorted({s["band"] for s in ss if s["band"] != "-"}),
            "mlo": bool(links_of.get(m)) or devs.get(m, {}).get("wifi7", False), "sessions": len(ss),
            "first_seen_line": c.get("first_line"),
            "first_seen_time": ts_of(index.lines[c["first_line"] - 1])[1] if c.get("first_line") else "", "final_state": (c.get("last_state") or {}).get("state", "-"),
            "final_line": (c.get("last_state") or {}).get("line"),
            "sae_commits": sae.get(m, 0), "eapol_retries": max(0, ptk.get(m, 0) - auth2.get(m, 0)),
            "dut_kickouts": k.get("dut", 0), "sta_left": k.get("sta", 0), "reload_drops": k.get("reload", 0),
            "silent": k.get("silent", 0), "handshake_failed": sum(1 for j in jj if j["kind"] == "Handshake failed"),
            "mlo_rejected": sum(1 for j in jj if j["kind"] == "MLO link rejected"),
            "auth_not_acked": sum(1 for j in jj if j["kind"] == "Auth not ACKed"),
        })
    clients.sort(key=lambda c: -(c["dut_kickouts"] + c["mlo_rejected"] + c["handshake_failed"] + c["sta_left"]
                                 + c["silent"] + c["reload_drops"] * 0.1))

    # ---------------------------------------------------------------- findings (ranked)
    findings = []
    dev = lambda m: devs.get(m, {}).get("label", "Unknown")
    if mlo_rej:
        cl = sorted({r["mac"] for r in mlo_rej})
        never = [m for m in cl if not any(s["client"] == m for s in sessions)]
        caps_hit = sorted({r["capture"] for r in mlo_rej})
        akms = sorted({r["akm"] for r in mlo_rej})
        findings.append({
            "side": "DUT side", "confidence": "High confidence", "impact": 1,
            "title": "MLO security mismatch between affiliated links" + (f" (capture {caps_hit[0]} only)" if len(caps_hit) == 1 and len(caps) > 1 else ""),
            "text": f"When a Wi-Fi 7 client set up an additional link, the DUT rejected that link with status 43 (invalid AKM) "
                    f"{len(mlo_rej)} time(s) for {len(cl)} client(s). The client offered {', '.join(akms)} and the partner "
                    f"BSS on the other band did not accept it." + (f" {len(never)} of them never finished joining: "
                                                                   f"{', '.join(never)}." if never else ""),
            "next": "Make the key management identical on every BSS of the same AP MLD (same sae / sae-ext-key settings "
                    "on the 2.4, 5 and 6 GHz members), then retest the MLO clients.",
            "evidence": mlo_rej[:4]})
    hs = [j for j in joinf if j["kind"] == "Handshake failed"]
    for cl in sorted({j["client"] for j in hs if j["client"]}):
        jj = [j for j in hs if j["client"] == cl]
        replied = sum(1 for j in jj if any(f"received eapol-key from {cl.lower()}" in index.low[x]
                                           for x in range(max(0, j["line"] - 400), j["line"] - 1)))
        findings.append({
            "side": "DUT side" if replied else "STA side", "confidence": "Medium confidence", "impact": 2 if replied else 4,
            "title": f"4-way handshake fails for {cl}" + (" even though it answers" if replied else " - no reply from the client"),
            "text": f"{cl} ({dev(cl)}) failed the 4-way handshake {len(jj)} time(s) (reason 15) at "
                    f"{', '.join(j['time'] for j in jj[:4])}. " +
                    ("The client sent EAPOL-Key replies before each timeout, so the two sides most likely derived different "
                     "keys (PMK / PMKSA handling) - a DUT-side MLO/SAE issue is likely, a client bug is possible."
                     if replied else "No EAPOL-Key reply from the client was logged before the timeout."),
            "next": "Reproduce with this client on one band only and on MLO with PMKSA caching off; if only the MLO case "
                    "fails, raise it with the driver / hostapd team with this log." if replied else
                    "Check the client's Wi-Fi state / power save at that time; retry after the 5 GHz DFS wait.",
            "evidence": [{"time": j["time"], "line": j["line"], "text": j["text"]} for j in jj[:4]]})
    kick = [d for d in disconnects if d["kind"] == "dut" and "ACK" in d["cause"]]
    if kick:
        roam = [m for m in {d["client"] for d in kick} if roam_aps.get(m)]
        findings.append({
            "side": "Mostly STA side" if roam else "DUT side", "confidence": "Medium confidence", "impact": 3,
            "title": "Low-ACK kickouts (client stopped acknowledging frames)" + (" - one client roams to another AP" if roam else ""),
            "text": f"The DUT disconnected clients {len(kick)} time(s) because they stopped acknowledging frames: "
                    + ", ".join(f"{m} x{n}" for m, n in Counter(d['client'] for d in kick).most_common()) + "."
                    + (" " + "; ".join(f"{m} reported current AP {roam_aps[m][0]['current_ap']} (not this DUT) in its "
                                       f"reassociation requests" for m in roam) + "." if roam else ""),
            "next": "Confirm whether the other AP is part of the test bed (expected roaming); otherwise take a sniffer "
                    "capture or an iw station dump before the drop.",
            "evidence": [{"time": d["time"], "line": d["line"], "text": f"{d['client']}: {d['cause']}"} for d in kick[:4]]
            + [roam_aps[m][0] for m in roam[:1]]})
    for c in clients:
        ss = [s for s in sessions if s["client"] == c["client"] and s["end_by"] == "sta" and s["end_epoch"] and s["start_epoch"]]
        bands = [s["band"] for s in ss]
        switches = sum(1 for a, b in zip(bands, bands[1:]) if a != b)
        if len(ss) >= 4 and switches >= 3:
            findings.append({
                "side": "STA side", "confidence": "High confidence", "impact": 4,
                "title": f"{c['client']} ping-pongs between bands",
                "text": f"{c['client']} ({c['device']}) left and rejoined {c['ssid']} {len(ss)} times between {ss[0]['start']} "
                        f"and {ss[-1]['end']}, switching band {switches} times ({' -> '.join(bands[:8])}). Each switch was its "
                        f"own disconnect by the station; the DUT handled every switch.",
                "next": "Treat as a client roaming issue; if band steering is enabled on the DUT, check it is not nudging "
                        "this client.",
                "evidence": [{"time": s["end"], "line": s["end_line"], "text": f"left {s['band']} - {s['cause']}"} for s in ss[:4]]})
    short = [s for s in sessions if s["end_by"] == "sta" and s["start_epoch"] and s["end_epoch"]
             and s["end_epoch"] - s["start_epoch"] <= 60]
    if short:
        findings.append({
            "side": "STA side", "confidence": "Medium confidence", "impact": 5,
            "title": "Short sessions ended by the clients",
            "text": f"{len(short)} session(s) ended by the station within 60 s of connecting: " + ", ".join(
                f"{s['client']} {int(s['end_epoch'] - s['start_epoch'])} s" for s in short[:6]) + ".",
            "next": "Check whether these line up with the start of a traffic test or with a client not getting an IP address.",
            "evidence": [{"time": s["end"], "line": s["end_line"], "text": f"{s['client']}: {s['cause']}"} for s in short[:4]]})
    rel = [d for d in disconnects if d["kind"] == "reload"]
    if restarts:
        cac_s = [c for c in cac if c["kind"] == "start"]
        findings.append({
            "side": "Expected", "confidence": "Test setup", "impact": 6,
            "title": "Wi-Fi reloads drop every client" + (" and take 5 GHz off air for the DFS wait" if cac_s else ""),
            "text": f"{len(rel)} disconnect(s) came from {len(restarts)} Wi-Fi reload / reconfiguration cycle(s) at "
                    + ", ".join(f"{r['start_time'].split()[3] if r.get('start_time') else '?'} (line {r['start_line']})" for r in restarts[:5])
                    + "." + (f" After a reload the 5 GHz BSS waited for the radar (DFS) check {len(cac_s)} time(s), "
                             f"{max(c['cac_s'] or 0 for c in cac_s)} s each, before clients could join it." if cac_s else ""),
            "next": "Start traffic tests at least 60 s after a reload, or use a non-DFS channel / width if the test does "
                    "not need it.",
            "evidence": [{"time": (r.get("start_time") or "").split()[3] if r.get("start_time") else "", "line": r["start_line"],
                          "text": r.get("trigger_text", "")} for r in restarts[:3]] + cac_s[:2]})
    drv_bits = []
    if eapol_ack0:
        drv_bits.append(f"every EAPOL frame was reported as not acknowledged (ack=0) for {len(eapol_ack0)} client(s), "
                        f"including ones that joined fine - the EAPOL TX status is wrong")
    for k, label in (("resource_busy", "'Resource busy' errors"), ("link_severed", "frame commands failed with 'Link has been severed'"),
                     ("nft", "nftables (NFT) errors")):
        if drv.get(k):
            drv_bits.append(f"{drv[k + '_n'][0]} {label}")
    if drv_bits:
        findings.append({
            "side": "DUT side", "confidence": "Low impact", "impact": 7,
            "title": "Driver / platform warnings worth passing to the platform team",
            "text": "; ".join(drv_bits) + ". None of these caused a drop on its own in this log.",
            "next": "Log these as low-priority driver bugs; the EAPOL TX status matters most because hostapd uses it to "
                    "time handshake retries.",
            "evidence": (drv.get("eapol_ack0") or [])[:2] + (drv.get("resource_busy") or [])[:1]
            + (drv.get("link_severed") or [])[:1] + (drv.get("nft") or [])[:1]})
    findings.sort(key=lambda f: f["impact"])

    kc = Counter(d["kind"] for d in disconnects)
    model = {
        "test_id": md.get("test_id"), "file": md.get("source_file"), "captures": caps,
        "ssids": sorted({b.get("ssid") for b in md.get("ap_bss") or [] if b.get("ssid")}),
        "bands": sorted({b.get("band") for b in md.get("ap_bss") or [] if b.get("band")}),
        "sessions": sessions, "disconnects": disconnects, "join_failures": joinf, "clients": clients,
        "findings": findings, "devices": devs,
        "kpis": {"clients_connected": len({s["client"] for s in sessions}), "disconnects": len(disconnects),
                 "join_failures": len(joinf), "reload": kc.get("reload", 0), "sta": kc.get("sta", 0),
                 "dut": kc.get("dut", 0), "silent": kc.get("silent", 0), "handshake": kc.get("handshake", 0)},
        "reasons": dict(Counter(f"Reason {d['reason']}, {INITIATOR[d['kind']].lower()}" if d["reason"] != "-"
                                else f"No reason code, {INITIATOR[d['kind']].lower()}" for d in disconnects).most_common()),
        "join_kinds": dict(Counter(j["kind"] for j in joinf).most_common()),
        "restarts": restarts or [], "dfs": cac,
    }
    _CACHE.clear()
    _CACHE[key] = model
    return model
