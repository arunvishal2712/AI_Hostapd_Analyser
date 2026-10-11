"""
Agentic RAG: investigate one event and its reason through the whole log.

The investigator is a bounded plan-act-observe loop over retrieval tools. It does not let the language model
search: every step is a deterministic query on the store, recorded in a trace (tool, arguments, what was found,
log lines), so the explanation the model writes can be checked step by step.

    1 locate      find the target events (client / type / reason / status / time window); widen if nothing found
    2 anchor      pick up to 3 representative occurrences (first, last, and the one in the asked window)
    3 before      the client's own events in the 60 s before each anchor (what led to it)
    4 around      AP-side events within +-30 s (restart, DFS, driver errors) - is the AP involved?
    5 together    other clients that disconnected within +-5 s - one client or the whole AP?
    6 recurrence  every occurrence of the same event in the whole log, per client and per minute (pattern)
    7 raw         the exact log lines around each anchor
    8 hypotheses  rule-scored causes with supporting and contradicting evidence, side (DUT / STA), confidence,
                  and what would confirm or rule each one out

Cost: every tool is an index lookup or a bounded scan, so one investigation is O(log n + k) - independent of
the log size except for the recurrence counts, which read the event index once (linear in the events).
"""
from __future__ import annotations

from collections import Counter

from common.reason_codes import REASON_CODE_MEANINGS
from engine import rules as R
from engine.retrieval import REASON_Q_RX, STATUS_Q_RX, count_events, events, ev_line, hms_of, ref, types_in

FAILURE_FOCUS = R.FAILURE_TYPES | R.DISCONNECT_TYPES
STA_REASONS = {3: "client is leaving", 8: "client is leaving (disassoc)", 1: "unspecified"}


def _signal_before(store, macs, ts, span=120):
    if ts is None or not macs:
        return None
    b0, b1 = int((ts - span) // 60), int(ts // 60)
    rows = store.q(f"SELECT SUM(n), MIN(mn), MAX(mx), SUM(sm) FROM metrics WHERE key = 'signal' AND bucket BETWEEN ? AND ? "
                   f"AND entity IN ({','.join('?' * len(macs))})", (b0, b1, *macs))
    n, mn, mx, sm = rows[0]
    return {"n": n, "min": mn, "max": mx, "avg": sm / n} if n else None


def investigate(store, question: str, u: dict, ents: dict, max_anchors: int = 3) -> dict:
    trace, evidence = [], []
    res = {"mode": "agent", "title": "Agentic investigation", "answer": [], "evidence": evidence, "tables": [],
           "trace": trace, "hypotheses": []}

    def step(tool, args, found, lines=()):
        trace.append({"step": len(trace) + 1, "tool": tool, "args": args, "found": found, "lines": list(lines)[:6]})

    macs = ents["all_macs"]
    types = types_in(question) & (FAILURE_FOCUS | {"connected", "reassoc_req", "dfs_cac_start", "radar", "ap_disabled",
                                                   "iface_removed", "bss_terminating", "drv_busy", "drv_severed",
                                                   "nft_error", "nl80211_error"})
    extra, eargs = "", []
    rm, sm = REASON_Q_RX.search(question), STATUS_Q_RX.search(question)
    if rm:
        extra += " AND reason = ?"
        eargs.append(int(rm.group(1)))
    if sm:
        extra += " AND status = ?"
        eargs.append(int(sm.group(1)))
    # ---- 1 locate
    target_types = types or FAILURE_FOCUS
    if types & {"fourway_fail", "disconnect_req", "mlo_reject", "sae_fail", "missing_acks", "inactivity", "deauth_rx",
                "disassoc_rx", "auth_no_ack"}:
        # investigate the failures themselves, not the informational frames of the same family (EAPOL started /
        # received / not ACKed, handshake completed) - those are looked at in the "events before" step
        target_types = types - {"eapol_start", "eapol_rx", "eapol_noack", "fourway_ok"}
    found = events(store, target_types, macs or None, None, u, limit=2000, extra=extra, args=eargs)
    exact = count_events(store, target_types, macs or None, None, u, extra=extra, args=eargs)
    if len(found) == 2000:   # keep the true last occurrence as a candidate anchor
        found += events(store, target_types, macs or None, None, u, limit=1, order="line DESC", extra=extra, args=eargs)
    flt = " ".join(f"{k}={v}" for k, v in zip(("reason" if rm else "status", "status"), eargs))
    step("find_events", f"types={','.join(sorted(target_types))[:90]} clients={','.join(ents['macs']) or 'any'}"
                        f" window={'-'.join(u['window']) if u.get('window') else 'whole log'}{' ' + flt if flt else ''}",
         f"{sum(v['n'] for v in exact.values())} event(s)", [e["line"] for e in found[:6]])
    if not found and u.get("window"):
        found = events(store, target_types, macs or None, None, None, limit=2000, extra=extra, args=eargs)
        exact = count_events(store, target_types, macs or None, None, None, extra=extra, args=eargs)
        step("widen", "dropped the time window", f"{len(found)} event(s) in the whole log", [e["line"] for e in found[:6]])
    if not found and types:
        found = events(store, FAILURE_FOCUS, macs or None, None, u, limit=2000)
        exact = count_events(store, FAILURE_FOCUS, macs or None, None, u)
        step("widen", "any failure / disconnect type", f"{len(found)} event(s)", [e["line"] for e in found[:6]])
    if not found:
        res["answer"].append("INCONCLUSIVE - no matching event was found anywhere in the log"
                             + (f" for {', '.join(ents['macs'])}" if ents["macs"] else "") + ".")
        res["coverage"] = store.meta.get("coverage", "")
        return res
    # prefer the decisive event types over their echoes (AP-STA-DISCONNECTED follows the real cause)
    prio = {"fourway_fail": 0, "mlo_reject": 0, "sae_fail": 0, "missing_acks": 1, "inactivity": 1, "disconnect_req": 1,
            "deauth_rx": 2, "disassoc_rx": 2, "unprot": 2, "deauth_local": 2, "auth_no_ack": 2, "akm_invalid": 3,
            "deauth_tx": 4, "disassoc_tx": 4, "disconnected": 5}
    decisive = [e for e in found if prio.get(e["type"], 3) <= 4] or found
    tc = Counter({t: v["n"] for t, v in exact.items()})
    # ---- 2 anchors
    anchors = [decisive[0]]
    if len(decisive) > 1:
        anchors.append(decisive[-1])
    if len(decisive) > 2:
        anchors.append(decisive[len(decisive) // 2])
    anchors = list({a["line"]: a for a in anchors}.values())[:max_anchors]
    step("pick_anchors", "first / middle / last decisive occurrence",
         "; ".join(f"line {a['line']} {a['hms'] or ''} {R.LABELS.get(a['type'], a['type'])}" for a in anchors),
         [a["line"] for a in anchors])
    scores = Counter()
    support, against = {}, {}
    # base rate: how many other clients disconnect in any 10 s window anyway (busy test beds churn all the time)
    span = (store.meta.get("last_ts") or 0) - (store.meta.get("first_ts") or 0)
    n_disc = sum(v["n"] for v in count_events(store, R.DISCONNECT_TYPES).values())
    expected = (n_disc / span * 10.0) if span > 0 else 0.0
    n_drv = sum(v["n"] for v in count_events(store, {"drv_busy", "drv_severed", "nl80211_error"}).values())
    expected_drv = (n_drv / span * 60.0) if span > 0 else 0.0

    def vote(h, w, line, why):
        scores[h] += w
        (support if w > 0 else against).setdefault(h, []).append((line, why))

    atab = []
    for a in anchors:
        mac = a["mac"]
        ms = [mac] + (ents["links"].get(mac, []) if mac else [])
        for o, ls in ents["links"].items():
            if mac in ls:
                ms = [o] + ls
        ts = a["ts"]
        # ---- 3 before: the client's own chain
        chain = []
        if mac and ts is not None:
            chain = store.q(f"SELECT line, hms, type, reason, detail FROM all_events WHERE mac IN ({','.join('?' * len(ms))})"
                            f" AND ts BETWEEN ? AND ? AND line <= ? ORDER BY line", (*ms, ts - 60, ts, a["line"]))
        cc = Counter(r[2] for r in chain)
        step("events_before", f"{mac} 60 s before line {a['line']}",
             ", ".join(f"{R.LABELS.get(t, t)} x{n}" for t, n in cc.most_common(6)) or "nothing logged",
             [r[0] for r in chain[-6:]])
        # ---- 4 around: AP-side context
        around = []
        if ts is not None:
            around = store.q(f"SELECT line, hms, type, iface, detail FROM all_events WHERE ts BETWEEN ? AND ? AND type IN "
                             f"({','.join('?' * len(R.AP_TYPES))}) ORDER BY line", (ts - 30, ts + 30, *sorted(R.AP_TYPES)))
        ac = Counter(r[2] for r in around)
        step("ap_context", f"+-30 s around line {a['line']}",
             ", ".join(f"{R.LABELS.get(t, t)} x{n}" for t, n in ac.most_common(6)) or "no AP-side event",
             [r[0] for r in around[:6]])
        # ---- 5 together
        together = []
        if ts is not None:
            together = store.q(f"SELECT DISTINCT mac FROM all_events WHERE ts BETWEEN ? AND ? AND mac IS NOT NULL AND "
                               f"type IN ({','.join('?' * len(R.DISCONNECT_TYPES))}) AND mac NOT IN ({','.join('?' * len(ms))})",
                               (ts - 5, ts + 5, *sorted(R.DISCONNECT_TYPES), *ms))
        step("co_affected", f"other clients disconnecting +-5 s of line {a['line']}",
             f"{len(together)} client(s)" + (": " + ", ".join(r[0] for r in together[:6]) if together else ""))
        # ---- 7 raw context
        raw = [ref(store, n, "anchor" if n == a["line"] else "context") for n in range(a["line"] - 2, a["line"] + 3)]
        evidence.extend(raw)
        sig = _signal_before(store, ms, ts)
        atab.append({"time": a["hms"] or "", "line": a["line"], "event": ev_line(a),
                     "before": ", ".join(f"{R.LABELS.get(t, t)} x{n}" for t, n in cc.most_common(4)) or "-",
                     "ap_side": ", ".join(f"{R.LABELS.get(t, t)} x{n}" for t, n in ac.most_common(3)) or "-",
                     "others": len(together),
                     "signal": f"{sig['min']:.0f}..{sig['max']:.0f} dBm" if sig else "-"})
        # ---- 8 hypothesis votes for this anchor
        teardown = [r for r in around if r[2] in ("ap_disabled", "iface_removed", "bss_terminating") and r[0] <= a["line"]]
        if teardown:
            vote("ap_restart", 3, teardown[-1][0], "AP interfaces went down just before")
        if teardown and len(together) >= 2:
            vote("ap_restart", 2, a["line"], f"{len(together)} other clients dropped at the same time")
        elif len(together) >= max(2, 3 * expected):
            vote("ap_wide", 2, a["line"], f"{len(together)} other clients dropped at the same time "
                                          f"(about {expected:.1f} expected by chance in 10 s)")
        elif together:
            vote("ap_wide", -1, a["line"], f"{len(together)} other client(s) dropped nearby, but about {expected:.1f} drop in any "
                                           f"10 s on this AP anyway - not unusual")
        else:
            vote("ap_wide", -1, a["line"], "no other client dropped at that time")
        if a["type"] in ("fourway_fail", "disconnect_req") and (a["reason"] in (15, 16) or a["type"] == "fourway_fail"):
            if cc.get("eapol_rx"):
                vote("key_mismatch", 3, a["line"], f"client answered {cc['eapol_rx']} EAPOL frame(s) before the timeout")
            else:
                vote("client_silent", 3, a["line"], "no EAPOL reply from the client before the timeout")
            if cc.get("eapol_noack") and not cc.get("eapol_rx"):
                vote("client_silent", 1, a["line"], f"{cc['eapol_noack']} EAPOL frame(s) not ACKed")
        if a["type"] in ("missing_acks", "inactivity", "auth_no_ack", "assoc_no_ack"):
            vote("link_loss", 2, a["line"], R.LABELS.get(a["type"]))
            if sig and sig["min"] is not None and sig["min"] < -75:
                vote("weak_rf", 2, a["line"], f"signal down to {sig['min']:.0f} dBm before")
            elif sig:
                vote("weak_rf", -1, a["line"], f"signal {sig['min']:.0f}..{sig['max']:.0f} dBm before - not weak")
            cur = store.q("SELECT value, line FROM attrs WHERE entity IN (%s) AND key = 'current_ap' ORDER BY line DESC LIMIT 1"
                          % ",".join("?" * len(ms)), ms)
            if cur:
                vote("roaming", 2, cur[0][1], f"client reported current AP {cur[0][0]} (another AP)")
        if a["type"] in ("deauth_rx", "disassoc_rx", "unprot"):
            vote("client_left", 3, a["line"], "the client sent the deauth/disassoc itself"
                 + (f" (reason {a['reason']}: {REASON_CODE_MEANINGS.get(a['reason'], '')})" if a["reason"] is not None else ""))
        if a["type"] in ("mlo_reject", "akm_invalid"):
            vote("mlo_akm", 4, a["line"], a.get("detail") or "MLO link rejected with status 43")
        if a["type"] == "sae_fail":
            vote("sae_password", 3, a["line"], "SAE failure")
        if a["type"] in ("deauth_tx", "disassoc_tx", "deauth_local") and not teardown:
            vote("ap_decision", 2, a["line"], "the AP sent the deauth/disassoc" + (f" (reason {a['reason']})" if a["reason"] else ""))
        drv = [r for r in around if r[2] in ("drv_busy", "drv_severed", "nl80211_error")]
        if drv and len(drv) >= max(2, 3 * expected_drv):
            vote("driver", 1, drv[0][0], f"{len(drv)} driver error(s) within 30 s (about {expected_drv:.1f} expected "
                                         f"in any minute)")
    res["tables"].append({"title": "Investigated occurrences", "columns": ["time", "line", "event", "before", "ap_side",
                                                                         "others", "signal"], "rows": atab})
    # ---- 5b pattern over ALL occurrences (not only the anchors): did the client answer before each 4-way timeout?
    hs = [e for e in found if e["type"] in ("fourway_fail", "disconnect_req") and e["mac"]
          and (e["reason"] in (15, 16) or e["type"] == "fourway_fail")]
    seen_hs = set()
    hs = [e for e in hs if not ((e["mac"], e["line"]) in seen_hs or seen_hs.add((e["mac"], e["line"])))]
    if len(hs) >= 3:
        replied = 0
        for e in hs:
            ms = [e["mac"]]
            for o, ls in ents["links"].items():
                if e["mac"] == o or e["mac"] in ls:
                    ms = [o] + ls
            q_ = store.q(f"SELECT COUNT(*) FROM all_events WHERE mac IN ({','.join('?' * len(ms))}) AND type = 'eapol_rx' "
                         f"AND line BETWEEN ? AND ?" + (" AND ts >= ?" if e["ts"] is not None else ""),
                         (*ms, e["line"] - 20000, e["line"], *([e["ts"] - 60] if e["ts"] is not None else [])))
            replied += 1 if q_[0][0] else 0
        frac = replied / len(hs)
        step("pattern_all_occurrences", f"{len(hs)} handshake timeouts: did the client send EAPOL-Key in the 60 s before?",
             f"client answered before {replied} of {len(hs)} ({frac:.0%})")
        if frac >= 0.6:
            vote("key_mismatch", 4, hs[0]["line"], f"in {replied} of {len(hs)} handshake timeouts the client had answered")
        elif frac <= 0.4:
            vote("client_silent", 4, hs[0]["line"], f"in {len(hs) - replied} of {len(hs)} handshake timeouts the client never answered")
    # ---- 6 recurrence through the whole log
    rec = count_events(store, {a["type"] for a in anchors}, None, None, None)
    per_client = store.q(f"SELECT mac, COUNT(*) FROM all_events WHERE type IN ({','.join('?' * len(anchors))}) AND mac IS NOT NULL"
                         f" GROUP BY mac ORDER BY 2 DESC LIMIT 8", [a["type"] for a in anchors])
    step("recurrence", "same event type(s) in the whole log",
         "; ".join(f"{R.LABELS.get(t, t)} x{v['n']} (lines {v['first_line']}-{v['last_line']})" for t, v in rec.items())
         + " | per client: " + ", ".join(f"{m} x{n}" for m, n in per_client))
    if per_client and len(per_client) == 1 and macs:
        vote("client_specific", 1, anchors[0]["line"], "only this client shows this event")
    # ---- hypotheses
    H = {
        "ap_restart": ("Wi-Fi reload / AP restart dropped the client", "DUT side (expected during reconfiguration)",
                       "Check what triggered the reload (config change, wifi command, crash) at the restart line."),
        "ap_wide": ("AP-wide problem: several clients dropped together", "DUT side",
                    "Correlate with driver / firmware messages and CPU or memory state at that moment."),
        "key_mismatch": ("4-way handshake failed although the client answered - keys / PMK mismatch",
                         "DUT side likely (MLO / SAE / PMKSA handling), client possible",
                         "Retry with PMKSA caching off and on a single band; compare the PMKID / AKM in both directions."),
        "client_silent": ("Client did not answer the 4-way handshake", "STA side",
                          "Check client power save / RF at that time; capture over the air to see if EAPOL M1 reached it."),
        "link_loss": ("Link loss - the client stopped acknowledging frames", "STA side or RF",
                      "Check distance / RSSI and whether the client roamed; take an iw station dump before the drop."),
        "weak_rf": ("Weak radio signal before the drop", "RF environment", "Move the client closer or check antennas / TX power."),
        "roaming": ("Client roamed to another AP", "STA side (expected if the other AP is part of the test)",
                    "Confirm the other AP's BSSID belongs to the test bed."),
        "client_left": ("Client left on its own (it sent the deauth/disassoc)", "STA side",
                        "Check the client's own logs for why it disconnected (user action, band steering, roaming)."),
        "mlo_akm": ("MLO link rejected: key management differs between the AP MLD links", "DUT side (configuration)",
                    "Make sae / sae-ext-key identical on every BSS of the AP MLD and retest."),
        "sae_password": ("SAE authentication failed - password / SAE group mismatch", "configuration",
                         "Verify the passphrase and sae_groups on both sides."),
        "ap_decision": ("The AP decided to disconnect the client", "DUT side",
                        "Look at the hostapd reason in the lines before the deauth."),
        "driver": ("Driver errors around the event", "DUT side (platform)", "Pass the driver lines to the platform team."),
        "client_specific": ("Only this client shows the problem", "STA side more likely", "Repeat with another client."),
    }
    ranked = [(h, sc) for h, sc in scores.most_common() if sc > 0 and h in H]
    total = sum(sc for _, sc in ranked) or 1
    hyp_rows = []
    for h, sc in ranked[:5]:
        title, side, confirm = H[h]
        conf = "High" if sc / total >= 0.5 and sc >= 3 else "Medium" if sc >= 2 else "Low"
        sup = support.get(h, [])
        con = against.get(h, [])
        res["hypotheses"].append({"id": h, "title": title, "side": side, "confidence": conf, "score": sc,
                                  "support": sup[:4], "against": con[:3], "confirm": confirm})
        hyp_rows.append({"line": sup[0][0] if sup else "", "hypothesis": title, "side": side, "confidence": conf,
                         "evidence": "; ".join(f"line {l}: {w}" for l, w in sup[:3]),
                         "against": "; ".join(f"line {l}: {w}" for l, w in con[:2]) or "-", "confirm": confirm})
        evidence.extend(ref(store, l, title) for l, _ in sup[:2])
    step("score_hypotheses", f"{len(scores)} candidate cause(s)",
         "; ".join(f"{H[h][0]} ({sc})" for h, sc in ranked[:4]) or "no rule fired")
    res["tables"].append({"title": "Hypotheses (ranked)", "columns": ["line", "hypothesis", "side", "confidence",
                                                                    "evidence", "against", "confirm"], "rows": hyp_rows})
    who = ", ".join(ents["macs"]) or "the clients"
    res["answer"].append(f"Investigated {sum(tc.values())} matching event(s) for {who} "
                         f"({', '.join(f'{R.LABELS.get(t, t)} x{n}' for t, n in tc.most_common(5))}); "
                         f"{len(anchors)} occurrence(s) examined in detail.")
    if ranked:
        h0 = res["hypotheses"][0]
        res["answer"].append(f"Most supported cause: {h0['title']} - {h0['side']}, confidence {h0['confidence']} "
                             f"(evidence: " + "; ".join(f"line {l}: {w}" for l, w in h0["support"][:3]) + ").")
        for h in res["hypotheses"][1:3]:
            res["answer"].append(f"Also possible: {h['title']} ({h['side']}, {h['confidence']}).")
    else:
        res["answer"].append("INCONCLUSIVE - the events were found but no cause rule matched; see the raw lines.")
    res["answer"].append("Recurrence in the whole log: " + "; ".join(
        f"{R.LABELS.get(t, t)} x{v['n']}" for t, v in rec.items()) + " | most affected: "
        + ", ".join(f"{m} x{n}" for m, n in per_client[:5]) + ".")
    res["coverage"] = (f"{store.meta.get('coverage', '')}; investigation read the event index (all occurrences) and "
                       f"{len(anchors)} raw-log windows.")
    seen = set()
    res["evidence"] = [e for e in evidence if not (e["line"] in seen or seen.add(e["line"]))][:24]
    return res
