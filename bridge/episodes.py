"""
Disconnect episodes per client, read straight from the raw hostapd log (one pass, cached per file).

For every client MAC (and its Wi-Fi 7 link addresses) each disconnect is grouped into an EPISODE:
consecutive disconnect markers for that MAC within EPISODE_GAP lines.  Every episode gets
  * who sent the deauth/disassoc (AP / client / not logged)
  * the reason code(s) in the log
  * a CAUSE LABEL chosen from the evidence in that episode, by priority:
      AP teardown  > key-handshake timeout > inactivity > driver/ACK failure > client left
      > unprotected (PMF-ignored) deauth/disassoc > AP local request > other
  * the log line that proves it (line number + text)
The label is an evidence summary, not a proven root cause (SKILL: correlation is not causation).
"""
from __future__ import annotations

import bisect
import re
from collections import Counter

MAC = r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}"
MAC_RX = re.compile(MAC)
TS_RX = re.compile(r"^((?:\w{3}\s+\w{3}\s+\d+\s+)?\d{1,2}:\d{2}:\d{2}(?:\s+\d{4})?|\[?\s*\d{3,}\.\d+\]?)")
REASON_RX = re.compile(r"reason(?:[ _]?code)?\s*[=:]?\s*\(?(\d+)")
PREFIX_RX = re.compile(r"^.*?hostapd(?:\[\d+\])?:\s*")
EPISODE_GAP = 400          # lines
TEARDOWN_WINDOW = 300      # an AP-wide teardown this many lines before the client's deauth

# (key, needle that must be in the lowercase line, extra regex or None, sender)
MARKERS = [
    ("wpa_disconnect", "authenticator requests disconnect", None, "AP"),
    ("ptk_disconnect", "wpa_ptk entering state disconnect", None, "AP"),
    ("eapol_timeout", "eapol-key timeout", None, "AP"),
    ("retry_limit", "retry limit", None, "AP"),
    ("inactivity", "due to inactivity", None, "AP"),
    ("inactivity", "timeout, sending deauthentication info", None, "AP"),
    ("inactivity", "timeout, sending disassociation info", None, "AP"),
    ("missing_ack", "excessive missing acks", None, "AP"),
    ("no_ack", "did not acknowledge", None, "AP"),
    ("local_deauth", "deauthenticated due to local deauth request", None, "AP"),
    ("unprot", "nl80211_cmd_unprot_", None, "client"),
    ("tx_deauth", "send_mlme", re.compile(r"stype_(?:deauth|disassoc)"), "AP"),
    ("rx_deauth", "rx frame", re.compile(r"stype_(?:deauth|disassoc)"), "client"),
    ("rx_deauth_txt", "deauthentication: sta=", None, "client"),
    ("rx_disassoc_txt", "disassociation: sta=", None, "client"),
    ("rx_disassoc_txt", "disassocation: sta=", None, "client"),      # (sic) hostapd's spelling
    ("ap_sta_disc", "ap_sta_disconnect addr", None, "AP"),
    ("sta_disconnected", "ap-sta-disconnected", None, None),
]
TEARDOWN_NEEDLES = ("deauthenticate all stations", "ap-disabled", "ctrl-event-terminating",
                    "interface state enabled->disabled")
CAUSES = [  # (label, test(markers set, reasons set))
    ("AP interface teardown / restart (AP deauthenticated all stations)", lambda m, r, t: t),
    ("4-way handshake / key exchange timeout - AP disconnected the client",
     lambda m, r, t: bool({"eapol_timeout", "retry_limit"} & m) or bool({15, 16} & r)),
    ("inactivity timeout - AP removed an idle client", lambda m, r, t: "inactivity" in m or 4 in r),
    ("frames not ACKed by the client (link loss / out of range)",
     lambda m, r, t: bool({"missing_ack", "no_ack"} & m) or 34 in r),
    ("client left (client sent deauth/disassoc)",
     lambda m, r, t: bool({"rx_deauth", "rx_deauth_txt", "rx_disassoc_txt"} & m)),
    ("client sent an UNPROTECTED deauth/disassoc (ignored by the AP because of PMF) - client probably left or roamed",
     lambda m, r, t: "unprot" in m),
    ("AP local deauth request", lambda m, r, t: "local_deauth" in m),
    ("AP sent deauth/disassoc (trigger not logged)", lambda m, r, t: "tx_deauth" in m or "ap_sta_disc" in m),
    ("disconnect reported, trigger not logged", lambda m, r, t: True),
]

_CACHE: dict = {}


def _proof_priority(key: str) -> int:
    order = ["wpa_disconnect", "inactivity", "missing_ack", "no_ack", "rx_deauth_txt", "rx_disassoc_txt", "rx_deauth",
             "unprot", "local_deauth", "eapol_timeout", "retry_limit", "ptk_disconnect", "ap_sta_disc", "tx_deauth",
             "sta_disconnected"]
    return order.index(key) if key in order else 99


def _sender_for(key: str, low: str, mac: str) -> str | None:
    if key == "tx_deauth":
        return "AP" if f"da={mac}" in low else None
    if key == "rx_deauth":
        return "client" if f"sa={mac}" in low else None
    if key == "unprot":
        return "client" if f"a2={mac}" in low else None
    return dict((k, s) for k, _, _, s in MARKERS).get(key)


def build(index, macs_with_links: dict[str, list[str]]) -> dict[str, dict]:
    """macs_with_links: {client_mac_upper: [link_mac_upper, ...]} -> {client_mac: summary}."""
    key = (id(index), len(index.low), tuple(sorted(macs_with_links)))
    if key in _CACHE:
        return _CACHE[key]
    alias = {}
    for m, links in macs_with_links.items():
        alias[m.lower()] = m
        for l in links or []:
            alias[l.lower()] = m
    teardown = index.candidates(TEARDOWN_NEEDLES)
    hits: dict[str, list] = {}
    # prefilter: the frame markers (send_mlme / rx frame + stype_deauth|disassoc) are selected by their frame type,
    # so the very frequent other RX/TX frame lines are never read (same result, far less work on large logs)
    # (and only unprotected DEAUTH / DISASSOC events, not the very frequent NL80211_CMD_UNPROT_BEACON ones)
    pre = [m[1] for m in MARKERS if m[1] not in ("send_mlme", "rx frame", "nl80211_cmd_unprot_")] + \
        ["stype_deauth", "stype_disassoc", "nl80211_cmd_unprot_deauth", "nl80211_cmd_unprot_disassoc"]
    for i in index.candidates(pre):
        low = index.low[i]
        if not low:
            continue
        for k, needle, rx, _ in MARKERS:
            if needle in low and (rx is None or rx.search(low)):
                if k == "no_ack" and ("authentication response" in low or "association response" in low):
                    continue
                break
        else:
            continue
        for mac in set(MAC_RX.findall(low)):
            owner = alias.get(mac)
            if not owner:
                continue
            snd = _sender_for(k, low, mac)
            if k in ("tx_deauth", "rx_deauth", "unprot") and snd is None:
                continue
            rm = REASON_RX.search(low)
            hits.setdefault(owner, []).append((i, k, snd, int(rm.group(1)) if rm else None))
    out = {}
    for owner, hs in hits.items():
        eps, cur = [], []
        for h in hs:
            if cur and h[0] - cur[-1][0] > EPISODE_GAP:
                eps.append(cur)
                cur = []
            cur.append(h)
        if cur:
            eps.append(cur)
        rows = []
        for ep in eps:
            marks = {h[1] for h in ep}
            if marks <= {"sta_disconnected"} and len(ep) == 1 and rows and ep[0][0] - rows[-1]["line"] < 2000:
                continue
            reasons = {h[3] for h in ep if h[3] is not None}
            first = ep[0][0]
            j = bisect.bisect_right(teardown, first) - 1
            td = j >= 0 and first - teardown[j] <= TEARDOWN_WINDOW
            cause = next(lbl for lbl, test in CAUSES if test(marks, reasons, td))
            proof = min(ep, key=lambda h: _proof_priority(h[1]))
            senders = Counter(h[2] for h in ep if h[1] in ("tx_deauth", "rx_deauth", "rx_deauth_txt", "rx_disassoc_txt",
                                                            "unprot", "wpa_disconnect", "inactivity", "local_deauth"))
            raw = index.lines[proof[0]]
            ts = TS_RX.search(raw)
            rows.append({
                "line": first + 1, "time": ts.group(1).strip() if ts else None, "cause": cause,
                "reasons": sorted(reasons), "sender": "/".join(s for s in senders if s) or "not logged",
                "proof_line": proof[0] + 1, "proof": PREFIX_RX.sub("", raw).strip()[:130],
                "teardown_line": teardown[j] + 1 if td else None,
            })
        out[owner] = {"episodes": rows, "causes": dict(Counter(r["cause"] for r in rows).most_common())}
    _CACHE.clear()
    _CACHE[key] = out
    return out


def describe(mac: str, summary: dict, max_rows: int = 6) -> str:
    rows = summary.get("episodes") or []
    if not rows:
        return f"DIRECT ANSWER: no disconnect of {mac} was found in the analysed log."
    ex = {}
    for r in rows:
        ex.setdefault(r["cause"], r)
    head = (f"DIRECT ANSWER: {mac} disconnected {len(rows)} time(s) in the log (disconnect episodes read from the raw log). "
            "Causes, most frequent first (count, first proof line):"
            + "".join(f"\n    * x{n} {c} (e.g. line {ex[c]['proof_line']}: {ex[c]['proof'][:110]})"
                      for c, n in summary["causes"].items()))
    body = "".join(
        f"\n    * line {r['line']}" + (f" ({r['time']})" if r.get("time") else "") + f": {r['cause']}"
        + (f", reason {', '.join(map(str, r['reasons']))}" if r["reasons"] else "")
        + f", sent by {r['sender']}"
        + (f", after AP teardown at line {r['teardown_line']}" if r.get("teardown_line") else "")
        for r in rows[:max_rows])
    if max_rows <= 0:
        return head
    more = f" ({len(rows) - max_rows} more not shown)" if len(rows) > max_rows else ""
    return head + f"\n  First {min(len(rows), max_rows)} episodes in time order{more}:" + body


def cause_line(mac: str, summary: dict) -> str:
    c = summary.get("causes") or {}
    return f"{mac}: " + ("; ".join(f"{k.split(' - ')[0].split(' (')[0]} x{n}" for k, n in c.items()) or "none")


# ------------------------------------------------------------------ AP restart / reconfiguration cycles
LIFE_NEEDLES = (("removing interface", "phy/radio removed"), ("interface state enabled->disabled", "interface disabled"),
                ("ap-disabled", "AP-DISABLED"), ("ctrl-event-terminating", "hostapd BSS terminating"),
                ("configuration file:", "configuration (re)loaded"), ("ap-enabled", "AP-ENABLED"),
                ("vap_up_fail", "VAP bring-up failed"))
HMS_RX = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})")
IFACE_RX = re.compile(r"((?:phy\d+-mld\d+|phy\d+-ap\d+|phy\d+\.\d+|wlan[\w.-]*))")
_LCACHE: dict = {}


def ap_restarts(index, gap_s: int = 90) -> list[dict]:
    key = (id(index), len(index.low))
    if key in _LCACHE:
        return _LCACHE[key]
    marks = []
    for i in index.candidates([n for n, _ in LIFE_NEEDLES]):
        low = index.low[i]
        if not low:
            continue
        for needle, label in LIFE_NEEDLES:
            if needle in low:
                t = HMS_RX.search(index.lines[i][:40])
                sec = int(t.group(1)) * 3600 + int(t.group(2)) * 60 + int(t.group(3)) if t else None
                im = IFACE_RX.search(PREFIX_RX.sub("", index.lines[i]))
                marks.append((i, sec, label, im.group(1) if im else None))
                break
    cycles, cur = [], []
    for m in marks:
        if cur and (m[1] is None or cur[-1][1] is None or m[1] - cur[-1][1] > gap_s or m[1] < cur[-1][1] - 3600):
            cycles.append(cur)
            cur = []
        cur.append(m)
    if cur:
        cycles.append(cur)
    out = []
    for c in cycles:
        labels = Counter(x[2] for x in c)
        if not ({"AP-DISABLED", "hostapd BSS terminating", "phy/radio removed", "VAP bring-up failed"} & set(labels)):
            if out and labels.get("AP-ENABLED"):
                out[-1]["enabled_after"] = out[-1].get("enabled_after") or (c[0][0] + 1)
            continue
        first = next((x for x in c if x[2] != "AP-ENABLED"), c[0])
        last = c[-1]
        en = [x for x in c if x[2] == "AP-ENABLED"]
        out.append({
            "start_line": first[0] + 1, "start_time": (TS_RX.search(index.lines[first[0]]) or [None])[0],
            "end_line": last[0] + 1, "trigger": f"{first[2]}" + (f" {first[3]}" if first[3] else ""),
            "trigger_text": PREFIX_RX.sub("", index.lines[first[0]]).strip()[:110],
            "events": dict(labels), "interfaces": sorted({x[3] for x in c if x[3] and "mld" in x[3]}),
            "enabled_after": en[-1][0] + 1 if en else None,
        })
    _LCACHE.clear()
    _LCACHE[key] = out
    return out


def describe_restarts(cycles: list[dict], max_rows: int = 6, direct: bool = True) -> str:
    if not cycles:
        return ("DIRECT ANSWER: NO AP restart found - no AP-DISABLED, BSS terminating or interface-removal line in the "
                "analysed log.")
    rel = [c for c in cycles if "phy/radio removed" in c["events"] or "configuration (re)loaded" in c["events"]]
    back = sum(1 for c in cycles if c.get("enabled_after"))
    head = (("DIRECT ANSWER: YES - the" if direct else "AP restarts: the") + f" AP interfaces went down {len(cycles)} time(s) (restart / reconfiguration cycles, "
            f"events within 90 s grouped); AP-ENABLED was logged again after {back} of them."
            + (f" {len(rel)} cycle(s) started with the radio/phy being removed or the configuration being reloaded - this "
               f"pattern is typical of a wifi reload / reconfiguration (netifd), not of a crash." if rel else ""))
    body = "".join(
        f"\n    * cycle {n}: line {c['start_line']}" + (f" ({c['start_time'].strip()})" if c.get("start_time") else "")
        + f" to line {c['end_line']}, started with '{c['trigger_text']}'; "
        + ", ".join(f"{k} x{v}" for k, v in c["events"].items())
        + (f"; AP-ENABLED again at line {c['enabled_after']}" if c.get("enabled_after") else "; no AP-ENABLED afterwards")
        for n, c in enumerate(cycles[:max_rows], 1))
    more = f"\n    * ... {len(cycles) - max_rows} more cycle(s)" if len(cycles) > max_rows else ""
    return head + body + more
