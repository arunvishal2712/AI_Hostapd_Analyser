"""
Disconnect-class event table (v3.4).

Follows the dashboard helper ``analyze_hostapd_logs`` / ``fail_on_hostapd_disconnections`` used in the test
suites (event types Deauthentication / Disassociation / Reassociation Request / 4-Way HS Timeout, one row per
event with timestamp, MAC, IP / client name, reason code and log snippet, plus the rule "any disconnect-class
event -> FAIL"), with these corrections for hostapd -dd / Wi-Fi 7 logs:

  * role aware: the MAC of a row is the CLIENT (never the AP/BSSID), Wi-Fi 7 link addresses are mapped to the
    client MLD address, and broadcast deauths are reported once as "all stations"
  * who sent it: AP (send_mlme / local request / timeout) or client (RX frame / handle_deauth)
  * one row per event: the 3-6 log lines hostapd writes for one frame are merged into one row
  * reason code from the line itself or from the AP's disconnect decision just before it, with its meaning
  * unprotected deauth/disassoc (ignored because of PMF) and link-loss disconnects are recognised
  * optional IP / client name / device type from LANforge (env HOSTAPD_LANFORGE=host:port), like the helper
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.reason_codes import REASON_CODE_MEANINGS  # noqa: E402

MAC = r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}"
BCAST = "ff:ff:ff:ff:ff:ff"
LABELS = {"deauth": "Deauthentication", "disassoc": "Disassociation", "reassoc": "Reassociation Request",
          "four_way": "4-Way HS Timeout"}
TS_RX = re.compile(r"^((?:\w{3}\s+)?\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?|\d{9,11}\.\d+)")
HMS_RX = re.compile(r"(\d{1,2}:\d{2}:\d{2})")
PREFIX_RX = re.compile(r"^.*?hostapd(?:\[\d+\])?:\s*")
REASON_RX = re.compile(r"reason(?:_code)?[= ]\(?(\d+)")
MERGE_LINES = 30

# (type, needle (lowercase substring), regex with the MAC in group 1, sender, detail)
RULES = [
    ("deauth", "deauthentication: sta=", re.compile(rf"deauthentication: STA=({MAC})", re.I), "client", "deauth frame received from the client"),
    ("deauth", "stype_deauth", re.compile(rf"send_mlme - da=({MAC}) .*STYPE_DEAUTH", re.I), "AP", "AP sent a deauth frame"),
    ("deauth", "stype_deauth", re.compile(rf"RX frame da=\S+ sa=({MAC}) .*STYPE_DEAUTH", re.I), "client", "deauth frame received from the client"),
    ("deauth", "deauthenticated due to", re.compile(rf"STA ({MAC}) IEEE 802\.11: deauthenticated due to (.+)", re.I), "AP", None),
    ("deauth", "timeout, sending deauth", re.compile(rf"Timeout, sending deauthentication info to STA ({MAC})", re.I), "AP", "inactivity / session timeout (ap_handle_timer)"),
    ("deauth", "missing acks", re.compile(rf"STA ({MAC}) IEEE 802\.11: disconnected due to excessive missing ACKs", re.I), "AP", "client stopped ACKing frames (link loss)"),
    ("deauth", "unprot_deauth", re.compile(rf"UNPROT_DEAUTHENTICATE\).* A2=({MAC})", re.I), "client", "UNPROTECTED deauth from the client - ignored by the AP (PMF)"),
    ("disassoc", "disassociate sta", re.compile(rf"disassociate STA ({MAC})", re.I), "AP", "AP disassociated the client"),
    ("disassoc", "stype_disassoc", re.compile(rf"send_mlme - da=({MAC}) .*STYPE_DISASSOC", re.I), "AP", "AP sent a disassoc frame"),
    ("disassoc", "stype_disassoc", re.compile(rf"RX frame da=\S+ sa=({MAC}) .*STYPE_DISASSOC", re.I), "client", "disassoc frame received from the client"),
    ("disassoc", "disassociation: sta=", re.compile(rf"disassociation: STA=({MAC})", re.I), "client", "disassoc frame received from the client"),
    ("disassoc", "disassocation: sta=", re.compile(rf"disassocation: STA=({MAC})", re.I), "client", "disassoc frame received from the client"),
    ("disassoc", "disassociated due to", re.compile(rf"STA ({MAC}) IEEE 802\.11: disassociated due to (.+)", re.I), "AP", None),
    ("disassoc", "timeout, sending disassoc", re.compile(rf"Timeout, sending disassociation info to STA ({MAC})", re.I), "AP", "inactivity timeout (ap_handle_timer)"),
    ("disassoc", "unprot_disassoc", re.compile(rf"UNPROT_DISASSOCIATE\).* A2=({MAC})", re.I), "client", "UNPROTECTED disassoc from the client - ignored by the AP (PMF)"),
    ("reassoc", "reassociation request: sta=", re.compile(rf"reassociation request: STA=({MAC})(?:.*?current_ap=({MAC}))?", re.I), "client", None),
    ("four_way", "requests disconnect", re.compile(rf"requests disconnect: STA ({MAC}) reason (\d+)", re.I), "AP", "4-way handshake / key exchange timeout - AP disconnects the client"),
]
_CACHE: dict = {}


def _alias_map(analysis: dict) -> tuple[dict, dict, set]:
    roles = analysis.get("mac_roles") or {}
    alias, ssid = {}, {}
    for c in roles.get("clients") or []:
        alias[c["mac"].lower()] = c["mac"]
        for l in c.get("link_addresses") or []:
            alias[l.lower()] = c["mac"]
        ssid[c["mac"]] = ", ".join(c.get("ssids") or [])
    for c in analysis.get("clients") or []:
        alias.setdefault(c["client_mac"].lower(), c["client_mac"])
    aps = {b["mac"].lower() for b in (analysis.get("metadata") or {}).get("ap_bss") or roles.get("ap_bss") or []}
    return alias, ssid, aps


def build(index, analysis: dict) -> list[dict]:
    key = (id(index), len(index.low), (analysis.get("metadata") or {}).get("test_id"))
    if key in _CACHE:
        return _CACHE[key]
    alias, ssid_of, aps = _alias_map(analysis)
    mlds = {m.lower() for b in (analysis.get("metadata") or {}).get("ap_bss") or [] for m in b.get("mld_addrs") or []}
    needles = sorted({r[1] for r in RULES})
    cand = index.candidates(needles)
    rows, open_rows = [], {}
    bcast_rows = []
    for i in cand:
        low = index.low[i]
        line = index.lines[i]
        for typ, needle, rx, sender, detail in RULES:
            if needle not in low:
                continue
            m = rx.search(line)
            if not m:
                continue
            mac = m.group(1).lower()
            if mac == BCAST:
                if typ in ("deauth", "disassoc") and (not bcast_rows or i - bcast_rows[-1]["_i"] > MERGE_LINES):
                    bcast_rows.append({"_i": i, "type": typ, "mac": "all stations", "sender": "AP",
                                       "detail": "AP deauthenticated all stations (BSS going down)"})
                break
            if mac in aps:
                break
            client = alias.get(mac, mac.upper())
            reason = None
            if typ == "four_way":
                reason = int(m.group(2))
            else:
                rm = REASON_RX.search(low)
                if rm:
                    reason = int(rm.group(1))
                else:  # the AP's disconnect decision just before the frame carries the reason
                    for j in range(max(0, i - 8), i):
                        if mac in index.low[j]:
                            rj = REASON_RX.search(index.low[j])
                            if rj:
                                reason = int(rj.group(1))
            det = detail or (f"due to {m.group(2).strip()}" if m.lastindex and m.lastindex >= 2 and typ != "reassoc"
                             else None)
            if typ == "reassoc" and m.lastindex and m.lastindex >= 2 and m.group(2):
                cur = m.group(2).lower()
                det = ("reassociation to the same AP" if cur in aps or cur in mlds
                       else f"client reports current AP {cur.upper()} (not a BSSID of this AP - roaming in)")
            k = (typ, client)
            prev = open_rows.get(k)
            if prev and i - prev["_last"] <= MERGE_LINES:
                prev["_last"] = i
                if prev["reason"] is None and reason is not None:
                    prev["reason"] = reason
                if det and (not prev["detail"] or "frame" in (prev["detail"] or "")) and "frame" not in det:
                    prev["detail"] = det
                if prev["sender"] != sender and typ != "four_way":
                    prev["sender"] = prev["sender"] if "UNPROTECTED" in (prev["detail"] or "") else sender
                break
            row = {"_i": i, "_last": i, "type": typ, "mac": client, "sender": sender, "reason": reason,
                   "detail": det}
            open_rows[k] = row
            rows.append(row)
            break
    out = []
    for r in sorted(rows + bcast_rows, key=lambda r: r["_i"]):
        raw = index.lines[r["_i"]]
        ts = TS_RX.search(raw)
        hms = HMS_RX.search(raw[:40])
        out.append({
            "type": r["type"], "event": LABELS[r["type"]], "line": r["_i"] + 1,
            "time": ts.group(1) if ts else "N/A", "hms": hms.group(1) if hms else None,
            "mac": r["mac"], "ssid": ssid_of.get(r["mac"], ""), "sender": r.get("sender", ""),
            "reason": r.get("reason"), "meaning": REASON_CODE_MEANINGS.get(r["reason"]) if r.get("reason") else None,
            "detail": r.get("detail") or "", "snippet": PREFIX_RX.sub("", raw).strip()[:170],
        })
    _CACHE.clear()
    _CACHE[key] = out
    return out


def select(rows: list[dict], types=None, macs=None, ssids=None, window=None) -> list[dict]:
    out = rows
    if types:
        out = [r for r in out if r["type"] in types]
    if macs:
        ms = {m.upper() for m in macs}
        out = [r for r in out if r["mac"] in ms]
    if ssids:
        out = [r for r in out if any(s in (r["ssid"] or "") for s in ssids)]
    if window:
        lo, hi = window
        out = [r for r in out if r["hms"] and lo <= r["hms"].zfill(8) <= hi]
    return out


def counts(rows: list[dict]) -> dict:
    c = {k: 0 for k in LABELS}
    for r in rows:
        c[r["type"]] += 1
    return c


def summary_line(rows: list[dict]) -> str:
    c = counts(rows)
    return (f"Total events: {len(rows)} | Deauth: {c['deauth']} | Disassoc: {c['disassoc']} | "
            f"Reassoc: {c['reassoc']} | 4-Way HS Timeout: {c['four_way']}")


def dashboard_verdict(rows: list[dict]) -> str:
    """Same rule as fail_on_hostapd_disconnections(): any disconnect-class event fails the test."""
    seen = [LABELS[k] for k, v in counts(rows).items() if v]
    return (f"FAIL - observed {', '.join(seen)} event(s) in the hostapd log" if seen
            else "PASS - no deauthentication / disassociation / reassociation / 4-way timeout event")


# ------------------------------------------------------------------ optional LANforge enrichment
_LF: dict = {"t": 0, "map": {}}


def lanforge_info() -> dict:
    """{mac_lower: {ip, client_name, device_type}} from LANforge (env HOSTAPD_LANFORGE=host:port), cached 5 min."""
    mgr = os.environ.get("HOSTAPD_LANFORGE", "").strip()
    if not mgr:
        return {}
    if time.time() - _LF["t"] < 300:
        return _LF["map"]
    out = {}
    try:
        def get(path):
            with urllib.request.urlopen(f"http://{mgr}{path}", timeout=5) as r:
                return json.load(r)
        hosts = {}
        for res in (get("/resource/all") or {}).get("resources", []):
            d = list(res.values())[0]
            if not d.get("phantom"):
                hosts[str(d.get("eid", "")).strip()] = (d.get("user") or d.get("hostname") or d.get("eid") or "").strip()
        for entry in (get("/ports/all/") or {}).get("interfaces", []):
            for pid, p in entry.items():
                if str(p.get("port type", "")).strip().upper() != "WIFI-STA":
                    continue
                mac = str(p.get("mac", "")).lower().strip()
                ip = str(p.get("ip", "")).strip()
                if mac:
                    eid = ".".join(str(pid).split(".")[:2])
                    out[mac] = {"ip": ip if ip and ip != "0.0.0.0" else "N/A",
                                "client_name": hosts.get(eid, str(pid)), "device_type": "Real"}
    except Exception:  # noqa: BLE001 - LANforge not reachable -> no enrichment
        out = _LF["map"]
    _LF.update(t=time.time(), map=out)
    return out


def markdown_table(rows: list[dict], limit: int = 25, enrich: dict | None = None, link: str = "") -> str:
    enrich = enrich or {}
    cols = ["#", "Event", "Time", "Line", "Client MAC", "SSID", "Sent by", "Reason", "Detail"]
    if enrich:
        cols[5:5] = ["IP", "Client name"]
    out = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for n, r in enumerate(rows[:limit], 1):
        e = enrich.get(r["mac"].lower(), {})
        cells = [str(n), r["event"], r["hms"] or r["time"], str(r["line"]), r["mac"], r["ssid"] or "-", r["sender"],
                 (f"{r['reason']} ({r['meaning']})" if r["reason"] and r["meaning"] else str(r["reason"] or "-")),
                 r["detail"] or "-"]
        if enrich:
            cells[5:5] = [e.get("ip", "N/A"), e.get("client_name", "N/A")]
        out.append("| " + " | ".join(c.replace("|", "/") for c in cells) + " |")
    if len(rows) > limit:
        out.append(f"({len(rows) - limit} more event(s) not shown - full table: http://localhost:8811/report/events{link})")
    return "\n".join(out)


def html_report(rows: list[dict], title: str, enrich: dict | None = None) -> str:
    """Stand-alone HTML table in the style of the dashboard helper's Allure attachment."""
    enrich = enrich or {}

    def cell(t):
        return (str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
    body = "".join(
        "<tr>" + "".join(f"<td>{cell(x)}</td>" for x in (
            n, r["event"], r["time"], r["line"], r["mac"], enrich.get(r["mac"].lower(), {}).get("ip", "N/A"),
            enrich.get(r["mac"].lower(), {}).get("client_name", "N/A"), r["ssid"] or "-", r["sender"],
            (f"{r['reason']} - {r['meaning']}" if r["reason"] else "N/A"), r["detail"] or "-", r["snippet"])) + "</tr>\n"
        for n, r in enumerate(rows, 1)) or "<tr><td colspan='12'><em>No matching hostapd events found in log.</em></td></tr>"
    c = counts(rows)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{cell(title)}</title>
<style>body{{font-family:Arial,sans-serif;padding:16px;font-size:13px}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #999;padding:6px 9px;font-size:12px;text-align:left;vertical-align:top}}th{{background:#f0f0f0}}
tr:nth-child(even){{background:#fafafa}}.v{{font-weight:bold}}</style></head><body>
<h2>{cell(title)}</h2>
<p class="v">Dashboard rule: {cell(dashboard_verdict(rows))}</p>
<p>Total events: <b>{len(rows)}</b> | Deauth: <b>{c['deauth']}</b> | Disassoc: <b>{c['disassoc']}</b> |
Reassoc: <b>{c['reassoc']}</b> | 4-Way HS Timeout: <b>{c['four_way']}</b></p>
<table><thead><tr><th>#</th><th>Event</th><th>Timestamp</th><th>Line</th><th>Client MAC</th><th>IP</th>
<th>Client name</th><th>SSID</th><th>Sent by</th><th>Reason code</th><th>Detail</th><th>Log snippet</th></tr></thead>
<tbody>{body}</tbody></table></body></html>"""
