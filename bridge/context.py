"""
Query Classifier + Context Aggregator (architecture doc sections 19-22).

    question -> classify() -> query_type + which sources to use (Parser / RAG / MAG / CAG)
             -> build_context() -> one FACTS block, sections in the doc's priority order:

        COMPUTED ANSWER          exact values for this question (parser)          highest authority
        CURRENT TEST STATISTICS  parser statistics of the current log
        REPORT                   pre-filled connectivity report (report questions)
        CLIENT TABLE             per-client status (parser + iw station dump)
        FINDINGS                 deterministic rule results
        CURRENT LOG EVIDENCE     RAG excerpts of the raw log
        HISTORICAL MEMORY        MAG - previous tests only
        TECHNICAL KNOWLEDGE      CAG - Wi-Fi reference, not observations
        MISSING INFORMATION      evidence the question needs but the log does not contain
        ANSWER STYLE             how to lay out the answer for this query type

The LLM reasons over this evidence; it never has to count, search or call tools itself
("LLM should reason about evidence, not manufacture the evidence").
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAG_DIR = ROOT / "cag"
sys.path.insert(0, str(ROOT))
try:
    from common.reason_codes import REASON_CODE_MEANINGS
except Exception:  # noqa: BLE001
    REASON_CODE_MEANINGS = {}

MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import episodes as ep_mod  # noqa: E402
import event_table  # noqa: E402
import skill  # noqa: E402  (runtime skill engine - skills/hostapd_analyzer/SKILL.md)

# ------------------------------------------------------------------ topics (what the question is about)
INTENTS = {
    "disconnect": r"disconnect|deauth|disassoc|drop|kick|left|leave|reason ?code|reason_code|reconnect|session",
    "retries": r"retr|tx fail|failed frame|error rate|loss|lossy",
    "signal": r"signal|rssi|dbm|weak|coverage|range|distance|noise",
    "rate": r"\brate|bitrate|throughput|speed|slow|mcs|nss|phy|mbit|performance|bandwidth",
    "ping": r"ping|latency|delay|rtt|unreachable|packet loss|internet|wan\b|lan\b",
    "mlo": r"mlo|multi.?link|\blink ?[0-2]|6 ?ghz|5 ?ghz|2\.4|band|channel|width|320|160|eht|wi-?fi ?7",
    "security": r"(?<!de)auth|\bassociation|\bre-?assoc|handshake|eapol|4-way|psk|password|sae|wpa|radius|\beap\b|\bkey|pmf|mfp",
    "infra": r"driver|beacon|interface|kernel|firmware|crash|errno|nft|ttlm|platform",
    "clients": r"client|station|\bsta\b|device|which|list|\bmac\b|connected",
    "history": r"history|before|previous|earlier|again|recurr|past|trend",
    "probe": r"probe|scan",
    "lifecycle": r"coming up|come up|bring.?up|\bup\b|start|enable|disable|restart|vap|beacon|bss\b|not working|down\b|interface",
    "overview": r"analy|summar|overview|status|health|root cause|why|problem|issue|report|what happened|verdict|pass|fail",
}
CAG_FOR = {
    "disconnect": ["04_deauth_disassoc_reason_codes.md"],
    "security": ["03_wpa_security_eapol.md", "02_authentication_association.md"],
    "infra": ["07_driver_platform_errors.md"],
    "retries": ["08_rf_station_metrics.md"], "signal": ["08_rf_station_metrics.md"],
    "rate": ["08_rf_station_metrics.md"], "ping": ["08_rf_station_metrics.md"],
    "mlo": ["05_roaming_80211kvr_mlo.md", "08_rf_station_metrics.md"],
    "clients": ["01_80211_client_lifecycle.md"],
    "overview": ["06_hostapd_config_qa_methodology.md"],
    "lifecycle": ["09_ap_bringup_mld.md"],
}

# ------------------------------------------------------------------ query types (doc section 20)
KNOWLEDGE_RX = (r"\bmean(s|ing)?\b|\bexplain|\bdefin(e|ition)|how does|how do .* work|difference between|"
                r"^\s*(what|who)\s+(is|are)\s+(?!the\b|my\b|our\b|this\b|these\b|those\b)|^\s*what's\s+(a|an)\b")
CURRENT_RX = r"\bthis\b|current|upload|\blog\b|\bfile\b|\btest\b|\bmy\b|here|observed|happen|\bour\b"
REPORT_RX = r"report|analy[sz]|summar|overview|health|detailed|\bfull\b|overall|what happened|verdict"
ROOT_RX = r"\bwhy\b|root ?cause|\bcause|reason for|\bfix\b|troubleshoot|debug|solve|recommend|problem|issue|wrong|fault|blame|responsib"
STATS_RX = r"\bcheck\b|whether|is .* working|how many|count|number of|total|\blist\b|\bwhich\b|\bwho\b|statistic|percent|\bshow\b|\bgive\b|\bwhat\b"
COMPARE_RX = r"compare|comparison|\bvs\.?\b|versus|difference|previous test|last test|other test"
HISTORY_RX = INTENTS["history"]

ROUTES = {  # doc section 19 routing table
    "GENERAL_WIFI_KNOWLEDGE": dict(use_parser=False, use_rag=False, use_mag=False, use_cag=True),
    "CURRENT_LOG_ANALYSIS": dict(use_parser=True, use_rag=True, use_mag=True, use_cag=True),
    "CLIENT_ANALYSIS": dict(use_parser=True, use_rag=True, use_mag=True, use_cag=True),
    "TEST_STATISTICS": dict(use_parser=True, use_rag=False, use_mag=False, use_cag=False),
    "HISTORICAL_ANALYSIS": dict(use_parser=True, use_rag=True, use_mag=True, use_cag=False),
    "COMPARISON": dict(use_parser=True, use_rag=False, use_mag=True, use_cag=False),
    "ROOT_CAUSE_ANALYSIS": dict(use_parser=True, use_rag=True, use_mag=True, use_cag=True),
}
REPORT_TYPES = ("CURRENT_LOG_ANALYSIS",)


def detect_intents(q: str) -> list[str]:
    ql = q.lower()
    found = [name for name, rx in INTENTS.items() if re.search(rx, ql)]
    return found or ["overview"]


def classify(question: str, client_macs: list | None = None, ap_macs: list | None = None) -> dict:
    """Query classifier -> {query_type, use_parser, use_rag, use_mag, use_cag, topics}."""
    q = question.lower().strip()
    has_mac = bool(client_macs) or bool(ap_macs)
    if not has_mac and re.search(KNOWLEDGE_RX, q) and not re.search(CURRENT_RX, q) and not re.search(r"client|station", q):
        qt = "GENERAL_WIFI_KNOWLEDGE"
    elif re.search(COMPARE_RX, q):
        qt = "COMPARISON"
    elif re.search(HISTORY_RX, q):
        qt = "HISTORICAL_ANALYSIS"
    elif re.search(REPORT_RX, q) and not has_mac:
        qt = "CURRENT_LOG_ANALYSIS"
    elif re.search(ROOT_RX, q):
        qt = "ROOT_CAUSE_ANALYSIS"
    elif client_macs:
        qt = "CLIENT_ANALYSIS"
    elif ap_macs or re.search(STATS_RX, q):
        qt = "TEST_STATISTICS"
    elif re.search(r"^(?:is|are|does|do|did|has|have|was|were|can)\b|\bare there\b|\bis there\b|\bany\b|\bdid\b|"
                   r"\bdoes\b|\bhas\b|\bhave\b|\bwere\b|\bwas\b", q) \
            and detect_intents(question) != ["overview"]:
        qt = "TEST_STATISTICS"      # focused yes/no question about one topic -> focused answer, not a report
    else:
        qt = "CURRENT_LOG_ANALYSIS"
    return {"query_type": qt, **ROUTES[qt], "topics": detect_intents(question)}


# ------------------------------------------------------------------ helpers
def _fmt(v, unit=""):
    if v is None:
        return "n/a"
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return f"{v}{unit}"


SUB = "\n    * "
PREFIX_CUT = re.compile(r"^.*?hostapd(?:\[\d+\])?:\s*")


def _clean(s: str) -> str:
    # keep the text safe inside Flowise prompt values (JSON + f-string templates)
    return s.replace("\\", "/").replace('"', "'").replace("{", "(").replace("}", ")")


def _cag(topics: list[str], budget: int = 2600, extra: list[str] | None = None) -> str:
    files = list(extra or [])
    for i in topics:
        for f in CAG_FOR.get(i, []):
            if f not in files:
                files.append(f)
    out, used = [], 0
    for f in files[:3]:
        p = CAG_DIR / f
        if not p.exists():
            continue
        room = budget - used
        if room < 300:
            break
        text = p.read_text(encoding="utf-8").strip()[:room]
        out.append(text)
        used += len(text)
    return "\n\n".join(out)


def _ap_macs(md: dict, rf: dict) -> dict:
    """AP address -> description (interface MLD address and every link address)."""
    out = {}
    for itf in rf.get("ap_interfaces") or []:
        if itf.get("addr"):
            out[itf["addr"].upper()] = (f"AP interface {itf.get('interface')} (SSID {itf.get('ssid') or md.get('ssid') or 'n/a'}) "
                                        f"MLD/interface address")
    for l in md.get("ap_links") or []:
        if l.get("addr"):
            d = f"AP link{l['link_id']} {l.get('band')} ch{l.get('channel')} {l.get('width_mhz')}MHz"
            a = l["addr"].upper()
            out[a] = out[a] + " and " + d if a in out else d
    for b in md.get("ap_bss") or []:
        a = (b.get("mac") or "").upper()
        if a and a not in out:
            out[a] = (f"AP BSS {b.get('interface') or ''} (SSID {b.get('ssid') or 'n/a'}; found in "
                      f"{', '.join((b.get('sources') or [])[:3])})").replace("BSS  (", "BSS (")
    return out


def _link_names(md: dict) -> dict:
    return {l["link_id"]: f"link{l['link_id']} {l.get('band')}" for l in md.get("ap_links") or []}


def _events_logged(st: dict) -> bool:
    keys = ("authentication_attempts", "association_successes", "association_failures", "handshake_successes",
            "handshake_failures", "deauthentication_events", "disassociation_events", "sta_connected_events",
            "sta_disconnected_events")
    return any(st.get(k) for k in keys)


def _verdict(fnd: list) -> tuple[str, dict]:
    sev = {}
    for f in fnd:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    if sev.get("critical") or sev.get("high"):
        v = "FAIL"
    elif fnd:
        v = "PASS WITH OBSERVATIONS"
    else:
        v = "PASS"
    return v, sev


def _sev_text(sev: dict) -> str:
    return ", ".join(f"{sev[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if sev.get(k)) or "none"


# ------------------------------------------------------------------ main
def build_context(question: str, a: dict, history: dict | None = None, rag_hits: list | None = None,
                  other_tests: list | None = None, comparison: dict | None = None,
                  log_hits: list | None = None, episodes: dict | None = None,
                  restarts: list | None = None, events: list | None = None, understood: dict | None = None,
                  enrich: dict | None = None, max_chars: int = 12000) -> dict:
    md, st = a.get("metadata", {}), a.get("statistics", {})
    rf = a.get("rf") or {}
    stations = rf.get("stations") or []
    sta_by_mac = {s["mac"]: s for s in stations}
    clients = a.get("clients") or []
    cli_by_mac = {c["client_mac"]: c for c in clients}
    fnd = a.get("findings") or []
    probes = rf.get("probe_requests") or {}
    probe_by_mac = {p["mac"]: p for p in probes.get("per_client") or []}
    aps = _ap_macs(md, rf)
    links = _link_names(md)
    tid = md.get("test_id")

    all_macs = sorted({m.upper().replace("-", ":") for m in MAC_RE.findall(question)})
    ap_macs = [m for m in all_macs if m in aps]
    cli_macs = [m for m in all_macs if m not in aps]
    route = classify(question, cli_macs, ap_macs)
    qt, topics = route["query_type"], route["topics"]
    ql = question.lower()
    events_logged = _events_logged(st)
    verdict, sev = _verdict(fnd)
    assoc = [s for s in stations if s.get("associated")]
    probing_only = [p for p in probes.get("per_client") or [] if p["mac"] not in sta_by_mac and p["mac"] not in cli_by_mac]
    known = sorted(set(sta_by_mac) | set(cli_by_mac))
    roles = a.get("mac_roles") or {}
    role_clients = roles.get("clients") or []
    role_by_mac = {c["mac"]: c for c in role_clients}
    bss = md.get("ap_bss") or roles.get("ap_bss") or []
    ask_ap = bool(re.search(r"\bap\b.*\bmac|\bmac.*\bap\b|bssid|access point|ap address|\bbss\b|beacon", ql))
    ask_cli = bool(re.search(r"client|station|\bsta\b|device|joined|connected|auth.*request|assoc.*request", ql))

    def bss_line(b):
        return (f"{b['mac']} - interface {b.get('interface') or 'n/a'}, SSID {b.get('ssid') or 'n/a'}"
                + (f", link {b['link_id']}" if b.get("link_id") is not None else "")
                + f"; evidence: {', '.join((b.get('sources') or [])[:4])}"
                + (f" (first at line {b['first_line']}: {b.get('sample', '')[-110:]})" if b.get("first_line") else "")
                + (f"; events: {', '.join(sorted(set(b.get('events') or [])))}" if b.get("events") else ""))

    def ssid_groups():
        g = {}
        for b in bss:
            key = b.get("ssid") or (next((x.get("ssid") for x in bss if x.get("interface") == b.get("interface")
                                          and x.get("ssid")), None)) or "SSID not logged"
            g.setdefault(key, []).append(b)
        return g

    def ssid_line(name, members):
        ifaces = sorted({b.get("interface") for b in members if b.get("interface")})
        mlds = list(dict.fromkeys(m for b in members for m in (b.get("mld_addrs") or [])))

        def lids(b):
            ids = b.get("link_ids") or ([b["link_id"]] if b.get("link_id") is not None else [])
            return "/".join(map(str, ids))
        members = sorted(members, key=lambda b: ((b.get("freq_mhz") or 9999), b["mac"]))
        links = ", ".join(b["mac"] + " (" + ", ".join(x for x in (
            f"link {lids(b)}" if lids(b) else "", f"{b['band']} {b['freq_mhz']} MHz" if b.get("band") else "",
            "vap_up_fail" if "vap_up_fail" in (b.get("events") or []) else "") if x) + ")" for b in members[:6]).replace(" ()", "")
        n_cli = sum(1 for c in role_clients if name in (c.get("ssids") or []))
        return (f"SSID {name} on {', '.join(ifaces) or 'n/a'}"
                + (f", AP MLD address {mlds[0]}" if len(mlds) == 1 else
                   f", AP MLD addresses seen (MLD configuration changed during the log): {', '.join(mlds)}" if mlds else "")
                + f", BSSIDs: {links}; clients that joined: {n_cli}")

    def ssid_in_question():
        toks = [t for t in re.findall(r"[a-z0-9_.-]{4,}", ql)]
        out = []
        for name in {b.get("ssid") for b in bss if b.get("ssid")}:
            nl = name.lower()
            if nl in ql or any(("_" in t or any(ch.isdigit() for ch in t) or t == nl) and nl.startswith(t) for t in toks):
                out.append(name)
        return sorted(out)

    def finding_lines(f):
        """Real log line numbers behind a finding (so the answer can cite them instead of guessing)."""
        ev = a.get("events") or []
        fid = f.get("id", "")
        pick = {
            "DRIVER_STA_PROGRAMMING_FAILURES": lambda e: {"sta_add_driver_failure", "sta_flags_driver_failure"}
            & set(e.get("error_categories") or []),
            "HANDSHAKE_FAILURES": lambda e: e["event"] == "HANDSHAKE_FAILURE"
            or (e["event"] == "DISCONNECT_REQUEST" and e.get("reason_code") in (15, 16)),
            "SECURITY_REASON_CODES": lambda e: e["event"] in ("DISCONNECT_REQUEST", "DEAUTHENTICATION", "DISASSOCIATION")
            and e.get("reason_code") in (2, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24),
            "CLIENT_INITIATED_DEAUTH_CHURN": lambda e: e["event"] == "DEAUTHENTICATION" and e.get("initiator") == "STA",
            "AUTH_RESPONSE_NOT_ACKED": lambda e: e.get("subtype") == "auth_resp_no_ack",
            "SAE_FAILURES": lambda e: e["event"] == "SAE_FAILURE",
        }.get(fid)
        if fid == "AP_RESTARTED" and restarts:
            return " (log lines: " + ", ".join(str(c["start_line"]) for c in restarts[:4]) + ")"
        if not pick:
            return ""
        ln = [str(e["line_no"]) for e in ev if pick(e)][:4]
        return f" (log lines: {', '.join(ln)})" if ln else ""

    def role_line(c):
        ls = c.get("last_state") or {}
        return (f"{c['mac']}" + (f" [SSID {', '.join(c['ssids'])}]" if c.get("ssids") else "")
                + f" auth req {c.get('auth_requests', 0)}, assoc req {c.get('assoc_requests', 0) + c.get('reassoc_requests', 0)}, "
                + (f"final state {ls['state']} (line {ls['line']})" if ls else f"status {c.get('status')}"))

    def connected_summary():
        now = [c for c in role_clients if (c.get("last_state") or {}).get("state") == "CONNECTED"]
        return (f"Client connection state at the END of the log: {len(now)} of {len(role_clients)} client(s) still connected"
                + (f" ({', '.join(c['mac'] + (' [' + ', '.join(c['ssids']) + ']' if c.get('ssids') else '') for c in now)})" if now else "")
                + f"; {len(role_clients) - len(now)} disconnected or never completed the connection.")

    def links_of(s):
        return ", ".join(links.get(i, f"link{i}") for i in (s.get("links_listed") or [])) or "n/a"

    def client_line(m):
        s, c = sta_by_mac.get(m), cli_by_mac.get(m)
        parts = [m + ":"]
        if c:
            src = "" if events_logged else " (from station dump flags)"
            parts.append(f"auth {c.get('authentication')}, assoc {c.get('association')}, 4-way handshake {c.get('handshake')}{src}, "
                         f"deauth {c.get('deauth_count')}, disassoc {c.get('disassoc_count')}, reconnects {c.get('reconnect_count')}, "
                         f"reason codes {sorted(set(c.get('reason_codes') or [])) or 'none'};")
        if s:
            parts.append(f"associated {s.get('associated')}, authorized {s.get('authorized')}, connected {_fmt(s.get('connected_time_s'), ' s')}, "
                         f"signal {_fmt(s.get('signal_avg_dbm'), ' dBm')}, tx packets {_fmt(s.get('tx_packets'))}, tx retries "
                         f"{_fmt(s.get('tx_retries'))}, tx failed {_fmt(s.get('tx_failed'))}, AP->client rate {s.get('tx_bitrate') or 'n/a'} "
                         f"(max seen {_fmt(s.get('tx_bitrate_max_mbps'))} Mbit/s), client->AP rate {_fmt(s.get('rx_bitrate'))} Mbit/s "
                         f"{s.get('rx_phy') or ''}, {'MLO' if s.get('mlo') else 'single-link'} on {links_of(s)};")
        if c:
            parts.append(f"problems: {', '.join(c.get('issues') or []) or 'none'}")
        return " ".join(parts)

    comp: list[str] = []      # COMPUTED ANSWER
    # ---------------------------------------------------------------- knowledge questions
    if qt == "GENERAL_WIFI_KNOWLEDGE":
        dist = st.get("reason_code_distribution") or a.get("reason_code_distribution") or {}
        for code in re.findall(r"reason\s*(?:code)?\s*[:=#]?\s*(\d+)", ql):
            meaning = REASON_CODE_MEANINGS.get(int(code))
            comp.append(f"Reason code {code} = {meaning or 'not a standard IEEE 802.11 reason code'}. "
                        f"A reason code is carried in a Deauthentication or Disassociation frame and can be sent by "
                        f"the client (STA) or by the AP; the log line shows which side sent it. The code states the "
                        f"sender's reason, not the underlying root cause (SKILL §51). "
                        f"In the current test ({tid}) it appears {dist.get(str(code), dist.get(int(code), 0))} time(s).")
    # ---------------------------------------------------------------- AP / client roles (beacon vs auth/assoc)
    q_ssids = ssid_in_question() if bss else []
    groups = ssid_groups() if bss else {}
    eps = episodes or {}
    want_why = bool(re.search(r"why|reason|cause|disconnect|deauth|disassoc|drop|kick|leav|lost|root", ql)) \
        or "disconnect" in topics or qt == "ROOT_CAUSE_ANALYSIS"
    focus_macs = list(cli_macs)
    for m in cli_macs:
        focus_macs += (role_by_mac.get(m) or {}).get("link_addresses") or []
    for name in q_ssids:
        for c in role_clients:
            if name in (c.get("ssids") or []):
                focus_macs += [c["mac"]] + (c.get("link_addresses") or [])
    band_q = bool(re.search(r"6 ?ghz|\b5 ?ghz|2\.4", ql)) and not stations and bool(role_clients)
    focus_fail = "security" in topics and bool(re.search(r"fail|error|timeout|time out|mismatch|reject|problem|issue|wrong", ql))
    ap_set = set(aps) | {b["mac"] for b in bss}

    def ev_list(types, label, limit=8, pred=None):
        evs = [e for e in a.get("events") or [] if e["event"] in types and e.get("client_mac") not in ap_set
               and (pred is None or pred(e))]
        if not evs:
            return f"{label}: none found in the analysed log."
        by: dict = {}
        for e in evs:
            by.setdefault(e.get("client_mac") or "MAC not logged", []).append(e)
        rows = sorted(by.items(), key=lambda kv: -len(kv[1]))
        return (f"{label}: {len(evs)} event(s), {len([k for k in by if k != 'MAC not logged'])} client(s) - " + "; ".join(
            f"{m}" + (f" [SSID {', '.join(role_by_mac[m]['ssids'])}]" if role_by_mac.get(m, {}).get("ssids") else "")
            + f" x{len(v)} (line{'s' if len(v) > 1 else ''} {', '.join(str(e['line_no']) for e in v[:4])}"
            + (", ..." if len(v) > 4 else "") + f"; e.g. {PREFIX_CUT.sub('', v[0].get('message') or '')[:115]})"
            for m, v in rows[:limit]) + (f"; ... {len(rows) - limit} more client(s)" if len(rows) > limit else ""))
    want_ssid = bool(re.search(r"(?<!b)ssid|network name|broadcast", ql))
    if qt != "GENERAL_WIFI_KNOWLEDGE" and bss and not q_ssids and (ask_ap or want_ssid or (qt in REPORT_TYPES and len(bss) <= 3)):
        if len(bss) <= 3 and not any(b.get("mld_addrs") for b in bss):
            comp.append(f"AP / BSS addresses (rule: the AP MAC is the BSSID it beacons with - found in BSS setup, beacon "
                        f"and frames sent by the AP): {len(bss)} - " + " | ".join(bss_line(b) for b in bss))
        else:
            names = [k for k in groups if k != "SSID not logged"]
            comp.append(f"DIRECT ANSWER: the AP broadcasts {len(names)} SSID(s) on {len(bss)} BSSID(s) (AP MAC = BSSID it "
                        f"beacons with / sends frames from): {', '.join(names)}. One line per SSID:"
                        + "".join(SUB + ssid_line(k, v) for k, v in groups.items()))
        nb = md.get("neighbor_bss") or roles.get("neighbor_bss") or []
        if nb and ask_ap:
            comp.append(f"Other BSSIDs only heard in received frames (neighbour APs, NOT this AP): "
                        + ", ".join(n["mac"] for n in nb[:5]))
    elif qt != "GENERAL_WIFI_KNOWLEDGE" and ask_ap and not bss:
        comp.append("AP / BSS address: no beacon, BSS-setup or AP-transmitted frame line with a MAC address in this log.")
    if qt != "GENERAL_WIFI_KNOWLEDGE" and (ask_cli or (qt in REPORT_TYPES and len(role_clients) <= 6)) and not cli_macs \
            and roles and not q_ssids and not focus_fail and not band_q \
            and not ({"disconnect"} & set(topics) and qt not in REPORT_TYPES):
        if role_clients:
            if re.search(r"connected|how many|count|number", ql):
                comp.append("DIRECT ANSWER: " + connected_summary())
            comp.append(f"Client MAC addresses (rule: a client is a MAC that sent an Authentication Request or "
                        f"(Re)Association Request to the AP): {len(role_clients)}. One line per client:"
                        + "".join(SUB + role_line(c) for c in role_clients[:21]))
            if not re.search(r"connected|how many|count|number", ql):
                comp.append(connected_summary())
        else:
            comp.append("Client MAC addresses: NONE - no MAC address sent an Authentication Request or "
                        "(Re)Association Request to the AP in this log, so no client tried to join"
                        + (f" ({len(roles.get('probing_only') or [])} device(s) only sent probe requests)."
                           if roles.get("probing_only") else ".")
                        + (" MAC addresses seen in the log belong to the AP itself (see AP / BSS addresses)." if bss else ""))
    for name in q_ssids:
        members = [b for b in bss if b.get("ssid") == name or (b.get("interface") and b.get("interface") in
                   {x.get("interface") for x in bss if x.get("ssid") == name})]
        on = [c for c in role_clients if name in (c.get("ssids") or [])]
        now = [c for c in on if (c.get("last_state") or {}).get("state") == "CONNECTED"]
        comp.append(f"DIRECT ANSWER: {len(on)} client(s) (STAs) joined SSID {name}"
                    + (f": {', '.join(c['mac'] for c in on)}" if on else "")
                    + f". Still connected at the END of the log: {len(now)}"
                    + (f" ({', '.join(c['mac'] for c in now)})" if now else " (none of them)") + ". One line per client:"
                    + "".join(SUB + c["mac"]
                              + (f": final state {c['last_state']['state']} at line {c['last_state']['line']}" if c.get("last_state")
                                 else f": status {c.get('status')}")
                              + (f", signal {c['signal_dbm']['min']}..{c['signal_dbm']['max']} dBm" if c.get("signal_dbm") else "")
                              + (f", Wi-Fi 7 link addresses {', '.join(c['link_addresses'][:3])}" if c.get("link_addresses") else "")
                              + (f"; join proof {next((x for x in c.get('samples') or [] if 'associat' in x.lower()), (c.get('samples') or [''])[0])[:150]}"
                                 if c.get("samples") else "")
                              for c in on))
        comp.append(ssid_line(name, members))
        if eps and want_why:
            allc, who = {}, {}
            for c in on:
                for k, n in (eps.get(c["mac"]) or {}).get("causes", {}).items():
                    allc[k] = allc.get(k, 0) + n
                    who.setdefault(k, []).append(f"{c['mac']} x{n}")
            n_ep = sum(allc.values())
            n_dis = sum(1 for c in on if (eps.get(c["mac"]) or {}).get("episodes"))
            comp.insert(0, f"DIRECT ANSWER (why): {n_dis} of the {len(on)} client(s) of SSID {name} disconnected at least "
                           f"once; together they had {n_ep} disconnect episode(s) in the raw log. Causes, most frequent "
                           f"first (episode count - which clients):"
                        + ("".join(SUB + f"x{n} {k} - clients: {', '.join(who[k])}"
                                   for k, n in sorted(allc.items(), key=lambda x: -x[1])) or SUB + "none found"))
    late_comp: list[str] = []
    # ---------------------------------------------------------------- disconnect-class event table (dashboard helper)
    u = understood or {}
    ev_types = [t for t in (u.get("events") or []) if t in ("deauth", "disassoc", "reassoc", "four_way")]
    if not ev_types and "disconnect" in topics:
        ev_types = ["deauth", "disassoc", "four_way"]
    shape = set(u.get("shape") or [])
    if "why" in shape and ({"deauth", "disassoc"} & set(ev_types)) and "four_way" not in ev_types:
        ev_types.append("four_way")
    client_focus = bool(re.search(r"\bclients?\b|\bstations?\b|\bdevices?\b|\bstas?\b|\bwhich\b|\bwho\b", ql)) \
        and not re.search(r"\bevents?\b|timeline|\bframes?\b|\bentries\b", ql)
    want_table = bool(events is not None and ev_types and qt != "GENERAL_WIFI_KNOWLEDGE" and (
        "timeline" in shape or u.get("window")
        or re.search(r"\bevents?\b|\bframes?\b|\bentries\b|\blog lines?\b|\boccurr|\bhappen", ql)
        or ({"reassoc", "four_way"} & set(ev_types) and not client_focus)
        or ("table" in shape and not client_focus)
        or (cli_macs and want_why)))
    if want_table:
        et = event_table
        sel = et.select(events, types=ev_types, macs=cli_macs or None, ssids=q_ssids or None, window=u.get("window"))
        n_bc = sum(1 for r in sel if r["mac"] == "all stations")
        if n_bc and not re.search(r"broadcast|all stations|restart|teardown|\bap\b", ql):
            sel = [r for r in sel if r["mac"] != "all stations"]
        scope = (", ".join(cli_macs) if cli_macs else f"SSID {', '.join(q_ssids)}" if q_ssids else "all clients") \
            + (f", {u['window'][0]}-{u['window'][1]}" if u.get("window") else "")
        (late_comp.append if (cli_macs and want_why) else (lambda x: comp.insert(0, x)))(
                    f"DIRECT ANSWER (event table, {scope}; one row per event, same event types as the dashboard "
                    f"helper analyze_hostapd_logs): {et.summary_line(sel)}. Dashboard rule "
                    f"(fail_on_hostapd_disconnections): {et.dashboard_verdict(sel)}.\n"
                    + et.markdown_table(sel, limit=12 if (cli_macs and want_why) else 22, enrich=enrich,
                                        link="?" + "&".join(x for x in (
                                            f"type={','.join(ev_types)}", f"mac={','.join(cli_macs)}" if cli_macs else "",
                                            f"ssid={','.join(q_ssids)}" if q_ssids else "") if x))
                    + (f"\n  (plus {n_bc} broadcast deauth/disassoc to 'all stations' sent while the AP restarted - not shown)"
                       if n_bc and not any(r["mac"] == "all stations" for r in sel) else "")
                    + "\n  (in the answer write [[TABLE]] on its own line where this table belongs - the exact table is "
                      "inserted there automatically; do not retype the rows and do not add rows, reasons or causes)")
    lc = roles.get("lifecycle") or {}
    ask_life = bool(re.search(r"start|\bup\b|enable|restart|reboot|reload|crash|stable|stability|vap|interface|down|bring", ql))
    if restarts is not None and qt != "GENERAL_WIFI_KNOWLEDGE" and (ask_life or qt in REPORT_TYPES):
        comp.append(ep_mod.describe_restarts(restarts, max_rows=6 if ask_life else 3, direct=ask_life))
    if lc and qt != "GENERAL_WIFI_KNOWLEDGE" and (qt in REPORT_TYPES or (qt == "ROOT_CAUSE_ANALYSIS" and not cli_macs)
                                                  or ask_life):
        comp.append("AP lifecycle events: " + ", ".join(f"{k} x{v}" for k, v in lc.items())
                    + ("; VAP bring-up failed for: " + ", ".join(f"{b['mac']} ({b.get('interface')})" for b in bss
                                                               if "vap_up_fail" in (b.get("events") or []))
                       if any("vap_up_fail" in (b.get("events") or []) for b in bss) else ""))
    # ---------------------------------------------------------------- AP addresses
    for m in ap_macs:
        comp.append(f"{m} is the {aps[m]} - it is the access point, not a client.")
        link_id = next((l["link_id"] for l in md.get("ap_links") or [] if (l.get("addr") or "").upper() == m), None)
        is_mld = "interface" in aps[m]
        on = [s for s in assoc if is_mld or link_id in (s.get("links_listed") or [])]
        comp.append(f"Clients associated to this AP ({'all links of the AP MLD' if is_mld else links.get(link_id)}): {len(on)} - "
                    + ("; ".join(f"{s['mac']} (links {links_of(s)}, signal {_fmt(s.get('signal_avg_dbm'), ' dBm')}, "
                                 f"connected {_fmt(s.get('connected_time_s'), ' s')})" for s in on) or "none")
                    + " (source: iw station dump).")
        if probing_only:
            comp.append(f"Other devices only sent probe requests and are NOT associated: {len(probing_only)} "
                        f"(e.g. {', '.join(p['mac'] for p in probing_only[:5])}).")
    # ---------------------------------------------------------------- client addresses
    for m in cli_macs:
        if m in role_by_mac:
            comp.append("Join attempts of " + role_line(role_by_mac[m])
                        + (". Log lines: " + " / ".join((role_by_mac[m].get("samples") or [])[:2]) if not want_why else ""))
        if want_why and m in eps:
            comp.append(ep_mod.describe(m, eps[m], max_rows=0 if events is not None else 6))
        if m in sta_by_mac or m in cli_by_mac:
            comp.append("Client " + client_line(m))
            rel = [f for f in fnd if m in f["observation"]]
            if rel:
                comp.append(f"Findings for {m}: " + " | ".join(f"[{f['severity'].upper()}] {f['observation']}" for f in rel))
        elif m in probe_by_mac:
            p = probe_by_mac[m]
            comp.append(f"{m} is not associated in {tid}: it only sent {p['probe_requests']} probe request(s) "
                        f"({p['rssi_min']}..{p['rssi_max']} dBm, {'/'.join(p['bands'])}).")
        else:
            comp.append(f"Answer for {m}: NO - this MAC address does not appear anywhere in test {tid} (it is not an AP "
                        f"address, not in the station dump, not a probing device and not in any hostapd event), so it "
                        f"was not connected during this capture. Clients that joined in this test: "
                        + (", ".join(known) or "none") + ".")

    # ---------------------------------------------------------------- topic answers (current log)
    if qt != "GENERAL_WIFI_KNOWLEDGE":
        if "retries" in topics and stations:
            rk = sorted(stations, key=lambda s: -(s.get("tx_retries") or 0))
            top_f = max(stations, key=lambda s: s.get("tx_failed") or 0)
            comp.append(f"Most tx retries: {rk[0]['mac']} with {_fmt(rk[0].get('tx_retries'))} retries "
                        f"({_fmt(rk[0].get('tx_packets'))} tx packets).")
            comp.append(f"Most tx failed: {top_f['mac']} with {_fmt(top_f.get('tx_failed'))} failed frames.")
            comp.append("Retry ranking: " + ", ".join(f"{s['mac']} {_fmt(s.get('tx_retries'))}" for s in rk))
        if "signal" in topics and stations:
            rk = sorted(stations, key=lambda s: s.get("signal_avg_dbm") if s.get("signal_avg_dbm") is not None else 0)
            comp.append(f"Weakest signal: {rk[0]['mac']} at {_fmt(rk[0].get('signal_avg_dbm'), ' dBm')}. Signal per client: "
                        + ", ".join(f"{s['mac']} {_fmt(s.get('signal_avg_dbm'), ' dBm')}" for s in rk))
        if "rate" in topics and stations:
            comp.append("AP->client tx rate now (max seen): " + "; ".join(
                f"{s['mac']} {s.get('tx_bitrate')} ({_fmt(s.get('tx_bitrate_max_mbps'))} Mbit/s)" for s in stations))
        if "disconnect" in topics and not cli_macs and not q_ssids:
            dis = [c for c in clients if (c.get("deauth_count") or 0) + (c.get("disassoc_count") or 0) > 0]
            if dis:
                dis.sort(key=lambda c: -((c.get("deauth_count") or 0) + (c.get("disassoc_count") or 0)))
                def _dis_line(c):
                    m = c["client_mac"]
                    r = role_by_mac.get(m, {})
                    n = c.get("deauth_count") or 0
                    by_s, by_a = c.get("deauth_by_sta") or 0, c.get("deauth_by_ap") or 0
                    parts = []
                    if n:
                        snd = [x for x in (f"client {by_s}" if by_s else "", f"AP {by_a}" if by_a else "",
                                           f"not logged {n - by_s - by_a}" if n - by_s - by_a > 0 else "") if x]
                        parts.append(f"deauth {n} (sent by {', '.join(snd)})")
                    if c.get("disassoc_count"):
                        parts.append(f"disassoc {c['disassoc_count']}")
                    rc = sorted(set(c.get("reason_codes") or []))
                    if rc:
                        parts.append(f"reason {', '.join(map(str, rc))}")
                    if r.get("last_state"):
                        parts.append(f"final state {r['last_state']['state']}")
                    ca = list(((eps.get(m) or {}).get("causes") or {}).items())[:2]
                    if ca:
                        parts.append("main cause: " + ", ".join(f"{k.split(' - ')[0].split(' (')[0]} x{v}" for k, v in ca))
                    ss = ", ".join(r.get("ssids") or [])
                    return m + (f" [{ss}]" if ss else "") + ": " + ", ".join(parts)
                if "table" in shape:
                    tl = ["| # | Client MAC | SSID | Deauth | Disassoc | Sent by | Reason codes | Final state | Main causes (raw log) |",
                          "|---|---|---|---|---|---|---|---|---|"]
                    for i, c in enumerate(dis[:21], 1):
                        m = c["client_mac"]
                        r = role_by_mac.get(m, {})
                        n, by_s, by_a = c.get("deauth_count") or 0, c.get("deauth_by_sta") or 0, c.get("deauth_by_ap") or 0
                        snd = ", ".join(x for x in (f"AP {by_a}" if by_a else "", f"client {by_s}" if by_s else "",
                                                    f"not logged {n - by_a - by_s}" if n - by_a - by_s > 0 else "") if x) or "-"
                        ca = list(((eps.get(m) or {}).get("causes") or {}).items())[:2]
                        tl.append(f"| {i} | {m} | {', '.join(r.get('ssids') or []) or '-'} | {n} | {c.get('disassoc_count') or 0} | "
                                  f"{snd} | {', '.join(map(str, sorted(set(c.get('reason_codes') or [])))) or '-'} | "
                                  f"{(r.get('last_state') or {}).get('state', '-')} | "
                                  + ("; ".join(f"{k.split(' - ')[0].split(' (')[0]} x{v}" for k, v in ca) or "-") + " |")
                    comp.append(f"DIRECT ANSWER: {len(dis)} client(s) had deauthentication/disassociation events.\n"
                                + "\n".join(tl) + "\n  (in the answer write [[TABLE]] on its own line where this table "
                                "belongs - the exact table is inserted there automatically)")
                else:
                  comp.append(f"DIRECT ANSWER: {len(dis)} client(s) had deauthentication/disassociation events: "
                            + ", ".join(c["client_mac"] for c in dis[:21]) + ". One line per client (counts, who sent it, "
                            "reason codes, causes read from the raw log):"
                            + "".join(f"\n    {i}. " + _dis_line(c) for i, c in enumerate(dis[:21], 1))
                            + f"\n  (copy all {len(dis[:21])} numbered lines)")
                if eps:
                    allc = {}
                    for c in dis:
                        for k, n in (eps.get(c["client_mac"]) or {}).get("causes", {}).items():
                            allc[k] = allc.get(k, 0) + n
                    if allc:
                        comp.append("Disconnect causes found in the raw log (all clients, per disconnect episode): "
                                    + "; ".join(f"{k} x{n}" for k, n in sorted(allc.items(), key=lambda x: -x[1])))
                meanings = a.get("reason_code_meanings") or {}
                if meanings:
                    comp.append("Reason codes seen: " + "; ".join(f"{k} = {v}" for k, v in meanings.items()))
            else:
                bd = roles.get("ap_broadcast_deauth") or []
                if bd:
                    comp.append(f"The AP itself sent {len(bd)} broadcast deauthentication/disassociation frame(s) "
                                f"(da=ff:ff:ff:ff:ff:ff) while tearing down its BSS: " + ", ".join(
                                    f"{x['bss']} at line {x['line']}" for x in bd[:8])
                                + ". These are addressed to all stations, not to a specific client"
                                + ("; no client was connected at that time." if not role_clients and not known else "."))
                for m in known:
                    sd = sta_by_mac.get(m) or {}
                    comp.append(f"{m}: {'CONNECTED' if sd.get('associated') else 'status unknown'} - associated "
                                f"{sd.get('associated', 'n/a')}, authorized {sd.get('authorized', 'n/a')}, connected time "
                                f"{_fmt(sd.get('connected_time_s'), ' s')}, deauth 0, disassoc 0, reconnects 0")
                comp.append("No client deauthentication or disassociation events were logged in this file"
                            + (f"; the station dump shows {len(assoc)} of {len(stations)} station(s) still associated and "
                               f"authorized (connected time: " + ", ".join(f"{s['mac']} {_fmt(s.get('connected_time_s'), ' s')}"
                                                                          for s in stations) + ")." if stations else "."))
        if "ping" in topics:
            for p in rf.get("ping_tests") or []:
                comp.append(f"Ping {p['target']} ({p['target_scope']}): sent {p['transmitted']}, received {p['received']}, "
                            f"loss {_fmt(p.get('loss_pct'), '%')}, RTT median {_fmt(p.get('rtt_median_ms'), ' ms')}, "
                            f"p95 {_fmt(p.get('rtt_p95_ms'), ' ms')}, max {_fmt(p.get('rtt_max_reported'), ' ms')}, "
                            f"replies over 100 ms {_fmt(p.get('replies_over_100ms'))}, 'Network unreachable' errors {p['unreachable_errors']}.")
        if "mlo" in topics and role_clients and not stations and bss:
            band_of = {b["mac"]: b.get("band") for b in bss}
            for band, rx in (("6GHz", r"6 ?ghz"), ("5GHz", r"\b5 ?ghz"), ("2.4GHz", r"2\.4")):
                if re.search(rx, ql):
                    on = [c for c in role_clients if any(band_of.get(x) == band for x in (c.get("bssids") or {}))]
                    comp.insert(0, f"DIRECT ANSWER: {len(on)} of {len(role_clients)} client(s) exchanged frames with a "
                                   f"{band} BSSID of this AP:" + "".join(
                                       SUB + c["mac"] + (f" [{', '.join(c['ssids'])}]" if c.get("ssids") else "")
                                       + f" via {', '.join(x for x in c['bssids'] if band_of.get(x) == band)}"
                                       + (f", final state {c['last_state']['state']}" if c.get("last_state") else "")
                                       for c in on) + ("" if on else SUB + "none"))
        if "mlo" in topics and stations:
            for band, rx in (("6GHz", r"6 ?ghz"), ("5GHz", r"\b5 ?ghz"), ("2.4GHz", r"2\.4")):
                if re.search(rx, ql):
                    ids = [l["link_id"] for l in md.get("ap_links") or [] if l.get("band") == band]
                    on = [x["mac"] for x in stations if set(ids) & set(x.get("links_listed") or [])]
                    comp.insert(0, f"ANSWER - clients using {band} (link {', '.join(map(str, ids)) or 'n/a'}): {len(on)} of "
                                   f"{len(stations)} - " + (", ".join(on) or "none"))
            for l in md.get("ap_links") or []:
                on = [x["mac"] for x in stations if l["link_id"] in (x.get("links_listed") or [])]
                act = [x["mac"] for x in stations if l["link_id"] in (x.get("active_links") or [])]
                comp.append(f"Clients on link{l['link_id']} {l.get('band')} ch{l.get('channel')}: set up {len(on)} ("
                            + (", ".join(on) or "none") + f"), carrying traffic {len(act)} (" + (", ".join(act) or "none") + ")")
            comp.append("MLO usage: " + "; ".join(
                f"{s['mac']} {'MLO' if s.get('mlo') else 'single-link'}, links set up {links_of(s)}, active "
                f"{', '.join(links.get(i, str(i)) for i in s.get('active_links') or []) or 'n/a'}" for s in stations))
        if "probe" in topics:
            comp.append(f"Probe requests: {probes.get('total', 0)} from {probes.get('clients', 0)} device(s); probe responses sent "
                        f"{probes.get('probe_responses_sent', 0)}; top: " + ", ".join(
                            f"{x['mac']} {x['probe_requests']} ({x['rssi_min']}..{x['rssi_max']} dBm {'/'.join(x['bands'])})"
                            for x in (probes.get("per_client") or [])[:6]))
        if "infra" in topics:
            inf = a.get("infrastructure_errors") or []
            comp.append("Driver/platform errors: " + ("; ".join(f"{e['category']} x{e['count']} (e.g. {e['sample'][:120]})"
                                                               for e in inf[:6]) if inf else "none in this log."))
        if "security" in topics:
            if events_logged:
                comp.append(f"Authentication: attempts {st.get('authentication_attempts')}, successes {st.get('authentication_successes')}, "
                            f"failures {st.get('authentication_failures')} (response not ACKed {st.get('authentication_response_not_acked')}); "
                            f"association ok {st.get('association_successes')}, failed {st.get('association_failures')}; "
                            f"4-way handshake ok {st.get('handshake_successes')}, failed {st.get('handshake_failures')}; "
                            f"PSK mismatch {st.get('psk_mismatch_events')}, SAE failures {st.get('sae_failures')}, EAP failures {st.get('eap_failures')}.")
                sec_q = re.sub(r"\bassociat\w*|reassoc\w*", "", ql)
                if re.search(r"(?<!de)auth|sae|password|psk", sec_q) or not re.search(r"handshake|eapol|4-way|key|assoc", ql):
                    comp.append(ev_list({"AUTH_FAILURE"}, "Authentication failures per client"))
                    comp.append(ev_list({"SAE_FAILURE", "PSK_MISMATCH"}, "SAE / password (PSK) failures per client"))
                if re.search(r"handshake|eapol|4-way|key|wpa", ql) or not re.search(r"(?<!de)auth|assoc", ql):
                    comp.append(ev_list({"HANDSHAKE_FAILURE"}, "4-way handshake failures logged as such (retry limit / failed)"))
                    comp.append(ev_list({"DISCONNECT_REQUEST"}, "4-way handshake timeouts: AP disconnected the client "
                                        "(WPA authenticator disconnect, reason 15 = 4-Way Handshake timeout)",
                                        pred=lambda e: e.get("reason_code") in (15, 16)))
                    comp.append(ev_list({"LINK_LOSS"}, "Not a handshake failure - AP disconnected clients that stopped ACKing "
                                        "frames (excessive missing ACKs)"))
                if re.search(r"\bassoc|reassoc", ql):
                    comp.append(ev_list({"ASSOC_FAILURE"}, "Association failures per client"))
            else:
                comp.append("Authentication / association / 4-way handshake failures observed: none - but this log contains "
                            "NO authentication, association or EAPOL events at all, so these counts cannot be measured from it "
                            "(say this in the answer). Station dump flags: "
                            + (", ".join(f"{s['mac']} authenticated={s.get('authenticated')} associated={s.get('associated')} "
                                         f"authorized={s.get('authorized')} MFP={s.get('mfp')}" for s in stations) or "none") + ".")
        if ("clients" in topics or re.search(r"how many|\blist\b|\ball\b", ql)) and not ap_macs and not cli_macs \
                and not role_clients:
            comp.append(f"Clients in this test: {len(known)} - " + "; ".join(
                f"{m} ({'associated' if sta_by_mac.get(m, {}).get('associated') else 'assoc ' + str(cli_by_mac.get(m, {}).get('association', 'n/a'))})"
                for m in known[:25]))
            if probing_only:
                comp.append(f"Devices that only sent probe requests (not associated): {len(probing_only)}.")
            top = a.get("top_unstable_clients") or []
            if top:
                comp.append("Most affected clients: " + "; ".join(
                    f"{c['client_mac']} ({len(c['issues'])} issue type(s): {', '.join(c['issues'][:4])})" for c in top[:5]))
        if qt in ("CURRENT_LOG_ANALYSIS", "ROOT_CAUSE_ANALYSIS"):
            comp.append(f"Overall verdict (rule based): {verdict} - findings: {_sev_text(sev)}.")
        if qt == "COMPARISON" and not comparison:
            comp.append(f"Comparison not possible: MAG memory contains only the current test {tid}; no previous test "
                        f"is stored. Put an older log in input_logs and run START.cmd to store it. Current test verdict: "
                        f"{verdict} (findings: {_sev_text(sev)}).")
        if qt == "HISTORICAL_ANALYSIS":
            for m, h in (history or {}).items():
                prev = [x for x in h.get("history") or [] if x["test_id"] != tid]
                if not h.get("found") or not prev:
                    comp.append(f"History of {m}: NO earlier test contains this client - MAG memory only has the current "
                                f"test {tid} for it, so there is no previous failure record. (Current-test problems are "
                                f"listed separately below and are NOT history.)")
                else:
                    comp.append(f"History of {m}: found in {len(prev)} earlier test(s): " + "; ".join(
                        f"{x['test_id']} failures {x.get('failure_count')}, auth {x.get('authentication')}, "
                        f"issues {', '.join(x.get('issues') or []) or 'none'}" for x in prev[:5]))

    # ---------------------------------------------------------------- SKILL: intent, domain, plan (§5-§7, §48)
    intents = skill.classify_intents(question, bool(cli_macs))
    domains = skill.detect_domains(question, intents)
    plan = skill.analysis_plan(intents)
    lines: list[str] = [
        "QUERY INTENT: " + " + ".join(intents),
        "TECHNICAL DOMAIN: " + "; ".join(f"{d} (expected flow: {skill.DOMAINS[d]['flow']})" for d in domains),
        "ANALYSIS PLAN: " + " | ".join(f"{i}) {x}" for i, x in enumerate(plan, 1)),
        "EVIDENCE LEVEL: " + skill.evidence_level(a, intents, log_hits),
        "",
    ] if qt != "GENERAL_WIFI_KNOWLEDGE" else [
        "QUERY INTENT: " + " + ".join(intents), "TECHNICAL DOMAIN: " + "; ".join(domains), ""]
    if understood:
        lines.insert(0, "UNDERSTOOD QUESTION: " + (understood.get("original") or question)
                     + (f" -> read as: {question}" if question != understood.get("original") else "")
                     + f" ({understood.get('summary')})")
    comp += late_comp
    if comp:
        lines.append("COMPUTED ANSWER (exact values for this question, from the parser - use these first):")
        lines += [f"- {c}" for c in comp]

    # ---------------------------------------------------------------- CURRENT TEST STATISTICS (parser)
    if route["use_parser"]:
        ap_line = (f"AP: interface {md.get('ap_interface') or 'n/a'}, SSID {md.get('ssid') or 'n/a'}, address "
                   f"{next(iter(aps), 'n/a')}; links: " + ("; ".join(
                       f"link{l['link_id']} {l.get('addr')} {l.get('band')} ch{l.get('channel')} {l.get('width_mhz')}MHz "
                       f"{_fmt(l.get('txpower_dbm'), ' dBm')}" for l in md.get("ap_links") or []) or "n/a"))
        if bss and not md.get("ap_links"):
            ap_line = (f"AP: {len([k for k in groups if k != 'SSID not logged'])} SSID(s) on {len(bss)} BSSID(s): " + "; ".join(
                f"{k} ({', '.join(sorted({b.get('interface') for b in v if b.get('interface')})) or 'n/a'}, {len(v)} BSSID(s))"
                for k, v in groups.items()))
        content = [f"{st.get('stations_in_station_dump', 0)} stations in iw station dump ({st.get('station_dump_snapshots', 0)} snapshots)",
                   f"{st.get('ping_targets', 0)} ping targets", f"{probes.get('total', 0)} probe requests"]
        lines.append(f"\nCURRENT TEST STATISTICS (parser, authoritative for counts) - test {tid}, file {md.get('source_file', 'n/a')}, "
                     f"{md.get('total_lines')} lines, format {md.get('log_format')}:")
        lines.append("- " + ap_line)
        lines.append(f"- Log content: {md.get('total_lines_matched')} hostapd events matched (incl. errors), " + ", ".join(content) + "."
                     + ("" if events_logged else " No authentication/association/EAPOL/deauth events are logged in this file."))
        lines.append(f"- Clients: {st.get('clients')} (associated per station dump: {len(assoc)}); probing-only devices: {len(probing_only)}"
                     + (f"; {connected_summary()}" if role_clients and not q_ssids else ""))
        lines.append(f"- Authentication: attempts {st.get('authentication_attempts')}, successes {st.get('authentication_successes')}, "
                     f"failures {st.get('authentication_failures')} | Association: successes {st.get('association_successes')}, "
                     f"failures {st.get('association_failures')} | 4-way handshake: ok {st.get('handshake_successes')}, "
                     f"failures {st.get('handshake_failures')}")
        lines.append(f"- Deauthentication {st.get('deauthentication_events')} (by STA {st.get('deauth_initiated_by_sta')}, by AP "
                     f"{st.get('deauth_initiated_by_ap')}) | Disassociation {st.get('disassociation_events')} | Reconnections "
                     f"{st.get('reconnections')} | Reason codes {st.get('reason_code_distribution') or 'none'} | Driver/platform errors "
                     f"{st.get('driver_errors')}")
        lines.append(f"- Rule-based verdict: {verdict} (findings: {_sev_text(sev)})")

    # ---------------------------------------------------------------- REPORT (report / root cause questions)
    if qt in REPORT_TYPES:
        rep = ["\nREPORT (pre-filled from the parser - inserted automatically where the answer writes [[REPORT]]):",
               "HOSTAPD CONNECTIVITY REPORT",
               (f"Test: {tid} | AP {len([k for k in groups if k != 'SSID not logged'])} SSID(s) on {len(bss)} BSSID(s): "
                + "; ".join(f"{k} on {', '.join(sorted({b.get('interface') for b in v if b.get('interface')})) or 'n/a'} "
                            f"({', '.join(sorted({b['band'] for b in v if b.get('band')})) or 'band n/a'})"
                            for k, v in groups.items())
                if len(groups) > 1 or len(bss) > 3 else
                f"Test: {tid} | AP {md.get('ap_interface') or 'n/a'} SSID {md.get('ssid') or 'n/a'} | "
                + ", ".join(f"link{l['link_id']} {l.get('band')} ch{l.get('channel')} {l.get('width_mhz')}MHz"
                            for l in md.get("ap_links") or [])),
               f"Clients: {st.get('clients')} ("
               + (f"{len(assoc)} associated in the station dump" if stations else "no iw station dump in this log")
               + f"), {len(probing_only)} probing-only devices"]
        if events_logged:
            rep += [f"Authentication: {st.get('authentication_successes')} ok / {st.get('authentication_failures')} failed",
                    f"Association: {st.get('association_successes')} ok / {st.get('association_failures')} failed",
                    f"4-way handshake: {st.get('handshake_successes')} ok / {st.get('handshake_failures')} failed"]
        else:
            rep.append("Authentication / Association / 4-way handshake: no such events in this log "
                       f"(station dump: {sum(1 for s in stations if s.get('authorized'))} of {len(stations)} clients authorized)")
        rep.append(f"Deauthentication: {st.get('deauthentication_events')} | Disassociation: {st.get('disassociation_events')} | "
                   f"Reconnections: {st.get('reconnections')} | Driver errors: {st.get('driver_errors')}")
        if st.get("reason_code_distribution"):
            rep.append("Reason codes: " + ", ".join(f"{k} x{v}" for k, v in st["reason_code_distribution"].items()))
        for s in stations:
            rep.append(f"Client {s['mac']}: signal {_fmt(s.get('signal_avg_dbm'), ' dBm')}, tx retries {_fmt(s.get('tx_retries'))}, "
                       f"tx failed {_fmt(s.get('tx_failed'))} of {_fmt(s.get('tx_packets'))} pkts, AP->client {s.get('tx_bitrate')}, "
                       f"{'MLO' if s.get('mlo') else 'single-link'} ({links_of(s)})")
        if bss and len(bss) <= 3:
            rep.append("AP / BSS: " + " | ".join(f"{b['mac']} ({b.get('interface') or 'n/a'}, SSID {b.get('ssid') or 'n/a'}"
                                                 + (", vap_up_fail" if "vap_up_fail" in (b.get("events") or []) else "") + ")"
                                                 for b in bss[:8]))
        if roles:
            rep.append(f"Clients that sent auth/assoc requests: {len(role_clients)}"
                       + (" - per SSID: " + ", ".join(f"{k} {sum(1 for c in role_clients if k in (c.get('ssids') or []))}"
                                                      for k in groups if k != "SSID not logged") if groups and role_clients else ""))
            if role_clients:
                rep.append(connected_summary())
        if events is not None:
            et = event_table
            rep.append(f"Disconnect-class events (dashboard helper): {et.summary_line(events)} -> dashboard rule: "
                       f"{et.dashboard_verdict(events)} (table: http://localhost:8811/report/events)")
        if eps:
            allc = {}
            for v in eps.values():
                for k, n in (v.get("causes") or {}).items():
                    allc[k] = allc.get(k, 0) + n
            if allc:
                rep.append("Disconnect causes (raw log, per disconnect episode, all clients): "
                           + "; ".join(f"{k.split(' - ')[0]} x{n}" for k, n in sorted(allc.items(), key=lambda x: -x[1])))
        if not stations:
            for c in (a.get("top_unstable_clients") or [])[:5]:
                if c["client_mac"] in role_by_mac or not roles:
                    iss = [i for i in c["issues"] if not i.startswith("driver/platform error")] or c["issues"]
                    rep.append(f"Client {c['client_mac']}: " + ", ".join(iss[:4]))
        for p in rf.get("ping_tests") or []:
            rep.append(f"Ping {p['target']} ({p['target_scope']}): loss {_fmt(p.get('loss_pct'), '%')}, median "
                       f"{_fmt(p.get('rtt_median_ms'), ' ms')}, max {_fmt(p.get('rtt_max_reported'), ' ms')}")
        seen, top = set(), []
        for f in fnd:
            key = (f["id"], f["observation"][:17])
            if key not in seen and f["severity"] in ("critical", "high", "medium"):
                seen.add(key)
                top.append(f"[{f['severity'].upper()}] {f['observation']}{finding_lines(f)}")
        if top:
            rep.append("Top issues:")
            rep += [f"{i}. {t}" for i, t in enumerate(top[:6], 1)]
        rep.append(f"Rule-based status: {verdict}")
        lines += rep

    # ---------------------------------------------------------------- CLIENT TABLE
    if route["use_parser"] and qt not in REPORT_TYPES and not cli_macs and known and (
            set(topics) & {"clients", "retries", "signal", "rate", "mlo", "disconnect", "security", "ping"} or ap_macs):
        lines.append("\nCLIENT TABLE (current test; tx = AP->client):")
        lines += ["- " + client_line(m) for m in known[:20]]

    # ---------------------------------------------------------------- SKILL: lifecycle state machine + timeline (§17, §18, §22)
    if route["use_parser"]:
        for m in cli_macs:
            if m in cli_by_mac or m in sta_by_mac or m in role_by_mac:
                lc_ = skill.client_lifecycle(m, a)
                lines.append(f"\nCLIENT LIFECYCLE {m} (UNKNOWN = not evidenced in the log; source: {lc_['source']}): "
                             f"authentication {lc_['authentication']} -> association {lc_['association']} -> "
                             f"4-way handshake {lc_['handshake']} -> connected {lc_['connected']}; deauth {lc_['deauth']}, "
                             f"disassoc {lc_['disassoc']}, reconnects {lc_['reconnects']}, reason codes {lc_['reason_codes'] or 'none'}")
                tl = skill.timeline(a, m, limit=10)
                if not (want_why and m in eps):
                    lines.append(f"TIMELINE {m} (parser events, exact log times): " + (" | ".join(tl) if tl else
                             "no timestamped hostapd event for this MAC in the log."))
        if not cli_macs and ({"TIMELINE_ANALYSIS", "DEAUTH_DISASSOC_ANALYSIS"} & set(intents) or qt == "ROOT_CAUSE_ANALYSIS"):
            tl = skill.timeline(a, None, limit=12)
            if tl:
                lines.append("\nTIMELINE (first parser events, exact log times): " + " | ".join(tl))

    # ---------------------------------------------------------------- FINDINGS
    if route["use_parser"] and qt not in ("TEST_STATISTICS", "COMPARISON") and qt not in REPORT_TYPES:
        rel = [f for f in fnd if any(m in f["observation"] for m in cli_macs)] if cli_macs else fnd
        if rel:
            lines.append("\nFINDINGS (deterministic rules, most severe first; type / evidence level in brackets):")
            direct = skill.DIRECT_IDS
            lines += [f"- [{f['severity'].upper()}] [{'OBSERVED FACT, level 4' if f['id'] in direct else 'DERIVED FACT, level 3'}] "
                      f"{f['id']}: {f['observation']}{finding_lines(f)}" for f in rel[:10]]
        elif not fnd:
            lines.append("\nFINDINGS: no rule triggered.")

    # ---------------------------------------------------------------- keyword RAG (raw log search)
    if log_hits:
        from log_search import format_results
        lines.append("\nCURRENT LOG EVIDENCE - keyword search in the raw log (keywords taken from the question; "
                     "line numbers refer to the uploaded file):")
        lines.append(format_results(log_hits)[:3000])

    # ---------------------------------------------------------------- RAG
    if route["use_rag"]:
        useful = [h for h in (rag_hits or []) if re.search(
            r"hostapd|STA|Station|wlan|deauth|assoc|auth|EAPOL|signal|tx |ping|packets", h["chunk"])]
        if cli_macs:
            useful = [h for h in useful if any(m.lower() in h["chunk"].lower() for m in cli_macs)] or useful
        if useful and (cli_macs or qt in ("ROOT_CAUSE_ANALYSIS", "HISTORICAL_ANALYSIS") or
                       not set(topics) <= {"overview", "clients"}):
            lines.append("\nCURRENT LOG EVIDENCE (RAG excerpts retrieved from the raw log):")
            for h in useful[:3]:
                lines.append("---\n" + h["chunk"][:600])

    # ---------------------------------------------------------------- MAG
    if route["use_mag"]:
        if history:
            lines.append("\nHISTORICAL MEMORY (MAG - HISTORICAL TEST data, never evidence for the CURRENT TEST):")
            for mac, h in history.items():
                if h.get("found"):
                    prev = [x for x in h["history"] if x["test_id"] != tid]
                    if prev:
                        lines.append(f"- {mac}: seen in {len(prev)} earlier test(s): " + "; ".join(
                            f"{x['test_id']} failures {x.get('failure_count')}" for x in prev[:5]))
                    else:
                        lines.append(f"- {mac}: no earlier test contains this client (only the current test {tid} is stored)")
                else:
                    lines.append(f"- {mac}: no record in any stored test")
        if qt in ("COMPARISON", "HISTORICAL_ANALYSIS"):
            if comparison:
                ch = comparison.get("changed_statistics") or {}
                lines.append(f"\nTEST COMPARISON (MAG): {comparison.get('test_a', {}).get('test_id')} (previous) vs "
                             f"{comparison.get('test_b', {}).get('test_id')} (current)")
                lines += [f"- {k}: {v.get('test_a')} -> {v.get('test_b')}" for k, v in list(ch.items())[:15]]
                lines.append(f"- findings only in the current test: {', '.join(comparison.get('findings_only_in_b') or []) or 'none'}")
                lines.append(f"- findings only in the previous test: {', '.join(comparison.get('findings_only_in_a') or []) or 'none'}")
            else:
                lines.append(f"\nTEST COMPARISON (MAG): no previous test is stored - only {tid} exists in memory. "
                             f"Not available in supplied context.")
        if other_tests:
            lines.append("OTHER STORED TESTS: " + ", ".join(other_tests))

    # ---------------------------------------------------------------- CAG
    if route["use_cag"]:
        extra = ["04_deauth_disassoc_reason_codes.md"] if "reason" in ql else []
        cag_topics = ["overview"] if qt == "CURRENT_LOG_ANALYSIS" else topics
        if any(f["id"] in ("VAP_UP_FAILED", "BEACON_SET_FAILURES", "INTERFACE_CREATE_FAILED", "AP_RESTARTED")
               for f in fnd) and (qt in REPORT_TYPES or qt == "ROOT_CAUSE_ANALYSIS"):
            cag_topics = ["lifecycle"] + [t for t in cag_topics if t != "lifecycle"]
        for d in domains:
            for f_ in skill.DOMAINS[d]["cag"]:
                if f_ not in extra and not any(f_ in CAG_FOR.get(t, []) for t in cag_topics):
                    extra.append(f_)
        cag = _cag(cag_topics, budget=3400 if qt == "GENERAL_WIFI_KNOWLEDGE" else 2400, extra=extra[:2])
        if cag:
            lines.append("\nTECHNICAL KNOWLEDGE (CAG reference - explains events, does NOT create evidence):\n" + cag)

    # ---------------------------------------------------------------- ANSWER STYLE
    style = {  # SKILL §43 adaptive response formats - clear, detailed, always in the same order
        "GENERAL_WIFI_KNOWLEDGE": "Definition question. Labels: **Definition** (one sentence), **How it works** (3-5 "
                                  "bullets), **How it shows up in hostapd logs** (typical log lines / fields), **In the "
                                  "current log** (only what the computed answer says, if anything).",
        "CURRENT_LOG_ANALYSIS": "Overall report. First write the line [[REPORT]] (the REPORT lines are inserted there "
                                "automatically - do not retype them). Then: **Key findings** (3-6 "
                                "bullets, most severe first, each with numbers and line numbers), **Root-cause candidates** "
                                "(each: supporting evidence, missing evidence, confidence HIGH/MEDIUM/LOW, validation test), "
                                "**Missing information**, **Recommended debugging** (what to capture, what to compare, what "
                                "result validates which candidate), **Final status** (use the rule-based status).",
        "ROOT_CAUSE_ANALYSIS": "Why-question. If COMPUTED ANSWER has a DIRECT ANSWER with disconnect causes, those logged "
                               "causes ARE the answer: list each with its count and proof line, most frequent first, and use "
                               "them as the root-cause candidates (no generic candidates without a log line). "
                               "Labels: **Summary** (2-3 sentences with the key numbers), **What happened** (every cause / "
                               "event with count, time and line number; copy an event table if one is given), **Where** "
                               "(SSID, interface, band, client), **Interpretation** (hedged), **Root-cause candidates** (each: "
                               "supporting evidence, missing evidence, confidence, validation test), **Missing information**, "
                               "**Next steps**.",
        "CLIENT_ANALYSIS": "Client question. Start from the DIRECT ANSWER line if there is one. Labels: **Summary** (2-3 "
                           "sentences), **Client** (MAC, SSID, band, final state), **Timeline** (only the logged events, with "
                           "times and line numbers), **Failure point** (from the lifecycle; UNKNOWN if not evidenced), "
                           "**Evidence**, **Possible causes** (hedged), **Historical observation** (HISTORICAL MEMORY only), "
                           "**Next steps**.",
        "TEST_STATISTICS": "Focused answer. Labels: **Summary** (one or two sentences answering the question with the key "
                           "numbers), **Details** (start from the DIRECT ANSWER: copy EVERY item of its list or table, one "
                           "bullet or row per item, with exactly the values written next to that item - never drop an item, "
                           "never add a cause, reason code or state that is not written next to it), **Evidence** (exact "
                           "values, line numbers), **What it means** (one to three sentences, hedged). Keep event counts "
                           "and unique-client counts separate.",
        "HISTORICAL_ANALYSIS": "Labels: **Historical observation** (say plainly whether earlier tests contain it), "
                               "**Current test**, **Interpretation** - never treat history as current evidence.",
        "COMPARISON": "Labels: **Current test**, **Previous test**, **Differences** (normalised by client count where "
                      "possible), **Limitations**. If no previous test is stored, say so plainly.",
    }[qt]
    if re.search(r"fault|blame|responsib|whose (fault|problem)|who is wrong|guilty", ql):
        style += (" AP-fault question (SKILL §31): weigh failure distribution, affected vs successful clients, event "
                  "origin, AP-side errors, client-side evidence, configuration, timing, load, RF, driver/firmware and "
                  "history. Attribute to the AP only what AP-side log lines show; otherwise write: 'The supplied hostapd "
                  "evidence is insufficient to attribute the failure specifically to the AP.'")
    missing = skill.missing_information(a, intents, domains, rag_ok=bool(rag_hits) or not route["use_rag"])
    tail = []
    if missing and qt != "GENERAL_WIFI_KNOWLEDGE":
        tail.append("\nMISSING INFORMATION (declare it; never fill it with assumptions):")
        tail += [f"- {m}" for m in missing]
    tail.append(f"\nQUERY TYPE: {qt}\nANSWER STYLE: {style}")
    tail_txt = _clean("\n".join(tail))
    body = _clean("\n".join(lines))
    facts = body[:max_chars - len(tail_txt) - 40] + ("\n[... evidence truncated to fit the context window ...]"
                                                     if len(body) > max_chars - len(tail_txt) - 40 else "") + tail_txt
    ir = skill.build_ir(question, a, intents, domains, plan, missing, log_hits, history, qt)
    return {"intents": topics, "skill_intents": intents, "domains": domains, "macs": all_macs, "client_macs": cli_macs,
            "ap_macs": ap_macs, "route": {k: v for k, v in route.items() if k != "topics"}, "facts": facts, "ir": ir,
            "focus_macs": focus_macs}
