"""
Runtime skill engine for the Hostapd AI Analyzer (implements skills/hostapd_analyzer/SKILL.md).

Deterministic parts of the skill - everything that must NOT be left to the LLM:
  * intent classification (SKILL §5, multi-intent)            -> classify_intents()
  * technical domain identification (§6)                      -> detect_domains()
  * question decomposition / analysis plan (§7, §44)          -> analysis_plan()
  * client lifecycle state machine with UNKNOWN (§17, §18)    -> client_lifecycle()
  * timeline of a client / of the test (§22)                  -> timeline()
  * evidence levels + typed findings (§8, §10, §45)           -> typed_findings()
  * missing information / negative evidence (§25, §41)        -> missing_information()
  * structured intermediate representation (§38)              -> build_ir()
  * response validator (§39, §40 pass 2, §49)                 -> validate_response()
  * standard final JSON (§46)                                 -> final_report()
"""
from __future__ import annotations

import re

MAC_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f]|:[0-9A-Fa-f])")
TIME_RE = re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b")

# ------------------------------------------------------------------ §5 intents (multi-label)
INTENTS = [
    ("SPECIFIC_REASON_CODE_QUERY", r"reason ?code|reason \d+|status code"),
    ("AUTHENTICATION_ANALYSIS", r"(?<!de)auth|\bsae\b|\beap\b|radius|802\.1x"),
    ("ASSOCIATION_ANALYSIS", r"(?<!dis)assoc|join"),
    ("HANDSHAKE_ANALYSIS", r"handshake|4.?way|eapol|group key|gtk|ptk"),
    ("SECURITY_ANALYSIS", r"wpa|wpa2|wpa3|sae|owe|pmf|mfp|802\.11w|psk|cipher|akm|security|password"),
    ("DEAUTH_DISASSOC_ANALYSIS", r"deauth|disassoc|disconnect|kick|drop"),
    ("ROAMING_ANALYSIS", r"roam|802\.11[krv]\b|\bft\b|fast transition|bss transition|btm|neighbor report"),
    ("MLO_ANALYSIS", r"\bmlo\b|\bmld\b|multi.?link|wi-?fi ?7|802\.11be|\beht\b|link ?id"),
    ("PERFORMANCE_ANALYSIS", r"throughput|speed|slow|rate|latency|ping|retr|performance|mcs|signal|rssi"),
    ("STABILITY_ANALYSIS", r"stab|endurance|crash|restart|reboot|flap|repeated|again and again|coming up|bring.?up|\bup\b|\bdown\b"),
    ("INTEROPERABILITY_ANALYSIS", r"interop|iot|vendor|compatib|specific client|device type"),
    ("REGRESSION_ANALYSIS", r"regress|worse|better than|since the last|new firmware|after upgrade"),
    ("HISTORICAL_ANALYSIS", r"before|previous|history|earlier|again|recurr|past|trend"),
    ("COMPARISON_ANALYSIS", r"compare|comparison|\bvs\.?\b|versus|difference|previous test|last test"),
    ("TIMELINE_ANALYSIS", r"timeline|sequence|when\b|order of|what time|time ?stamp|flow of events"),
    ("ROOT_CAUSE_ANALYSIS", r"\bwhy\b|root ?cause|\bcause|reason for|\bfix\b|troubleshoot|debug|not working|fail|fault|blame|responsib"),
    ("STATISTICS_QUERY", r"how many|count|number of|total|statistic|percent|rate of|list\b|which\b"),
    ("CONFIGURATION_QUERY", r"config|ssid|channel|band|width|country|security mode|hostapd\.conf|setting|ap mac|bssid|access point|mac address of the ap|\bap\b.*\bmac\b"),
    ("CLIENT_ANALYSIS", r"client|station|\bsta\b|device|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"),
    ("CONNECTIVITY_ANALYSIS", r"connect|connectivity|online|reachab|link up"),
    ("SPECIFIC_EVENT_QUERY", r"\bshow\b|\bfind\b|\bline\b|\bgrep\b|\bsearch\b|beacon|probe|frame"),
    ("GENERAL_ANALYSIS", r"analy[sz]|report|summar|overview|overall|health|status|what happened|detailed"),
]

# ------------------------------------------------------------------ §6 / §20 domains: vocabulary + state flow
DOMAINS = {
    "802.11 MAC / client lifecycle": {
        "rx": r"auth|assoc|client|station|join|connect|lifecycle|beacon|probe|bssid|ap mac",
        "flow": "DISCONNECTED -> AUTHENTICATING -> AUTHENTICATED -> ASSOCIATING -> ASSOCIATED -> 4-WAY HANDSHAKE -> CONNECTED -> DISCONNECT -> RECONNECT",
        "cag": ["01_80211_client_lifecycle.md", "02_authentication_association.md"]},
    "WPA2 / WPA3 / SAE / EAPOL / PMF": {
        "rx": r"wpa|sae|eapol|4.?way|handshake|pmf|mfp|psk|owe|security|key|eap\b|radius",
        "flow": "ASSOCIATED -> (SAE commit/confirm for WPA3) -> EAPOL 1/4 -> 2/4 -> 3/4 -> 4/4 -> PTK installed -> GTK -> AUTHORIZED",
        "cag": ["03_wpa_security_eapol.md"]},
    "Deauthentication / Disassociation": {
        "rx": r"deauth|disassoc|disconnect|reason|kick|drop",
        "flow": "CONNECTED -> DEAUTH/DISASSOC (initiator + reason code) -> RECONNECT or GONE",
        "cag": ["04_deauth_disassoc_reason_codes.md"]},
    "Roaming / 802.11k/v/r": {
        "rx": r"roam|802\.11[krv]|\bft\b|btm|neighbor|transition",
        "flow": "CONNECTED(AP1) -> scan / neighbor report / BTM -> REASSOC or FT to AP2 -> CONNECTED(AP2)",
        "cag": ["05_roaming_80211kvr_mlo.md"]},
    "Wi-Fi 7 / MLO": {
        "rx": r"mlo|mld|multi.?link|wi-?fi ?7|802\.11be|eht|link ?id|ttlm",
        "flow": "AP MLD created -> links assigned (link_id) -> STA MLD associates on one link -> other links set up -> traffic on active links",
        "cag": ["05_roaming_80211kvr_mlo.md", "09_ap_bringup_mld.md"]},
    "AP bring-up / driver / firmware": {
        "rx": r"coming up|come up|bring.?up|vap|beacon|interface|driver|firmware|nl80211|restart|start|enable|down\b|\bup\b|dfs|channel|afc|power",
        "flow": "config -> interface/MLD created -> BSS setup (hwaddr, ssid) -> keys + beacon set -> channel/DFS -> AP-ENABLED -> beaconing",
        "cag": ["09_ap_bringup_mld.md", "07_driver_platform_errors.md"]},
    "RF / performance": {
        "rx": r"signal|rssi|rate|throughput|retr|tx fail|latency|ping|loss|slow|mcs|performance",
        "flow": "associated -> link quality (signal, MCS) -> tx retries/failures -> throughput / latency",
        "cag": ["08_rf_station_metrics.md"]},
    "QA methodology / overall": {
        "rx": r"report|overall|summar|analy|status|health",
        "flow": "scope -> population -> auth -> assoc -> handshake -> deauth/disassoc -> reconnect -> patterns -> history -> candidates -> missing evidence -> validation",
        "cag": ["06_hostapd_config_qa_methodology.md"]},
}

# ------------------------------------------------------------------ §7 / §44 analysis plans
PLANS = {
    "CLIENT_ANALYSIS": ["identify the client MAC and its role (client vs AP)", "collect every event for that MAC",
                        "rebuild its lifecycle (auth -> assoc -> handshake -> connected)", "find deauth/disassoc + reason codes",
                        "check timing and reconnect attempts", "inspect preceding errors", "check MAG history"],
    "AUTHENTICATION_ANALYSIS": ["count auth requests / successes / failures", "list failure reasons and affected clients",
                                "check SAE/EAP lines", "check timing and recurrence"],
    "ASSOCIATION_ANALYSIS": ["count (re)association requests / successes / failures", "correlate with authentication",
                             "check capabilities / rejects"],
    "HANDSHAKE_ANALYSIS": ["look for EAPOL / 4-way / group-key lines", "count completions vs timeouts",
                           "never invent EAPOL messages that are not in the log"],
    "DEAUTH_DISASSOC_ANALYSIS": ["list deauth/disassoc with time, MAC, direction, reason code",
                                 "separate AP broadcast teardown from client disconnects", "check preceding / following events"],
    "ROOT_CAUSE_ANALYSIS": ["state what happened (observed)", "where it happened (stage, interface, client)",
                            "evidence that explains it", "plausible causes with supporting / contradicting / missing evidence",
                            "how to validate each cause"],
    "GENERAL_ANALYSIS": ["scope and client population", "auth / assoc / handshake", "deauth / disassoc / reconnect",
                         "affected clients and patterns", "history", "root-cause candidates", "missing evidence",
                         "debugging actions"],
    "MLO_ANALYSIS": ["identify AP MLD and link addresses", "per-link client usage", "separate MLD-level and link-level events"],
    "STABILITY_ANALYSIS": ["AP lifecycle (created / enabled / terminated / vap_up_fail)", "restart counts and timing",
                           "errors preceding each restart"],
    "PERFORMANCE_ANALYSIS": ["signal, rates, retries, tx failures per client", "ping loss / latency", "rate collapse"],
    "COMPARISON_ANALYSIS": ["normalise both tests (clients, duration, config)", "compare rates, not only raw counts"],
    "HISTORICAL_ANALYSIS": ["MAG records for the client / test", "label everything historical"],
    "STATISTICS_QUERY": ["take exact counts from the parser", "distinguish event count vs unique clients"],
    "SPECIFIC_REASON_CODE_QUERY": ["definition from CAG", "who sent it (direction) from the log", "why - only if evidenced"],
    "CONFIGURATION_QUERY": ["read configuration lines from the log", "UNKNOWN for anything not in the log"],
}


def classify_intents(question: str, has_client_mac: bool = False) -> list[str]:
    q = question.lower()
    out = [name for name, rx in INTENTS if re.search(rx, q)]
    if has_client_mac and "CLIENT_ANALYSIS" not in out:
        out.insert(0, "CLIENT_ANALYSIS")
    return out or ["GENERAL_ANALYSIS"]


def detect_domains(question: str, intents: list[str]) -> list[str]:
    q = question.lower()
    found = [d for d, spec in DOMAINS.items() if re.search(spec["rx"], q)]
    if not found and "GENERAL_ANALYSIS" in intents:
        found = ["QA methodology / overall"]
    return found[:3] or ["802.11 MAC / client lifecycle"]


def analysis_plan(intents: list[str]) -> list[str]:
    steps: list[str] = []
    for i in intents:
        for s in PLANS.get(i, []):
            if s not in steps:
                steps.append(s)
    return steps[:10]


# ------------------------------------------------------------------ §17 / §18 lifecycle
def client_lifecycle(mac: str, a: dict) -> dict:
    roles = a.get("mac_roles") or {}
    rc = next((c for c in roles.get("clients") or [] if c["mac"] == mac), None)
    cl = next((c for c in a.get("clients") or [] if c["client_mac"] == mac), None)
    sta = next((s for s in (a.get("rf") or {}).get("stations") or [] if s["mac"] == mac), None)
    cnt = (rc or {}).get("counts", {})

    def state(ok, fail, requested=False):
        if ok:
            return "SUCCESS"
        if fail:
            return "FAIL"
        return "REQUESTED (result not in log)" if requested else "UNKNOWN"

    auth = state(cnt.get("authenticated") or (cl or {}).get("authentication") == "SUCCESS" or (sta or {}).get("authenticated"),
                 cnt.get("auth_no_ack") or (cl or {}).get("authentication") == "FAIL",
                 (rc or {}).get("auth_requests"))
    assoc = state(cnt.get("associated") or (cl or {}).get("association") == "SUCCESS" or (sta or {}).get("associated"),
                  (cl or {}).get("association") == "FAIL", (rc or {}).get("assoc_requests"))
    hs = state(cnt.get("4way_ok") or (cl or {}).get("handshake") == "SUCCESS" or (sta or {}).get("authorized"),
               (cl or {}).get("handshake") == "FAIL")
    connected = ("YES" if cnt.get("connected") or (sta or {}).get("associated") and (sta or {}).get("authorized")
                 else "NO" if auth == "FAIL" or assoc == "FAIL" or hs == "FAIL" else "UNKNOWN")
    return {"client_mac": mac, "authentication": auth, "association": assoc, "handshake": hs, "connected": connected,
            "deauth": (cl or {}).get("deauth_count", cnt.get("deauth", 0)),
            "disassoc": (cl or {}).get("disassoc_count", cnt.get("disassoc", 0)),
            "reconnects": (cl or {}).get("reconnect_count", 0),
            "reason_codes": sorted(set((cl or {}).get("reason_codes") or [])),
            "source": ", ".join(x for x, y in (("hostapd events", cl and cl.get("event_counts")), ("frames", rc),
                                              ("station dump", sta)) if y) or "none"}


# ------------------------------------------------------------------ §22 timeline
def timeline(a: dict, mac: str | None = None, limit: int = 14) -> list[str]:
    noise = {"STA_REMOVED", "DRIVER_ERROR", "DEAUTH_CALLBACK", "DISASSOC_CALLBACK", "ERROR", "WARNING"}
    ev = [e for e in a.get("events") or [] if (not mac or e.get("client_mac") == mac) and e.get("event") not in noise]
    out = []
    for e in ev[:limit]:
        ts = e.get("timestamp") or "time n/a"
        rc = f" reason={e['reason_code']}" if e.get("reason_code") is not None else ""
        who = f" by {e['initiator']}" if e.get("initiator") else ""
        out.append(f"line {e.get('line_no')}, {ts}: {e['event']}{who}{rc}"
                   + (f" ({e['client_mac']})" if e.get("client_mac") and not mac else ""))
    if len(ev) > limit:
        out.append(f"... {len(ev) - limit} more event(s)")
    return out


# ------------------------------------------------------------------ §8 / §10 / §45 typed findings
DIRECT_IDS = {"BEACON_SET_FAILURES", "VAP_UP_FAILED", "INTERFACE_CREATE_FAILED", "SYSTEM_FD_EXHAUSTION",
              "DRIVER_STA_PROGRAMMING_FAILURES", "HANDSHAKE_FAILURES", "SECURITY_REASON_CODES", "MLO_TTLM_FAILURES",
              "AUTH_RESPONSE_NOT_ACKED", "PING_UNREACHABLE"}


def typed_findings(a: dict) -> list[dict]:
    out = []
    for f in a.get("findings") or []:
        direct = f["id"] in DIRECT_IDS
        m = (f.get("metrics") or {}).get("mac")
        if not m:
            mm = MAC_RE.search(f["observation"])
            m = mm.group(0).upper() if mm else None
        out.append({"type": "OBSERVED_FACT" if direct else "DERIVED_FACT", "id": f["id"], "severity": f["severity"],
                    "client_mac": m, "evidence": f["observation"],
                    "evidence_level": "LEVEL 4 - direct (log reports it)" if direct else
                    "LEVEL 3 - strong (computed from logged values)",
                    "confidence": "HIGH"})
    return out


# ------------------------------------------------------------------ §25 / §41 missing information
def missing_information(a: dict, intents: list[str], domains: list[str], rag_ok: bool = True) -> list[str]:
    st, md = a.get("statistics") or {}, a.get("metadata") or {}
    roles = a.get("mac_roles") or {}
    frames = roles.get("frames") or {}
    stations = (a.get("rf") or {}).get("stations") or []
    events_logged = any(st.get(k) for k in ("authentication_attempts", "association_successes", "handshake_successes",
                                            "handshake_failures", "deauthentication_events", "disassociation_events"))
    miss = []
    if not events_logged and not roles.get("clients"):
        miss.append("No client authentication / association / EAPOL / deauth events in this log - client connection "
                    "behaviour cannot be analysed from it.")
    elif not (st.get("handshake_successes") or st.get("handshake_failures") or st.get("eapol_key_timeouts")) and \
            ({"HANDSHAKE_ANALYSIS", "SECURITY_ANALYSIS"} & set(intents) or "GENERAL_ANALYSIS" in intents):
        miss.append("Individual EAPOL / 4-way handshake messages are not in the log (needs hostapd -dd or an EAPOL packet capture).")
    if not stations and ({"PERFORMANCE_ANALYSIS"} & set(intents) or "RF / performance" in domains):
        miss.append("No RF metrics (iw station dump: signal, rates, retries) in the log.")
    if not md.get("log_start") and not any(e.get("timestamp") for e in (a.get("events") or [])[:50]):
        miss.append("Timestamps are not available in the supplied evidence.")
    if not md.get("security"):
        miss.append("Security configuration (WPA2/WPA3/SAE/PMF/AKM) is not in the log - UNKNOWN unless hostapd.conf is supplied.")
    if not (md.get("channel") or md.get("ap_links")):
        if any(b.get("freq_mhz") for b in md.get("ap_bss") or []):
            miss.append("Channel width / tx power of the BSSs are not in the log (only band / frequency from frames).")
        else:
            miss.append("Operating channel / band / width of the running BSS is not confirmed in the log.")
    if "ROOT_CAUSE_ANALYSIS" in intents or "CLIENT_ANALYSIS" in intents:
        miss.append("Client-side logs (wpa_supplicant / device logs) are not supplied.")
    if "AP bring-up / driver / firmware" in domains or "STABILITY_ANALYSIS" in intents:
        miss.append("Driver / firmware debug (dmesg, ath12k logs) is not supplied.")
    if not frames and "SPECIFIC_EVENT_QUERY" in intents:
        miss.append("No 802.11 management-frame lines (hostapd -dd) in the log.")
    if not rag_ok:
        miss.append("Semantic retrieval is unavailable - analysis limited to parser output and keyword search.")
    return miss[:7]


def evidence_level(a: dict, intents: list[str], log_hits: list | None) -> str:
    fnd = a.get("findings") or []
    if any(f["id"] in DIRECT_IDS for f in fnd):
        return "LEVEL 4 - direct: the log explicitly reports the failures listed in FINDINGS."
    if fnd:
        return "LEVEL 3 - strong: findings are computed from logged values."
    if log_hits and any(h.get("matches") for h in log_hits):
        return "LEVEL 2 - moderate: related log lines exist but no rule-based finding."
    if a.get("events"):
        return "LEVEL 1 - weak/partial: only generic events are present."
    return "LEVEL 0 - no relevant evidence."


# ------------------------------------------------------------------ §38 structured intermediate representation
def build_ir(question: str, a: dict, intents, domains, plan, missing, log_hits, history, qt) -> dict:
    md, st = a.get("metadata") or {}, a.get("statistics") or {}
    keep = {k: v for k, v in st.items() if isinstance(v, (int, float)) and v}
    return {
        "query": {"text": question, "intent": intents, "domain": domains, "query_type": qt},
        "current_test": {"test_id": md.get("test_id"), "source_file": md.get("source_file"), "statistics": keep},
        "current_evidence": [{"keyword": h["keyword"], "matches": h["matches"], "lines": [h["first_line"], h["last_line"]],
                              "examples": h["examples"][:3]} for h in (log_hits or [])],
        "findings": typed_findings(a),
        "historical_evidence": [{"mac": m, **{k: h.get(k) for k in ("found", "total_tests", "total_failures")}}
                                for m, h in (history or {}).items()],
        "technical_context": [c for d in domains for c in DOMAINS[d]["cag"]],
        "analysis_scope": {"plan": plan, "state_flow": [DOMAINS[d]["flow"] for d in domains]},
        "missing_information": missing,
    }


# ------------------------------------------------------------------ §39 / §40 response validator
CAUSAL_RX = re.compile(r"\b(caused by|is caused|because of|due to|the root cause is|root cause was|resulted in|led to)\b", re.I)
HEDGE_RX = re.compile(r"\b(likely|possibl|may|might|could|candidate|consistent with|suggest|not confirmed|hypothes|appears)\w*", re.I)
OVERCONF_RX = re.compile(r"\b(definitely|certainly|undoubtedly|clearly caused|confirmed that|proves that|is faulty)\b", re.I)
OVERCONF_SUB = {"definitely": "possibly", "certainly": "possibly", "undoubtedly": "possibly", "clearly caused": "may have caused",
                "confirmed that": "the evidence suggests that", "proves that": "suggests that", "is faulty": "may be at fault"}
CODE_RX = re.compile(r"```.*?```", re.S)


def _norm_mac(m: str) -> str:
    return m.upper().replace("-", ":")


def validate_response(answer: str, facts: str, question: str, raw_text: str = "", line_lookup=None,
                      aliases=None, refs=None, view_link=None) -> dict:
    """Check the LLM answer against the evidence it was given. Returns the corrected answer + a report."""
    text = answer or ""
    issues, fixes = [], []
    if CODE_RX.search(text):
        text = CODE_RX.sub("[code removed - the analyzer answers from evidence only]", text)
        fixes.append("removed a code block")
    in_log = raw_text if callable(raw_text) else (lambda s, _t=(raw_text or "").lower(): s.lower() in _t)
    known = {_norm_mac(m) for m in MAC_RE.findall(facts + "\n" + question)}
    bad_macs = sorted(m for m in {_norm_mac(m) for m in MAC_RE.findall(text)} - known if not in_log(m))
    for m in bad_macs:
        text = re.sub(re.escape(m), f"{m} [NOT IN EVIDENCE]", text, flags=re.I)
    if bad_macs:
        issues.append(f"MAC address(es) not found in the evidence: {', '.join(bad_macs)}")
    # a quoted "line N" must really mention the MAC written next to it (catches swapped MACs / line numbers)
    if line_lookup:
        wrong = []
        for tl in text.split("\n"):
            cited = re.findall(r"\blines?\s+(\d{1,8})\b", tl, re.I)
            macs = {_norm_mac(m) for m in MAC_RE.findall(tl)}
            if len(cited) != 1 or not macs:
                continue
            raw = (line_lookup(int(cited[0])) or "").lower()
            if not raw:
                continue
            ok = any(any(x.lower() in raw for x in ({m} | set((aliases or (lambda _m: set()))(m)))) for m in macs)
            if not ok:
                wrong.append((cited[0], sorted(macs)[0]))
        for n, m in wrong[:6]:
            text = re.sub(rf"(\blines?\s+{n}\b)", rf"\1 [line {n} does not mention {m}]", text, count=1, flags=re.I)
        if wrong:
            issues.append("quoted log line(s) do not match the MAC next to them: "
                          + ", ".join(f"line {n} / {m}" for n, m in wrong[:6]))
    ev_text = facts + "\n" + question
    rc_bad = sorted({c for c in re.findall(r"reason(?: code)?\s*[=:#]?\s*(\d+)", text, re.I)
                     if not re.search(rf"reason(?: code)?\s*[=:#]?\s*\(?{c}\b|\b{c} = ", ev_text, re.I)})
    if rc_bad:
        issues.append(f"reason code(s) not present in the evidence: {', '.join(rc_bad)}")
    known_times = set(TIME_RE.findall(MAC_RE.sub(" ", ev_text)))
    bad_times = sorted(t for t in set(TIME_RE.findall(MAC_RE.sub(" ", text))) - known_times if not in_log(t))
    if bad_times:
        issues.append(f"timestamp(s) not found in the evidence: {', '.join(bad_times[:5])}")
    nums_ev = set(re.findall(r"\d+(?:\.\d+)?", ev_text))
    stripped = MAC_RE.sub(" ", TIME_RE.sub(" ", text))
    bad_nums = sorted({n for n in re.findall(r"(?<![\w.:/-])\d{2,}(?:\.\d+)?(?![\w:/-])", stripped)
                       if n not in nums_ev and n not in rc_bad and not re.fullmatch(r"(19|20)\d\d|80211|802", n)}, key=len)[:6]
    if bad_nums:
        issues.append(f"number(s) not found in the evidence (check before trusting): {', '.join(bad_nums)}")
    # causality without hedge -> qualify the sentence (§9 rules 6/7); over-confidence -> tone down
    text, qf = _requalify(text)
    fixes += qf
    # completeness guard: the DIRECT ANSWER list / table must reach the user even when the model shortened it
    ql_ = (question or "").lower()
    wants_all = bool(re.search(r"\blist\b|\ball\b|\bevery\b|\beach\b|\btable\b|\bshow\b|\bevents\b|which clients|"
                               r"\bclients\b|\bstas?\b|\bstations\b|\bdevices\b|timeline", ql_)) \
        and not re.search(r"\bmost\b|\bleast\b|\btop\b|\bworst\b|\bbest\b|highest|lowest|\bfirst\b|\blast\b", ql_)
    rep = re.search(r"\nREPORT \(pre-filled[^\n]*\n(.*?)(?:\n\n|\Z)", facts or "", re.S)
    if rep:
        rtxt = rep.group(1).strip()
        if re.search(r"\[\[\s*REPORT\s*\]\]", text, re.I):        # the report always goes to the top
            text = rtxt + "\n\n" + re.sub(r"\[\[\s*REPORT\s*\]\]", "", text, flags=re.I).strip()
            fixes.append("inserted the parser report")
        elif "HOSTAPD CONNECTIVITY REPORT" not in text:
            text = rtxt + "\n\n" + text
            fixes.append("added the parser report at the top")
    text = re.sub(r"\[\[\s*REPORT\s*\]\]", "", text, flags=re.I)
    text = "\n".join(l for l in text.split("\n")
                     if not re.search(r"^\s*[-*|.\d ]*\.\.\.\s*\(copy (?:all|the remaining|every)", l, re.I))
    blocks = _direct_blocks(facts)
    tblock = next((x for x in blocks if "|---" in x), None)
    if tblock:
        btab = [l for l in tblock.split("\n") if l.startswith("|")]
        extra = [l for l in tblock.split("\n") if l.startswith("(") and "more event" in l]
        if re.search(r"\[\[\s*TABLE\s*\]\]", text, re.I):          # placeholder -> exact table
            # the model sometimes also retypes the table: keep only the exact one
            junk = re.compile(r"^\s*(?:\d+\.\s*)?\|"                                  # retyped table rows
                              r"|\(\s*copy (?:all|the remaining|every|this)|omitting the rest|rest of the table"
                              r"|^\s*\.\.\.\s*\(", re.I)
            text = "\n".join(l for l in text.split("\n") if not junk.search(l))
            text = re.sub(r"\[\[\s*TABLE\s*\]\]", lambda _m: "\n".join(btab + extra), text, count=1, flags=re.I)
            text = re.sub(r"\[\[\s*TABLE\s*\]\]", "", text, flags=re.I)
            fixes.append("inserted the exact parser table")
        else:
            alines = text.split("\n")
            ai = [i for i, l in enumerate(alines) if l.lstrip().startswith("|")]
            if ai:                                                 # model retyped the table: complete it if short
                start = end = ai[0]
                while end + 1 < len(alines) and (alines[end + 1].lstrip().startswith("|") or re.search(
                        r"omit|rest of|\.\.\.|more rows|and so on|copy every", alines[end + 1], re.I)):
                    end += 1
                seg = "\n".join(alines[start:end + 1])
                n_model = sum(1 for l in alines[start:end + 1] if l.lstrip().startswith("|"))
                if n_model < len(btab) or re.search(r"omit|rest of the table|\.\.\.|copy every", seg, re.I):
                    alines[start:end + 1] = btab + extra
                    text = "\n".join(alines)
                    fixes.append("completed the table with every row from the parser")
            elif wants_all or tblock is (blocks[0] if blocks else None):
                text = (text.rstrip() + "\n\n**Complete table from the parser** (added by the evidence check):\n"
                        + "\n".join(btab + extra))
                fixes.append("added the complete parser table")
    for blk in (blocks[:1] if wants_all else []):
        if "|---" in blk:
            continue
        bm = {_norm_mac(m) for m in MAC_RE.findall(blk)}
        am = {_norm_mac(m) for m in MAC_RE.findall(text)}
        if len(bm) >= 3 and len(bm & am) < 0.7 * len(bm):
            text = (text.rstrip() + "\n\n**Complete list from the parser** (added by the evidence check because the "
                    "answer above left items out):\n" + blk)
            fixes.append("added the complete parser list")
    text, ref_fixes = enforce_log_refs(text, line_lookup, refs)
    fixes += ref_fixes
    text = re.sub(r"\n{3,}", "\n\n", text)
    fixes = sorted(set(fixes))
    status = ("WARNINGS" if issues else "PASSED with adjustments" if fixes else "PASSED")
    footer = [f"\n\n---\n**Evidence check ({status})**"]
    n_mac = len({_norm_mac(m) for m in MAC_RE.findall(answer or "")})
    footer.append(f"- {n_mac} MAC address(es) checked against the log / parser output"
                  + ("; all found." if n_mac and not bad_macs else "." if n_mac else " (none in this answer)."))
    if not issues:
        footer.append("- Numbers, reason codes and timestamps match the supplied evidence.")
    footer += [f"- WARNING: {i}" for i in issues]
    if fixes:
        footer.append("- Adjusted: " + "; ".join(fixes))
    if view_link:
        footer.append(f"- Tables, charts and the connection timeline for this question: {view_link}")
    return {"answer": text.rstrip() + "\n".join(footer), "status": status, "issues": issues, "fixes": fixes}


LINE_REF_RX = re.compile(r"\b(?:line\s+|L)(\d{1,8})\b")
HMS_ONLY_RX = re.compile(r"\b\d{2}:\d{2}:\d{2}\b")
LOG_TS_RX = re.compile(r"^\w{3}\s+\w{3}\s+\d{1,2}\s+(\d{2}:\d{2}:\d{2})")


def enforce_log_refs(text: str, line_lookup=None, refs=None, min_refs: int = 2) -> tuple[str, list]:
    """Every fact must be checkable: a cited 'line N' gets its hostapd time added when the answer left it out, and
    an answer with fewer than min_refs (time, line) pairs gets a 'Log references' list from the computed view."""
    fixes = []
    if line_lookup:
        out = []
        added = 0
        for ln in text.split("\n"):
            if ln.lstrip().startswith("|"):
                out.append(ln)
                continue

            def add_time(m):
                nonlocal added
                window = ln[max(0, m.start() - 30):m.end() + 30]
                if HMS_ONLY_RX.search(window):
                    return m.group(0)
                tm = LOG_TS_RX.match(line_lookup(int(m.group(1))) or "")
                if not tm:
                    return m.group(0)
                added += 1
                return f"{m.group(0)} ({tm.group(1)})"
            out.append(LINE_REF_RX.sub(add_time, ln))
        text = "\n".join(out)
        if added:
            fixes.append(f"added the hostapd time to {added} line reference(s)")
    pairs = sum(1 for ln in text.split("\n") if LINE_REF_RX.search(ln) and HMS_ONLY_RX.search(ln))
    pairs += sum(1 for ln in text.split("\n") if ln.lstrip().startswith("|") and HMS_ONLY_RX.search(ln)
                 and re.search(r"\|\s*\d{2,8}\s*\|", ln))
    if pairs < min_refs and refs:
        text = (text.rstrip() + "\n\n**Log references** (hostapd time, line number - check them in the raw log):\n"
                + "\n".join(f"- {r['time']}, line {r['line']}: {r['text']}" + (f" ({r['about']})" if r.get("about") else "")
                            for r in refs[:8]))
        fixes.append("added log references (time + line) from the parser")
    return text, fixes


def _direct_blocks(facts: str) -> list[str]:
    """DIRECT ANSWER bullets of the COMPUTED ANSWER with their sub-lines / table rows."""
    out, cur = [], None
    for line in (facts or "").split("\n"):
        if line.startswith("- DIRECT ANSWER"):
            if cur:
                out.append("\n".join(cur))
            cur = [line[2:].replace("DIRECT ANSWER", "Answer", 1)]
        elif cur is not None and (line.startswith("    ") or line.startswith("|") or line.startswith("  (")
                                  or line.startswith("(")):
            if "(copy this table unchanged" in line or "(copy all" in line or "[[TABLE]]" in line:
                continue
            cur.append(line.strip() if line.startswith("    ") and not line.strip().startswith("|") else line)
        elif cur is not None:
            out.append("\n".join(cur))
            cur = None
    if cur:
        out.append("\n".join(cur))
    return out


def _requalify(text: str) -> tuple[str, list[str]]:
    fixes, lines = [], []
    for line in text.split("\n"):
        if line.lstrip().startswith("|"):
            lines.append(line)
            continue
        parts = re.split(r"(?<=[.!?])\s+", line)
        for i, sent in enumerate(parts):
            if CAUSAL_RX.search(sent) and not HEDGE_RX.search(sent):
                body = sent.rstrip()
                end = body[-1] if body and body[-1] in ".!?" else ""
                parts[i] = body.rstrip(".!?") + " (possible cause - not proven by the supplied evidence)" + end
                fixes.append("qualified an unhedged causal claim")
            if OVERCONF_RX.search(parts[i]):
                parts[i] = OVERCONF_RX.sub(lambda m: OVERCONF_SUB.get(m.group(0).lower(), "possibly"), parts[i])
                fixes.append("toned down an over-confident claim")
        lines.append(" ".join(parts))
    return "\n".join(lines), fixes


# ------------------------------------------------------------------ §46 final JSON
def final_report(a: dict) -> dict:
    md, st = a.get("metadata") or {}, a.get("statistics") or {}
    roles = a.get("mac_roles") or {}
    fnd = typed_findings(a)
    sev = [f["severity"] for f in fnd]
    status = ("FAIL" if {"critical", "high"} & set(sev) else "PASS WITH OBSERVATIONS" if fnd else
              "INCONCLUSIVE" if not a.get("events") and not (a.get("rf") or {}).get("stations") else "PASS")
    macs = [c["mac"] for c in roles.get("clients") or []] or [c["client_mac"] for c in a.get("clients") or []]
    intents = ["GENERAL_ANALYSIS"]
    return {
        "summary": f"Test {md.get('test_id')}: {len(macs)} client(s) sent auth/assoc requests, "
                   f"{len(roles.get('ap_bss') or [])} AP/BSS address(es), {len(fnd)} rule-based finding(s).",
        "status": status,
        "statistics": {k: v for k, v in st.items() if isinstance(v, (int, float))},
        "findings": fnd,
        "client_analysis": [client_lifecycle(m, a) for m in macs[:50]],
        "timeline": timeline(a, limit=40),
        "historical_comparison": [],
        "root_cause_candidates": [],
        "missing_information": missing_information(a, intents, ["QA methodology / overall"]),
        "recommendations": [],
        "confidence": "HIGH for the listed findings (parser); cause attribution needs the LLM analysis + validation",
    }
