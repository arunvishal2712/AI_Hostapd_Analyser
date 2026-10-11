"""
Keyword RAG over the raw hostapd log.

The user's question is turned into keyword groups (beacon, authentication, association, deauth,
EAPOL, errors, channel/DFS, MLD, power/AFC, start-up, a MAC address, quoted words ...). Every group
is matched against the raw log lines; the result per group is the number of matching lines, the
first / last line number and a few de-duplicated example lines (with their line numbers). This is
exact evidence the LLM can quote, and it complements the semantic (embedding) search in rag.py.
"""
from __future__ import annotations

import re
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[=>]")
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
REGISTER_RE = re.compile(r"Register frame|Subscribe to mgmt|Supported vendor|Supported cipher", re.I)
PREFIX_RE = re.compile(r"^.*?hostapd(?:\[\d+\])?:\s*")

# (question regex, label, needles = lowercase substrings that pre-select lines, refining regex on the line)
GROUPS = [
    (r"(?<!b)ssid|bssid|\bap mac|ap address|access point|\bbss\b|broadcast|\bmld\b",
     "BSS setup (AP MAC address + SSID)", ["with hwaddr"], r"using interface .* with hwaddr"),
    (r"beacon", "beacon", ["beacon"], r"beacon"),
    (r"(?<!de)auth", "authentication",
     ["authentication", "wlan_fc_stype_auth", "authenticated", "auth_alg", "sae: "],
     r"(?<!de)authentication|WLAN_FC_STYPE_AUTH\b|IEEE 802\.11: authenticated|did not acknowledge authentication|"
     r"auth_alg=|SAE: .*(commit|confirm|peer|STA)"),
    (r"(?<!dis)assoc|join|connect", "association",
     ["association request", "reassociation", "wlan_fc_stype_assoc", "wlan_fc_stype_reassoc", "associated",
      "ap-sta-connected"],
     r"(?<!dis)association request|reassociation|WLAN_FC_STYPE_(RE)?ASSOC|IEEE 802\.11: (re)?associated|AP-STA-CONNECTED"),
    (r"deauth|disconnect|kick|drop", "deauthentication",
     ["deauth", "ap-sta-disconnected"], r"deauth|AP-STA-DISCONNECTED"),
    (r"disassoc|disconnect|drop", "disassociation", ["disassoc"], r"disassoc"),
    (r"eapol|4.?way|handshake|\bkey|wpa|psk|\bsae\b|\bowe\b|security|pmf", "EAPOL / keys / security",
     ["eapol", "4-way", "pairwise key", "group key", "wpa:", "key_mgmt", "pmf", "ieee80211w"],
     r"EAPOL|4-?way|pairwise key|group key|WPA:|key_mgmt|pmf|ieee80211w"),
    (r"probe|scan", "probe / scan", ["probe", "scan"], r"probe|scan"),
    (r"error|fail|issue|problem|wrong|why|root|cause|debug|not work|down|crash", "errors / failures",
     ["fail", "error", "invalid", "denied", "not supported", "unable", "could not", "cannot", "err=-", "ret=-",
      "timeout", "timed out", "reject"],
     r"fail|error|invalid|denied|not supported|unable|could not|cannot|err=-|ret=-|timeout|timed out|reject"),
    (r"channel|freq|dfs|\bcac\b|radar|country|band|width|5 ?ghz|6 ?ghz|2\.4", "channel / frequency / DFS",
     ["channel", "freq=", "dfs", "cac", "radar", "country", "acs", "bandwidth", "ch_switch"],
     r"channel|freq=|dfs|cac|radar|country|ACS|bandwidth|ch_switch"),
    (r"\bmld\b|\bmlo\b|multi.?link|link id|link_id|wi-?fi ?7|\beht\b|802\.11be", "MLD / MLO links",
     ["mld", "link_id", "link id", "eht", "802.11be", "ttlm"], r"mld|link_id|link id|eht|802\.11be|ttlm"),
    (r"power|\bafc\b|eirp|\btpe\b|txpower|tx power", "power / AFC / EIRP",
     ["afc", "eirp", "tpe", "power"], r"afc|eirp|tpe|power"),
    (r"start|bring|\bup\b|enable|disable|restart|terminat|\binit|\bvap\b|lifecycle|boot|\bstop",
     "AP start-up / interface lifecycle",
     ["ap-enabled", "ap-disabled", "interface state", "setup of interface", "vap_up", "terminating", "ap mld",
      "hostapd_add_iface", "removing interface", "initialize interface"],
     r"AP-ENABLED|AP-DISABLED|interface state|Setup of interface|vap_up|TERMINATING|AP MLD .*(created|Freed)|"
     r"hostapd_add_iface|removing interface|Initialize interface"),
    (r"\bnft\b|qos|firewall", "nftables / QoS", ["nft", "qos"], r"NFT:|nft|qos"),
    (r"(?<!b)ssid", "SSID", ["ssid"], r"(?<![bB])ssid"),
    (r"driver|nl80211|vendor|firmware|ath1", "driver / nl80211", ["nl80211", "vendor command", "driver"],
     r"nl80211: .*(fail|err)|vendor command|driver"),
]
STOP = set("""a an the is are was were be been of to in on for and or with from this that these those it its
what which who whom how why when where does do did can could should would will shall may might please give show
list tell me my our your about any all each every per log logs file hostapd uploaded current test there here
find found get out value values status mac address addresses client clients station stations ap
overall report detailed detail details summary summarize summarise analyse analyze analysis check explain
coming working work going happened happen issue issues problem problems need want know see look also more
associated connected which there their then than into over under after before during using used
frame frames message messages line lines entry entries broadcasted broadcast attached which name names
deauthenticated disconnected authenticated""".split())
SECRET_RE = re.compile(r"(password|passphrase|psk|pmk|ptk|gtk|key)[^:]*- hexdump.*|hexdump(_ascii)?\(len=\d+\):.*", re.I)
DEFAULT_REPORT_GROUPS = ("errors / failures", "AP start-up / interface lifecycle", "authentication",
                         "association", "deauthentication")


_CACHE: dict = {}


class LogIndex:
    """Raw log lines kept in memory once per file (original + lowercase); hexdump lines are skipped."""

    def __init__(self, lines: list[str]):
        self.lines = lines
        self.low = [("" if "hexdump" in l.lower() else l.lower()) for l in lines]

    def candidates(self, needles) -> list[int]:
        nds = tuple(needles)
        return [i for i, l in enumerate(self.low) if l and any(nd in l for nd in nds)]

    def raw_candidates(self, needles) -> list[int]:
        """Case-sensitive search on the raw lines, hexdump lines included."""
        nds = tuple(needles)
        return [i for i, l in enumerate(self.lines) if any(nd in l for nd in nds)]

    def contains(self, s: str) -> bool:
        s = s.lower()
        return any(s in l for l in self.low)


def load_index(path: Path) -> LogIndex:
    try:
        st = path.stat()
    except OSError:
        return LogIndex([])
    key = (str(path), st.st_mtime, st.st_size)
    if key not in _CACHE:
        _CACHE.clear()
        _CACHE[key] = LogIndex(load_lines(path))
    return _CACHE[key]


def load_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if "\x1b" in text:
        text = ANSI_RE.sub("", text)
    return [l.rstrip("\r") for l in text.splitlines()]


def _shape(line: str) -> str:
    s = PREFIX_RE.sub("", line)
    s = MAC_RE.sub("MAC", s)
    s = re.sub(r"0x[0-9a-fA-F]+", "HEX", s)
    return re.sub(r"\d+", "N", s)[:80]


def groups_for(question: str, report: bool = False) -> list[tuple[str, list, re.Pattern]]:
    q = question.lower()
    out = []
    if report:
        out += [(label, nd, re.compile(lrx, re.I)) for _, label, nd, lrx in GROUPS if label in DEFAULT_REPORT_GROUPS]
    for qrx, label, nd, lrx in GROUPS:
        if re.search(qrx, q):
            out.append((label, nd, re.compile(lrx, re.I)))
    for m in sorted({m.upper().replace("-", ":") for m in MAC_RE.findall(question)}):
        out.append((f"MAC {m}", [m.lower()], re.compile(re.escape(m), re.I)))
    for w in re.findall(r"[\"']([^\"']{3,40})[\"']", question):
        out.append((f"text '{w}'", [w.lower()], re.compile(re.escape(w), re.I)))
    for w in re.findall(r"[A-Za-z_][A-Za-z0-9_\-]{3,}", MAC_RE.sub(" ", question)):
        wl = w.lower()
        if wl in STOP or any(re.search(g[0], wl) for g in GROUPS):
            continue
        out.append((f"word '{w}'", [wl], re.compile(re.escape(w), re.I)))
    seen, uniq = set(), []
    for label, nd, rx in out:
        if label not in seen:
            seen.add(label)
            uniq.append((label, nd, rx))
    return uniq[:8]


def search(lines, question: str, max_examples: int = 5, report: bool = False, focus: list | None = None) -> list[dict]:
    """lines: LogIndex (preferred, cached) or a plain list of lines.
    focus: MAC addresses the question is about - topic groups then only show lines of those clients."""
    idx = lines if hasattr(lines, "candidates") else LogIndex(lines)
    if hasattr(idx, "store"):
        return search_store(idx.store, question, max_examples, report, focus)
    results = []
    if report:
        max_examples = 3
    for label, needles, rx in groups_for(question, report):
        raw_words = label.startswith(("MAC", "text", "word"))
        hits = [i for i in idx.candidates(needles)
                if rx.search(idx.lines[i]) and (raw_words or not REGISTER_RE.search(idx.lines[i]))]
        fl = [m.lower() for m in focus or []]
        if fl and not raw_words:
            hits = [i for i in hits if any(m in idx.low[i] for m in fl)]
            label = f"{label} - lines of the client(s) asked about"
        shapes, examples = set(), []
        sample = hits[:4000]
        for i in sample:
            sh = _shape(idx.lines[i])
            if sh in shapes:
                continue
            shapes.add(sh)
            if len(examples) < max_examples:
                clean = SECRET_RE.sub(lambda m: m.group(0).split("hexdump")[0] + "hexdump [removed]",
                                      PREFIX_RE.sub("", idx.lines[i]))
                examples.append(f"line {i + 1}: {clean.strip()[:190]}")
        results.append({"keyword": label, "matches": len(hits),
                        "distinct": len(shapes) if len(hits) <= 4000 else f">={len(shapes)}",
                        "first_line": hits[0] + 1 if hits else None, "last_line": hits[-1] + 1 if hits else None,
                        "examples": examples})
    return results


def search_store(store, question: str, max_examples: int = 5, report: bool = False, focus: list | None = None) -> list[dict]:
    """The same keyword search on the v4 engine store, at template level: every message shape is classified once
    (its regex result is the same for every line of that shape), counts come from the shape counts written at ingest
    and from the (MAC, shape) counts for a focused client. O(number of shapes) - independent of the log size."""
    if report:
        max_examples = 3
    tpls = store.q("SELECT id, low, example, n, first_line, last_line FROM templates ORDER BY first_line")
    fl = [m.upper() for m in focus or []]
    results = []
    for label, needles, rx in groups_for(question, report):
        raw_words = label.startswith(("MAC", "text", "word"))
        if label.startswith("MAC"):
            mac = label.split()[1]
            r = store.q("SELECT n, first_line, last_line FROM macs WHERE mac = ?", (mac,))
            n, f, l = r[0] if r else (0, None, None)
            ex = store.q("SELECT e.first_line FROM ent_tpl e WHERE e.mac = ? ORDER BY e.first_line LIMIT ?", (mac, max_examples))
            results.append({"keyword": label, "matches": n, "distinct": len(store.q("SELECT 1 FROM ent_tpl WHERE mac = ?", (mac,))),
                            "first_line": f, "last_line": l,
                            "examples": [f"line {x}: {PREFIX_RE.sub('', store.line(x)).strip()[:190]}" for (x,) in ex]})
            continue
        hit = []
        for tid, low, example, n, f, l in tpls:
            if "hexdump" in low or not any(nd in low or nd in example.lower() for nd in needles):
                continue
            if not rx.search(example) or (not raw_words and REGISTER_RE.search(example)):
                continue
            hit.append((tid, n, f, l))
        if fl and not raw_words and hit:
            ids = [h[0] for h in hit]
            rows = store.q(f"SELECT tpl, SUM(n), MIN(first_line), MAX(last_line) FROM ent_tpl WHERE mac IN "
                           f"({','.join('?' * len(fl))}) AND tpl IN ({','.join('?' * len(ids))}) GROUP BY tpl", (*fl, *ids))
            hit = sorted((t, n, f, l) for t, n, f, l in rows)
            label = f"{label} - lines of the client(s) asked about"
        hit.sort(key=lambda h: h[2])
        results.append({"keyword": label, "matches": sum(h[1] for h in hit), "distinct": len(hit),
                        "first_line": min((h[2] for h in hit), default=None),
                        "last_line": max((h[3] for h in hit), default=None),
                        "examples": [f"line {h[2]}: " + SECRET_RE.sub(lambda m: m.group(0).split("hexdump")[0] + "hexdump [removed]",
                                                                      PREFIX_RE.sub("", store.line(h[2]))).strip()[:190]
                                     for h in hit[:max_examples]]})
    return results


def format_results(results: list[dict]) -> str:
    out = []
    for r in results:
        if not r["matches"]:
            out.append(f"- keyword [{r['keyword']}]: NO matching line in the raw log.")
            continue
        out.append(f"- keyword [{r['keyword']}]: {r['matches']} matching line(s), {r['distinct']} distinct message "
                   f"type(s), lines {r['first_line']}-{r['last_line']}. Examples:")
        out += [f"    {e}" for e in r["examples"]]
    return "\n".join(out)
