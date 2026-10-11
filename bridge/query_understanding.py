"""
Question understanding (v3.4) - runs before the query classifier.

A small local model answers much better when the question is unambiguous, so the bridge first rewrites the
user's prompt into a clean, explicit form and tells the model what it understood:

  * typo correction against a Wi-Fi / hostapd vocabulary       ("deauthenticted" -> "deauthenticated")
  * synonyms -> canonical terms                                ("kicked", "dropped" -> "disconnected")
  * MAC addresses in any notation (aa-bb-.., aabb.ccdd.eeff, aabbccddeeff) and partial MACs
    ("client ending f6:df") resolved to the full MAC of a known client
  * SSID names matched loosely ("iop testing" -> IoP_Testing_root)
  * requested event types (deauth / disassoc / reassoc / 4-way timeout / auth / assoc),
    output shape (table / list / count / why / timeline / detailed), time window, band
The result is shown to the model as "UNDERSTOOD QUESTION" at the top of the FACTS.
"""
from __future__ import annotations

import difflib
import re

VOCAB = sorted(set("""
access point ap bssid ssid beacon broadcast broadcasted client clients station stations sta stas device devices
authentication authenticated authenticate association associated associate reassociation reassociated
deauthentication deauthenticated deauth disassociation disassociated disassoc disconnect disconnected
disconnection disconnections connect connected connection reconnect reconnected handshake eapol wpa wpa2 wpa3
sae psk password pmf timeout timeouts failure failures failed fail error errors reason code codes status
report overall summary analyse analyze analysis verify check list show give table timeline sequence count
number many which what why when where who how explain detail detailed details root cause problem issue
restart restarting restarted interface enabled disabled channel band frequency signal rssi retries roaming
roam mlo mld link links latency ping driver firmware hostapd log logs uploaded attached event events
""".split()))

COMMON = set("""
last most best this that then than from with have were when what will into over only also same each many some
time data line lines test file give gave make made take took look like just very much more less such here there
these those they them their your yours ours mine please could would should shall might must need needs want wants
does done doing been being above below after before under between during since until while where whose whom
same other another every everything anything nothing first second third next previous again still even ever
whatever whenever however about against along among around without within across through into onto upon
tell told find found says said know known seen shown shows showing gets got getting keep kept went come came
read reads write wrote open opened close closed start started stop stopped send sent receive received
high higher low lower good bad fine okay real true false full part parts items item type types kind way
name names value values level levels rate rates size page pages node nodes flow flows chat model models
""".split())

SYNONYMS = [
    (r"\bkick(?:ed|s|ing)?\s*(?:out|off)?\b|\bdropp?(?:ed|ing|s)?\b|\bthrown out\b|\bfell off\b|\blost connection\b",
     "disconnected"),
    (r"\bstas?\b|\bstations?\b|\bdevices?\b|\busers?\b|\bphones?\b|\blaptops?\b", "clients"),
    (r"\baccess ?points?\b|\brouter\b", "AP"),
    (r"\bnetwork name\b|\bwifi name\b|\bwi-fi name\b", "SSID"),
    (r"\bfour[- ]?way\b|\b4 ?way\b", "4-way"),
    (r"\bre-?assoc\w*", "reassociation"),
    (r"\bde-?auth\w*", "deauthentication"),
    (r"\bdis-?assoc\w*", "disassociation"),
]

EVENT_TYPES = [
    ("deauth", r"(?<!re)deauth|kicked|disconnect"),
    ("disassoc", r"disassoc|disconnect"),
    ("reassoc", r"reassoc|roam"),
    ("four_way", r"4-?way|handshake|eapol|reason 15|key exchange"),
    ("auth_fail", r"(?<!de)auth\w* fail|auth\w* error|sae|password|psk"),
]
SHAPES = [
    ("table", r"\btable\b|\btabular\b|\bcolumns?\b"),
    ("list", r"\blist\b|\ball\b|\bevery\b|\beach\b|\bshow\b|\bgive\b|\bwhich\b"),
    ("count", r"how many|\bcount\b|number of|\btotal\b"),
    ("why", r"\bwhy\b|root ?cause|\bcause\b|\breason\b|explain|what happened"),
    ("timeline", r"timeline|sequence|order of|\bwhen\b|history of"),
    ("detailed", r"detail|clear|full|complete|in depth|elaborate|verbose"),
]
MAC_FULL = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}(?![0-9a-f])", re.I)
MAC_DOTTED = re.compile(r"(?<![0-9a-f.])([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})(?![0-9a-f.])", re.I)
MAC_BARE = re.compile(r"(?<![0-9a-f:])([0-9a-f]{12})(?![0-9a-f:])", re.I)
MAC_PART = re.compile(r"(?<![0-9a-f:])((?:[0-9a-f]{2}:){1,4}[0-9a-f]{2})(?![0-9a-f:])", re.I)
TIME_RX = re.compile(r"\b(\d{1,2}):(\d{2})(?::(\d{2}))?\b")


def _fix_typos(q: str, extra: set) -> tuple[str, list]:
    words = re.findall(r"[A-Za-z][A-Za-z0-9_\-]*", q)
    vocab = VOCAB + sorted(extra)
    fixes = []
    for w in set(words):
        lw = w.lower()
        if len(lw) < 4 or lw in vocab or lw in extra or lw in COMMON or any(ch.isdigit() for ch in lw):
            continue
        m = difflib.get_close_matches(lw, vocab, n=1, cutoff=0.74 if len(lw) <= 5 else 0.8)
        if m and m[0] != lw:
            q = re.sub(rf"\b{re.escape(w)}\b", m[0], q)
            fixes.append(f"{w} -> {m[0]}")
    return q, sorted(fixes)


def understand(question: str, known_macs: list | None = None, ssids: list | None = None,
               lexicon: dict | None = None) -> dict:
    """lexicon: terms learned from earlier questions (engine/learning.py) -> canonical word / phrase."""
    orig = (question or "").strip()
    known = [m.upper() for m in known_macs or []]
    ssids = [s for s in ssids or [] if s]
    q = orig
    notes = []
    learned = []
    for term, canon in (lexicon or {}).items():
        if term and canon and term != canon.lower() and re.search(rf"(?<![\w:]){re.escape(term)}(?![\w:])", q, re.I):
            q = re.sub(rf"(?<![\w:]){re.escape(term)}(?![\w:])", canon, q, flags=re.I)
            learned.append(f"{term} -> {canon}")
    # MAC notations -> aa:bb:cc:dd:ee:ff
    q = MAC_DOTTED.sub(lambda m: ":".join(re.findall("..", "".join(m.groups()))), q)
    q = MAC_BARE.sub(lambda m: ":".join(re.findall("..", m.group(1))) if re.search(r"[a-f]", m.group(1), re.I)
                     or len(set(m.group(1))) > 2 else m.group(0), q)
    q = MAC_FULL.sub(lambda m: m.group(0).replace("-", ":").upper(), q)
    full = {m.upper() for m in MAC_FULL.findall(q)}
    # partial MAC ("ending f6:df") -> unique known client
    for part in MAC_PART.findall(q):
        p = part.upper()
        if any(p in f for f in full):
            continue
        hits = [m for m in known if m.endswith(p) or m.startswith(p)]
        if len(hits) == 1:
            q = q.replace(part, hits[0])
            notes.append(f"partial MAC {part} = {hits[0]}")
        elif len(hits) > 1:
            notes.append(f"partial MAC {part} matches {len(hits)} clients: {', '.join(hits[:6])}")
    # typos (SSID names and their parts are protected)
    protect = {s.lower() for s in ssids} | {t for s in ssids for t in re.split(r"[_\-\s]+", s.lower()) if t}
    q, fixes = _fix_typos(q, protect)
    if learned:
        notes.append("learned from earlier questions: " + ", ".join(learned))
    # loose SSID match: "iop testing" -> IoP_Testing_root
    ql = q.lower()
    ssid_hit = []
    for s in ssids:
        parts = [t for t in re.split(r"[_\-\s]+", s.lower()) if t and t not in ("root",)]
        if s.lower() in ql or (parts and len(parts) > 1 and all(re.search(rf"\b{re.escape(t)}", ql) for t in parts)) \
                or (len(parts) == 1 and re.search(rf"\b{re.escape(parts[0])}\b", ql)):
            ssid_hit.append(s)
            if s.lower() not in ql:
                q += f" (SSID {s})"
    # synonyms -> canonical words are ADDED so the classifier and the keyword search see them
    added = []
    for rx, canon in SYNONYMS:
        if re.search(rx, q, re.I) and canon.lower() not in q.lower():
            added.append(canon)
    if added:
        q = q + " [" + " ".join(added) + "]"
    ql = q.lower()
    events = [k for k, rx in EVENT_TYPES if re.search(rx, ql)]
    shape = [k for k, rx in SHAPES if re.search(rx, ql)]
    times = [f"{int(h):02d}:{mi}:{se or '00'}" for h, mi, se in TIME_RX.findall(ql)
             if not MAC_FULL.search(ql[max(0, ql.find(h) - 3):ql.find(h) + 12])]
    window = None
    if times:
        if re.search(r"\bbetween\b|\bfrom\b.*\bto\b", ql) and len(times) >= 2:
            window = (times[0], times[1])
        elif re.search(r"\bafter\b|\bsince\b|\bfrom\b", ql):
            window = (times[0], "23:59:59")
        elif re.search(r"\bbefore\b|\buntil\b|\btill\b", ql):
            window = ("00:00:00", times[0])
        else:
            window = (times[0], times[0][:5] + ":59")
    band = next((b for b, rx in (("6GHz", r"6 ?ghz"), ("5GHz", r"\b5 ?ghz"), ("2.4GHz", r"2\.4")) if re.search(rx, ql)), None)
    macs = sorted({m.upper() for m in MAC_FULL.findall(q)})
    desc = []
    if events:
        desc.append("event types: " + ", ".join(events))
    if macs:
        desc.append("client/AP MAC: " + ", ".join(macs))
    if ssid_hit:
        desc.append("SSID: " + ", ".join(ssid_hit))
    if band:
        desc.append("band: " + band)
    if window:
        desc.append(f"time window: {window[0]} - {window[1]}")
    desc.append("wanted output: " + (", ".join(shape) if shape else "direct answer"))
    summary = "; ".join(desc)
    if fixes:
        summary += "; spelling fixed: " + ", ".join(fixes)
    if notes:
        summary += "; " + "; ".join(notes)
    return {"question": q, "original": orig, "fixes": fixes, "notes": notes, "macs": macs, "ssids": ssid_hit,
            "events": events, "shape": shape, "window": window, "band": band, "summary": summary}
