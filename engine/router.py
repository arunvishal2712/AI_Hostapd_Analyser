"""
Question -> retrieval mode(s).

    context  a specific value: a line, a count, a channel / signal / SSID / AID, the events of a client at a time
    graph    the whole story of one thing: a client, a BSS / SSID, or one event type (who / where / when)
    agent    investigate why something happened (reason, cause, root cause) through the whole log
    wide     summarise one subject from top to bottom (overall, trend, timeline, everything about)

Rules give each mode a score from the wording and the entities in the question; the query memory adds what was
learned from earlier questions (thumbs up / down, validation results). The best one or two modes run.
"""
from __future__ import annotations

import re

RULES = {
    "agent": [(r"\bwhy\b|root ?cause|\bcause[sd]?\b|\breason\b|investigat|explain|what happened|what went wrong|"
               r"how come|due to|responsible|diagnos|troubleshoot", 3.0),
              (r"fail|reject|drop|disconnect|kick|timeout|mismatch|error", 0.8)],
    "wide": [(r"summar|overall|overview|top to bottom|start to end|beginning to end|whole log|entire|throughout|"
              r"trend|over time|all .* events|everything|full picture|big picture|report", 3.0),
             (r"timeline|phases?|history", 1.5)],
    "graph": [(r"story|lifecycle|life ?cycle|journey|history of|everything about|related|relationship|connected to|"
               r"which clients .* (bss|ssid|interface|ap)|who .* (connected|joined)|where .* connect|sessions?|"
               r"\bpath\b|between .* and", 2.5),
              (r"\bclients? of\b|\bon (the )?(ssid|bss|interface)\b|\bwho\b|which (clients|stations|devices)", 1.5)],
    "context": [(r"\bwhat (is|was|were) the\b|\bwhich (channel|frequency|band|ssid|bssid)\b|\bvalue\b|\bexact\b|"
                 r"\bline \d+|\blines \d+|\bshow (me )?(the )?line|\bat \d{1,2}:\d{2}|\bhow many\b|\bcount\b|number of|"
                 r"signal|rssi|channel|frequency|\baid\b|firmware|version|cac time|\bwhen did\b|\bfirst\b|\blast\b", 2.5),
                (r"[\"“'][^\"”']{4,}[\"”']", 2.0)],
}


def route(question: str, understood: dict, learned: dict | None = None, max_modes: int = 2) -> dict:
    q = (understood.get("question") or question or "").lower()
    sc = {m: 0.0 for m in RULES}
    why = []
    for m, rules in RULES.items():
        for rx, w in rules:
            if re.search(rx, q):
                sc[m] += w
                why.append(f"{m}+{w:g}")
    shape = set(understood.get("shape") or [])
    if "why" in shape:
        sc["agent"] += 1.0
    if "count" in shape:
        sc["context"] += 1.0
    if "timeline" in shape:
        sc["wide"] += 0.7
        sc["graph"] += 0.5
    if understood.get("macs") and not any(sc.values()):
        sc["graph"] += 2.0
        why.append("client named -> graph")
    if understood.get("ssids") and sc["graph"] < 1:
        sc["graph"] += 1.0
    for m, v in (learned or {}).items():
        if m in sc and v:
            add = max(-2.0, min(2.0, v))
            sc[m] += add
            why.append(f"learned {m}{add:+.1f}")
    if not any(v > 0 for v in sc.values()):
        sc["wide"] = 1.0
        why.append("default -> wide")
    ranked = sorted(sc.items(), key=lambda kv: -kv[1])
    modes = [ranked[0][0]]
    if len(ranked) > 1 and ranked[1][1] > 0 and ranked[1][1] >= 0.5 * ranked[0][1] and max_modes > 1:
        modes.append(ranked[1][0])
    # an investigation always looks at exact values too; a wide summary of a client benefits from its story
    return {"modes": modes, "scores": {k: round(v, 2) for k, v in ranked}, "why": ", ".join(why) or "default"}
