"""Engine results -> FACTS text for the model, view blocks for the Workbench, and the evidence ledger."""
from __future__ import annotations

MODE_NAMES = {"context": "CONTEXT RETRIEVAL (exact values)", "graph": "GRAPH RAG (whole story of one thing)",
              "agent": "AGENTIC RAG (investigation with trace)", "wide": "WIDE RETRIEVAL (top-to-bottom summary)"}


def render(results: list[dict], route: dict, budget: int = 4200) -> str:
    out = [f"ENGINE RETRIEVAL (v4.0, router chose: {', '.join(MODE_NAMES[r['mode']] for r in results)}; "
           f"router scores {route.get('scores')})"]
    for r in results:
        out.append(f"- {MODE_NAMES[r['mode']]}: {r['title']}")
        if r.get("coverage"):
            out.append(f"  COVERAGE: {r['coverage']}")
        for a in r["answer"]:
            out.append(f"  * {a}")
        if r["mode"] == "agent" and r.get("trace"):
            out.append("  AGENT TRACE: " + " | ".join(f"{t['step']}. {t['tool']}: {t['found']}" for t in r["trace"])[:900])
        for t in r.get("tables", [])[:2]:
            rows = t["rows"][:8]
            if not rows:
                continue
            cols = [c for c in t["columns"] if c not in ("why",)][:7]
            out.append(f"  TABLE {t['title']} ({len(t['rows'])} rows, first {len(rows)}):")
            for row in rows:
                out.append("    - " + "; ".join(f"{c}={str(row.get(c, ''))[:70]}" for c in cols if row.get(c) not in ("", None)))
        ev = r.get("evidence") or []
        if ev:
            out.append("  EVIDENCE (hostapd time, line: text):")
            for e in ev[:10]:
                out.append(f"    - ({e['time'] or 'no time'}, line {e['line']}) {e['text'][:150]}"
                           + (f"  [{e['why']}]" if e.get("why") else ""))
    text = "\n".join(out)
    if len(text) > budget:
        text = text[:budget].rsplit("\n", 1)[0] + "\n  ... (more in the Workbench view)"
    return text


def refs(results: list[dict], limit: int = 20) -> list[dict]:
    seen, out = set(), []
    for r in results:
        for e in r.get("evidence") or []:
            if e["line"] not in seen and e.get("time"):
                seen.add(e["line"])
                out.append({"time": e["time"], "line": e["line"], "text": e["text"][:140],
                            "about": e.get("why") or r["title"]})
    return out[:limit]


def blocks(results: list[dict], route: dict) -> list[dict]:
    """Workbench blocks: one header per mode, answer bullets, the agent trace, tables (Time + Line first)."""
    out = [{"type": "engine", "modes": [r["mode"] for r in results], "names": [MODE_NAMES[r["mode"]] for r in results],
            "scores": route.get("scores"), "why": route.get("why")}]
    for r in results:
        out.append({"type": "markdown", "title": MODE_NAMES[r["mode"]],
                    "text": f"**{r['title']}**\n\n" + "\n".join(f"- {a}" for a in r["answer"])
                    + (f"\n\n*Coverage: {r['coverage']}*" if r.get("coverage") else "")})
        if r.get("trace") and r["mode"] == "agent":
            out.append({"type": "trace", "title": "Agent trace - every step and what it found", "steps": r["trace"]})
        if r.get("hypotheses"):
            out.append({"type": "findings", "items": [
                {"title": h["title"], "side": h["side"], "confidence": f"{h['confidence']} confidence",
                 "impact": i + 1, "text": "Supported by: " + "; ".join(f"line {l}: {w}" for l, w in h["support"][:3])
                 + ("  Against: " + "; ".join(f"line {l}: {w}" for l, w in h["against"][:2]) if h["against"] else ""),
                 "next": h["confirm"],
                 "evidence": [e for e in r["evidence"] if e.get("why") == h["title"]][:3]}
                for i, h in enumerate(r["hypotheses"])]})
        for t in r.get("tables", []):
            if t["title"].startswith("Hypotheses") and r.get("hypotheses"):
                continue          # shown as finding cards above
            cols = list(t["columns"])
            if "time" not in cols:
                cols = ["time"] + cols
            if "line" not in cols:
                cols.insert(1, "line")
            rows = []
            for row in t["rows"]:
                rr = dict(row)
                rr.setdefault("time", "")
                rows.append(rr)
            out.append({"type": "table", "title": t["title"], "columns": [{"key": c, "label": c.replace("_", " ").capitalize()}
                                                                         for c in cols],
                        "rows": rows[:400], "total": len(rows), "note": None, "id": t["title"][:30]})
        if r.get("evidence"):
            out.append({"type": "table", "title": f"Evidence - {MODE_NAMES[r['mode']].split(' (')[0].title()}",
                        "columns": [{"key": "time", "label": "Time"}, {"key": "line", "label": "Line"},
                                    {"key": "why", "label": "Why"}, {"key": "text", "label": "Log line"}],
                        "rows": r["evidence"][:60], "total": len(r["evidence"]), "note": None, "id": "evidence-" + r["mode"]})
    return out
