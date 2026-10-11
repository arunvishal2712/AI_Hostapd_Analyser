"""The engine's single entry point: question -> route -> retrievers -> FACTS / view blocks / evidence ledger."""
from __future__ import annotations

import time

from engine import agent, facts, graph, learning, retrieval, router
from engine.textnorm import parse_prefix


def _fill_times(store, results):
    for r in results:
        for t in r.get("tables", []):
            for row in t["rows"]:
                ln = row.get("line")
                if ln and not row.get("time") and isinstance(ln, int):
                    _, hms, _ = parse_prefix(store.line(ln))
                    row["time"] = hms or ""


def run(store, question: str, u: dict, analysis: dict | None = None, devices: dict | None = None,
        modes: list | None = None, learn: bool = True, test_id: str = "") -> dict:
    t0 = time.time()
    learned, similar = learning.mode_scores(question) if learn else ({}, [])
    rt = router.route(question, u, learned)
    if modes:
        rt = {**rt, "modes": modes, "why": rt["why"] + "; forced " + ",".join(modes)}
    ents = retrieval.resolve(store, u, analysis)
    results = []
    for m in rt["modes"]:
        if m == "context":
            results.append(retrieval.context(store, question, u, ents))
        elif m == "wide":
            results.append(retrieval.wide(store, question, u, ents))
        elif m == "graph":
            results.append(graph.story(store, question, u, ents, analysis, devices))
        elif m == "agent":
            results.append(agent.investigate(store, question, u, ents))
    _fill_times(store, results)
    refs = facts.refs(results)
    qid = learning.record(question, test_id, u, rt["modes"], rt["why"], refs) if learn else 0
    if learn:
        learning.note_fixes(u.get("fixes") or [])
    style = learning.style_example(question) if learn else None
    text = facts.render(results, rt)
    if style:
        text += ("\n- LAYOUT THAT WORKED FOR A SIMILAR QUESTION (thumbs up; values masked - use the layout only, never "
                 "these placeholders):\n  " + style.replace("\n", "\n  "))
    return {"route": rt, "results": results, "facts": text, "refs": refs, "blocks": facts.blocks(results, rt),
            "query_id": qid, "similar": similar, "entities": ents, "ms": int((time.time() - t0) * 1000)}
