"""
Query memory: every question is a learning input.

Nothing here changes model weights. Each question is stored with how it was understood (spelling fixes, resolved
MACs / SSIDs, wanted shape), the retrieval modes the router chose, the evidence lines used, the validator verdict,
the latency and - when the user gives it - thumbs up / down and a comment. From that memory the system learns:

  * routing   per-word statistics (word -> mode, positive / negative) and the nearest earlier questions with good
              feedback move the router towards the retrieval mode that answered similar questions well
  * lexicon   spelling fixes and synonyms that were confirmed (thumbs up, or used twice without a thumbs down)
              are added to the question-understanding vocabulary
  * style     the layout of well-rated answers (headings / bullets / tables, values masked) is offered to the
              model as an example for similar questions - never their values
  * insight   /learning shows what users ask most, which answers failed validation and which got thumbs down

Weak signals: an answer that passed the evidence check counts +0.3, one with warnings -0.3; explicit feedback is
+-1. Everything is local SQLite (output/learning/learning.sqlite) and can be inspected or deleted.
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "output" / "learning" / "learning.sqlite"
MODES = ("context", "graph", "agent", "wide")
WORD_RX = re.compile(r"[a-z][a-z0-9\-]{2,}")
STOP = {"the", "and", "for", "with", "what", "which", "that", "this", "from", "are", "was", "were", "has", "have", "how",
        "does", "did", "show", "give", "tell", "about", "any", "all", "please", "can", "you", "log", "file", "hostapd",
        "test", "there", "their", "its", "into", "when", "where", "who", "whom"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY, ts REAL, test_id TEXT, question TEXT, rewritten TEXT,
    understood TEXT, modes TEXT, route_why TEXT, evidence_n INTEGER, refs TEXT, status TEXT, issues TEXT,
    latency_ms INTEGER, answer TEXT, feedback INTEGER, comment TEXT, via TEXT, implicit REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS token_mode(token TEXT, mode TEXT, pos REAL DEFAULT 0, neg REAL DEFAULT 0,
    PRIMARY KEY(token, mode)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS lexicon(term TEXT PRIMARY KEY, canonical TEXT, weight REAL, source TEXT, updated REAL);
CREATE INDEX IF NOT EXISTS q_ts ON queries(ts);
"""
_LOCK = threading.Lock()
_CON: dict = {}


def _con(db: Path | None = None) -> sqlite3.Connection:
    db = Path(db or DB)
    c = _CON.get(str(db))
    if c is None:
        db.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(str(db), check_same_thread=False)
        c.executescript(SCHEMA)
        _CON[str(db)] = c
    return c


def tokens(q: str) -> list[str]:
    ql = re.sub(r"(?:[0-9a-f]{2}:){1,5}[0-9a-f]{2}", " mac ", (q or "").lower())
    ql = re.sub(r"\b\d{1,2}:\d{2}(?::\d{2})?\b", " clocktime ", ql)
    return [w for w in WORD_RX.findall(ql) if w not in STOP]


def record(question: str, test_id: str, understood: dict, modes: list, route_why: str, refs: list,
           db: Path | None = None) -> int:
    with _LOCK:
        c = _con(db)
        cur = c.execute("INSERT INTO queries(ts, test_id, question, rewritten, understood, modes, route_why, evidence_n, refs)"
                        " VALUES (?,?,?,?,?,?,?,?,?)",
                        (time.time(), test_id, question, understood.get("question"),
                         json.dumps({k: understood.get(k) for k in ("fixes", "notes", "macs", "ssids", "events", "shape",
                                                                     "window", "band")}),
                         ",".join(modes), route_why, len(refs), json.dumps(refs[:40])))
        c.commit()
        return cur.lastrowid


def validated(qid: int, status: str, issues: list, answer: str, latency_ms: int | None = None, via: str = "",
              db: Path | None = None):
    """Implicit feedback from the evidence check."""
    if not qid:
        return
    w = 0.3 if status == "PASSED" else 0.1 if status.startswith("PASSED") else -0.3
    with _LOCK:
        c = _con(db)
        row = c.execute("SELECT question, modes, implicit FROM queries WHERE id = ?", (qid,)).fetchone()
        if not row:
            return
        c.execute("UPDATE queries SET status = ?, issues = ?, answer = ?, latency_ms = COALESCE(?, latency_ms), via = ?, "
                  "implicit = ? WHERE id = ?", (status, json.dumps(issues)[:2000], (answer or "")[:6000], latency_ms, via,
                                                w, qid))
        _learn_route(c, row[0], (row[1] or "").split(","), w - (row[2] or 0))
        c.commit()


def set_meta(qid: int, latency_ms: int, via: str, db: Path | None = None):
    with _LOCK:
        c = _con(db)
        c.execute("UPDATE queries SET latency_ms = ?, via = ? WHERE id = ?", (latency_ms, via, qid))
        c.commit()


def feedback(qid: int, rating: int, comment: str = "", better_mode: str | None = None, db: Path | None = None) -> dict:
    rating = 1 if rating > 0 else -1
    with _LOCK:
        c = _con(db)
        row = c.execute("SELECT question, modes, understood, feedback FROM queries WHERE id = ?", (qid,)).fetchone()
        if not row:
            return {"ok": False, "error": "unknown query id"}
        prev = row[3] or 0
        c.execute("UPDATE queries SET feedback = ?, comment = ? WHERE id = ?", (rating, comment[:1000], qid))
        modes = [m for m in (row[1] or "").split(",") if m]
        _learn_route(c, row[0], modes, rating - prev)
        if better_mode in MODES:
            _learn_route(c, row[0], [better_mode], 1.5)
            if rating < 0:
                _learn_route(c, row[0], [m for m in modes if m != better_mode], -0.5)
        if rating > 0:
            und = json.loads(row[2] or "{}")
            for fx in und.get("fixes") or []:
                if " -> " in fx:
                    a, b = fx.split(" -> ", 1)
                    _lex(c, a.lower(), b, 1.0, "confirmed spelling fix")
        c.commit()
    return {"ok": True}


def _learn_route(c, question, modes, w):
    if not w:
        return
    for t in set(tokens(question)):
        for m in modes:
            if m not in MODES:
                continue
            c.execute("INSERT INTO token_mode(token, mode, pos, neg) VALUES (?,?,?,?) ON CONFLICT(token, mode) DO UPDATE "
                      "SET pos = pos + excluded.pos, neg = neg + excluded.neg",
                      (t, m, max(w, 0), max(-w, 0)))


def _lex(c, term, canonical, w, source):
    c.execute("INSERT INTO lexicon(term, canonical, weight, source, updated) VALUES (?,?,?,?,?) ON CONFLICT(term) DO UPDATE "
              "SET weight = weight + excluded.weight, canonical = excluded.canonical, updated = excluded.updated",
              (term, canonical, w, source, time.time()))


def add_synonym(term: str, canonical: str, db: Path | None = None):
    with _LOCK:
        c = _con(db)
        _lex(c, term.lower().strip(), canonical.strip(), 2.0, "added by user")
        c.commit()


def lexicon(min_weight: float = 1.0, db: Path | None = None) -> dict:
    with _LOCK:
        return {t: c_ for t, c_, w in _con(db).execute("SELECT term, canonical, weight FROM lexicon WHERE weight >= ?",
                                                       (min_weight,))}


def note_fixes(fixes: list, db: Path | None = None):
    """A spelling fix used again counts a little towards confirmation (2 uses without a thumbs down = learned)."""
    if not fixes:
        return
    with _LOCK:
        c = _con(db)
        for fx in fixes:
            if " -> " in fx:
                a, b = fx.split(" -> ", 1)
                _lex(c, a.lower(), b, 0.5, "repeated spelling fix")
        c.commit()


def mode_scores(question: str, db: Path | None = None) -> tuple[dict, list]:
    """Learned preference per mode (log-odds, smoothed) + the most similar earlier questions with good outcomes."""
    toks = set(tokens(question))
    if not toks:
        return {}, []
    with _LOCK:
        c = _con(db)
        ph = ",".join("?" * len(toks))
        rows = c.execute(f"SELECT token, mode, pos, neg FROM token_mode WHERE token IN ({ph})", list(toks)).fetchall()
        recent = c.execute("SELECT id, question, modes, feedback, implicit, status FROM queries "
                           "WHERE (feedback IS NOT NULL OR implicit != 0) ORDER BY id DESC LIMIT 3000").fetchall()
    sc = Counter()
    for t, m, p, n in rows:
        sc[m] += math.log((p + 1) / (n + 1))
    sims = []
    for qid, q, modes, fb, imp, st in recent:
        tq = set(tokens(q))
        if not tq:
            continue
        j = len(toks & tq) / len(toks | tq)
        if j >= 0.5:
            sims.append({"id": qid, "question": q, "modes": modes, "similarity": round(j, 2),
                         "outcome": fb if fb is not None else imp, "status": st})
    sims.sort(key=lambda d: (-d["similarity"], -(d["outcome"] or 0)))
    for s in sims[:5]:
        for m in (s["modes"] or "").split(","):
            if m in MODES:
                sc[m] += 0.8 * s["similarity"] * (1 if (s["outcome"] or 0) > 0 else -1)
    return dict(sc), sims[:5]


def style_example(question: str, db: Path | None = None) -> str | None:
    """Layout of the best-rated answer to a similar question, with every value masked."""
    toks = set(tokens(question))
    with _LOCK:
        rows = _con(db).execute("SELECT question, answer FROM queries WHERE feedback = 1 AND answer IS NOT NULL "
                                "ORDER BY id DESC LIMIT 500").fetchall()
    best, bj = None, 0.0
    for q, a in rows:
        tq = set(tokens(q))
        j = len(toks & tq) / len(toks | tq) if tq else 0
        if j > bj:
            best, bj = a, j
    if not best or bj < 0.5:
        return None
    body = best.split("\n---\n")[0]
    body = re.sub(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", "AA:AA:AA:00:00:01", body)
    body = re.sub(r"\b\d{1,2}:\d{2}:\d{2}\b", "HH:MM:SS", body)
    body = re.sub(r"\d+", "N", body)
    lines = [l for l in body.splitlines() if l.strip()][:14]
    return "\n".join(l[:140] for l in lines)


def stats(db: Path | None = None) -> dict:
    with _LOCK:
        c = _con(db)
        n = c.execute("SELECT COUNT(*), SUM(feedback = 1), SUM(feedback = -1), SUM(status = 'PASSED'), "
                      "SUM(status = 'WARNINGS'), AVG(latency_ms) FROM queries").fetchone()
        modes = c.execute("SELECT modes, COUNT(*), AVG(COALESCE(feedback, implicit)) FROM queries GROUP BY modes "
                          "ORDER BY 2 DESC LIMIT 12").fetchall()
        recent = c.execute("SELECT id, ts, test_id, question, modes, status, feedback, latency_ms FROM queries "
                           "ORDER BY id DESC LIMIT 50").fetchall()
        bad = c.execute("SELECT id, question, modes, status, comment FROM queries WHERE feedback = -1 OR status = 'WARNINGS'"
                        " ORDER BY id DESC LIMIT 20").fetchall()
        lex = c.execute("SELECT term, canonical, weight, source FROM lexicon ORDER BY weight DESC LIMIT 50").fetchall()
        toks = Counter()
        for (q,) in c.execute("SELECT question FROM queries ORDER BY id DESC LIMIT 2000"):
            toks.update(set(tokens(q)))
    return {"queries": n[0] or 0, "thumbs_up": n[1] or 0, "thumbs_down": n[2] or 0, "passed": n[3] or 0,
            "warnings": n[4] or 0, "avg_latency_ms": round(n[5] or 0),
            "modes": [{"modes": m, "n": k, "avg_outcome": round(v or 0, 2)} for m, k, v in modes],
            "recent": [dict(zip(("id", "ts", "test_id", "question", "modes", "status", "feedback", "latency_ms"), r))
                       for r in recent],
            "problems": [dict(zip(("id", "question", "modes", "status", "comment"), r)) for r in bad],
            "lexicon": [dict(zip(("term", "canonical", "weight", "source"), r)) for r in lex],
            "top_words": toks.most_common(25)}
