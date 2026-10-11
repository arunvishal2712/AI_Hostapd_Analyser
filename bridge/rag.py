"""
Retrieval over the raw log of one test (the RAG part).

* Semantic: log chunks embedded once with Ollama (nomic-embed-text) and cached
  in output/rag/<test_id>.emb.json; the question is embedded at query time.
* Lexical: exact MAC / keyword scoring over the same chunks -- always used,
  and the only method when Ollama is not reachable.
"""
from __future__ import annotations

import json
import math
import os
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAG_DIR = ROOT / "output" / "rag"
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
WORD_RE = re.compile(r"[a-z0-9_.:\-]{3,}")
STOP = {"the", "and", "for", "with", "what", "which", "that", "this", "from", "are", "was", "were", "has", "have",
        "how", "why", "does", "did", "show", "list", "give", "tell", "about", "any", "all", "out", "more", "most",
        "test", "log", "logs", "current", "please", "there", "client", "clients", "status"}


# Chunking (v3.4): small chunks with a large overlap, so one chunk = one short event sequence and an event
# that sits on a chunk border is still complete in the neighbouring chunk.
CHUNK_LINES = int(os.environ.get("RAG_CHUNK_LINES", "6"))       # was 12
CHUNK_CHARS = int(os.environ.get("RAG_CHUNK_CHARS", "480"))     # was 900
CHUNK_OVERLAP = int(os.environ.get("RAG_CHUNK_OVERLAP", "3"))   # was 0 (lines shared with the next chunk)
MAX_CHUNKS = int(os.environ.get("RAG_MAX_CHUNKS", "6000"))


def chunk_params() -> dict:
    return {"lines": CHUNK_LINES, "chars": CHUNK_CHARS, "overlap": CHUNK_OVERLAP}


def _chunks(text: str, max_lines: int = CHUNK_LINES, max_chars: int = CHUNK_CHARS,
            overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Sliding window over the non-empty lines: a chunk ends at max_lines or max_chars, the next chunk starts
    `overlap` lines before the end of the previous one."""
    lines = [l.rstrip()[:240] for l in text.splitlines() if l.strip()]
    out, i, n = [], 0, len(lines)
    overlap = max(0, min(overlap, max_lines - 1))
    while i < n:
        j, size = i, 0
        while j < n and j - i < max_lines and (j == i or size + len(lines[j]) <= max_chars):
            size += len(lines[j]) + 1
            j += 1
        out.append("\n".join(lines[i:j]))
        if j >= n:
            break
        i = max(i + 1, j - overlap)
    return out


def _embed(texts: list[str], timeout: int = 120) -> list[list[float]] | None:
    try:
        vecs = []
        for i in range(0, len(texts), 32):
            req = urllib.request.Request(f"{OLLAMA}/api/embed", data=json.dumps(
                {"model": EMBED_MODEL, "input": texts[i:i + 32]}).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                vecs.extend(json.load(r)["embeddings"])
        return vecs
    except Exception:  # noqa: BLE001 - Ollama down / model missing -> lexical only
        return None


def _cos(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


_MEM: dict = {}


def build_index(test_id: str, with_embeddings: bool = True) -> dict:
    src = RAG_DIR / f"{test_id}.txt"
    if not src.exists():
        return {"chunks": [], "vectors": None}
    chunks = _chunks(src.read_text(encoding="utf-8", errors="ignore"))[:MAX_CHUNKS]
    vectors = _embed(chunks) if with_embeddings and chunks else None
    if vectors:
        vectors = [[round(x, 5) for x in v] for v in vectors]
    idx = {"model": EMBED_MODEL, "params": chunk_params(), "chunks": chunks, "vectors": vectors}
    (RAG_DIR / f"{test_id}.emb.json").write_text(json.dumps(idx, separators=(",", ":")), encoding="utf-8")
    _MEM.pop(test_id, None)
    return idx


def index_is_current(test_id: str) -> bool:
    p = RAG_DIR / f"{test_id}.emb.json"
    if not p.exists():
        return False
    try:
        idx = json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return False
    return idx.get("params") == chunk_params() and idx.get("vectors") is not None


def load_index(test_id: str) -> dict:
    p = RAG_DIR / f"{test_id}.emb.json"
    src = RAG_DIR / f"{test_id}.txt"
    key = (p.stat().st_mtime, p.stat().st_size) if p.exists() else None
    if key and _MEM.get(test_id, (None,))[0] == key:
        return _MEM[test_id][1]
    if p.exists() and (not src.exists() or p.stat().st_mtime >= src.stat().st_mtime):
        idx = json.loads(p.read_text(encoding="utf-8"))
        if idx.get("params") != chunk_params():          # chunk settings changed -> rebuild
            idx = build_index(test_id)
        elif idx.get("vectors") is None:                 # try to upgrade a lexical-only index
            vecs = _embed(idx["chunks"]) if idx["chunks"] else None
            if vecs:
                idx["vectors"] = vecs
                p.write_text(json.dumps(idx, separators=(",", ":")), encoding="utf-8")
    else:
        idx = build_index(test_id)
    if idx.get("vectors"):
        idx["_norms"] = [math.sqrt(sum(x * x for x in v)) or 1.0 for v in idx["vectors"]]
    if p.exists():
        _MEM[test_id] = ((p.stat().st_mtime, p.stat().st_size), idx)
    return idx


def search(test_id: str, question: str, k: int = 6, focus: list | None = None) -> list[dict]:
    idx = load_index(test_id)
    chunks = idx.get("chunks") or []
    if not chunks:
        return []
    macs = {m.lower() for m in MAC_RE.findall(question)} | {m.lower() for m in focus or []}
    words = {w for w in WORD_RE.findall(question.lower()) if w not in STOP} - macs
    lex = []
    for c in chunks:
        low = c.lower()
        s = sum(5 for m in macs if m in low) + sum(1 for w in words if w in low)
        lex.append(s)
    sem = [0.0] * len(chunks)
    if idx.get("vectors"):
        q = _embed([question], timeout=30)
        if q:
            qv = q[0]
            qn = math.sqrt(sum(x * x for x in qv)) or 1.0
            norms = idx.get("_norms") or [1.0] * len(idx["vectors"])
            sem = [sum(a * b for a, b in zip(qv, v)) / (qn * nv) for v, nv in zip(idx["vectors"], norms)]
    lmax = max(lex) or 1
    score = [0.6 * s + 0.4 * (l / lmax) for s, l in zip(sem, lex)] if idx.get("vectors") else lex
    order = sorted(range(len(chunks)), key=lambda i: -score[i])
    return [{"chunk": chunks[i], "score": round(float(score[i]), 3)} for i in order[:k] if score[i] > 0]
