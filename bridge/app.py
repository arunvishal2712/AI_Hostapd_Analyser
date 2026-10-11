"""
Bridge API: the HTTP surface Flowise's tool nodes call into.

Flowise itself cannot run a Python parser or query SQLite natively, so
this small FastAPI service does the deterministic/structured work
(Parser + MAG + CAG bundle) and hands back plain JSON. The LLM inside
Flowise never computes these numbers -- it only explains what this
service reports.

Run:  python bridge/app.py            (defaults: 127.0.0.1:8811)
Env:  BRIDGE_HOST, BRIDGE_PORT
Docs: http://localhost:8811/docs      (interactive OpenAPI UI)
"""

import json
import os
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "parser"))
sys.path.insert(0, str(ROOT / "mag"))
sys.path.insert(0, str(ROOT / "bridge"))

import database as mag_db  # noqa: E402
import rag  # noqa: E402
import episodes  # noqa: E402
import event_table  # noqa: E402
import query_understanding  # noqa: E402
import insights  # noqa: E402
import views  # noqa: E402
import assistant  # noqa: E402
import client_timeline  # noqa: E402
import devices as dev_id  # noqa: E402
from engine import ENGINE_VERSION  # noqa: E402
from engine import learning as eng_learning  # noqa: E402
from engine import pipeline as eng_pipeline  # noqa: E402
from engine import store as eng_store  # noqa: E402
import log_search  # noqa: E402
from context import build_context  # noqa: E402
import skill  # noqa: E402
from common.paths import CURRENT_TEST_FILE, FLOWISE_LOGIN_FILE  # noqa: E402
from common.reason_codes import REASON_CODE_MEANINGS  # noqa: E402
from hostapd_parser import PARSER_VERSION, analyze  # noqa: E402

CAG_DIR = ROOT / "cag"
OUTPUT_JSON_DIR = ROOT / "output" / "json"
UPLOAD_DIR = ROOT / "output" / "logs"
OUTPUT_JSON_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

TEST_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")

app = FastAPI(title="Hostapd AI Analyzer Bridge", version="2.0",
              description="Parser + MAG + CAG service for the Flowise hostapd analysis agent.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"])

mag_db.init_db()

TOOL_PREFIX = "/tool"
TOOL_ARG_HINT = ('Pass the arguments inside a "queryParams" object, e.g. '
                 '{"queryParams": {"test_id": "latest"}} or {"queryParams": {"test_id": "HOSTAPD204", '
                 '"mac": "AA:BB:CC:DD:EE:FF"}}. Call list_tests to see valid test_ids.')


@app.middleware("http")
async def agent_tool_mode(request: Request, call_next):
    """
    Flowise tool nodes call the bridge under /tool/... . In that mode every
    failure is returned as HTTP 200 with a JSON {"error", "hint"} body,
    because Flowise's Requests tools only surface "HTTP Error 4xx" to the
    LLM and drop the body -- the model could never self-correct. Plain
    REST callers (curl, dashboards) use the un-prefixed paths and get
    normal status codes.
    """
    path = request.scope["path"]
    if not (path == TOOL_PREFIX or path.startswith(TOOL_PREFIX + "/")):
        return await call_next(request)

    inner = path[len(TOOL_PREFIX):] or "/"
    unfilled = [seg[1:] for seg in inner.split("/") if seg.startswith(":") or seg.startswith("%3A")]
    if unfilled:
        return JSONResponse({"error": f"Tool called without required argument(s): {', '.join(unfilled)}",
                             "hint": TOOL_ARG_HINT})
    request.scope["path"] = inner
    request.scope["raw_path"] = inner.encode()
    response = await call_next(request)
    if response.status_code < 400:
        return response
    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        detail = json.loads(body).get("detail", body.decode(errors="ignore"))
    except (ValueError, AttributeError):
        detail = body.decode(errors="ignore")
    return JSONResponse({"error": detail, "status": response.status_code, "hint": TOOL_ARG_HINT})


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _check_test_id(test_id: str) -> str:
    test_id = test_id.strip()
    if not TEST_ID_RE.match(test_id):
        raise HTTPException(400, "test_id may only contain letters, digits, '_', '-', '.' (max 64 chars)")
    return test_id


def _resolve_test_id(test_id: str) -> str:
    """Accept 'latest'/'current' so the agent can work without knowing the id."""
    if test_id.strip().lower() in ("latest", "current", "last"):
        # START.cmd marks the newest file in input_logs\ as the current test
        try:
            cur = json.loads(CURRENT_TEST_FILE.read_text(encoding="utf-8")).get("test_id")
            if cur and (OUTPUT_JSON_DIR / f"{cur}.analysis.json").exists():
                return cur
        except (OSError, ValueError):
            pass
        latest = mag_db.latest_test_id()
        if latest is None:
            raise HTTPException(404, "No tests have been parsed yet. Upload a log via POST /parse.")
        return latest
    return _check_test_id(test_id)


_ANALYSIS_CACHE: dict = {}


def _load_analysis(test_id: str) -> dict:
    """Parsed analysis JSON, cached by file time (a 10 GB log gives a large JSON - parse it once, not per request)."""
    test_id = _resolve_test_id(test_id)
    path = OUTPUT_JSON_DIR / f"{test_id}.analysis.json"
    if not path.exists():
        known = sorted(p.name.replace(".analysis.json", "") for p in OUTPUT_JSON_DIR.glob("*.analysis.json"))
        raise HTTPException(404, f"No parsed analysis found for test_id={test_id}. Known test_ids: {known}")
    st = path.stat()
    key = (str(path), st.st_mtime, st.st_size)
    hit = _ANALYSIS_CACHE.get(key)
    if hit is None:
        for k in [k for k in _ANALYSIS_CACHE if k[0] == str(path)]:
            del _ANALYSIS_CACHE[k]
        while len(_ANALYSIS_CACHE) >= 3:
            _ANALYSIS_CACHE.pop(next(iter(_ANALYSIS_CACHE)))
        hit = _ANALYSIS_CACHE[key] = json.loads(path.read_text(encoding="utf-8"))
    return hit


# ---------------------------------------------------------------------------
# v4.0 engine store: random access to the raw log without loading it
# ---------------------------------------------------------------------------
STORE_DIR = ROOT / "output" / "store"
LOGINDEX_MAX_MB = int(os.environ.get("LOGINDEX_MAX_MB", "600"))
_SINDEX: dict = {}
_ENGINE_CACHE: dict = {}


def _store(full: dict):
    """The engine store of this test when it exists and still matches the raw log, else None."""
    src = _raw_log_path(full)
    if src is None:
        return None
    try:
        st = eng_store.open_store(full["metadata"]["test_id"], STORE_DIR, source=src)
    except eng_store.StoreMissing:
        return None
    except Exception:  # noqa: BLE001 - a damaged store is rebuilt by the next ingest
        return None
    return st if st.check_source() else None


def _index(full: dict):
    """Line index for the legacy analysis code: disk-backed StoreIndex when the engine store exists (any size),
    the in-memory LogIndex only for small logs."""
    st = _store(full)
    if st is not None:
        si = _SINDEX.get(id(st))
        if si is None or si.store is not st:
            _SINDEX.clear()
            si = _SINDEX[id(st)] = eng_store.StoreIndex(st)
        return si
    src = _raw_log_path(full)
    if src is None or not src.is_file():
        return None
    if src.stat().st_size > LOGINDEX_MAX_MB * 1024 * 1024:
        raise HTTPException(503, f"{src.name} is {src.stat().st_size // 2**20} MB - the engine store is missing or out "
                                 f"of date; run START.cmd (or tools/ingest_logs.py) to index it")
    return log_search.load_index(src)


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[=>]")


def _raw_log_path(full: dict):
    md = full.get("metadata", {})
    for cand in (ROOT / md["source_file"] if md.get("source_file") else None, UPLOAD_DIR / f"{md.get('test_id')}.log"):
        if cand is not None and cand.exists():
            return cand
    return None


def _norm_mac(mac: str) -> str:
    mac = mac.strip()
    if not MAC_RE.match(mac):
        raise HTTPException(400, f"'{mac}' is not a valid MAC address (format AA:BB:CC:DD:EE:FF)")
    return mac.upper().replace("-", ":")


# ---------------------------------------------------------------------------
# health / UI
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "parser_version": PARSER_VERSION, "tests_in_memory": len(mag_db.list_tests())}


@app.get("/", response_class=HTMLResponse)
def index():
    rows = "".join(
        f"<tr><td><a href='/analysis/{t['test_id']}'>{t['test_id']}</a></td><td>{(t['created_at'] or '')[:19]}</td>"
        f"<td>{t['ap_name'] or ''}</td><td>{t['client_count']}</td><td>{t['authentication_failures']}</td>"
        f"<td>{t['handshake_failures']}</td><td>{t['driver_errors'] or 0}</td></tr>"
        for t in mag_db.list_tests()
    ) or "<tr><td colspan=7>No tests yet</td></tr>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Hostapd AI Analyzer</title>
<style>body{{font-family:system-ui,Segoe UI,sans-serif;max-width:960px;margin:24px auto;padding:0 16px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:4px 8px;text-align:left}}
fieldset{{margin:16px 0}}label{{display:inline-block;min-width:90px}}input{{margin:3px}}</style></head><body>
<h2>Hostapd AI Analyzer &mdash; bridge v2.0</h2>
<fieldset><legend>Upload a hostapd log (parse + store in MAG memory)</legend>
<form action="/parse" method="post" enctype="multipart/form-data">
<label>Log file</label><input type="file" name="file" required><br>
<label>Test ID</label><input name="test_id" required placeholder="e.g. HOSTAPD205"><br>
<label>AP name</label><input name="ap_name"> <label>SSID</label><input name="ssid"><br>
<label>Security</label><input name="security" placeholder="WPA2/WPA3/SAE"> <label>Channel</label><input name="channel" type="number"><br>
<button type="submit">Parse</button></form></fieldset>
<h3>Tests in memory</h3><table><tr><th>test_id</th><th>parsed</th><th>AP</th><th>clients</th><th>auth fail</th>
<th>4-way fail</th><th>driver err</th></tr>{rows}</table>
<p><b><a href="/ui">Open the Workbench</a></b> &middot; <a href="/report">Full visual report</a> &middot; <a href="/docs">API docs</a> &middot; <a href="/cag">CAG knowledge</a> &middot; <a href="/mag/top-unstable">Top unstable clients</a></p>
</body></html>"""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@app.post("/parse")
async def parse_log(
    file: UploadFile = File(...),
    test_id: str = Form(...),
    ap_name: Optional[str] = Form(None),
    ssid: Optional[str] = Form(None),
    security: Optional[str] = Form(None),
    channel: Optional[str] = Form(None),
    year: Optional[str] = Form(None),
):
    """
    Parse an uploaded hostapd log into exact statistics, persist it into
    MAG, and return a compact summary (full JSON: GET /analysis/{test_id}/full).
    This is the ONLY source of truth for counts.
    """
    test_id = _check_test_id(test_id)
    # v4.0: stream the upload to disk (any size), then parse it streamed and build the engine store
    dest = UPLOAD_DIR / f"{test_id}.log"
    size = 0
    with dest.open("wb") as f:
        while True:
            chunk = await file.read(8 * 1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            size += len(chunk)
    if size == 0 or (size < 65536 and not dest.read_bytes().strip()):
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "Uploaded file is empty")
    ch = int(channel) if channel and str(channel).strip().isdigit() else None
    yr = int(year) if year and str(year).strip().isdigit() else None

    from hostapd_parser import analyze_file
    from engine.ingest import ingest as eng_ingest
    result = analyze_file(dest, test_id, ap_name or None, ssid or None, security or None, ch, yr)
    (OUTPUT_JSON_DIR / f"{test_id}.analysis.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    try:
        eng_ingest(dest, test_id, STORE_DIR, year=yr)
    except Exception as e:  # noqa: BLE001 - the parser result is still usable without the store
        print(f"engine ingest failed for {test_id}: {e}")
    mag_db.ingest_analysis(result)

    return {
        "metadata": result["metadata"],
        "statistics": result["statistics"],
        "findings": result["findings"],
        "top_unstable_clients": result["top_unstable_clients"],
    }


@app.get("/tests")
def list_tests():
    """All tests stored in MAG memory, newest first."""
    return {"tests": mag_db.list_tests()}


@app.get("/analysis/{test_id}")
def get_analysis(test_id: str):
    """Authoritative statistics + deterministic findings for one test
    (compact: fits a tool-call result). test_id may be 'latest'."""
    full = _load_analysis(test_id)
    return {
        "metadata": full["metadata"],
        "statistics": full["statistics"],
        "findings": [{"id": f["id"], "severity": f["severity"], "observation": f["observation"]}
                     for f in full.get("findings", [])],
        "top_unstable_clients": [
            {k: c.get(k) for k in ("client_mac", "failure_score", "failure_count", "issues")}
            for c in full.get("top_unstable_clients", [])
        ],
        "reason_code_meanings": full.get("reason_code_meanings", {}),
    }


@app.get("/analysis/{test_id}/full")
def get_analysis_full(test_id: str):
    return _load_analysis(test_id)


@app.get("/analysis/{test_id}/infrastructure")
def get_infrastructure(test_id: str):
    """Driver / beacon / system error categories with first/last occurrence and samples."""
    full = _load_analysis(test_id)
    return {"test_id": full["metadata"]["test_id"], "infrastructure_errors": full.get("infrastructure_errors", [])}


@app.get("/analysis/{test_id}/rf")
def get_rf(test_id: str):
    """RF / performance facts from console captures: AP links (iw dev), per-station
    signal, tx failed/retries, bitrates, PHY mode, MLO links (iw station dump), ping
    loss/latency and probe-request statistics."""
    full = _load_analysis(test_id)
    rf = full.get("rf") or {}
    return {
        "test_id": full["metadata"]["test_id"],
        "ap": {"interface": full["metadata"].get("ap_interface"), "ssid": full["metadata"].get("ssid"),
               "links": full["metadata"].get("ap_links", [])},
        "stations_latest": rf.get("stations", []),
        "ping_tests": rf.get("ping_tests", []),
        "probe_requests": {k: v for k, v in (rf.get("probe_requests") or {}).items() if k != "per_client"}
        | {"top_clients": (rf.get("probe_requests") or {}).get("per_client", [])[:8]},
        "station_dump_snapshots": len(rf.get("station_snapshots", [])),
    }


@app.get("/analysis/{test_id}/client/{mac}")
def get_current_client(test_id: str, mac: str, max_events: int = Query(12, ge=1, le=500)):
    """One client's behaviour in THIS test: summary + its chronological events."""
    full = _load_analysis(test_id)
    mac = _norm_mac(mac)
    summary = next((c for c in full.get("clients", []) if c["client_mac"] == mac), None)
    if summary is None:
        return {"test_id": full["metadata"]["test_id"], "client_mac": mac, "found": False}
    evts = [e for e in full.get("events", []) if e.get("client_mac") == mac]
    return {
        "test_id": full["metadata"]["test_id"], "client_mac": mac, "found": True,
        "summary": summary, "total_events": len(evts),
        "events": [{k: e.get(k) for k in ("line_no", "event", "reason_code", "message")}
                   for e in evts[:max_events]],
        "events_truncated": len(evts) > max_events,
    }


@app.get("/analysis/{test_id}/search")
def search_events(test_id: str, q: Optional[str] = None, mac: Optional[str] = None,
                  event: Optional[str] = None, limit: int = Query(20, le=200)):
    """Deterministic keyword search over the parsed log lines of one test
    (case-insensitive substring on the raw line; optional MAC/event filters)."""
    full = _load_analysis(test_id)
    macn = _norm_mac(mac) if mac else None
    ql = q.lower() if q else None
    ev = event.upper() if event else None
    raw = _raw_log_path(full)
    if raw is not None and ev is None:
        # search the whole raw log (covers console captures: station dumps, ping, frame debug)
        hits = []
        for i, line in enumerate(raw.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            line = _ANSI_RE.sub("", line).replace("\r", "").rstrip()
            low = line.lower()
            if "hexdump(" in low or not line.strip():
                continue
            if (ql is None or ql in low) and (macn is None or macn.lower() in low):
                hits.append({"line_no": i, "event": None, "message": line[:300]})
        return {"test_id": full["metadata"]["test_id"], "source": raw.name, "total_matches": len(hits),
                "matches": hits[:limit]}
    hits = [e for e in full.get("events", [])
            if (ql is None or ql in e["message"].lower())
            and (macn is None or e.get("client_mac") == macn)
            and (ev is None or e.get("event") == ev)]
    return {"test_id": full["metadata"]["test_id"], "total_matches": len(hits),
            "matches": [{"line_no": e.get("line_no"), "event": e["event"], "message": e["message"]}
                        for e in hits[:limit]]}


# ---------------------------------------------------------------------------
# Question -> FACTS (used by the Flowise chatflow)
# ---------------------------------------------------------------------------

def _context(question: str, test_id: str = "latest") -> dict:
    """Query classifier + context aggregator: Parser + RAG + MAG + CAG -> one FACTS block."""
    full = _load_analysis(test_id)
    tid = full["metadata"]["test_id"]
    q_orig = (question or "").strip() or "Give an overall report of the current test"
    roles = full.get("mac_roles") or {}
    u = _understand(q_orig, full)
    q = u["question"]
    probe = build_context(q, full, understood=u)  # cheap first pass: query type, MACs
    route = probe["route"]
    macs = list(probe["client_macs"])
    if not macs and route["use_mag"] and route["query_type"] != "GENERAL_WIFI_KNOWLEDGE":
        macs = [c["client_mac"] for c in (full.get("top_unstable_clients") or [])[:3]]
    want_hist = route["use_mag"] and route["query_type"] != "COMPARISON"
    history = {m: mag_db.get_client_history(m) for m in macs} if want_hist else {}
    tests = mag_db.list_tests() if route["use_mag"] else []
    others = [t["test_id"] for t in tests if t["test_id"] != tid]
    comparison = None
    if others and route["query_type"] in ("COMPARISON", "HISTORICAL_ANALYSIS"):
        try:
            comparison = mag_db.compare_tests(others[0], tid)
        except Exception:  # noqa: BLE001
            comparison = None
    log_hits, eps, restarts, ev_rows = [], {}, None, None
    if route["query_type"] != "GENERAL_WIFI_KNOWLEDGE":
        try:
            idx = _index(full)
            if idx is not None:
                log_hits = log_search.search(idx, q,
                                             report=route["query_type"] in ("CURRENT_LOG_ANALYSIS", "ROOT_CAUSE_ANALYSIS"),
                                             focus=probe.get("focus_macs"))
                role_cli = (full.get("mac_roles") or {}).get("clients") or []
                known = {c["mac"]: c.get("link_addresses") or [] for c in role_cli}
                for c in full.get("clients") or []:
                    known.setdefault(c["client_mac"], [])
                if known:
                    eps = episodes.build(idx, known)
                restarts = episodes.ap_restarts(idx)
                ev_rows = event_table.build(idx, full)
        except Exception:  # noqa: BLE001
            log_hits = log_hits or []
    hits = []
    if route["use_rag"]:
        try:
            hits = rag.search(tid, q, k=6, focus=probe.get("focus_macs"))
        except Exception:  # noqa: BLE001
            hits = []
    meta = {"query_id": 0, "refs": [], "modes": []}
    extra = ""
    if route["query_type"] != "GENERAL_WIFI_KNOWLEDGE":
        eng = _engine(q_orig, tid, full, u, learn=True)
        if eng:
            extra += "\n\n" + eng["facts"]
            meta.update(query_id=eng["query_id"], refs=eng["refs"], modes=eng["route"]["modes"])
        try:
            extra += "\n\n" + _view_facts(_view(q_orig, tid), limit=1800)
        except Exception:  # noqa: BLE001 - the view is optional for the text answer
            pass
    else:
        meta["query_id"] = eng_learning.record(q_orig, tid, u, ["knowledge"], "general Wi-Fi question", [])
    # llama3 has an 8K-token window: parser facts + engine retrieval + view together stay within FACTS_BUDGET
    budget = max(8000, FACTS_BUDGET - len(extra)) if extra else 12000
    ctx = build_context(q, full, history=history, rag_hits=hits, other_tests=others,
                        comparison=comparison, log_hits=log_hits, episodes=eps,
                        restarts=restarts, events=ev_rows, understood=u,
                        enrich=event_table.lanforge_info(), max_chars=budget) | {"test_id": tid, "understood": u}
    ctx["facts"] += extra
    ctx["query_id"] = meta["query_id"]
    _FACTS_CACHE[q_orig] = (ctx["facts"], tid, q, meta)
    while len(_FACTS_CACHE) > 64:
        _FACTS_CACHE.pop(next(iter(_FACTS_CACHE)))
    return ctx


_FACTS_CACHE: dict[str, tuple] = {}
FACTS_BUDGET = int(os.environ.get("FACTS_BUDGET", "16000"))


def _understand(question: str, full: dict) -> dict:
    roles = full.get("mac_roles") or {}
    try:
        lex = eng_learning.lexicon()
    except Exception:  # noqa: BLE001
        lex = {}
    return query_understanding.understand(
        question, sorted({c["mac"] for c in roles.get("clients") or []} | {c["client_mac"] for c in full.get("clients") or []}),
        sorted({b.get("ssid") for b in (full["metadata"].get("ap_bss") or []) if b.get("ssid")}), lexicon=lex)


def _engine(question: str, tid: str, full: dict, u: dict | None = None, learn: bool = False):
    """v4.0 engine retrieval for one question (router -> context / graph / agent / wide), cached per question."""
    key = (tid, question)
    hit = _ENGINE_CACHE.get(key)
    if hit is not None and (not learn or hit.get("query_id")):
        return hit
    st = _store(full)
    if st is None:
        return None
    try:
        res = eng_pipeline.run(st, question, u or _understand(question, full), full, learn=learn, test_id=tid)
    except Exception as e:  # noqa: BLE001 - never let retrieval break the answer
        print(f"engine retrieval failed: {e!r}")
        return None
    _ENGINE_CACHE[key] = res
    while len(_ENGINE_CACHE) > 64:
        _ENGINE_CACHE.pop(next(iter(_ENGINE_CACHE)))
    return res


def _in_log(full: dict):
    """Membership test on the cached raw-log index (fast substring search, no full-text regex)."""
    try:
        idx = _index(full)
    except HTTPException:
        idx = None

    def check(s: str) -> bool:
        if idx is None:
            return False
        return idx.contains(s)
    return check


def _raw_text(full: dict) -> str:  # kept for compatibility
    return ""


@app.post("/validate")
async def validate_post(request: Request):
    """SKILL §39/§40 response validator: check the LLM answer against the evidence it was given."""
    body = await request.json()
    q = (str(body.get("question", "")).strip() or "Give an overall report of the current test")
    answer = str(body.get("answer", ""))
    if q not in _FACTS_CACHE:
        _context(q, str(body.get("test_id") or "latest"))
    return _validate(q, answer, str(body.get("test_id") or "latest"), link=body.get("source") != "workbench")


def _validate(q: str, answer: str, test_id: str = "latest", link: bool = True) -> dict:
    if q not in _FACTS_CACHE:
        _context(q, test_id)
    facts, tid, q_read, meta = _FACTS_CACHE[q]
    full = _load_analysis(tid)
    idx = _index(full)
    links = {}
    for c in (full.get("mac_roles") or {}).get("clients") or []:
        links[c["mac"]] = set(c.get("link_addresses") or [])
    refs = list(meta.get("refs") or [])
    try:
        refs += _view(q, tid)["refs"]
    except Exception:  # noqa: BLE001 - references are a bonus, never block the answer
        pass
    out = skill.validate_response(
        answer, facts, q_read, _in_log(full),
        line_lookup=(lambda n: idx.lines[n - 1] if idx and 0 < n <= len(idx.lines) else ""),
        aliases=lambda m: links.get(m, set()), refs=refs,
        view_link=(f"{BRIDGE_PUBLIC}/ui?q={urllib.parse.quote(q)}" if link else None))
    qid = meta.get("query_id")
    if qid:
        try:
            eng_learning.validated(qid, out["status"], out["issues"], out["answer"])
        except Exception:  # noqa: BLE001
            pass
        out["answer"] += (f"\n- Query #{qid} - rate this answer in the Workbench (thumbs up / down) so the analyser "
                          f"learns from it." if link else "")
    out["query_id"] = qid
    return out


# ---------------------------------------------------------------------------
# v3.5 Workbench: visual output area (tables, charts, timeline, comparison) + AI answer
# ---------------------------------------------------------------------------
BRIDGE_PUBLIC = os.environ.get("BRIDGE_PUBLIC_URL", "http://localhost:8811")
UI_DIR = ROOT / "bridge" / "ui"
_VIEW_CACHE: dict = {}


def _view_facts(v: dict, limit: int = 2600) -> str:
    """Short text version of the visual view, so the model explains exactly what the user sees."""
    out = [f"VISUAL VIEW (shown next to the answer): {v['title']}" + (f" - {v['subtitle']}" if v.get("subtitle") else "")]
    for b in v["blocks"]:
        if b.get("src") == "engine":
            continue
        if b["type"] == "kpis":
            out.append("  KPIs: " + "; ".join(f"{k['label']} = {k['value']}" for k in b["items"]))
        elif b["type"] == "findings":
            for f in b["items"]:
                ev = ", ".join(f"{e['time']} line {e['line']}" for e in f["evidence"][:3])
                out.append(f"  FINDING [{f['side']}, {f['confidence']}]: {f['title']} - {f['text']} Next step: {f['next']} "
                           f"(evidence: {ev})")
        elif b["type"] in ("bar",):
            out.append(f"  CHART {b['title']}: " + ", ".join(f"{d['label']} {d['value']}" for d in b["data"]))
        elif b["type"] == "table":
            out.append(f"  TABLE {b['title']}: {b['total']} rows (each with time and line)")
        elif b["type"] == "timeline":
            out.append(f"  TIMELINE {b['title']}: {len(b['lanes'])} clients")
        elif b["type"] == "compare":
            out.append(f"  COMPARISON {b['title']}: " + "; ".join(f"{r['metric']}: {r['a']} vs {r['b']}" for r in b["rows"]))
    text = "\n".join(out)
    return text if len(text) <= limit else text[:limit].rsplit("\n", 1)[0] + "\n  ..."


def _model(test_id: str = "latest"):
    """Insights model (sessions, disconnects, join failures, findings ...) + event rows for one test."""
    full = _load_analysis(test_id)
    tid = full["metadata"]["test_id"]
    idx = _index(full)
    if idx is None:
        raise HTTPException(404, f"the raw log of {tid} is not available - upload it again")
    known = {c["mac"]: c.get("link_addresses") or [] for c in (full.get("mac_roles") or {}).get("clients") or []}
    for c in full.get("clients") or []:
        known.setdefault(c["client_mac"], [])
    model = insights.build(idx, full, episodes.build(idx, known) if known else {}, episodes.ap_restarts(idx))
    try:
        (OUTPUT_JSON_DIR / f"{tid}.insights.json").write_text(json.dumps(views.summary(model)), encoding="utf-8")
    except OSError:
        pass
    return full, model, idx, event_table.build(idx, full)


def _summary(test_id: str) -> dict:
    p = OUTPUT_JSON_DIR / f"{test_id}.insights.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return views.summary(_model(test_id)[1])


def _view(question: str, test_id: str = "latest") -> dict:
    full, model, idx, ev = _model(test_id)
    tid = full["metadata"]["test_id"]
    key = (tid, question, len(idx.lines))
    if key in _VIEW_CACHE:
        return _VIEW_CACHE[key]
    u = _understand(question, full)
    others = None
    known = sorted(p.name.replace(".analysis.json", "") for p in OUTPUT_JSON_DIR.glob("*.analysis.json"))
    named = [t for t in known if re.search(rf"(?<![\w-]){re.escape(t)}(?![\w-])", question, re.I)]
    if re.search(views.RX["compare"], question, re.I) and named:
        pair = named[:2] if len(named) >= 2 else ([named[0], tid] if named[0] != tid else [])
        if len(pair) == 2:
            others = [_summary(t) for t in pair]
            full, model, idx, ev = _model(test_id)  # restore the current test in the caches
    v = views.build(question, u, model, full, ev, event_table.select, others)
    v |= {"test_id": tid, "question": question, "visual": views.wants_visual(question, u),
          "macs": [m for m in u.get("macs") or []][:4]}
    eng = _engine(question, tid, full, u)
    if eng:
        v["blocks"] = [dict(b, src="engine") for b in eng["blocks"]] + v["blocks"]
        v["refs"] = (eng["refs"][:10] + v["refs"])[:20]
        v["engine"] = {"modes": eng["route"]["modes"], "scores": eng["route"]["scores"], "why": eng["route"]["why"],
                       "ms": eng["ms"], "query_id": eng.get("query_id") or 0}
    _VIEW_CACHE[key] = v
    while len(_VIEW_CACHE) > 64:
        _VIEW_CACHE.pop(next(iter(_VIEW_CACHE)))
    return v


@app.post("/view")
async def view_post(request: Request):
    """Question -> deterministic visual view (blocks: kpis, findings, bar, stacked, grouped, timeline, compare, table)."""
    body = await request.json()
    q = str(body.get("question", "")).strip() or "Give an overall report of the current test"
    return _view(q, str(body.get("test_id") or "latest"))


@app.get("/view")
def view_get(q: str = "", test_id: str = "latest"):
    return _view(q.strip() or "Give an overall report of the current test", test_id)


VIEW_LINK_RX = re.compile(r"\n?- Tables, charts and the connection timeline for this question: \S+")


@app.post("/ask")
def ask_post(body: dict):
    """Ask the AI (Flowise chatflow, fallback Ollama) - used by the Workbench chat."""
    q = str(body.get("question", "")).strip() or "Give an overall report of the current test"
    tid = str(body.get("test_id") or "latest")
    res = assistant.ask(q, FLOWISE_LOGIN_FILE, facts_for=lambda x: _context(x, tid)["facts"],
                        validate=lambda x, a: _validate(x, a, tid, link=False)["answer"])
    res["answer"] = VIEW_LINK_RX.sub("", res.get("answer") or "")
    hit = _FACTS_CACHE.get(q)
    res["query_id"] = hit[3].get("query_id") if hit else 0
    if res["query_id"]:
        eng_learning.set_meta(res["query_id"], int(res.get("seconds", 0) * 1000), res.get("via", ""))
    return res


@app.on_event("startup")
def _warm_up():
    """Build the current test's views in the background right after start, so the first question does not wait for
    the one-time pass over a large log (sessions, episodes, device identification)."""
    import threading

    def warm():
        try:
            _view("Give an overall report of the current test", "latest")
        except Exception as e:  # noqa: BLE001 - only a cache warm-up
            print(f"warm-up skipped: {e!r}")
    if os.environ.get("BRIDGE_WARMUP", "1") == "1":
        threading.Thread(target=warm, daemon=True).start()


@app.post("/feedback")
def feedback_post(body: dict):
    """Thumbs up / down (+ comment, + the retrieval mode that would have been better) for one answered question."""
    qid = int(body.get("query_id") or 0)
    rating = int(body.get("rating") or 0)
    if not qid or rating == 0:
        raise HTTPException(400, "query_id and rating (+1 / -1) are required")
    return eng_learning.feedback(qid, rating, str(body.get("comment") or ""), body.get("better_mode"))


@app.get("/learning")
def learning_stats():
    """What the analyser learned from the questions: counts, modes, problems, learned vocabulary."""
    return eng_learning.stats()


@app.get("/learning/page", response_class=HTMLResponse, include_in_schema=False)
def learning_page():
    s = eng_learning.stats()
    e = lambda x: str(x if x is not None else "").replace("&", "&amp;").replace("<", "&lt;")  # noqa: E731
    fb = lambda v: "👍" if v == 1 else "👎" if v == -1 else ""  # noqa: E731
    rows = "".join(f"<tr><td>{r['id']}</td><td>{e(r['question'])}</td><td>{e(r['modes'])}</td><td>{e(r['status'])}</td>"
                   f"<td>{fb(r['feedback'])}</td><td>{e(r['latency_ms'])}</td></tr>" for r in s["recent"])
    probs = "".join(f"<tr><td>{r['id']}</td><td>{e(r['question'])}</td><td>{e(r['modes'])}</td><td>{e(r['status'])}</td>"
                    f"<td>{e(r['comment'])}</td></tr>" for r in s["problems"]) or "<tr><td colspan=5>none</td></tr>"
    lex = "".join(f"<tr><td>{e(r['term'])}</td><td>{e(r['canonical'])}</td><td>{r['weight']:.1f}</td><td>{e(r['source'])}</td></tr>"
                  for r in s["lexicon"]) or "<tr><td colspan=4>nothing learned yet</td></tr>"
    modes = "".join(f"<tr><td>{e(r['modes'])}</td><td>{r['n']}</td><td>{r['avg_outcome']:+.2f}</td></tr>" for r in s["modes"])
    words = ", ".join(f"{w} ({n})" for w, n in s["top_words"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Analyser learning</title><style>
:root{{--bg:#f4f3ef;--card:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--line:#e1e0d9;--acc:#2a78d6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111110;--card:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--line:#2e2d2a;--acc:#3987e5}}}}
body{{background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:0;padding:16px}}
main{{max-width:1100px;margin:0 auto}} .card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:12px 0;overflow:auto}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}}
th{{color:var(--ink2)}} .k{{display:inline-block;margin-right:22px}} .k b{{font-size:22px;display:block}} input,button{{font:inherit;padding:4px 8px}}
</style></head><body><main><h2>What the analyser learned from your questions</h2>
<div class="card"><span class="k"><b>{s['queries']}</b>questions</span><span class="k"><b>{s['thumbs_up']}</b>👍</span>
<span class="k"><b>{s['thumbs_down']}</b>👎</span><span class="k"><b>{s['passed']}</b>passed the evidence check</span>
<span class="k"><b>{s['warnings']}</b>with warnings</span><span class="k"><b>{s['avg_latency_ms'] / 1000:.1f} s</b>average answer time</span></div>
<div class="card"><h3>Retrieval modes and their outcome</h3><table><tr><th>modes</th><th>questions</th><th>avg outcome (-1..+1)</th></tr>{modes}</table>
<p>Most asked about: {e(words)}</p></div>
<div class="card"><h3>Learned vocabulary</h3><table><tr><th>term</th><th>means</th><th>weight</th><th>source</th></tr>{lex}</table>
<form onsubmit="event.preventDefault();fetch('/learning/synonym',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{term:this.t.value,canonical:this.c.value}})}}).then(()=>location.reload())">
<p>Teach a term: <input name="t" placeholder="e.g. camera" required> means <input name="c" placeholder="e.g. D-Link DCS-8000LH" required> <button>Add</button></p></form></div>
<div class="card"><h3>Answers to improve (👎 or evidence-check warnings)</h3><table><tr><th>#</th><th>question</th><th>modes</th><th>check</th><th>comment</th></tr>{probs}</table></div>
<div class="card"><h3>Recent questions</h3><table><tr><th>#</th><th>question</th><th>modes</th><th>check</th><th>rating</th><th>ms</th></tr>{rows}</table></div>
</main></body></html>"""


@app.post("/learning/synonym")
def learning_synonym(body: dict):
    term, canon = str(body.get("term") or "").strip(), str(body.get("canonical") or "").strip()
    if not term or not canon:
        raise HTTPException(400, "term and canonical are required")
    eng_learning.add_synonym(term, canon)
    return {"ok": True, "lexicon": eng_learning.lexicon()}


@app.get("/engine/status")
def engine_status(test_id: str = "latest"):
    full = _load_analysis(test_id)
    st = _store(full)
    if st is None:
        return {"test_id": full["metadata"]["test_id"], "store": None,
                "hint": "no engine store - run START.cmd / tools/ingest_logs.py"}
    return {"test_id": full["metadata"]["test_id"], "store": str(st.db.name), "meta": st.meta}


@app.get("/engine/retrieve")
def engine_retrieve(q: str, test_id: str = "latest", mode: str = ""):
    """Run the engine retrievers directly (debug / automation): mode = context | graph | agent | wide | '' (router)."""
    full = _load_analysis(test_id)
    st = _store(full)
    if st is None:
        raise HTTPException(404, "no engine store for this test")
    modes = [m for m in mode.split(",") if m in ("context", "graph", "agent", "wide")] or None
    r = eng_pipeline.run(st, q, _understand(q, full), full, modes=modes, learn=False, test_id=full["metadata"]["test_id"])
    return {k: r[k] for k in ("route", "results", "facts", "refs", "ms", "entities")}


@app.get("/log/context")
def log_context(line: int, n: int = 12, test_id: str = "latest"):
    """Raw log lines around one line number (the Workbench opens this when a line number is clicked)."""
    full = _load_analysis(test_id)
    src = _raw_log_path(full) or (ROOT / "__no_raw_log__")
    idx = _index(full)
    if idx is None:
        raise HTTPException(404, "raw log not available")
    n = max(1, min(n, 200))
    a, b = max(1, line - n), min(len(idx.lines), line + n)
    return {"test_id": full["metadata"]["test_id"], "file": src.name, "line": line, "total": len(idx.lines),
            "lines": [{"n": i, "text": _ANSI_RE.sub("", idx.lines[i - 1])[:2000]} for i in range(a, b + 1)]}


@app.get("/ui", include_in_schema=False)
def workbench():
    return FileResponse(UI_DIR / "workbench.html", media_type="text/html")


@app.get("/report", include_in_schema=False)
def report_page():
    return FileResponse(UI_DIR / "workbench.html", media_type="text/html")


# ---------------------------------------------------------------------------
# Timeline button: per-client event timeline (engine store only)
# ---------------------------------------------------------------------------
_DEV_CACHE: dict = {}


def _devices(full: dict, idx) -> dict:
    """Device labels per client: reuse the insights model when it is already built, else identify once and cache."""
    tid = full["metadata"]["test_id"]
    for k, m in list(insights._CACHE.items()):
        if k[2] == tid and isinstance(m, dict) and m.get("devices"):
            return m["devices"]
    key = (tid, id(idx), len(idx.lines))
    if key not in _DEV_CACHE:
        alias, _ = client_timeline.groups(full)
        links: dict = {}
        for m, c in alias.items():
            links.setdefault(c, [])
            if m != c:
                links[c].append(m)
        try:
            _DEV_CACHE.clear()
            _DEV_CACHE[key] = dev_id.identify(idx, links)
        except Exception:  # noqa: BLE001 - labels are optional
            _DEV_CACHE[key] = {}
    return _DEV_CACHE[key]


def _timeline_store(test_id: str):
    full = _load_analysis(test_id)
    st = _store(full)
    if st is None:
        raise HTTPException(503, "the engine store of this test is missing or out of date - run START.cmd "
                                 "(or tools/ingest_logs.py) to index the log")
    return full, st


@app.get("/timeline", include_in_schema=False)
def timeline_page():
    return FileResponse(UI_DIR / "workbench.html", media_type="text/html")


@app.get("/timeline/clients")
def timeline_clients(test_id: str = "latest"):
    """All clients: counters (connections, reconnections, disconnections, deauth, failures), sessions for the
    swimlane and AP restart markers."""
    full, st = _timeline_store(test_id)
    try:
        devs = _devices(full, _index(full))
    except HTTPException:
        devs = {}
    res = client_timeline.overview(st, full, devs)
    src = _raw_log_path(full)
    return res | {"test_id": full["metadata"]["test_id"], "file": src.name if src else ""}


def _kinds(kinds: str):
    return [k for k in kinds.split(",") if k] or None


@app.get("/timeline/client/{mac}")
def timeline_client(mac: str, test_id: str = "latest", kinds: str = "", offset: int = 0, limit: int = 300):
    """One client: every connection, reconnection, disconnection, deauth / disassoc (reason code + meaning),
    failure and AP restart, in log order with time and line."""
    full, st = _timeline_store(test_id)
    res = client_timeline.client(st, full, _norm_mac(mac), _kinds(kinds), max(0, offset), limit)
    return res | {"test_id": full["metadata"]["test_id"]}


@app.get("/timeline/client/{mac}/csv", include_in_schema=False)
def timeline_client_csv(mac: str, test_id: str = "latest", kinds: str = ""):
    import csv
    import io
    full, st = _timeline_store(test_id)
    res = client_timeline.client(st, full, _norm_mac(mac), _kinds(kinds), 0, 2000)
    total = res["total"]
    rows = res["items"]
    off = len(rows)
    while off < total:
        more = client_timeline.client(st, full, _norm_mac(mac), _kinds(kinds), off, 2000)["items"]
        if not more:
            break
        rows += more
        off += len(more)
    buf = io.StringIO()
    csv.writer(buf).writerows(client_timeline.to_csv_rows(rows))
    name = res["mac"].replace(":", "") + "_timeline.csv"
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _event_rows(test_id: str, type: str = "", mac: str = "", ssid: str = ""):
    full = _load_analysis(test_id)
    idx = _index(full)
    if idx is None:
        raise HTTPException(404, "raw log of this test is not available")
    rows = event_table.build(idx, full)
    rows = event_table.select(rows, types=[t for t in type.split(",") if t] or None,
                              macs=[m for m in mac.upper().split(",") if m] or None,
                              ssids=[x for x in ssid.split(",") if x] or None)
    return full, rows


@app.get("/report/events", response_class=HTMLResponse)
def report_events(test_id: str = "latest", type: str = "", mac: str = "", ssid: str = ""):
    """Disconnect-class event table (Deauth / Disassoc / Reassoc / 4-way timeout) as an HTML page - the same
    table the dashboard helper analyze_hostapd_logs() attaches to Allure, role-aware and de-duplicated."""
    full, rows = _event_rows(test_id, type, mac, ssid)
    return event_table.html_report(rows, f"Hostapd Log Analysis - {full['metadata']['test_id']} - All Events",
                                   event_table.lanforge_info())


@app.get("/report/events.json")
def report_events_json(test_id: str = "latest", type: str = "", mac: str = "", ssid: str = ""):
    full, rows = _event_rows(test_id, type, mac, ssid)
    return {"test_id": full["metadata"]["test_id"], "summary": event_table.summary_line(rows),
            "dashboard_verdict": event_table.dashboard_verdict(rows), "counts": event_table.counts(rows), "events": rows}


@app.get("/skill/report")
def skill_report(test_id: str = "latest"):
    """SKILL §46 standard final JSON (deterministic part) for dashboards / automation."""
    return skill.final_report(_load_analysis(test_id))


@app.get("/context")
def context_get(q: str = "", test_id: str = "latest"):
    """Everything the LLM needs to answer one question, as a compact FACTS block."""
    return _context(q, test_id)


@app.post("/context")
async def context_post(request: Request):
    body = await request.json()
    return _context(str(body.get("question", "")), str(body.get("test_id") or "latest"))


# ---------------------------------------------------------------------------
# MAG
# ---------------------------------------------------------------------------

@app.get("/mag/client/{mac}")
def mag_client(mac: str):
    """Historical record for one client across all previously parsed tests."""
    return mag_db.get_client_history(_norm_mac(mac))


@app.get("/mag/test/{test_id}")
def mag_test(test_id: str):
    """Stored summary (stats + findings) for a specific historical test."""
    return mag_db.get_test_summary(_resolve_test_id(test_id))


@app.delete("/mag/test/{test_id}")
def mag_delete_test(test_id: str):
    test_id = _check_test_id(test_id)
    return {"test_id": test_id, "deleted": mag_db.delete_test(test_id)}


@app.get("/mag/top-unstable")
def mag_top_unstable(limit: int = Query(5, ge=1, le=100)):
    """Clients with the most cumulative failure events across all tests on record."""
    return mag_db.get_top_unstable_clients(limit)


@app.get("/mag/findings/{finding_id}")
def mag_finding(finding_id: str):
    """Which tests on record raised a given finding (e.g. BEACON_SET_FAILURES)."""
    return mag_db.get_finding_history(finding_id)


@app.get("/mag/compare")
def mag_compare(test_a: str, test_b: str):
    return mag_db.compare_tests(_resolve_test_id(test_a), _resolve_test_id(test_b))


# ---------------------------------------------------------------------------
# CAG
# ---------------------------------------------------------------------------

def cag_text() -> str:
    docs = sorted(CAG_DIR.glob("*.md"))
    return "\n\n---\n\n".join(doc.read_text(encoding="utf-8") for doc in docs)


@app.get("/cag", response_class=PlainTextResponse)
def cag_bundle():
    """
    The full static Wi-Fi/hostapd knowledge base, concatenated.

    Intentionally NOT retrieved via vector search: the corpus is small and
    fixed, so it is injected as a single static block (true cache-augmented
    generation) -- Ollama reuses the KV-cache for this identical prefix.
    """
    text = cag_text()
    if not text:
        raise HTTPException(404, "No CAG knowledge files found in cag/")
    return text


@app.get("/cag/topics")
def cag_topics():
    return {"topics": [doc.stem for doc in sorted(CAG_DIR.glob("*.md"))]}


# ---------------------------------------------------------------------------
# One-click launcher support: Flowise auto-login
# ---------------------------------------------------------------------------

_FLOWISE_ORIGINS = {"http://localhost:3000", "http://127.0.0.1:3000"}


@app.get("/local/flowise-login", include_in_schema=False)
def local_flowise_login(request: Request):
    """Hands the locally generated Flowise admin login to Flowise's own
    autologin page (tools/flowise_autologin.html). Loopback clients only,
    and only for the Flowise origin, so other web pages cannot read it."""
    origin = request.headers.get("origin")
    if request.client is None or request.client.host not in ("127.0.0.1", "::1", "testclient"):
        raise HTTPException(403, "loopback only")
    if origin is not None and origin not in _FLOWISE_ORIGINS:
        raise HTTPException(403, "origin not allowed")
    if not FLOWISE_LOGIN_FILE.exists():
        raise HTTPException(404, "Flowise login not provisioned yet - run START.cmd")
    data = json.loads(FLOWISE_LOGIN_FILE.read_text(encoding="utf-8"))
    headers = {"Cache-Control": "no-store"}
    if origin:
        headers["Access-Control-Allow-Origin"] = origin
    return JSONResponse({k: data.get(k) for k in ("email", "password", "target")}, headers=headers)


@app.get("/reason-codes/{code}")
def reason_code(code: int):
    return {"code": code, "meaning": REASON_CODE_MEANINGS.get(code, "Reserved / vendor-specific reason code")}


if __name__ == "__main__":
    import uvicorn
    # Loopback by default: the bridge has no authentication. Set BRIDGE_HOST=0.0.0.0 to expose it on the LAN.
    uvicorn.run(app, host=os.environ.get("BRIDGE_HOST", "127.0.0.1"), port=int(os.environ.get("BRIDGE_PORT", "8811")))
