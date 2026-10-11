# Architecture Review: CAG + RAG + MAG for Hostapd Analysis

Your original design (`Hostapd_CAG_MAG_RAG_Flowise_Architecture.md`) gets the
hardest part right: **the LLM must not compute statistics**. Everything below
is refinement on top of that, not a rejection of it.

## What's already correct and should not change

- **Deterministic parser as the source of truth for counts.** This is the
  single most important architectural decision in the whole doc and it's
  correct. Kept as-is.
- **MAG as structured storage, not a vector store.** "Has this client failed
  before" is a SQL query, not a similarity search. SQLite is the right tool.
- **Splitting into multiple Flowise flows instead of one giant graph.**
  Correct instinct, kept.

## Three changes worth making

### 1. CAG should not be a second vector store

The doc's Flow A (Module 4) re-runs the RAG pattern on the Wi-Fi knowledge
docs: loader -> splitter -> embeddings -> vector store -> retriever. That
makes it "a second RAG index," not cache-augmented generation.

The actual CAG literature idea is: when a knowledge corpus is small and
**fixed**, skip retrieval entirely and inject the whole thing as a static
prefix in the prompt. Two things fall out of that:

- No embedding step, no retrieval step, no top-K tuning, no risk of the
  retriever missing the one relevant paragraph for a definitional question.
- Because the block is byte-identical on every request, Ollama's own
  inference engine (llama.cpp backend) reuses the KV-cache for that prefix
  instead of recomputing it -- this is the actual "cache" in
  cache-augmented generation, and it's free once you structure the prompt
  so the CAG block always comes first, unchanged.

This repo implements CAG as `cag/*.md` concatenated by the bridge's
`GET /cag` endpoint, meant to be pasted into the agent's system prompt once,
not fetched as a tool call per question. Six docs today (~2-3k tokens
total) -- comfortably inside any local model's context window. If the
knowledge base later grows past what's comfortable as a static block
(hundreds of docs), *that's* the point where it graduates to a real
retriever -- not before.

### 2. Replace the hand-built Query Classifier + Conditional router with a tool-calling agent

The original Module 6/7 design (an LLM call that emits
`{use_cag, use_rag, use_mag, use_parser}` JSON, then a Conditional node
routing to each) is the pre-2024 Flowise pattern. It works, but:

- It's a second LLM call before the real reasoning call (latency).
- The classifier can mis-route (say "no" to MAG on a question that
  actually needed history) with no recovery -- the conditional path already
  excluded it.
- It hardcodes routing logic that has to be manually kept in sync with new
  question types.

Modern Flowise (v2+) has a **Tool Agent** node: give a tool-calling-capable
model (Ollama's function-calling models -- qwen2.5, llama3.1/3.2,
mistral-nemo all support this) a set of tools, and the model decides which
to call, in what order, and can call more than one per question -- e.g.
Parser stats -> then MAG history -> then answer, all inside one agent loop,
with no separate classifier call and no missed branch.

This collapses Modules 6 and 7 into the agent's own reasoning:

| Old module | Replacement |
|---|---|
| Module 6 Query Classifier | Tool Agent's own tool-selection (native to the model) |
| Module 7 Context Aggregator | Tool Agent's own context window (results feed back into its loop) |
| Module 3 RAG retriever | Exposed as a `search_current_log` tool |
| Module 5 MAG | Exposed as `get_client_history` / `get_test_summary` / `get_top_unstable_clients` tools (HTTP calls to the bridge) |
| Module 2 Parser | Exposed as `get_test_statistics` tool (HTTP call to the bridge) |
| Module 4 CAG | Static block in the agent's System Message (see #1) |

The routing table in your doc (section 19) is still useful -- it's exactly
the reasoning the tool-calling model needs to do on its own, so it doubles
as a good chunk of the agent's system prompt ("if the question is about
exact counts, call get_test_statistics; if about a specific client's past
behavior, call get_client_history; ...").

### 3. MAG and the Parser should live behind one small HTTP bridge, not custom Flowise Function nodes

Flowise's "Custom Function" node runs JS in a sandboxed VM -- it can't
import `sqlite3` or shell out to a Python parser without fighting the
sandbox (`NODE_FUNCTION_ALLOW_EXTERNAL`, native module issues on Windows).
Rather than fight that, this repo runs a small FastAPI service
(`bridge/app.py`) exposing the parser and MAG as plain HTTP endpoints, and
Flowise's **Custom Tool** nodes just call it. This is also independently
testable/curlable, and reusable outside Flowise (a future dashboard hits
the same API).

## Net result

```
                    ┌─────────────────────────┐
                    │   Tool Agent (Ollama)    │
                    │  System Msg: CAG block   │
                    │  + routing guidance      │
                    └────────────┬────────────┘
                                 │ decides which tool(s) to call
        ┌────────────┬──────────┼──────────┬────────────────┐
        ▼            ▼          ▼          ▼                ▼
  get_test_stats  get_client  get_test  get_top      search_current_log
  (bridge/parse)  _history    _summary  _unstable    (RAG retriever tool,
                  (MAG)       (MAG)     (MAG)         existing vector store)
```

One Flowise chatflow, one LLM call per user turn (the agent loop), CAG paid
for once as a cached prefix, MAG and Parser as ordinary tools instead of
bespoke conditional branches.

## What did NOT change from your plan

- SQLite schema (tests/clients/events/issues) -- kept almost verbatim,
  see `mag/schema.sql`.
- Reason-code table and source-authority priority rules (Parser > current
  log > history > stable knowledge > general model knowledge) -- carried
  into the agent's system prompt verbatim.
- Report structure (sections 1-14 of your doc) -- kept as the agent's
  output format instruction.
- Build order -- parser first, then CAG, then MAG, then the agent -- this
  repo follows that order exactly.

## Possible future upgrade (not built now, noted for later)

If MAG's questions grow beyond "this client" / "this test" into relational
ones ("which AP models see this failure most", "did this start after a
firmware bump") a small graph layer (client -> test -> AP -> firmware
version edges) would answer those more naturally than more SQL joins.
Not worth the complexity yet with one AP and a handful of tests on record --
revisit if/when the test matrix grows.

## v2 additions (2026-09-24)

- **Parser findings layer.** The parser now emits rule-based `findings`
  (e.g. `AUTH_RESPONSE_NOT_ACKED`, `BEACON_SET_FAILURES`,
  `DRIVER_STA_PROGRAMMING_FAILURES`, `SYSTEM_FD_EXHAUSTION`) with the numbers
  attached. They are deterministic facts ("200 of 230 auth attempts not
  ACKed"), not conclusions -- the LLM still does the interpretation, but a
  3B model no longer has to discover the pattern itself.
- **Infrastructure errors are first-class.** Real OpenWrt logs (HOSTAPD204)
  show that platform/driver errors (ENFILE on interface creation, EINVAL on
  beacon set, EAGAIN on station flags, MLO TTLM rejects) precede and likely
  explain the client symptoms. They get their own endpoint/tool and a CAG doc,
  and the prompt tells the agent to check them before blaming clients.
- **MAG remembers findings**, so "has this AP shown beacon-set failures
  before?" is one SQL query (`get_finding_history`).
- **Agent-mode HTTP errors** (`/tool/*`): Flowise's Requests tools surface
  only "HTTP Error 4xx" to the model; the bridge returns 200 + `hint` in
  that mode so the model can retry with corrected arguments.
