[Uploading README.md…]()
# Hostapd AI Analyzer

AI analysis of OpenWrt / hostapd Wi-Fi logs with Flowise + Ollama, combining
**CAG** (static Wi-Fi knowledge), **RAG** (search over the raw log) and
**MAG** (SQLite memory of every test and client). A deterministic parser
produces all numbers; the LLM only explains them.

## One click

1. Put your log in **`input_logs\`** — the **newest file there is the current test**.
2. Double-click **`START.cmd`**.

The browser opens the **Workbench** (`http://localhost:8811/ui`) and Flowise, already
signed in, on the **Hostapd AI Analyzer** chatflow. Ask in the Workbench (or with the purple
**chat** button in Flowise), e.g.:

- *Analyse the current test*
- *Why is client 7C:2A:CA:B1:23:17 slow?*
- *Show the ping and station-dump results*

**First run:** 10–20 minutes. START.cmd installs everything it needs (Python
packages, portable Node.js 24, Flowise 3.1.4, Ollama + the best installed chat model (8B preferred, e.g. `llama3:latest`) and
`nomic-embed-text`) and Flowise's very first start on Windows takes a few
minutes while the antivirus scans its files — the window shows progress.
**Later runs:** about a minute. Only **Python 3.10+** must exist (installed via
winget if missing).

**"SQLITE_BUSY: database is locked" on the sign-in page:** run `STOP.cmd`, then `START.cmd` (START
installs the fix from `tools/patch_flowise.py` and restarts Flowise automatically when needed).

**Stop:** `STOP.cmd`. **Problems:** see `logs\launcher.log`, `logs\flowise.log`, `logs\bridge.log`.

## Production engine (v4.0) - logs up to 10 GB

START indexes every log with one streaming pass (parallel over the file, constant memory) into
`output\store\<TEST>.sqlite`; the raw log stays where it is and any line is read back on demand. Each question
is routed to the retrieval that fits it:

| Technique | Ask for example | You get |
|---|---|---|
| **Context retrieval** | *What is the channel and CAC time of phy00-mld0?* / *show line 495* / *how many deauths between 11:36 and 11:42* | exact values and counts with (time, line) |
| **Graph RAG** | *Tell me the whole story of client 5C:AD:BA:AC:F6:DF* | links, where it connected, join funnel, every session and how it ended, restarts and clients that dropped with it |
| **Agentic RAG** | *Why did client ending f6:df get reason 15?* | a step-by-step investigation (trace) and ranked causes with evidence, side and how to confirm |
| **Wide retrieval** | *Summarize all MLO link rejections from top to bottom* | phases in time order, totals, busiest minutes, every message shape - with a 100 % coverage line |
| **Query learning** | rate answers with 👍 / 👎 in the Workbench | routing, vocabulary and answer layout improve; see `http://localhost:8811/learning/page` |

Details, data model, complexity and benchmark: `docs\ARCHITECTURE_V4.md`.

## Workbench, Full report and Timeline (v4.1)

`http://localhost:8811/ui` - **only a question box**. Each answer appears under its question:

| You ask | You get |
|---|---|
| a plain question - *what is the channel of phy00-mld3?*, *how many clients connected?* | the short AI answer only |
| a table or a detailed explanation - *in tabular form*, *explain in detail*, *show the timeline*, *summarize*, *compare*, *overall report* | the AI answer **plus a pictographic view**: KPI tiles with icons, findings, charts, timeline, tables with event icons |
| anything that names a client MAC together with the above | also that client's event timeline |

Buttons on top:

- **Full report** (`/report`) - the whole log as one visual report (print / save as PDF).
- **Timeline** (`/timeline`) - every client MAC: a swimlane of all sessions with how each one ended (client left,
  AP kicked it, AP restart, silent reconnect, handshake failed) and, per client, the event timeline: **connected,
  reconnected (and how long it was offline), disconnected (how long it was connected and why), deauth / disassoc
  (sent by AP or client, reason code, its IEEE meaning and a plain-language explanation), join failures (status
  code meaning), link loss, roaming and the AP restarts that hit it**. Filter by event kind, sort clients by
  problems, download a client's timeline as CSV.

Every item has the **hostapd time and log line**; click a line number to see the raw log around it. Answers in
the Flowise chat end with a link that opens the pictographic view of that question.

## How a question is answered

The chatflow follows the CAG + MAG + RAG architecture document (sections 19-24): the model only
**reasons over evidence**, it never counts, searches or calls tools itself. Use an 8B model (the
launcher auto-selects one, e.g. `llama3:latest`); the 3B `llama3.2:3b` misreads the facts.

1. **Custom JS Function** sends the question to the bridge (`POST /context`).
2. **Query Classifier** (`bridge/context.py`) picks the query type and the sources, as in the
   routing table:

   | Query type | Example | Parser | RAG | MAG | CAG |
   |---|---|:-:|:-:|:-:|:-:|
   | GENERAL_WIFI_KNOWLEDGE | what does reason code 3 mean? | - | - | - | yes |
   | CURRENT_LOG_ANALYSIS | give an overall report | yes | yes | yes | yes |
   | TEST_STATISTICS | which client has more retries? | yes | - | - | - |
   | CLIENT_ANALYSIS | is AA:BB:CC:DD:EE:FF connected? | yes | yes | yes | yes |
   | ROOT_CAUSE_ANALYSIS | why is 7C:2A:.. slow? | yes | yes | yes | yes |
   | HISTORICAL_ANALYSIS | has 5C:AD:.. failed before? | yes | yes | yes | - |
   | COMPARISON | compare with the previous test | yes | - | yes | - |

3. **Context Aggregator** builds one FACTS block in the priority order of the document:
   COMPUTED ANSWER (exact values for this question) > CURRENT TEST STATISTICS (parser) > REPORT
   (pre-filled connectivity report) > CLIENT TABLE / FINDINGS > CURRENT LOG EVIDENCE (RAG) >
   CLIENT HISTORY (MAG, labelled historical) > SYSTEM KNOWLEDGE (CAG) > ANSWER STYLE.
   **AP vs client roles** (`parser/mac_roles.py`): the AP MAC is the BSSID it beacons with (BSS setup,
   beacon lines, MLD addresses, frames the AP sends); a client is a MAC that sent an Authentication
   Request or (Re)Association Request. AP addresses are never listed as clients.
   **Keyword RAG** (`bridge/log_search.py`): keywords from the question (beacon, auth, assoc, deauth,
   EAPOL, errors, channel, MLD, start-up, a MAC ...) are searched in the raw log; the matching line
   numbers and example lines are given to the model as evidence.
4. **Chat Prompt Template** adds the source rules (parser is authoritative, never invent MACs or
   numbers, "Not available in supplied context.", history is not current, no code).
5. **LLM Chain + Ollama** writes the answer in the layout the ANSWER STYLE asks for.

See exactly what the model receives: `http://localhost:8811/context?q=which%20client%20has%20more%20retries`
(the JSON also shows the chosen `route`). START.cmd ends with a self-test whose answer is saved in
`logs\selftest_answer.txt`.

## Questions that work well (examples, tested on a 1.15M-line Wi-Fi 7 MLO log)

- `what ssid is broadcasted and give its mac address` / `what is the AP mac address` - SSIDs with interface,
  AP MLD address and one BSSID per link (band / MHz).
- `list the STA connected to IoP_Testing SSID` - partial SSID names work; each client with its final state.
- `how many clients are connected` - clients still connected at the end of the log vs disconnected.
- `list out the deauthenticated clients` - per client: deauth / disassoc counts, who sent them, reason codes,
  final state and the main disconnect causes read from the raw log.
- `why did client 5C:AD:BA:AC:F6:DF disconnect` - every disconnect episode with its cause and proof line
  (4-way handshake timeout reason 15, inactivity, not ACKed, client left, unprotected deauth ignored by PMF,
  AP teardown).
- `why are clients disconnecting from sonos SSID`, `are there any authentication failures`,
  `which clients failed the 4-way handshake`, `is the AP restarting`, `give an overall report`.

Every answer ends with an **Evidence check**: MACs, reason codes, numbers and quoted line numbers are
checked against the log; anything that does not match is marked in the answer.

## Event table (like the dashboard helper)

`http://localhost:8811/report/events` shows every Deauthentication / Disassociation / Reassociation Request /
4-Way HS Timeout of the current log in one table (time, line, client MAC, SSID, sent by, reason code, detail,
log snippet) with the dashboard rule "any such event -> FAIL". Filters: `?type=deauth,disassoc`, `&mac=...`,
`&ssid=...`. Ask in the chat e.g. `list all deauth and disassoc events between 11:36 and 11:42`.
For IP addresses / client names from LANforge start with `START.cmd -Lanforge 192.168.1.10:8080`.

## Model settings

Temperature 0.9 (more varied wording), top_p 0.9, top_k 40, repeat penalty 1.1, context 8192 tokens.
For the most literal answers start with `START.cmd -Temperature 0.3`. The Response Validator adds the complete
parser list / table if the model leaves items out.

## Runtime skill (SKILL.md)

`skills/hostapd_analyzer/SKILL.md` defines how the analyzer must reason (evidence first, no invented
events / MACs / timestamps / reason codes / statistics, correlation is not causation, missing information
must be declared). `skills/hostapd_analyzer/IMPLEMENTATION.md` maps every section to the code:
`bridge/skill.py` (intents, domains, analysis plan, lifecycle, timeline, evidence level, missing
information, IR, final JSON), `flowise/system_prompt.md` (hallucination control) and the **Response
Validator** node in Flowise (`POST /validate`), which checks every answer against the evidence and adds an
"Evidence check" footer. To add a new technical area, add an entry to `skill.DOMAINS` (keywords, expected
state flow, CAG file) and a CAG markdown file in `cag/`.

Flowise canvas: Context (bridge /context) -> Chat Prompt Template -> LLM Chain (+ Ollama) -> Response Validator.

## What the parser understands

- hostapd logs: `hostapd -t`, OpenWrt syslog / `logread`, ISO timestamps —
  auth/assoc/4-way/deauth events, reason codes, driver/beacon/system errors
- AP console captures (PuTTY / serial): `iw dev` (SSID, MLO links, band,
  channel, width, tx power), `iw <if> station dump` (signal, tx failed /
  retries, bitrate, EHT/HE/legacy, MLO links used), `ping` (loss, latency),
  hostapd `-dd` frame debug (probe requests / responses per client)

Logs removed from `input_logs\` are removed from memory on the next start.

## Folder layout

```
START.cmd / STOP.cmd   one-click start / stop
input_logs/            your logs (newest = current test)
parser/                deterministic parser (hostapd events + console-capture RF metrics)
mag/                   SQLite memory (tests, clients, events, findings)
cag/                   Wi-Fi / hostapd / driver / RF knowledge (CAG block)
bridge/                FastAPI service used by the Flowise tools (http://localhost:8811/docs)
flowise/               chatflow generator + system prompt
tools/                 launcher, Flowise setup, log ingest, Flowise package lock
tests/                 pytest suite + fixtures
docs/                  architecture notes and changelog
output/, logs/         generated
```

Heavy runtime files (Node.js, Flowise with ~1500 npm packages, the Flowise
database and its auto-generated login) live in
`%LOCALAPPDATA%\HostapdAIAnalyzer`, outside this folder.

## Options

- Better tool-calling model (needs ~8 GB free RAM): open a terminal here and run
  `START.cmd -ChatModel qwen2.5:7b`
- Flowise login (normally automatic): `%LOCALAPPDATA%\HostapdAIAnalyzer\flowise_data\login.json`
- Faster Flowise start: an administrator can exclude
  `%LOCALAPPDATA%\HostapdAIAnalyzer` from Microsoft Defender real-time scanning.
- Tests: `.venv\Scripts\python -m pytest -q tests`
#   A I _ H o s t a p d _ A n a l y s e r 
 
 
