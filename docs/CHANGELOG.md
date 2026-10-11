# Changelog

## v4.1 (2026-10-07) - query-only Workbench, pictographic answers, Timeline button
- **Workbench** (`/ui`): only the question box - no introduction, no example chips, no report before the first
  question. Each answer appears under its question. A plain question gets the short AI answer only; a request for
  a table or a detailed explanation (also timeline, chart, summary, comparison, report) gets the answer plus a
  **pictographic view** (KPI tiles with icons, findings, charts, timeline, tables with an icon per event).
  Decided by `views.wants_visual()`; `/view` returns `visual` and `macs`. A named client MAC adds its timeline.
  When the AI model is unreachable, the answer computed directly from the indexed log is shown instead.
- **Full report** button kept (`/report`).
- **Timeline** button (`/timeline`, new `bridge/client_timeline.py`): per client MAC - connected, reconnected
  (time offline), disconnected (session length + cause), deauth / disassoc (sent by AP / client, reason code +
  IEEE meaning + plain-language explanation; a deauth frame inherits the reason of the request that caused it),
  join failures (status code meaning), link loss, roaming, AP restarts, DFS and broadcast deauth while the client
  was connected. Swimlane of all sessions, per-kind filters, paging, CSV. Wi-Fi 7 link addresses are merged into
  their MLD client. Built from the engine store with indexed queries only (linear in that client's events).
  Endpoints: `GET /timeline/clients`, `GET /timeline/client/{mac}` (`kinds`, `offset`, `limit`),
  `GET /timeline/client/{mac}/csv`.
- `common/reason_codes.py`: plain-language explanations for the common reason codes, IEEE status-code table.
- **Parser 2.10 - MAC role fix**: a `HOSTAPD-LOG-TRIGGER addr=<MAC> ... event=auth_reject` line names the
  station, but it was counted as AP evidence; a phone with auth / assoc requests and AP-STA-CONNECTED was then
  listed as an AP and the report showed "Clients seen: 0" (HostapdsamsungM04wifi7.txt). Hard client evidence now
  overrides it (`mac_roles.OVERRIDABLE_AP`). The Timeline also treats every MAC with AP-STA-CONNECTED as a client.
  START re-indexes once because the parser version changed (about 1 min for 186 MB). 73 tests.

## v4.0 (2026-10-04) - production engine: logs up to 10 GB, linear time, five retrieval techniques, query learning
- **Streaming engine** (`engine/`): one pass over the raw log, split into byte ranges processed in parallel
  (`engine/ingest.py`). Per line: timestamp, message shape (template), MAC postings and typed events chosen once
  per shape. Everything goes into an on-disk store `output/store/<TEST>.sqlite` (events, message shapes, which
  2048-line block mentions which MAC / shape, per-minute rollups, attributes, sessions, graph edges). The raw log is
  never copied or held in memory: any line is one seek away (`engine/store.py`). Time O(n), memory constant
  (~100 MB per worker for any size). Measured: 10 GB / 62 million lines in 6 min 37 s on 2 vCPUs (store 84 MB);
  full START ingest of 10 GB (engine + parser) 20 min on 2 vCPUs (~5-10 min on 4-8 cores); questions on the 10 GB
  log answer in 0.02-0.25 s. See docs/ARCHITECTURE_V4.md.
- **Streamed, parallel parser**: `hostapd_parser.analyze_file()` gives the same analysis as `analyze()` without
  loading the file: event classification is cached per message shape (25x faster) and byte ranges are parsed on
  all cores and merged in file order (items that depend on earlier ranges - MLME frames to an AP found earlier, MLD
  link set-up, SAE/EAPOL MAC context - are resolved during the merge; tested equal down to 3 KB ranges).
  HOSTAPD-FINAL (186 MB): 3 min -> about 30 s for the whole ingest.
- **Parser 2.9**: hostapd's own spelling "disassocation: STA=" is now recognised (parser, MAC roles, episodes, event
  table, engine) - on HOSTAPD-FINAL 26 client-sent disassociations (reason 8) were missing before.
- **Five techniques** (router `engine/router.py` picks one or two per question):
  1. **Query learning** (`engine/learning.py`): every question is stored with its understanding, route, evidence,
     validation result and thumbs up / down; word statistics and similar earlier questions steer the router,
     confirmed spelling fixes / taught terms extend the vocabulary, well-rated answers give the layout example.
     Page: `http://localhost:8811/learning/page`. No model weights change.
  2. **Context retrieval** (`engine/retrieval.py`): exact values (channel, frequency, CAC time, signal, AID, SSID,
     BSSID, firmware ...), lines by number, exact event counts by client / type / reason / status / time window,
     every line of a quoted phrase.
  3. **Graph RAG** (`engine/graph.py`): the whole story of a client (links, where it connected, join funnel, every
     session and how it ended, AP restarts that dropped it, clients that dropped together with it), of an SSID /
     interface, or of an event type (who / where / when), and relation paths.
  4. **Agentic RAG** (`engine/agent.py`): a bounded investigator - locate, anchor, events before, AP context,
     co-affected clients, recurrence, raw lines, ranked hypotheses with supporting / contradicting evidence, side,
     confidence and how to confirm. Every step is a store query shown as a trace.
  5. **Wide retrieval** (`engine/retrieval.py` `wide`): top-to-bottom map-reduce of one subject over the per-minute
     rollups - phases, totals, busiest minutes and the complete inventory of message shapes, with a coverage line.
- **No hallucination by construction**: counts come from the full pass, evidence text is read back from the raw log,
  every result has a COVERAGE line, a semantic index is never silently partial (logs too large to embed line by
  line get a complete *shape catalog* instead), and line numbers match text editors (CRLF / LF / lone CR).
- **Legacy views on any size**: insights, episodes, event table, device identification and the keyword search run on
  a disk-backed `StoreIndex` (identical results, tested) - only the blocks of matching message shapes are read.
- **Bridge**: `/context` adds an ENGINE RETRIEVAL section to the FACTS; `/view` puts the engine blocks (modes,
  findings, agent trace, tables) first; new `/feedback`, `/learning`, `/learning/page`, `/learning/synonym`,
  `/engine/status`, `/engine/retrieve`; `/parse` streams uploads of any size to disk. Analysis JSON cached per file.
- **Workbench**: engine mode chips, agent trace, thumbs up / down + "better mode" + comment under every AI answer.
- FACTS budget (`FACTS_BUDGET`, default 16,000 characters) so parser facts + engine retrieval + view summary fit
  llama3's 8K-token window; the bridge warms up the views of the current test in the background at start.
- System prompt rule 18 (how to use each retrieval mode). 68 tests (incl. a randomised test that any substring of
  any line is found on exactly the same lines by the disk index as by the in-memory index).

## v3.5 (2026-10-01) - visual output area (Workbench): tables, charts, timeline, comparison; mandatory time + line
- **Workbench** `http://localhost:8811/ui` (opens automatically at the end of START): chat on the left, a visual
  output panel on the right. Every question is turned into a view of KPI tiles, ranked findings, bar / stacked /
  grouped charts, a per-client **connection timeline** (bar colour = band, end mark = who ended the session,
  x = failed join, dashed line = Wi-Fi reload, shaded band = DFS wait), side-by-side **comparisons** and sortable,
  filterable tables with CSV download. Light / dark theme, print / PDF, works on a phone. Fully offline (no CDN).
- **Full visual report** `http://localhost:8811/report`, laid out like the sample report: KPIs, findings with
  side (DUT / STA / Expected), confidence, next step and log evidence, charts, timeline, client table, disconnect
  table, join failures, device identification, capture 1 vs capture 2.
- **Time + line are mandatory**: every table row, finding and chart tooltip carries the hostapd time and the log
  line; click a line number to see the raw log around it (`GET /log/context?line=N`). The Response Validator adds
  the time to any "line N" the model wrote without it and appends **Log references** when the answer has fewer
  than two (time, line) pairs. System prompt rule 17.
- **New analysis model** `bridge/insights.py`: console captures (PuTTY sessions, firmware, operator actions such
  as `wifi` / `vi /etc/config/wireless`), per-client sessions with band and who ended them (DUT kickout /
  station left / Wi-Fi reload / silent reconnect), join failures (MLO link rejected status 43 with the offered
  AKM, 4-way handshake failed, auth not ACKed, SAE mismatch), SAE commits and EAPOL retries per client, ranked
  findings (MLO security mismatch, handshake failures with/without client replies, low-ACK kickouts + roaming to
  another AP, band ping-pong, short sessions, Wi-Fi reloads + DFS wait, driver / platform warnings).
- **Device identification** `bridge/devices.py`: WPS manufacturer / model, vendor elements (Apple, Qualcomm,
  MediaTek, Huawei, Broadcom ...), MAC vendor prefix, Wi-Fi 7 (EHT / multi-link element) - from the frame
  hexdumps in `-dd` logs, always shown with its evidence.
- **Question -> view** `bridge/views.py`: report, why-disconnect, client (full MAC or partial), SSID / band / time
  window, events (deauth / disassoc / reassoc / 4-way), join failures, AP restarts, devices, driver warnings,
  capture-vs-capture and test-vs-test comparison ("compare TEST_001 with TEST_002").
- **API**: `POST /view` (deterministic view JSON), `POST /ask` (asks the Flowise chatflow; falls back to Ollama
  with the same prompt, settings and validator), `GET /log/context`, `GET /ui`, `GET /report`. The FACTS now end
  with a short **VISUAL VIEW** section so the model explains exactly what the user sees; answers in the Flowise
  chat end with a link to the visual view of that question.
- 54 tests.

## v3.4 (2026-09-30) - clearer, more detailed answers; question understanding; dashboard-style event table
- **Question understanding** (`bridge/query_understanding.py`): spelling is fixed against a Wi-Fi vocabulary
  ("deauthenticted", "clints faild authentcation", "verufy"), synonyms are added ("kicked out", "dropped" ->
  disconnected; stations / devices -> clients), MACs in any notation (aa-bb-.., aabb.ccdd.eeff, aabbccddeeff) and
  partial MACs ("client ending f6:df") are resolved, SSIDs are matched loosely ("iop testing"), and the wanted
  output (table / list / count / why / timeline / detailed), time window ("after 11:40", "between 11:36 and
  11:42") and band are detected. The model sees this as the first FACTS line "UNDERSTOOD QUESTION".
- **Event table** (`bridge/event_table.py`) modelled on the test-suite helper `analyze_hostapd_logs` /
  `fail_on_hostapd_disconnections`: Deauthentication / Disassociation / Reassociation Request / 4-Way HS
  Timeout, one row per event (time, line, client MAC, SSID, who sent it, reason code + meaning, detail) and the
  same dashboard rule (any such event -> FAIL). Improvements over the helper: client MAC instead of the first
  MAC in the line, Wi-Fi 7 link addresses mapped to the client, one row per event instead of one per log line,
  broadcast deauths reported once, unprotected (PMF) and link-loss disconnects recognised. Optional IP / client
  name from LANforge (`START.cmd -Lanforge host:port`). HTML page: `http://localhost:8811/report/events`
  (filters `?type=deauth,disassoc&mac=..&ssid=..`), JSON: `/report/events.json`.
- **RAG chunks**: 6 lines / 480 characters per chunk (was 12 / 900) with a 3-line overlap (was none); the RAG text
  keeps line numbers and times (`L294681 11:36:49 ...`), drops frame-path noise and now covers the whole log
  (before: only the first 400 KB). Settings: env `RAG_CHUNK_LINES`, `RAG_CHUNK_CHARS`, `RAG_CHUNK_OVERLAP`; the
  index is rebuilt automatically when they change.
- **Model settings**: temperature 0.9 (was 0.1), top_p 0.9, top_k 40, repeat_penalty 1.1, context 8192.
  Change with `START.cmd -Temperature 0.3`.
- **Answer layout**: every answer starts with a **Summary** with the key numbers, then **Details** (complete
  list / table), **Evidence**, **What it means**, **Next steps**; per-client deauth tables when a table is asked;
  two format examples in the system prompt.
- **Completeness guard** in the Response Validator: if the model shortened or dropped the main list / table
  (more likely at temperature 0.9), the complete parser list / table is appended to the answer.
- Parser 2.8 (forces a re-parse so the new RAG text is built). 42 tests.

## v3.3 (2026-09-27) - answer quality on large Wi-Fi 7 MLO logs (tested on hostapd-final.txt, 1.15M lines)
- AP / client roles: the bridge-FDB rule that turned 21 clients into "AP addresses" is gone; weak AP evidence
  (BSSID only) no longer beats strong client evidence; BSSIDs only heard in RECEIVED frames are reported as
  neighbour APs; Wi-Fi 7 link STA addresses are merged into the client MLD address; band / frequency and the
  AP MLD address(es) per BSSID come from the log ("MLD: Set link_id=N, mld_addr=, own_addr=").
- SSID answers are grouped per SSID (interface, AP MLD address, BSSIDs per link with band/MHz, clients).
  "clients connected to <SSID>" matches partial SSID names (IoP_Testing -> IoP_Testing_root) and gives each
  client's final state (CONNECTED / DISCONNECTED at line N) plus a join proof line.
- New `bridge/episodes.py`: every disconnect of every client is read from the raw log and grouped into
  episodes with a cause label + proof line: AP teardown/restart, 4-way handshake timeout (reason 15), inactivity,
  frames not ACKed, client left, UNPROTECTED deauth/disassoc ignored because of PMF, AP local request.
  "why did <MAC> disconnect", "list deauthenticated clients" and "why do clients drop from <SSID>" use it.
- New AP restart / reconfiguration cycles (removing interface -> AP-DISABLED -> config reload -> AP-ENABLED).
- Parser 2.7: "WPA authenticator requests disconnect ... reason 15" counted as a 4-way handshake timeout (reason
  codes now include 15); "Use EAPOL-Key timeout ..." is no longer counted (it is only a timer); "excessive missing
  ACKs" is a link-loss disconnect, not a handshake failure; SAE "Confirm mismatch" is attributed to the STA of
  the preceding frame (password / PMK mismatch suspected); unprotected deauth/disassoc (PMF) events.
- Focused yes/no questions ("are there any auth failures", "is the AP restarting") get focused answers with
  per-client lists (MAC, count, line numbers) instead of the full report.
- COMPUTED ANSWER starts with a DIRECT ANSWER line (one sub-line per item) - the model copies it instead of
  re-counting; keyword log evidence is restricted to the client(s) / SSID asked about.
- Response Validator: a quoted "line N" must really contain the MAC written next to it (catches swapped MACs).
- Speed: raw-log index cached in memory; /context 0.3-5 s and /validate ~1 s on a 186 MB log.
- 37 tests. Verified with llama3:latest on hostapd-final.txt (SSIDs + MACs, clients per SSID, deauth list,
  why a client disconnects, AP restarting, AP MAC, why clients drop from sonos, overall report).

## v3.2.1 (2026-09-27) - fix "SQLITE_BUSY: database is locked" on the Flowise sign-in page
- Cause (reproduced with parallel logins on Flowise 3.1.4): Flowise runs all requests over one SQLite
  connection; two sign-ins at the same moment (autologin page + START self-test) leave a transaction open,
  the database stays write-locked and every later sign-in fails until Flowise is restarted.
- `tools/patch_flowise.py` (run by START.cmd, idempotent): sign-in requests are queued one at a time,
  SQLite busy_timeout 15 s for Flowise and its session store. After the patch 80 parallel sign-ins all
  succeeded (before: all failed and the lock stayed).
- START.cmd restarts an already-running Flowise once to load the fix, and if a sign-in ever reports a
  locked database it restarts Flowise automatically (the leftover journal is rolled back on restart).
- `flowise_setup.py` retries sign-in; the self-test waits for the browser sign-in; the autologin page
  retries and shows a clear message instead of the raw SQLite error.

## v3.2 (2026-09-26) - runtime skill (skills/hostapd_analyzer/SKILL.md)
- New `skills/hostapd_analyzer/SKILL.md` (behaviour spec) + `IMPLEMENTATION.md` (section -> code map).
- New `bridge/skill.py`: multi-intent classifier (22 SKILL intents), technical domains with expected state
  flow + CAG files (extensible), analysis plan per intent, client lifecycle state machine (UNKNOWN when not
  evidenced), timelines with exact log times, typed findings (OBSERVED / DERIVED FACT, evidence level),
  evidence level 0-4, missing-information list, structured intermediate representation, standard final JSON.
- FACTS now follow the SKILL analysis contract: QUERY INTENT, TECHNICAL DOMAIN, ANALYSIS PLAN, EVIDENCE LEVEL,
  COMPUTED ANSWER, CURRENT TEST STATISTICS, CURRENT LOG EVIDENCE, HISTORICAL MEMORY, TECHNICAL KNOWLEDGE,
  MISSING INFORMATION, ANSWER STYLE (adaptive formats; "why" and "is the AP at fault" rules).
- System prompt = SKILL hallucination-control block + evidence categories + prompt-injection rule.
- Response Validator (SKILL §39/§40/§49): new Flowise node after the LLM Chain -> bridge `POST /validate`;
  MACs not in the evidence are marked [NOT IN EVIDENCE], invented reason codes / timestamps / numbers are
  listed, unhedged causal and over-confident claims are qualified, code blocks removed; every answer ends
  with an "Evidence check" footer.
- New endpoints: `POST /validate`, `GET /skill/report` (SKILL §46 JSON); `/context` returns `ir`.
- 34 tests. Verified with llama3:latest on Hostapd2.txt (AP MAC, why not coming up, AP at fault, report,
  authentication check, reason code 3).

## v3.1 (2026-09-26) - AP vs client roles + keyword RAG on the raw log
- parser/mac_roles.py: AP / BSSID = address seen in beacon / BSS setup ("Using interface X with hwaddr",
  mld_addr / own_addr, MLD link addr, vap events, frames the AP sends with sa=bssid, iw dev); client = MAC
  that sent an Authentication Request or (Re)Association Request (RX frame sa=/A2=, "authentication: STA=",
  "association request: STA=", "IEEE 802.11: authenticated/associated", AP-STA-CONNECTED, EAPOL, station
  dump); probing-only devices kept separate. "Register frame type" lines are ignored (start-up, not frames).
  AP addresses are never counted as clients (Hostapd2.txt previously showed its 5 BSS addresses as clients).
- New findings: VAP_UP_FAILED, AP_RESTARTED, NO_CLIENT_JOIN_ATTEMPTS; AP broadcast deauth at teardown is
  reported as such, not as a client disconnect. NFT lines are no longer counted as errors.
- bridge/log_search.py: keywords from the question (beacon, auth, assoc, deauth, EAPOL, errors, channel/DFS,
  MLD, power/AFC, start-up, SSID, MAC, quoted words) are searched in the raw log; counts, line ranges and
  de-duplicated example lines go into the FACTS (passwords / key hexdumps are hidden).
- cag/09_ap_bringup_mld.md: AP bring-up / vap_up_fail / beacon -22 knowledge and debugging steps.
- Verified with llama3:latest on Hostapd2.txt (AP MAC, clients, report, why AP not up, deauth, SSIDs).

## v3.0 (2026-09-24) - Query Classifier + Context Aggregator (architecture doc sections 19-24)
- Cause of the wrong answers in the chat: Flowise was still running the old v2.1 tool-agent chatflow with
  llama3.2:3b (it invented MACs such as 00:11:22:33:44:55 and printed code); START.cmd had not been re-run.
- bridge/context.py rewritten: query classifier (GENERAL_WIFI_KNOWLEDGE, CURRENT_LOG_ANALYSIS,
  TEST_STATISTICS, CLIENT_ANALYSIS, ROOT_CAUSE_ANALYSIS, HISTORICAL_ANALYSIS, COMPARISON) with the
  doc's routing table; context aggregator with COMPUTED ANSWER, CURRENT TEST STATISTICS, pre-filled
  HOSTAPD CONNECTIVITY REPORT, CLIENT TABLE, FINDINGS, RAG evidence, MAG history, CAG knowledge and an
  ANSWER STYLE per query type.
- AP MAC recognition (interface / MLO link addresses): "this is the AP MAC, list its clients" works.
- Unknown MACs, per-band clients, per-client disconnection status, reason-code meanings, "no history
  before the current test" and "no auth events in this log" are answered explicitly.
- System prompt = the doc's SOURCE RULES; answers start directly, no FACTS echo, no code.
- Verified with the real llama3:latest on the user's Ollama (20 questions).
- Self-test asks for the overall report and prints the answer in the START window.

## v2.4 (2026-09-24) - correct answers with an 8B model
- Tested on the real Ollama: llama3.2:3b misreads the FACTS (named the wrong client for "most retries");
  llama3:latest (8B) answers correctly in ~20-30 s on this PC.
- Launcher now picks the best installed chat model automatically (llama3.1:8b > llama3:latest >
  qwen2.5:7b > mistral > llama3.2:3b); override with `START.cmd -ChatModel <name>`.
- Overview questions get a rule-based verdict, connectivity and "main problems" lines; RAG excerpts
  are only added when they contain Wi-Fi lines.
- `flowise_setup.py --selftest`: after START the launcher asks the live chatflow one question and saves
  the answer to `logs/selftest_answer.txt` (flags code/empty/FACTS UNAVAILABLE answers).

## v2.3 (2026-09-24) - grounded answers
- Problem: llama3.2:3b in the 10-tool Tool Agent printed Python code instead of calling tools, invented
  arguments (schema errors) and reused the example MAC from the prompt, so answers were irrelevant.
- The chatflow is now a deterministic pipeline: Custom JS Function -> bridge `/context` (topic routing,
  Parser facts + computed direct answer, MAG history, RAG, CAG sections) -> Chat Prompt Template ->
  LLM Chain + Ollama. Short system prompt: answer only from FACTS, never write code.
- New `bridge/context.py` (FACTS builder) and `bridge/rag.py` (Ollama-embedding RAG with keyword fallback,
  index cached in `output/rag/`, built at ingest). Tool-agent flow kept as `build_agent_chatflow.py`.

## v2.2 (2026-09-24)
- Fixed "Flowise did not start": services now run from detached `.cmd` wrappers (the old PowerShell
  output pipes killed Flowise when the launcher window closed), the first start may take up to 20 min
  with live progress, crashes are detected and shown, and a better-sqlite3 pre-flight check runs first.
- Runtime (Node, Flowise, Flowise DB/login) moved to `%LOCALAPPDATA%\HostapdAIAnalyzer` (existing
  installs are moved automatically); bridge is restarted on every START so it always runs current code.
- Newest file in `input_logs/` = current test (`latest`), injected into the agent prompt and RAG node;
  logs removed from `input_logs/` are removed from MAG.
- Console-capture parsing (`parser/session_capture.py`): `iw dev`, `iw station dump`, `ping`, probe
  frames -> RF findings (tx failure, weak signal, rate collapse, legacy fallback, idle MLO links,
  ping loss/latency). New tool `get_rf_metrics`, CAG doc `08_rf_station_metrics.md`; keyword search
  now covers the raw log. Test fixtures moved to `tests/fixtures/`.

## v2.1 (2026-09-24) - one-click
- `START.cmd` replaces setup.cmd / start-*.cmd: installs/starts everything (portable Node 24, Flowise 3.1.4,
  Ollama + models), parses `input_logs/`, creates the Flowise admin account and chatflow automatically and
  opens the chatflow canvas already signed in. `STOP.cmd` stops bridge + Flowise. Log: `logs/launcher.log`.
- Flowise data now lives in `tools/flowise_data/` (self-contained, not in your user profile).
- Logs go in `input_logs/` (file name = test id); duplicate TEST_002 and old backups removed.
- Parser ignores shell-capture noise (`iw` station-dump counters, ping output, OpenWrt banner, prompts).
- Bridge binds to 127.0.0.1 by default; chatflow uses 127.0.0.1 URLs (avoids IPv6 localhost issues on Windows).

## v2.0 (2026-09-24)

### Fixed (correctness)
- **Parser missed OpenWrt syslog metadata**: timestamps without a year (`Jul 16 13:18:06 OpenWrt hostapd:`) and interfaces after the syslog prefix were never extracted -> every HOSTAPD204 event had `timestamp=None`, `interface=None` and the timeline fell back to sequence buckets. Now parses epoch, syslog, logread and ISO-8601; interfaces incl. `phy0-ap0`, `wlan0-1`.
- **Reason codes dropped**: `reason_code=3` was not matched (regex only accepted `reason=`), so HOSTAPD204 reported an empty reason-code distribution. Now `{3: 15, 39: 2}`.
- **Deauth double counting**: `Deauthentication callback for STA` (TX-status of an AP-sent deauth) was counted as a separate deauth (29 -> 22 real deauths). Deauths are now split by initiator: 17 from STA, 5 from AP.
- **4-way handshake double counting**: `EAPOL-Key timeout` + `4-Way Handshake failed` for the same attempt were counted as two failures (TEST_001: 18 -> 9). EAPOL retransmit timeouts are reported separately.
- **MAG drifted on re-upload**: re-parsing a test_id incremented `total_tests` and duplicated events/issues. Ingest is now idempotent and client aggregates are recomputed from source rows. `total_failures` now counts failure events (was: number of distinct issue strings, so 22 failures showed as 1).
- **Hardcoded `C:\Users\mothe\...` paths** in `build_chatflow.py`, `validate_agent.py`, `ollama_watchdog.ps1` replaced with project-relative paths.
- **Windows encoding**: all file I/O is explicit UTF-8 (Windows default cp1252 could break on non-ASCII log lines).
- **Path traversal**: `test_id` is validated before being used as a filename.
- **Flowise install was a partial copy** (8 of ~1500 packages) -> `setup.cmd` detects and reinstalls from the lockfile.

### Added
- Parser: infrastructure error categories (fd exhaustion, interface create, beacon set, MU-EDCA, driver STA add/flags, MLO TTLM, channel, nftables), rule-based `findings`, auth-response-not-ACKed metric, PSK-mismatch / SAE / EAP / group-key events, `AP-STA-CONNECTED/DISCONNECTED`, adaptive timeline buckets, full reason-code table 1-51.
- MAG: `findings` table, finding history across tests, statistics diff in compare, delete/rebuild CLI, automatic schema migration of old DBs.
- Bridge: `/tests`, `latest` alias, per-client current-test view, keyword search, infrastructure view, finding history, upload web page at `/`, agent-friendly `/tool/*` error mode.
- CAG: `07_driver_platform_errors.md` (OpenWrt/driver error meanings + triage order), more reason codes, deauth-initiator guidance.
- Chatflow: 9 bridge tools + RAG, log embedded so the imported flow runs immediately, system-message brace escaping, maxIterations 10, smaller RAG chunks.
- Windows: `setup.cmd/ps1`, `start-all.cmd`, venv-aware start scripts, `requirements.txt`, pytest suite (11 tests).

Original files are kept in `_backup_original/` (including the v1 MAG DB and v1 analysis JSONs).
