"""
Hostapd log engine (v4.0) - linear-time analysis of very large hostapd logs (tested to multi-GB, designed for 10 GB).

    textnorm   line prefix / timestamp parsing and message templates (numbers, MACs, hex masked)
    rules      typed event + attribute extraction from one line (pure function, cached per template)
    ingest     one streaming pass, parallel over byte ranges -> SQLite store (O(n) time, bounded memory)
    store      the on-disk store: random access to any line, events, templates, postings, rollups, graph
    graph      Graph RAG: entity graph (client / BSS / interface / SSID / MLD / session) and stories
    retrieval  Context retrieval (exact values, lines, keywords) and Wide retrieval (top-to-bottom map-reduce)
    agent      Agentic RAG: a bounded investigator that plans, calls retrieval tools and records a trace
    learning   query memory: every question, its understanding, route, evidence, validation and feedback
    router     question -> retrieval mode(s), rules + what was learned from earlier questions
    facts      retrieval results -> FACTS text with (time, line) evidence and a size budget
"""
ENGINE_VERSION = "4.0"
