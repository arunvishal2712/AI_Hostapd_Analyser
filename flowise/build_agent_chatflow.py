"""
Generates the Hostapd Hybrid Analysis Agent chatflow as importable Flowise JSON.

Node schemas below were extracted directly from the installed
flowise-components package (dist/nodes/**) so field names match exactly
what this Flowise version (3.1.x) expects -- not guessed from documentation.

Usage:
    python flowise/build_chatflow.py [--model llama3.2:3b] [--bridge http://localhost:8811]
Then in Flowise: Chatflows -> Add New -> (gear) Load Chatflow -> pick
flowise/hostapd_hybrid_agent.json -> upload the current log in the Text File node -> Save.
"""
import argparse
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYSTEM_PROMPT_PATH = ROOT / "flowise" / "agent_system_prompt.md"
CAG_DIR = ROOT / "cag"
OUT_PATH = ROOT / "flowise" / "hostapd_agent_advanced.json"

_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument("--bridge", default="http://127.0.0.1:8811", help="Bridge base URL as seen from Flowise")
_ap.add_argument("--ollama", default="http://127.0.0.1:11434", help="Ollama base URL as seen from Flowise")
_ap.add_argument("--model", default="llama3.2:3b", help="Tool-calling chat model (e.g. qwen2.5:7b, llama3.1:8b)")
_ap.add_argument("--embed-model", default="nomic-embed-text")
_ap.add_argument("--num-ctx", default="8192")
_ap.add_argument("--current-test", default=None, help="test_id the agent should treat as the current test")
_ap.add_argument("--log", default=None,
                 help="Log embedded into the Text File (RAG) node so the imported flow runs immediately; "
                      "pass --log none to leave it empty and upload in the Flowise UI")
_ap.add_argument("-o", "--output", default=str(OUT_PATH))
ARGS = _ap.parse_args()

BRIDGE = ARGS.bridge.rstrip("/")
TOOLS_BASE = BRIDGE + "/tool"  # agent-friendly error mode, see bridge/app.py
OUT_PATH = Path(ARGS.output)


def load_cag() -> str:
    """Same bytes as GET /cag on the bridge (sorted cag/*.md joined by ---)."""
    docs = sorted(CAG_DIR.glob("*.md"))
    return "\n\n---\n\n".join(d.read_text(encoding="utf-8") for d in docs)


def build_system_message() -> str:
    prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    if ARGS.current_test:
        prompt = (f"CURRENT TEST: {ARGS.current_test} -- the newest log in input_logs. Use this test_id whenever "
                  f"the user does not name another test.\n\n") + prompt
    cag = load_cag()
    # Replace the placeholder line with the actual CAG content
    prompt = prompt.split("CAG block; paste the output")[0]
    prompt += "CAG block, injected once as a static prefix):\n---\n\n" + cag
    # Flowise feeds the System Message through a LangChain f-string prompt
    # template: literal { } must be doubled or the flow fails with
    # "Single '}' in template".
    return prompt.replace("{", "{{").replace("}", "}}")


def _default_log():
    logs = sorted((p for p in (ROOT / "input_logs").glob("*") if p.suffix.lower() in (".txt", ".log")),
                  key=lambda p: p.stat().st_mtime)
    return logs[-1] if logs else None


def embedded_log():
    """Flowise's Text File node crashes the whole flow when no file is set, so
    embed one (as the same data-URI format the UI upload produces)."""
    if ARGS.log and ARGS.log.lower() == "none":
        return None
    path = Path(ARGS.log) if ARGS.log else _default_log()
    if path is None:
        return None
    b64 = base64.b64encode(path.read_bytes()).decode()
    return f"data:text/plain;base64,{b64},filename:{path.name}"


nodes = []
edges = []


def node(id_, position, data):
    nodes.append({
        "id": id_,
        "position": position,
        "type": "customNode",
        "data": data,
        "width": 300,
        "height": 400,
        "selected": False,
        "positionAbsolute": position,
        "dragging": False,
    })


def edge(source, source_handle, target, target_handle):
    edges.append({
        "source": source,
        "sourceHandle": source_handle,
        "target": target,
        "targetHandle": target_handle,
        "type": "buttonedge",
        "id": f"{source}-{source_handle}-{target}-{target_handle}",
    })


def out_anchor(node_id, name, label, types, description=""):
    type_str = "|".join(types)
    return {
        "id": f"{node_id}-output-{name}-{type_str}",
        "name": name,
        "label": label,
        "description": description,
        "type": type_str,
    }


# ---------------------------------------------------------------------------
# 1. Current-log RAG: textFile -> splitter -> embeddings -> vector store -> retrieverTool
# ---------------------------------------------------------------------------

node("recursiveCharacterTextSplitter_0", {"x": -200, "y": -400}, {
    "id": "recursiveCharacterTextSplitter_0", "label": "Recursive Character Text Splitter",
    "version": 2, "name": "recursiveCharacterTextSplitter", "type": "RecursiveCharacterTextSplitter",
    "baseClasses": ["RecursiveCharacterTextSplitter", "TextSplitter", "BaseDocumentTransformer", "Runnable"],
    "category": "Text Splitters",
    "description": "Split documents recursively by different characters",
    "inputParams": [
        {"label": "Chunk Size", "name": "chunkSize", "type": "number", "default": 1000, "optional": True,
         "id": "recursiveCharacterTextSplitter_0-input-chunkSize-number", "display": True},
        {"label": "Chunk Overlap", "name": "chunkOverlap", "type": "number", "default": 200, "optional": True,
         "id": "recursiveCharacterTextSplitter_0-input-chunkOverlap-number", "display": True},
    ],
    "inputAnchors": [],
    "inputs": {"chunkSize": "1200", "chunkOverlap": "100", "separators": ""},
    "outputAnchors": [out_anchor("recursiveCharacterTextSplitter_0", "recursiveCharacterTextSplitter",
                                  "RecursiveCharacterTextSplitter",
                                  ["RecursiveCharacterTextSplitter", "TextSplitter", "BaseDocumentTransformer", "Runnable"])],
    "outputs": {}, "selected": False,
})

node("textFile_0", {"x": 150, "y": -400}, {
    "id": "textFile_0", "label": "Text File", "version": 3, "name": "textFile", "type": "Document",
    "baseClasses": ["Document"], "category": "Document Loaders",
    "description": "Load the CURRENT hostapd test log (upload the .log file here after import)",
    "inputParams": [
        {"label": "Txt File", "name": "txtFile", "type": "file",
         "fileType": ".txt, .log, .md",
         "id": "textFile_0-input-txtFile-file", "display": True},
    ],
    "inputAnchors": [
        {"label": "Text Splitter", "name": "textSplitter", "type": "TextSplitter", "optional": True,
         "id": "textFile_0-input-textSplitter-TextSplitter", "display": True},
    ],
    "inputs": {"textSplitter": "{{recursiveCharacterTextSplitter_0.data.instance}}", "metadata": "", "omitMetadataKeys": "",
               **({"txtFile": embedded_log()} if embedded_log() else {})},
    "outputAnchors": [
        {"id": "textFile_0-output-document-Document|json", "name": "document", "label": "Document",
         "description": "Array of document objects", "type": "Document | json"},
    ],
    "outputs": {"output": "document"}, "selected": False,
})
edge("recursiveCharacterTextSplitter_0",
     "recursiveCharacterTextSplitter_0-output-recursiveCharacterTextSplitter-RecursiveCharacterTextSplitter|TextSplitter|BaseDocumentTransformer|Runnable",
     "textFile_0", "textFile_0-input-textSplitter-TextSplitter")

node("ollamaEmbedding_0", {"x": 150, "y": 0}, {
    "id": "ollamaEmbedding_0", "label": "Ollama Embedding", "version": 2, "name": "ollamaEmbedding",
    "type": "OllamaEmbeddings", "baseClasses": ["OllamaEmbeddings", "Embeddings"], "category": "Embeddings",
    "description": "Generate embeddings using Ollama", "inputParams": [
        {"label": "Base URL", "name": "baseUrl", "type": "string", "default": "http://localhost:11434",
         "id": "ollamaEmbedding_0-input-baseUrl-string", "display": True},
        {"label": "Model Name", "name": "modelName", "type": "string", "placeholder": "llama2",
         "id": "ollamaEmbedding_0-input-modelName-string", "display": True},
    ],
    "inputAnchors": [],
    "inputs": {"baseUrl": ARGS.ollama, "modelName": ARGS.embed_model, "numGpu": "", "numThread": "", "useMMap": True},
    "outputAnchors": [out_anchor("ollamaEmbedding_0", "ollamaEmbedding", "OllamaEmbeddings", ["OllamaEmbeddings", "Embeddings"])],
    "outputs": {}, "selected": False,
})

node("memoryVectorStore_0", {"x": 550, "y": -200}, {
    "id": "memoryVectorStore_0", "label": "In-Memory Vector Store", "version": 1, "name": "memoryVectorStore",
    "type": "Memory", "baseClasses": ["Memory", "VectorStoreRetriever", "BaseRetriever"], "category": "Vector Stores",
    "description": "In-memory vectorstore holding the current test log",
    "inputParams": [
        {"label": "Top K", "name": "topK", "description": "Number of top results", "placeholder": "4", "type": "number",
         "optional": True, "id": "memoryVectorStore_0-input-topK-number", "display": True},
    ],
    "inputAnchors": [
        {"label": "Document", "name": "document", "type": "Document", "list": True, "optional": True,
         "id": "memoryVectorStore_0-input-document-Document", "display": True},
        {"label": "Embeddings", "name": "embeddings", "type": "Embeddings",
         "id": "memoryVectorStore_0-input-embeddings-Embeddings", "display": True},
    ],
    "inputs": {"document": ["{{textFile_0.data.instance}}"], "embeddings": "{{ollamaEmbedding_0.data.instance}}", "topK": "3"},
    "outputAnchors": [
        {"name": "output", "label": "Output", "type": "options", "description": "", "options": [
            {"id": "memoryVectorStore_0-output-retriever-Memory|VectorStoreRetriever|BaseRetriever", "name": "retriever",
             "label": "Memory Retriever", "description": "", "type": "Memory | VectorStoreRetriever | BaseRetriever"},
            {"id": "memoryVectorStore_0-output-vectorStore-Memory|VectorStore", "name": "vectorStore",
             "label": "Memory Vector Store", "description": "", "type": "Memory | VectorStore"},
        ], "default": "retriever"},
    ],
    "outputs": {"output": "retriever"}, "selected": False,
})
edge("textFile_0", "textFile_0-output-document-Document|json", "memoryVectorStore_0", "memoryVectorStore_0-input-document-Document")
edge("ollamaEmbedding_0", "ollamaEmbedding_0-output-ollamaEmbedding-OllamaEmbeddings|Embeddings", "memoryVectorStore_0", "memoryVectorStore_0-input-embeddings-Embeddings")

node("retrieverTool_0", {"x": 950, "y": -350}, {
    "id": "retrieverTool_0", "label": "Retriever Tool", "version": 3, "name": "retrieverTool", "type": "RetrieverTool",
    "baseClasses": ["RetrieverTool", "DynamicTool", "Tool", "StructuredTool", "BaseLangChain", "Runnable"],
    "category": "Tools", "description": "Use a retriever as allowed tool for agent",
    "inputParams": [
        {"label": "Retriever Name", "name": "name", "type": "string", "id": "retrieverTool_0-input-name-string", "display": True},
        {"label": "Retriever Description", "name": "description", "type": "string", "rows": 3,
         "id": "retrieverTool_0-input-description-string", "display": True},
        {"label": "Return Source Documents", "name": "returnSourceDocuments", "type": "boolean", "optional": True,
         "id": "retrieverTool_0-input-returnSourceDocuments-boolean", "display": True},
    ],
    "inputAnchors": [
        {"label": "Retriever", "name": "retriever", "type": "BaseRetriever",
         "id": "retrieverTool_0-input-retriever-BaseRetriever", "display": True},
    ],
    "inputs": {
        "name": "search_current_log",
        "description": "Semantically search the raw text of the CURRENT hostapd test log for evidence about a specific client MAC or event (e.g. a handshake failure message). Returns log snippets, not statistics -- use get_test_statistics for exact counts.",
        "retriever": "{{memoryVectorStore_0.data.instance}}",
        "returnSourceDocuments": False,
    },
    "outputAnchors": [out_anchor("retrieverTool_0", "retrieverTool", "RetrieverTool", ["RetrieverTool", "DynamicTool", "Tool", "StructuredTool", "BaseLangChain", "Runnable"])],
    "outputs": {}, "selected": False,
})
edge("memoryVectorStore_0", "memoryVectorStore_0-output-retriever-Memory|VectorStoreRetriever|BaseRetriever",
     "retrieverTool_0", "retrieverTool_0-input-retriever-BaseRetriever")

# ---------------------------------------------------------------------------
# 2. Bridge tools (Parser + MAG) as self-contained Requests Get nodes
# ---------------------------------------------------------------------------

TID = {"type": "string", "required": True, "in": "path",
       "description": "Test identifier, e.g. HOSTAPD204. Use 'latest' for the current test (newest log in input_logs)."}
MACP = {"type": "string", "required": True, "in": "path", "description": "Client MAC address, e.g. AA:BB:CC:DD:EE:FF"}

REQUEST_TOOLS = [
    {
        "id": "requestsGet_listtests", "pos": {"x": 950, "y": -50},
        "name": "list_tests",
        "description": "List every test stored in memory (test_id, AP, parse time, headline counts), newest first. Use when the user has not named a test or asks which tests exist.",
        "url": f"{TOOLS_BASE}/tests",
        "schema": {"verbose": {"type": "boolean", "required": False, "in": "query", "description": "unused; call with no arguments"}},
    },
    {
        "id": "requestsGet_stats", "pos": {"x": 950, "y": 150},
        "name": "get_test_statistics",
        "description": "Get the authoritative exact statistics (client count, authentication/association/handshake failures, auth-response-not-ACKed count, deauths split by who initiated them, reason-code distribution, driver error categories), the deterministic findings list, and the top unstable clients for one parsed test. Always use this instead of estimating counts yourself.",
        "url": f"{TOOLS_BASE}/analysis/:test_id",
        "schema": {"test_id": TID},
    },
    {
        "id": "requestsGet_infra", "pos": {"x": 950, "y": 350},
        "name": "get_infrastructure_errors",
        "description": "Get driver/platform/system errors for one test grouped by category (interface creation, beacon set failures, file-descriptor exhaustion, driver refusing stations, MLO TTLM, channel errors) with counts, errno values, first/last time and a sample line. Use before blaming clients.",
        "url": f"{TOOLS_BASE}/analysis/:test_id/infrastructure",
        "schema": {"test_id": TID},
    },
    {
        "id": "requestsGet_rf",
        "name": "get_rf_metrics",
        "description": "Get RF and performance facts for a test from the AP console capture: AP links (band, channel, width, tx power), every station's signal, ack signal, tx packets/retries/failed, tx/rx bitrate and PHY mode (EHT/HE/legacy), MLO links set up vs actually used, ping loss and latency per target, probe requests.",
        "url": f"{TOOLS_BASE}/analysis/:test_id/rf",
        "schema": {"test_id": TID},
    },
    {
        "id": "requestsGet_curclient", "pos": {"x": 950, "y": 550},
        "name": "get_current_client",
        "description": "Get one client's behaviour in a specific test: its summary (auth/assoc/handshake state, deauths by STA vs AP, reason codes, issues) and its chronological log events.",
        "url": f"{TOOLS_BASE}/analysis/:test_id/client/:mac",
        "schema": {"test_id": TID, "mac": MACP},
    },
    {
        "id": "requestsGet_search", "pos": {"x": 950, "y": 750},
        "name": "search_log_events",
        "description": "Exact, case-insensitive keyword search over the raw log of one test (hostapd lines, station dumps, ping output). Returns matching lines with line numbers. Optional filters: mac (client MAC) and event (parsed hostapd event type, e.g. AUTH_FAILURE, DEAUTHENTICATION, DRIVER_ERROR).",
        "url": f"{TOOLS_BASE}/analysis/:test_id/search",
        "schema": {
            "test_id": TID,
            "q": {"type": "string", "required": False, "in": "query", "description": "Keyword or phrase to find, e.g. 'beacon' or 'reason_code=39'"},
            "mac": {"type": "string", "required": False, "in": "query", "description": "Only lines for this client MAC"},
            "event": {"type": "string", "required": False, "in": "query", "description": "Only this parsed event type"},
        },
    },
    {
        "id": "requestsGet_client", "pos": {"x": 950, "y": 950},
        "name": "get_client_history",
        "description": "Look up a Wi-Fi client's historical record across ALL previously parsed tests (MAG memory) by MAC address. Use this to answer 'has this client failed before' questions. Results from tests other than the one currently discussed are HISTORICAL, not current.",
        "url": f"{TOOLS_BASE}/mag/client/:mac",
        "schema": {"mac": MACP},
    },
    {
        "id": "requestsGet_topunstable", "pos": {"x": 950, "y": 1150},
        "name": "get_top_unstable_clients",
        "description": "Get the clients with the most cumulative failure events across all tests ever recorded in MAG memory. Use for 'which clients are most problematic overall' questions.",
        "url": f"{TOOLS_BASE}/mag/top-unstable",
        "schema": {"limit": {"type": "number", "required": False, "in": "query", "description": "How many clients to return, default 5"}},
    },
    {
        "id": "requestsGet_finding", "pos": {"x": 950, "y": 1350},
        "name": "get_finding_history",
        "description": "Check which historical tests raised the same deterministic finding id (e.g. BEACON_SET_FAILURES, AUTH_RESPONSE_NOT_ACKED, DRIVER_STA_PROGRAMMING_FAILURES) to tell a one-off from a recurring problem.",
        "url": f"{TOOLS_BASE}/mag/findings/:finding_id",
        "schema": {"finding_id": {"type": "string", "required": True, "in": "path", "description": "Finding id from get_test_statistics findings"}},
    },
    {
        "id": "requestsGet_compare", "pos": {"x": 950, "y": 1550},
        "name": "compare_tests",
        "description": "Compare two tests side by side: every statistic that changed plus findings present in only one or both tests.",
        "url": f"{TOOLS_BASE}/mag/compare",
        "schema": {
            "test_a": {"type": "string", "required": True, "in": "query", "description": "First (baseline) test_id"},
            "test_b": {"type": "string", "required": True, "in": "query", "description": "Second test_id"},
        },
    },
]

# Lay the tool nodes out on a 3-column grid so they do not overlap on the canvas.
for _i, _t in enumerate(REQUEST_TOOLS):
    _t["pos"] = {"x": 950 + (_i % 3) * 340, "y": 220 + (_i // 3) * 420}

for t in REQUEST_TOOLS:
    node(t["id"], t["pos"], {
        "id": t["id"], "label": "Requests Get", "version": 2, "name": "requestsGet", "type": "RequestsGet",
        "baseClasses": ["RequestsGet", "DynamicStructuredTool", "Tool", "StructuredTool", "BaseLangChain", "Runnable"],
        "category": "Tools", "description": "Execute HTTP GET requests",
        "inputParams": [
            {"label": "URL", "name": "requestsGetUrl", "type": "string", "acceptVariable": True,
             "id": f"{t['id']}-input-requestsGetUrl-string", "display": True},
            {"label": "Name", "name": "requestsGetName", "type": "string", "additionalParams": True, "optional": True,
             "id": f"{t['id']}-input-requestsGetName-string", "display": True},
            {"label": "Description", "name": "requestsGetDescription", "type": "string", "rows": 4,
             "additionalParams": True, "optional": True, "id": f"{t['id']}-input-requestsGetDescription-string", "display": True},
            {"label": "Query Params Schema", "name": "requestsGetQueryParamsSchema", "type": "code", "optional": True,
             "additionalParams": True, "id": f"{t['id']}-input-requestsGetQueryParamsSchema-code", "display": True},
            {"label": "Max Output Length", "name": "requestsGetMaxOutputLength", "type": "number", "default": "2000",
             "optional": True, "additionalParams": True, "id": f"{t['id']}-input-requestsGetMaxOutputLength-number", "display": True},
        ],
        "inputAnchors": [],
        "inputs": {
            "requestsGetUrl": t["url"],
            "requestsGetName": t["name"],
            "requestsGetDescription": t["description"],
            "requestsGetHeaders": "",
            "requestsGetQueryParamsSchema": json.dumps(t["schema"], indent=2),
            "requestsGetMaxOutputLength": "6000",
        },
        "outputAnchors": [out_anchor(t["id"], "requestsGet", "RequestsGet",
                                      ["RequestsGet", "DynamicStructuredTool", "Tool", "StructuredTool", "BaseLangChain", "Runnable"])],
        "outputs": {}, "selected": False,
    })

# ---------------------------------------------------------------------------
# 3. Memory + Model + Tool Agent
# ---------------------------------------------------------------------------

node("bufferMemory_0", {"x": 2050, "y": -400}, {
    "id": "bufferMemory_0", "label": "Buffer Memory", "version": 2, "name": "bufferMemory", "type": "BufferMemory",
    "baseClasses": ["BufferMemory", "BaseChatMemory", "BaseMemory"], "category": "Memory",
    "description": "Retrieve chat messages stored in database",
    "inputParams": [
        {"label": "Session Id", "name": "sessionId", "type": "string", "default": "", "additionalParams": True,
         "optional": True, "id": "bufferMemory_0-input-sessionId-string", "display": True},
        {"label": "Memory Key", "name": "memoryKey", "type": "string", "default": "chat_history",
         "additionalParams": True, "id": "bufferMemory_0-input-memoryKey-string", "display": True},
    ],
    "inputAnchors": [],
    "inputs": {"sessionId": "", "memoryKey": "chat_history"},
    "outputAnchors": [out_anchor("bufferMemory_0", "bufferMemory", "BufferMemory", ["BufferMemory", "BaseChatMemory", "BaseMemory"])],
    "outputs": {}, "selected": False,
})

node("chatOllama_0", {"x": 2050, "y": 0}, {
    "id": "chatOllama_0", "label": "Ollama", "version": 5, "name": "chatOllama", "type": "ChatOllama",
    "baseClasses": ["ChatOllama", "BaseChatModel", "BaseLanguageModel", "Runnable"], "category": "Chat Models",
    "description": "Chat completion using open-source LLM on Ollama",
    "inputParams": [
        {"label": "Base URL", "name": "baseUrl", "type": "string", "default": "http://localhost:11434",
         "id": "chatOllama_0-input-baseUrl-string", "display": True},
        {"label": "Model Name", "name": "modelName", "type": "string", "placeholder": "llama2",
         "id": "chatOllama_0-input-modelName-string", "display": True},
        {"label": "Temperature", "name": "temperature", "type": "number", "step": 0.1, "default": 0.9, "optional": True,
         "id": "chatOllama_0-input-temperature-number", "display": True},
        {"label": "Context Window Size", "name": "numCtx", "type": "number", "step": 1, "optional": True,
         "additionalParams": True, "id": "chatOllama_0-input-numCtx-number", "display": True},
    ],
    "inputAnchors": [
        {"label": "Cache", "name": "cache", "type": "BaseCache", "optional": True,
         "id": "chatOllama_0-input-cache-BaseCache", "display": True},
    ],
    "inputs": {
        "cache": "", "baseUrl": ARGS.ollama, "modelName": ARGS.model, "temperature": "0.1",
        "streaming": True, "numCtx": ARGS.num_ctx,
    },
    "outputAnchors": [out_anchor("chatOllama_0", "chatOllama", "ChatOllama", ["ChatOllama", "BaseChatModel", "BaseLanguageModel", "Runnable"])],
    "outputs": {}, "selected": False,
})

TOOL_INPUT_REFS = ["{{retrieverTool_0.data.instance}}"] + [f"{{{{{t['id']}.data.instance}}}}" for t in REQUEST_TOOLS]

node("toolAgent_0", {"x": 2450, "y": -200}, {
    "id": "toolAgent_0", "label": "Tool Agent", "version": 2.0, "name": "toolAgent", "type": "AgentExecutor",
    "baseClasses": ["AgentExecutor", "BaseChain", "Runnable"], "category": "Agents",
    "description": "Agent that uses Function Calling to pick the tools and args to call",
    "inputParams": [
        {"label": "System Message", "name": "systemMessage", "type": "string", "rows": 4, "optional": True,
         "additionalParams": True, "id": "toolAgent_0-input-systemMessage-string", "display": True},
        {"label": "Max Iterations", "name": "maxIterations", "type": "number", "optional": True,
         "additionalParams": True, "id": "toolAgent_0-input-maxIterations-number", "display": True},
    ],
    "inputAnchors": [
        {"label": "Tools", "name": "tools", "type": "Tool", "list": True, "id": "toolAgent_0-input-tools-Tool", "display": True},
        {"label": "Memory", "name": "memory", "type": "BaseChatMemory", "id": "toolAgent_0-input-memory-BaseChatMemory", "display": True},
        {"label": "Tool Calling Chat Model", "name": "model", "type": "BaseChatModel", "id": "toolAgent_0-input-model-BaseChatModel", "display": True},
        {"label": "Input Moderation", "name": "inputModeration", "type": "Moderation", "optional": True, "list": True,
         "id": "toolAgent_0-input-inputModeration-Moderation", "display": True},
    ],
    "inputs": {
        "tools": TOOL_INPUT_REFS,
        "memory": "{{bufferMemory_0.data.instance}}",
        "model": "{{chatOllama_0.data.instance}}",
        "systemMessage": build_system_message(),
        "maxIterations": "10",
        "enableDetailedStreaming": True,
    },
    "outputAnchors": [out_anchor("toolAgent_0", "toolAgent", "Tool Agent", ["AgentExecutor", "BaseChain", "Runnable"])],
    "outputs": {}, "selected": False,
})

edge("retrieverTool_0", f"retrieverTool_0-output-retrieverTool-RetrieverTool|DynamicTool|Tool|StructuredTool|BaseLangChain|Runnable",
     "toolAgent_0", "toolAgent_0-input-tools-Tool")
for t in REQUEST_TOOLS:
    edge(t["id"], f"{t['id']}-output-requestsGet-RequestsGet|DynamicStructuredTool|Tool|StructuredTool|BaseLangChain|Runnable",
         "toolAgent_0", "toolAgent_0-input-tools-Tool")
edge("bufferMemory_0", "bufferMemory_0-output-bufferMemory-BufferMemory|BaseChatMemory|BaseMemory",
     "toolAgent_0", "toolAgent_0-input-memory-BaseChatMemory")
edge("chatOllama_0", "chatOllama_0-output-chatOllama-ChatOllama|BaseChatModel|BaseLanguageModel|Runnable",
     "toolAgent_0", "toolAgent_0-input-model-BaseChatModel")

chatflow = {"nodes": nodes, "edges": edges}
OUT_PATH.write_text(json.dumps(chatflow, indent=2), encoding="utf-8")
print(f"Wrote {len(nodes)} nodes, {len(edges)} edges -> {OUT_PATH}")
