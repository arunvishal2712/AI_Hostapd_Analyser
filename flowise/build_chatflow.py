"""
Generates the importable Flowise chatflow "Hostapd AI Analyzer" (Flowise 3.1.x).

Pipeline (works reliably with small local models such as llama3.2:3b):

  [Custom JS Function]  POSTs the user's question to the bridge /context endpoint, which returns a
   "Hostapd context"     FACTS block: Parser statistics + findings, MAG history, RAG log excerpts
                         (Ollama embeddings) and the matching CAG knowledge sections
          |
  [Chat Prompt Template] system rules + "FACTS: {facts}  QUESTION: {question}"
          |
  [LLM Chain] <-- [ChatOllama]   writes the answer from the FACTS only

The earlier tool-calling agent (the model decides which of 10 tools to call) is still available via
flowise/build_agent_chatflow.py for larger models (qwen2.5:7b+), but 3B models print tool calls as
code instead of calling them, so it is no longer the default.

Usage: python flowise/build_chatflow.py [--model llama3.2:3b] [--current-test ID]
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--bridge", default="http://127.0.0.1:8811")
ap.add_argument("--ollama", default="http://127.0.0.1:11434")
ap.add_argument("--model", default="llama3:latest")
ap.add_argument("--embed-model", default="nomic-embed-text")  # used by the bridge for RAG (kept for CLI compatibility)
ap.add_argument("--num-ctx", default="8192")
ap.add_argument("--temperature", default="0.9", help="Ollama sampling temperature (0 = deterministic, 1 = creative)")
ap.add_argument("--top-p", default="0.9")
ap.add_argument("--top-k", default="40")
ap.add_argument("--repeat-penalty", default="1.1")
ap.add_argument("--current-test", default=None)
ap.add_argument("--log", default=None, help="ignored (RAG runs in the bridge); kept for CLI compatibility")
ap.add_argument("-o", "--output", default=str(ROOT / "flowise" / "hostapd_hybrid_agent.json"))
ARGS = ap.parse_args()

nodes, edges = [], []


def node(id_, x, y, data, height=400):
    nodes.append({"id": id_, "position": {"x": x, "y": y}, "type": "customNode", "data": data, "width": 300,
                  "height": height, "selected": False, "positionAbsolute": {"x": x, "y": y}, "dragging": False})


def edge(source, source_handle, target, target_handle):
    edges.append({"source": source, "sourceHandle": source_handle, "target": target, "targetHandle": target_handle,
                  "type": "buttonedge", "id": f"{source}-{source_handle}-{target}-{target_handle}"})


def param(nid, label, name, typ, **kw):
    return {"label": label, "name": name, "type": typ, "id": f"{nid}-input-{name}-{typ}", "display": True, **kw}


# ---------------------------------------------------------------- 1. context fetcher (Parser + MAG + RAG + CAG)
JS = f"""// Hostapd context: asks the bridge for everything the model needs to answer this question.
// Parser = exact statistics + findings, MAG = history, RAG = log excerpts, CAG = Wi-Fi knowledge.
const fetch = require('node-fetch');
const question = String($input || '');
try {{
  const res = await fetch('{ARGS.bridge}/context', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ question: question, test_id: 'latest' }})
  }});
  if (!res.ok) return 'FACTS UNAVAILABLE: the analysis bridge answered HTTP ' + res.status + '. Tell the user to run START.cmd again.';
  const data = await res.json();
  return data.facts;
}} catch (e) {{
  return 'FACTS UNAVAILABLE: the analysis bridge (' + '{ARGS.bridge}' + ') is not running. Tell the user to run START.cmd again.';
}}"""

nid = "customFunction_0"
node(nid, 0, 0, {
    "id": nid, "label": "Custom JS Function", "version": 3, "name": "customFunction", "type": "CustomFunction",
    "baseClasses": ["CustomFunction", "Utilities"], "category": "Utilities",
    "description": "Hostapd context: Parser + MAG + RAG + CAG from the bridge",
    "inputParams": [
        param(nid, "Input Variables", "functionInputVariables", "json", optional=True, acceptVariable=True, list=True),
        param(nid, "Function Name", "functionName", "string", optional=True, placeholder="My Function"),
        param(nid, "Javascript Function", "javascriptFunction", "code"),
    ],
    "inputAnchors": [{"label": "Additional Tools", "name": "tools", "type": "Tool", "optional": True, "list": True,
                      "id": f"{nid}-input-tools-Tool", "display": True}],
    "inputs": {"functionInputVariables": "", "functionName": "Hostapd context (Parser + MAG + RAG + CAG)",
               "tools": "", "javascriptFunction": JS},
    "outputAnchors": [{"name": "output", "label": "Output", "type": "options", "description": "", "options": [
        {"id": f"{nid}-output-output-string|number|boolean|json|array", "name": "output", "label": "Output",
         "description": "", "type": "string | number | boolean | json | array"},
        {"id": f"{nid}-output-EndingNode-CustomFunction", "name": "EndingNode", "label": "Ending Node",
         "description": "", "type": "CustomFunction"}], "default": "output"}],
    "outputs": {"output": "output"}, "selected": False,
})

# ---------------------------------------------------------------- 2. prompt
system = (ROOT / "flowise" / "system_prompt.md").read_text(encoding="utf-8").strip()
system = system.replace("{", "(").replace("}", ")")  # no stray template variables
human = "FACTS:\n{facts}\n\nQUESTION: {question}"

nid = "chatPromptTemplate_0"
node(nid, 420, 0, {
    "id": nid, "label": "Chat Prompt Template", "version": 2, "name": "chatPromptTemplate", "type": "ChatPromptTemplate",
    "baseClasses": ["ChatPromptTemplate", "BaseChatPromptTemplate", "BasePromptTemplate", "Runnable"],
    "category": "Prompts", "description": "System rules + FACTS + QUESTION",
    "inputParams": [
        param(nid, "System Message", "systemMessagePrompt", "string", rows=4),
        param(nid, "Human Message", "humanMessagePrompt", "string", rows=4),
        param(nid, "Format Prompt Values", "promptValues", "json", optional=True, acceptVariable=True, list=True),
    ],
    "inputAnchors": [],
    "inputs": {"systemMessagePrompt": system, "humanMessagePrompt": human,
               "promptValues": json.dumps({"facts": "{{customFunction_0.data.instance}}", "question": "{{question}}"})},
    "outputAnchors": [{"id": f"{nid}-output-chatPromptTemplate-ChatPromptTemplate|BaseChatPromptTemplate|BasePromptTemplate|Runnable",
                       "name": "chatPromptTemplate", "label": "ChatPromptTemplate", "description": "",
                       "type": "ChatPromptTemplate | BaseChatPromptTemplate | BasePromptTemplate | Runnable"}],
    "outputs": {}, "selected": False,
}, height=600)
edge("customFunction_0", "customFunction_0-output-output-string|number|boolean|json|array",
     "chatPromptTemplate_0", "chatPromptTemplate_0-input-promptValues-json")

# ---------------------------------------------------------------- 3. model
nid = "chatOllama_0"
node(nid, 420, 780, {
    "id": nid, "label": "Ollama", "version": 5, "name": "chatOllama", "type": "ChatOllama",
    "baseClasses": ["ChatOllama", "BaseChatModel", "BaseLanguageModel", "Runnable"], "category": "Chat Models",
    "description": "Local LLM on Ollama",
    "inputParams": [
        param(nid, "Base URL", "baseUrl", "string", default="http://localhost:11434"),
        param(nid, "Model Name", "modelName", "string", placeholder="llama2"),
        param(nid, "Temperature", "temperature", "number", step=0.1, default=0.9, optional=True),
        param(nid, "Context Window Size", "numCtx", "number", step=1, optional=True, additionalParams=True),
        param(nid, "Top P", "topP", "number", step=0.1, optional=True, additionalParams=True),
        param(nid, "Top K", "topK", "number", step=1, optional=True, additionalParams=True),
        param(nid, "Repeat Penalty", "repeatPenalty", "number", step=0.1, optional=True, additionalParams=True),
    ],
    "inputAnchors": [{"label": "Cache", "name": "cache", "type": "BaseCache", "optional": True,
                      "id": f"{nid}-input-cache-BaseCache", "display": True}],
    "inputs": {"cache": "", "baseUrl": ARGS.ollama, "modelName": ARGS.model, "temperature": ARGS.temperature,
               "streaming": True, "numCtx": ARGS.num_ctx, "keepAlive": "60m", "topP": ARGS.top_p,
               "topK": ARGS.top_k, "repeatPenalty": ARGS.repeat_penalty},
    "outputAnchors": [{"id": f"{nid}-output-chatOllama-ChatOllama|BaseChatModel|BaseLanguageModel|Runnable",
                       "name": "chatOllama", "label": "ChatOllama", "description": "",
                       "type": "ChatOllama | BaseChatModel | BaseLanguageModel | Runnable"}],
    "outputs": {}, "selected": False,
})

# ---------------------------------------------------------------- 4. chain
nid = "llmChain_0"
node(nid, 860, 300, {
    "id": nid, "label": "LLM Chain", "version": 3, "name": "llmChain", "type": "LLMChain",
    "baseClasses": ["LLMChain", "BaseChain", "Runnable"], "category": "Chains",
    "description": "Writes the answer from the FACTS",
    "inputParams": [param(nid, "Chain Name", "chainName", "string", optional=True, placeholder="Name Your Chain")],
    "inputAnchors": [
        {"label": "Language Model", "name": "model", "type": "BaseLanguageModel", "id": f"{nid}-input-model-BaseLanguageModel", "display": True},
        {"label": "Prompt", "name": "prompt", "type": "BasePromptTemplate", "id": f"{nid}-input-prompt-BasePromptTemplate", "display": True},
        {"label": "Output Parser", "name": "outputParser", "type": "BaseLLMOutputParser", "optional": True,
         "id": f"{nid}-input-outputParser-BaseLLMOutputParser", "display": True},
        {"label": "Input Moderation", "name": "inputModeration", "type": "Moderation", "optional": True, "list": True,
         "id": f"{nid}-input-inputModeration-Moderation", "display": True},
    ],
    "inputs": {"model": "{{chatOllama_0.data.instance}}", "prompt": "{{chatPromptTemplate_0.data.instance}}",
               "outputParser": "", "inputModeration": "", "chainName": "Hostapd analysis"},
    "outputAnchors": [{"name": "output", "label": "Output", "type": "options", "description": "", "options": [
        {"id": f"{nid}-output-llmChain-LLMChain|BaseChain|Runnable", "name": "llmChain", "label": "LLM Chain",
         "description": "", "type": "LLMChain | BaseChain | Runnable"},
        {"id": f"{nid}-output-outputPrediction-string|json", "name": "outputPrediction", "label": "Output Prediction",
         "description": "", "type": "string | json"}], "default": "llmChain"}],
    "outputs": {"output": "outputPrediction"}, "selected": False,
})
edge("chatOllama_0", "chatOllama_0-output-chatOllama-ChatOllama|BaseChatModel|BaseLanguageModel|Runnable",
     "llmChain_0", "llmChain_0-input-model-BaseLanguageModel")
edge("chatPromptTemplate_0", "chatPromptTemplate_0-output-chatPromptTemplate-ChatPromptTemplate|BaseChatPromptTemplate|BasePromptTemplate|Runnable",
     "llmChain_0", "llmChain_0-input-prompt-BasePromptTemplate")

# ---------------------------------------------------------------- 5. response validator (SKILL §39/§40/§49)
VJS = f"""// Response Validator (SKILL.md §39/§40): checks the LLM answer against the evidence it was given.
// Unknown MACs are marked [NOT IN EVIDENCE], invented reason codes / timestamps / numbers are listed,
// unhedged causal or over-confident claims are qualified, code blocks are removed.
const fetch = require('node-fetch');
const question = String($input || '');
const answer = typeof $answer === 'string' ? $answer : JSON.stringify($answer);
try {{
  const res = await fetch('{ARGS.bridge}/validate', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ question: question, answer: answer, test_id: 'latest' }})
  }});
  if (!res.ok) return answer + '\\n\\n(Evidence check unavailable: bridge answered HTTP ' + res.status + ')';
  const data = await res.json();
  return data.answer;
}} catch (e) {{
  return answer + '\\n\\n(Evidence check unavailable: the analysis bridge is not running)';
}}"""

nid = "customFunction_1"
node(nid, 1280, 300, {
    "id": nid, "label": "Custom JS Function", "version": 3, "name": "customFunction", "type": "CustomFunction",
    "baseClasses": ["CustomFunction", "Utilities"], "category": "Utilities",
    "description": "Response Validator: checks every MAC / number / reason code / claim against the evidence",
    "inputParams": [
        param(nid, "Input Variables", "functionInputVariables", "json", optional=True, acceptVariable=True, list=True),
        param(nid, "Function Name", "functionName", "string", optional=True, placeholder="My Function"),
        param(nid, "Javascript Function", "javascriptFunction", "code"),
    ],
    "inputAnchors": [{"label": "Additional Tools", "name": "tools", "type": "Tool", "optional": True, "list": True,
                      "id": f"{nid}-input-tools-Tool", "display": True}],
    "inputs": {"functionInputVariables": json.dumps({"answer": "{{llmChain_0.data.instance}}"}),
               "functionName": "Response Validator (evidence check)", "tools": "", "javascriptFunction": VJS},
    "outputAnchors": [{"name": "output", "label": "Output", "type": "options", "description": "", "options": [
        {"id": f"{nid}-output-output-string|number|boolean|json|array", "name": "output", "label": "Output",
         "description": "", "type": "string | number | boolean | json | array"},
        {"id": f"{nid}-output-EndingNode-CustomFunction", "name": "EndingNode", "label": "Ending Node",
         "description": "", "type": "CustomFunction"}], "default": "output"}],
    "outputs": {"output": "EndingNode"}, "selected": False,
})
edge("llmChain_0", "llmChain_0-output-outputPrediction-string|json",
     "customFunction_1", "customFunction_1-input-functionInputVariables-json")

# ---------------------------------------------------------------- sticky note explaining the flow
nid = "stickyNote_0"
node(nid, -40, 860, {
    "id": nid, "label": "Sticky Note", "version": 2, "name": "stickyNote", "type": "StickyNote",
    "baseClasses": ["StickyNote"], "category": "Utilities", "description": "Add a sticky note",
    "inputParams": [param(nid, "", "note", "string", rows=1, optional=True)], "inputAnchors": [],
    "inputs": {"note": "Hostapd AI Analyzer (runtime skill: skills/hostapd_analyzer/SKILL.md)\n\n"
                       "1. Context node -> bridge /context: Query Classifier (intents + domains + analysis plan), "
                       "Parser statistics, keyword + semantic RAG, MAG history, CAG knowledge, missing information, "
                       "evidence level.\n2. Chat Prompt Template: hallucination-control rules + FACTS + QUESTION.\n"
                       "3. LLM Chain + Ollama: evidence-based interpretation.\n"
                       "4. Response Validator -> bridge /validate: every MAC / number / reason code / timestamp / "
                       "causal claim is checked against the evidence.\n\n"
                       f"Current test: {ARGS.current_test or 'newest file in input_logs'}"},
    "outputAnchors": [{"id": f"{nid}-output-stickyNote-StickyNote", "name": "stickyNote", "label": "StickyNote",
                       "description": "", "type": "StickyNote"}], "outputs": {}, "selected": False,
}, height=180)

out = Path(ARGS.output)
out.write_text(json.dumps({"nodes": nodes, "edges": edges}, indent=2), encoding="utf-8")
print(f"Wrote {len(nodes)} nodes, {len(edges)} edges -> {out}")
