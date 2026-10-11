"""
Ask the AI from the Workbench (v3.5).

1. Preferred: the saved Flowise chatflow "Hostapd AI Analyzer" (same RAG + MAG + CAG pipeline, same validator
   as the Flowise chat window) through Flowise's internal-prediction API, signed in with the local admin
   account the launcher created (login.json).
2. Fallback when Flowise is not reachable: the bridge builds the same FACTS, sends the same system prompt to
   Ollama with the same model settings, and runs the same validator.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLOWISE_URL = os.environ.get("FLOWISE_URL", "http://localhost:3000").rstrip("/")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3:latest")
FLOW_NAME = os.environ.get("FLOWISE_CHATFLOW", "Hostapd AI Analyzer")
OPTIONS = {"temperature": float(os.environ.get("OLLAMA_TEMPERATURE", "0.9")), "top_p": 0.9, "top_k": 40,
           "repeat_penalty": 1.1, "num_ctx": 8192}


class _Flowise:
    def __init__(self, login_file: Path):
        self.login_file = login_file
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.flow_id = None
        self.signed_in = False

    def call(self, method, path, body=None, timeout=20):
        req = urllib.request.Request(FLOWISE_URL + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "x-request-from": "internal"})
        try:
            with self.opener.open(req, timeout=timeout) as r:
                raw = r.read().decode(errors="ignore")
                return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="ignore")

    def sign_in(self):
        login = json.loads(self.login_file.read_text(encoding="utf-8"))
        code, _ = self.call("POST", "/api/v1/auth/login", {"email": login["email"], "password": login["password"]})
        if code >= 300:
            raise RuntimeError(f"Flowise sign-in failed (HTTP {code})")
        self.signed_in = True
        if login.get("chatflow_id"):
            self.flow_id = login["chatflow_id"]
        else:
            code, flows = self.call("GET", "/api/v1/chatflows")
            flow = next((f for f in flows or [] if isinstance(f, dict) and f.get("name") == FLOW_NAME), None) \
                if isinstance(flows, list) else None
            if not flow:
                raise RuntimeError(f"chatflow '{FLOW_NAME}' not found in Flowise")
            self.flow_id = flow["id"]

    def predict(self, question: str, timeout: int) -> str:
        if not self.signed_in:
            self.sign_in()
        for attempt in (1, 2):
            code, resp = self.call("POST", f"/api/v1/internal-prediction/{self.flow_id}",
                                   {"question": question, "streaming": False}, timeout=timeout)
            if code in (401, 403) and attempt == 1:
                self.sign_in()
                continue
            if code >= 300:
                raise RuntimeError(f"Flowise answered HTTP {code}: {str(resp)[:200]}")
            return resp.get("text") if isinstance(resp, dict) else str(resp)
        raise RuntimeError("Flowise sign-in expired")


_FW: _Flowise | None = None


def _ollama(system: str, human: str, timeout: int) -> str:
    body = {"model": MODEL, "stream": False, "keep_alive": "60m", "options": OPTIONS,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": human}]}
    req = urllib.request.Request(OLLAMA_URL + "/api/chat", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())["message"]["content"]


def ask(question: str, login_file: Path, facts_for, validate, timeout: int = 300) -> dict:
    """facts_for(question) -> facts text; validate(question, answer) -> validated answer text."""
    global _FW
    t0 = time.time()
    err = None
    if login_file.is_file():
        try:
            if _FW is None or _FW.login_file != login_file:
                _FW = _Flowise(login_file)
            text = _FW.predict(question, timeout)
            return {"answer": text, "via": "Flowise chatflow", "seconds": round(time.time() - t0, 1)}
        except Exception as e:  # noqa: BLE001 - fall back to Ollama
            err = str(e)
            _FW = None
    try:
        system = (ROOT / "flowise" / "system_prompt.md").read_text(encoding="utf-8").strip()
        facts = facts_for(question)
        raw = _ollama(system, f"FACTS:\n{facts}\n\nQUESTION: {question}", timeout)
        return {"answer": validate(question, raw), "via": f"Ollama {MODEL} (Flowise not reachable" +
                (f": {err[:80]})" if err else ")"), "seconds": round(time.time() - t0, 1)}
    except Exception as e:  # noqa: BLE001
        return {"answer": "", "via": "none", "error": f"the AI model is not reachable: {e}",
                "seconds": round(time.time() - t0, 1)}
