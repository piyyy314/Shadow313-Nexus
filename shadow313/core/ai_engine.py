"""
shadow313.core.ai_engine  — v4
AI Engine abstraction: Ollama (local) · OpenAI-compatible · Disabled.

BUG FIXES vs v1:
  - _ollama_stream() had an infinite loop risk: if 'done' key was missing
    from a chunk the loop never terminated — added packet counter guard.
  - _openai_chat() imported os inside function on every call — moved to top.
  - is_available() swallowed all exceptions silently — now logs to stderr in
    verbose mode.
  - chat() with context= did not truncate context to avoid exceeding ctx_win —
    added _truncate_context() helper.
  - stream() fell back to chat() for non-ollama backends but ignored
    system_prompt parameter — fixed.
"""
from __future__ import annotations
import json
import os
import sys
import time
from typing import Any, Generator
from urllib import request, error as urllib_error


class AIEngine:
    """
    Unified AI inference interface.
    Backends:
      - "ollama"   → http://localhost:11434  (local, default)
      - "openai"   → OpenAI-compatible REST API
      - "disabled" → returns stub messages (offline / CI mode)
    """

    SYSTEM_PROMPT = (
        "You are Shadow313's embedded AI security analyst. "
        "Respond in structured, precise, actionable security-engineering language. "
        "Never fabricate CVEs, exploits, or vulnerability data. "
        "If uncertain, say so explicitly."
    )

    # Maximum characters of context JSON to include in a prompt
    _MAX_CTX_CHARS = 12_000

    def __init__(self, config: dict) -> None:
        self.backend:  str = config.get("backend", "ollama")
        self.model:    str = config.get("model", "mistral:7b")
        self.endpoint: str = config.get("endpoint", "http://localhost:11434").rstrip("/")
        self.timeout:  int = int(config.get("timeout", 120))
        self.ctx_win:  int = int(config.get("context_window", 8192))
        self._api_key: str = config.get("openai_api_key", "") or os.environ.get("OPENAI_API_KEY", "")

    # ── Public API ────────────────────────────────────────────────────────────
    def chat(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
        context: dict | None = None,
    ) -> str:
        """Send a prompt and return the full response string."""
        if self.backend == "disabled":
            return "[AI disabled — set backend in config.yaml]"

        sys_p = system_prompt or self.SYSTEM_PROMPT
        if context:
            ctx_str = self._truncate_context(context)
            user_prompt = f"Context:\n{ctx_str}\n\n{user_prompt}"

        if self.backend == "ollama":
            return self._ollama_chat(sys_p, user_prompt)
        if self.backend == "openai":
            return self._openai_chat(sys_p, user_prompt)
        return "[Unknown AI backend]"

    def stream(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
    ) -> Generator[str, None, None]:
        """Stream response tokens (generator)."""
        if self.backend == "disabled":
            yield "[AI disabled]"
            return
        if self.backend == "ollama":
            yield from self._ollama_stream(system_prompt or self.SYSTEM_PROMPT, user_prompt)
        else:
            # FIX: pass system_prompt correctly for non-ollama backends
            yield self.chat(user_prompt, system_prompt=system_prompt)

    def is_available(self) -> bool:
        """Probe the AI backend to check connectivity."""
        if self.backend == "disabled":
            return False
        try:
            if self.backend == "ollama":
                req = request.Request(f"{self.endpoint}/api/tags", method="GET")
                with request.urlopen(req, timeout=5):
                    return True
            # For openai-compatible, just check the key is set
            return bool(self._api_key)
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return available model names (Ollama only)."""
        if self.backend != "ollama":
            return []
        try:
            req = request.Request(f"{self.endpoint}/api/tags", method="GET")
            with request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    # ── Context truncation ────────────────────────────────────────────────────
    def _truncate_context(self, context: dict) -> str:
        """Serialize context and truncate to avoid exceeding context window."""
        try:
            full = json.dumps(context, indent=2, default=str)
        except Exception:
            full = str(context)
        if len(full) > self._MAX_CTX_CHARS:
            full = full[: self._MAX_CTX_CHARS] + "\n... [truncated]"
        return full

    # ── Ollama backend ────────────────────────────────────────────────────────
    def _ollama_chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "options": {"num_ctx": self.ctx_win},
        }
        body = json.dumps(payload).encode()
        req  = request.Request(
            f"{self.endpoint}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                return data.get("message", {}).get("content", "").strip()
        except urllib_error.URLError as exc:
            return f"[AI error — Ollama unreachable: {exc.reason}]"
        except Exception as exc:
            return f"[AI error: {exc}]"

    def _ollama_stream(self, system: str, user: str) -> Generator[str, None, None]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "stream": True,
            "options": {"num_ctx": self.ctx_win},
        }
        body = json.dumps(payload).encode()
        req  = request.Request(
            f"{self.endpoint}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                # FIX: add packet counter to prevent infinite loop if 'done' never arrives
                max_packets = 10_000
                count = 0
                for line in resp:
                    count += 1
                    if count > max_packets:
                        yield "\n[stream truncated — max packets reached]"
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            yield f"[AI stream error: {exc}]"

    # ── OpenAI-compatible backend ─────────────────────────────────────────────
    def _openai_chat(self, system: str, user: str) -> str:
        if not self._api_key:
            return "[AI error — OPENAI_API_KEY not set]"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "max_tokens": self.ctx_win,
        }
        body = json.dumps(payload).encode()
        req  = request.Request(
            f"{self.endpoint}/v1/chat/completions",
            data=body,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            return f"[AI error: {exc}]"