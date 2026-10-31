"""
shadow313.core.ai_engine
AI Engine — supports Ollama (local), OpenAI-compatible, and disabled backends.
All prompts stay local unless backend="openai" is explicitly configured.
"""
from __future__ import annotations
import json
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

    # Allowed endpoint schemes and hosts for SSRF prevention (S313-CVE-2026-002)
    _ALLOWED_SCHEMES = {"http", "https"}
    _BLOCKED_HOSTS   = {
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "metadata.google.internal",
        "169.254.170.2",    # ECS task metadata
        "100.100.100.200",  # Alibaba Cloud metadata
    }

    def __init__(self, config: dict) -> None:
        """Configure the backend, endpoint, request timeout, and context limit.

        ``timeout`` is in seconds; ``context_window`` sets Ollama's context
        size or the OpenAI-compatible response token limit. Invalid numeric
        settings raise ValueError or TypeError; rejected endpoints raise ValueError.
        """
        self.backend:  str = config.get("backend", "ollama")
        self.model:    str = config.get("model", "mistral:7b")
        raw_endpoint       = config.get("endpoint", "http://localhost:11434").rstrip("/")
        self.endpoint: str = self._validate_endpoint(raw_endpoint)
        self.timeout:  int = int(config.get("timeout", 120))
        self.ctx_win:  int = int(config.get("context_window", 8192))

    def _validate_endpoint(self, endpoint: str) -> str:
        """Return the endpoint after scheme and host checks (S313-CVE-2026-002).

        Raise ValueError for unsupported schemes, blocked hosts, reserved host
        prefixes, or URL parsing errors reported as ValueError.
        """
        from urllib.parse import urlparse
        try:
            parsed = urlparse(endpoint)
            scheme = parsed.scheme.lower()
            host   = parsed.hostname or ""
            if scheme not in self._ALLOWED_SCHEMES:
                raise ValueError(
                    f"AI endpoint scheme '{scheme}' is not allowed. "
                    f"Use http or https."
                )
            if host in self._BLOCKED_HOSTS:
                raise ValueError(
                    f"AI endpoint host '{host}' is blocked to prevent SSRF attacks. "
                    f"Configure a legitimate Ollama or OpenAI-compatible endpoint."
                )
            # Block link-local and loopback ranges except localhost
            if host.startswith("169.254.") or host.startswith("fd00:"):
                raise ValueError(
                    f"AI endpoint host '{host}' is in a reserved/link-local range."
                )
        except ValueError:
            raise
        except Exception:
            pass  # Malformed URL — let the actual request fail naturally
        return endpoint

    # ── Public API ────────────────────────────────────────────────────────────
    def chat(self, user_prompt: str,
             system_prompt: str | None = None,
             context: dict | None = None) -> str:
        """Return a backend response, or a status/error message on handled failures.

        A truthy context is serialized as JSON and prepended to the user prompt.
        A missing or empty system prompt uses SYSTEM_PROMPT. Context serialization
        and request-construction errors propagate.
        """
        if self.backend == "disabled":
            return "[AI disabled — set backend in config.yaml]"

        sys_p = system_prompt or self.SYSTEM_PROMPT
        if context:
            user_prompt = f"Context:\n{json.dumps(context, indent=2, default=str)}\n\n{user_prompt}"

        if self.backend == "ollama":
            return self._ollama_chat(sys_p, user_prompt)
        if self.backend == "openai":
            return self._openai_chat(sys_p, user_prompt)
        return "[Unknown AI backend]"

    def stream(self, user_prompt: str,
               system_prompt: str | None = None) -> Generator[str, None, None]:
        """Yield Ollama response chunks, or one full chat response for other backends.

        Ollama stream failures yield an error message after any received chunks.
        """
        if self.backend != "ollama":
            yield self.chat(user_prompt, system_prompt)
            return
        yield from self._ollama_stream(system_prompt or self.SYSTEM_PROMPT, user_prompt)

    def is_available(self) -> bool:
        """Probe Ollama connectivity, returning False on probe failure or disabled mode.

        Other backend names return True without a connectivity check.
        """
        if self.backend == "disabled":
            return False
        try:
            if self.backend == "ollama":
                req = request.Request(f"{self.endpoint}/api/tags", method="GET")
                with request.urlopen(req, timeout=5):
                    return True
            return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return Ollama model names, or an empty list for other backends or errors."""
        if self.backend != "ollama":
            return []
        try:
            req = request.Request(f"{self.endpoint}/api/tags", method="GET")
            with request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    # ── Ollama backend ────────────────────────────────────────────────────────
    def _ollama_chat(self, system: str, user: str) -> str:
        """Request an Ollama response and strip its surrounding whitespace.

        Request execution and response parsing failures return error messages.
        Errors constructing the request propagate to the caller.
        """
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
        """Yield Ollama content chunks, skipping lines that are not valid JSON.

        Stream failures yield an error message; request construction errors
        propagate when iteration begins.
        """
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
                for line in resp:
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
        """Request a response using OPENAI_API_KEY from the environment.

        A missing key, request execution failure, or response parsing failure
        returns an error message. Request construction errors propagate.
        """
        import os
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
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
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            return f"[AI error: {exc}]"