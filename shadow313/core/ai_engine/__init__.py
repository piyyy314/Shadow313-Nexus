# ruff: noqa: S310
"""Unified AI inference engine for Ollama, OpenAI-compatible APIs, and AI gateways."""

from __future__ import annotations

import collections.abc
import json
import os
import urllib.error
import urllib.request


class AIEngine:
    """
    Unified AI inference interface.
    Backends:
      - "ollama"   → http://localhost:11434  (local, default)
      - "openai"   → OpenAI-compatible REST API
      - "gateway"  → Vercel AI Gateway or a configured OpenAI-compatible gateway
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

    # Restrict schemes and known metadata destinations.
    # Endpoint values are administrator-controlled.
    _ALLOWED_SCHEMES = {"http", "https"}
    _BLOCKED_HOSTS   = {
        "169.254.169.254",       # AWS/GCP/Azure instance metadata
        "metadata.google.internal",
        "169.254.170.2",         # ECS task metadata
        "100.100.100.200",       # Alibaba Cloud metadata
    }

    def __init__(self, config: dict) -> None:
        self.backend:  str = config.get("backend", "ollama")
        self.model:    str = config.get("model", "mistral:7b")
        configured_endpoint = config.get("endpoint")
        local_defaults = {"http://localhost:11434", "http://ollama:11434"}
        if self.backend == "gateway":
            endpoint_default = os.environ.get(
                "AI_GATEWAY_ENDPOINT", "https://ai-gateway.vercel.sh/v1"
            )
        elif self.backend == "openai":
            endpoint_default = "https://api.openai.com/v1"
        else:
            endpoint_default = "http://localhost:11434"
        if not configured_endpoint or (
            self.backend in {"openai", "gateway"}
            and configured_endpoint.rstrip("/") in local_defaults
        ):
            configured_endpoint = endpoint_default
        raw_endpoint = configured_endpoint.rstrip("/")
        self.endpoint: str = self._validate_endpoint(raw_endpoint)
        self.timeout:  int = int(config.get("timeout", 120))
        self.ctx_win:  int = int(config.get("context_window", 8192))
        if self.backend == "gateway":
            self._api_key = (
                config.get("gateway_api_key", "")
                or os.environ.get("AI_GATEWAY_API_KEY", "")
            )
        elif self.backend == "openai":
            self._api_key = (
                config.get("openai_api_key", "")
                or os.environ.get("OPENAI_API_KEY", "")
            )
        else:
            self._api_key = ""

    def _validate_endpoint(self, endpoint: str) -> str:
        """Validate an administrator-configured HTTP(S) AI endpoint."""
        from ipaddress import IPv6Address, ip_address
        from urllib.parse import urlsplit

        parsed = urlsplit(endpoint)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        if scheme not in self._ALLOWED_SCHEMES:
            raise ValueError("AI endpoint must use http or https")
        if not host or parsed.username is not None or parsed.password is not None:
            raise ValueError("AI endpoint must include a host and must not include user info")
        # Accessing .port validates malformed port strings before any urllib.request.
        _ = parsed.port
        if host in self._BLOCKED_HOSTS:
            raise ValueError(f"AI endpoint host '{host}' is blocked")

        normalized_host = host
        try:
            ipv6 = IPv6Address(host)
        except ValueError:
            ipv6 = None
        if ipv6 and ipv6.ipv4_mapped:
            normalized_host = str(ipv6.ipv4_mapped)

        if (
            normalized_host in self._BLOCKED_HOSTS
            or normalized_host.startswith(("169.254.", "fd00:", "fe80:", "fc00:"))
        ):
            raise ValueError(
                f"AI endpoint host '{host}' is in a blocked link-local or metadata range"
            )

        try:
            address = ip_address(normalized_host)
        except ValueError:
            address = None
        if address and (address.is_link_local or address.is_unspecified or address.is_multicast):
            raise ValueError(
                f"AI endpoint IP '{host}' is not a permitted destination"
            )
        return endpoint

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
        if self.backend in {"openai", "gateway"}:
            return self._openai_chat(sys_p, user_prompt)
        return "[Unknown AI backend]"

    def stream(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
    ) -> collections.abc.Generator[str, None, None]:
        """Stream Ollama tokens; other compatible providers yield one full response chunk."""
        if self.backend == "disabled":
            yield "[AI disabled]"
            return
        if self.backend == "ollama":
            yield from self._ollama_stream(system_prompt or self.SYSTEM_PROMPT, user_prompt)
        else:
            # FIX: pass system_prompt correctly for non-ollama backends
            yield self.chat(user_prompt, system_prompt=system_prompt)

    def is_available(self) -> bool:
        """Check local Ollama connectivity or cloud-provider credential configuration."""
        if self.backend == "disabled":
            return False
        try:
            if self.backend == "ollama":
                req = urllib.request.Request(f"{self.endpoint}/api/tags", method="GET")
                with urllib.request.urlopen(req, timeout=5):  # nosec B310
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
            req = urllib.request.Request(f"{self.endpoint}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
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
        req  = urllib.request.Request(
            f"{self.endpoint}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                data = json.loads(resp.read())
                return data.get("message", {}).get("content", "").strip()
        except urllib.error.URLError as exc:
            return f"[AI error — Ollama unreachable: {exc.reason}]"
        except Exception as exc:
            return f"[AI error: {exc}]"

    def _ollama_stream(
        self, system: str, user: str
    ) -> collections.abc.Generator[str, None, None]:
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
        req  = urllib.request.Request(
            f"{self.endpoint}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
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
            return "[AI error — configure the selected provider API key]"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "max_tokens": self.ctx_win,
        }
        body = json.dumps(payload).encode()
        req  = urllib.request.Request(
            (
                f"{self.endpoint}/chat/completions"
                if self.endpoint.endswith("/v1")
                else f"{self.endpoint}/v1/chat/completions"
            ),
            data=body,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            return f"[AI error: {exc}]"
