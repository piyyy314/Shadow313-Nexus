from __future__ import annotations
"""
shadow313.integrations.telegram.bot
────────────────────────────────────
Shadow313 NEXUS Telegram Alert Bot

Sends 313-BIND security alerts, Ghost-Watch events, and VSAT findings
to a Telegram chat. Runs as a lightweight asyncio service inside Docker.

Environment variables (set in docker-compose.yml or .env):
  TELEGRAM_BOT_TOKEN      — Bot token from @BotFather
  TELEGRAM_CHAT_ID        — Target chat/channel ID (e.g. -1001234567890)
  SHADOW313_API_URL        — FastAPI event bus (default: http://shadow313-api:8000)
  TELEGRAM_MIN_SEVERITY   — Minimum severity: LOW|MEDIUM|HIGH|CRITICAL (default: HIGH)
  TELEGRAM_POLL_INTERVAL  — Seconds between polls (default: 10)

Quick start:
  1. Message @BotFather → /newbot → copy token
  2. Add bot to your channel, get chat ID via @userinfobot
  3. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env
  4. docker compose --profile telegram up -d telegram-bot
"""

import asyncio
import html
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional
import urllib.request
import urllib.error

logger = logging.getLogger("shadow313.telegram")

BOT_TOKEN       = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID         = os.getenv("TELEGRAM_CHAT_ID", "")
API_URL         = os.getenv("SHADOW313_API_URL", "")
OLLAMA_URL      = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "matarmohamad313/shadow313-nexus")
MIN_SEVERITY    = os.getenv("TELEGRAM_MIN_SEVERITY", "HIGH").upper()
POLL_INTERVAL   = int(os.getenv("TELEGRAM_POLL_INTERVAL", "2"))

SEVERITY_ORDER  = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_EMOJI  = {"LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
TELEGRAM_API    = f"https://api.telegram.org/bot{BOT_TOKEN}"


def _tg_request(method: str, payload: dict) -> Optional[dict]:
    if not BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set")
        return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        logger.error("Telegram API %s: %s", e.code, e.read().decode())
        return None
    except Exception as e:
        logger.error("Telegram request failed: %s", e)
        return None


def _ollama_generate(prompt: str) -> str:
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_URL.rstrip('/')}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return str(data.get("response", "No response from Ollama.")).strip()


def _authorized(chat_id: object) -> bool:
    return str(chat_id) == str(CHAT_ID)


def _send_command_reply(chat_id: object, text: str) -> None:
    result = send_message(text, chat_id=chat_id)
    if not result or not result.get("ok"):
        logger.warning("Failed to reply to Telegram command")


def _handle_update(update: dict) -> None:
    message = update.get("message") or update.get("edited_message") or {}
    chat = message.get("chat", {})
    chat_id = chat.get("id")
    text = str(message.get("text", "")).strip()
    if not text or not _authorized(chat_id):
        return

    if text == "/help":
        _send_command_reply(chat_id, "<b>SATExpert commands</b>\n/help — show commands\n/status — check Ollama\n/ask &lt;question&gt; — ask the local model")
    elif text == "/status":
        try:
            with urllib.request.urlopen(f"{OLLAMA_URL.rstrip('/')}/api/tags", timeout=10) as resp:
                data = json.loads(resp.read())
            models = ", ".join(m.get("name", "unknown") for m in data.get("models", [])) or "none"
            _send_command_reply(chat_id, f"Ollama online. Models: <code>{html.escape(models)}</code>")
        except Exception as exc:
            _send_command_reply(chat_id, f"Ollama unavailable: <code>{html.escape(str(exc))}</code>")
    elif text.startswith("/ask "):
        question = text[5:].strip()
        if not question:
            _send_command_reply(chat_id, "Usage: /ask &lt;question&gt;")
            return
        try:
            answer = _ollama_generate(
                "You are SATExpert, a defensive satellite and VSAT security assistant. "
                "Give concise, evidence-based guidance and flag uncertainty.\n\n" + question
            )
            _send_command_reply(chat_id, html.escape(answer[:3900]))
        except Exception as exc:
            _send_command_reply(chat_id, f"SATExpert request failed: <code>{html.escape(str(exc))}</code>")
    elif text.startswith("/"):
        _send_command_reply(chat_id, "Unknown command. Use /help.")


def _fetch_updates(offset: int) -> list[dict]:
    result = _tg_request("getUpdates", {"offset": offset, "timeout": 1, "allowed_updates": ["message"]})
    return result.get("result", []) if result and result.get("ok") else []
def send_message(text: str, parse_mode: str = "HTML", chat_id: object = None) -> Optional[dict]:
    destination = CHAT_ID if chat_id is None else chat_id
    if not destination:
        logger.warning("Telegram chat ID not set")
        return None
    return _tg_request("sendMessage", {
        "chat_id": destination,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    })


def send_alert(event: dict) -> None:
    severity  = event.get("severity", "UNKNOWN").upper()
    emoji     = SEVERITY_EMOJI.get(severity, "⚪")
    source    = event.get("source", event.get("module", "NEXUS"))
    message   = event.get("message", event.get("msg", str(event)))
    ts        = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    bind_id   = event.get("bind_id", "")
    technique = event.get("technique", event.get("tid", ""))

    lines = [
        f"{emoji} <b>Shadow313 NEXUS — {severity}</b>",
        f"<code>[{str(ts)[:19]}]</code>",
        "",
        f"<b>Source:</b> {html.escape(str(source))}",
        f"<b>Alert:</b> {html.escape(str(message))}",
    ]
    if technique:
        lines.append(f"<b>ATT&amp;CK:</b> <code>{html.escape(str(technique))}</code>")
    if bind_id:
        lines.append(f"<b>313-BIND:</b> <code>{html.escape(str(bind_id))}</code>")

    result = send_message("\n".join(lines))
    if result and result.get("ok"):
        logger.info("Alert sent: %s — %s", severity, str(message)[:60])
    else:
        logger.warning("Failed to send alert: %s", str(message)[:60])


def _fetch_events(since_ts: float) -> list:
    if not API_URL:
        return []
    url = f"{API_URL.rstrip('/')}/api/events?since={since_ts}&limit=50"
    key = os.environ.get("SHADOW313_API_KEY", "")
    if not key:
        logger.warning("Event polling disabled: configure SHADOW313_API_KEY and an event provider")
        return []
    req = urllib.request.Request(url, headers={"Accept": "application/json", "X-API-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            return data if isinstance(data, list) else data.get("events", [])
    except Exception as e:
        logger.debug("Event poll failed (API may be starting): %s", e)
        return []


def _severity_passes(event: dict) -> bool:
    sev = event.get("severity", "LOW").upper()
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(MIN_SEVERITY, 2)


def send_startup_message() -> None:
    text = (
        "⬡ <b>Shadow313 NEXUS Bot Online</b>\n"
        f"<code>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</code>\n\n"
        f"Monitoring: <code>{API_URL}</code>\n"
        f"Min severity: <b>{MIN_SEVERITY}</b>\n"
        f"Poll interval: <b>{POLL_INTERVAL}s</b>\n\n"
        "313-BIND · FIPS 205 · Ottawa, ON, Canada"
    )
    send_message(text)


async def run_bot() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN is not set. Set it in .env or docker-compose.yml")
        return
    if not CHAT_ID:
        logger.error("TELEGRAM_CHAT_ID is not set. Set it in .env or docker-compose.yml")
        return

    logger.info("Shadow313 Telegram Bot starting — min_severity=%s poll=%ss",
                MIN_SEVERITY, POLL_INTERVAL)
    send_startup_message()
    since_ts = time.time()
    update_offset = 0

    while True:
        try:
            for update in _fetch_updates(update_offset):
                update_offset = max(update_offset, int(update.get("update_id", 0)) + 1)
                _handle_update(update)
            events = _fetch_events(since_ts) if API_URL else []
            for event in events:
                if _severity_passes(event):
                    send_alert(event)
                event_ts = event.get("ts", event.get("timestamp_unix", since_ts))
                if isinstance(event_ts, (int, float)):
                    since_ts = max(since_ts, event_ts)
        except Exception as e:
            logger.error("Polling loop error: %s", e)
        await asyncio.sleep(POLL_INTERVAL)


def main() -> None:
    asyncio.run(run_bot())


if __name__ == "__main__":
    main()
