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
from __future__ import annotations

import asyncio
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
API_URL         = os.getenv("SHADOW313_API_URL", "http://shadow313-api:8000")
MIN_SEVERITY    = os.getenv("TELEGRAM_MIN_SEVERITY", "HIGH").upper()
POLL_INTERVAL   = int(os.getenv("TELEGRAM_POLL_INTERVAL", "10"))

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


def send_message(text: str, parse_mode: str = "HTML") -> Optional[dict]:
    if not CHAT_ID:
        logger.warning("TELEGRAM_CHAT_ID not set")
        return None
    return _tg_request("sendMessage", {
        "chat_id": CHAT_ID,
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
        f"<b>Source:</b> {source}",
        f"<b>Alert:</b> {message}",
    ]
    if technique:
        lines.append(f"<b>ATT&amp;CK:</b> <code>{technique}</code>")
    if bind_id:
        lines.append(f"<b>313-BIND:</b> <code>{bind_id}</code>")

    result = send_message("\n".join(lines))
    if result and result.get("ok"):
        logger.info("Alert sent: %s — %s", severity, message[:60])
    else:
        logger.warning("Failed to send alert: %s", message[:60])


def _fetch_events(since_ts: float) -> list:
    url = f"{API_URL}/api/events?since={since_ts}&limit=50"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
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

    while True:
        try:
            events = _fetch_events(since_ts)
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
