# ruff: noqa: S310
"""
shadow313.integrations.telegram.bot
────────────────────────────────────
Shadow313 NEXUS Telegram Alert Bot

Sends 313-BIND security alerts, Ghost-Watch events, and VSAT findings
to a Telegram chat. Runs as a lightweight asyncio service inside Docker.

Environment variables (set in docker-compose.yml or .env):
  TELEGRAM_BOT_TOKEN      — Bot token from @BotFather
  TELEGRAM_CHAT_ID        — Target chat/channel ID (e.g. -1001234567890)
  SHADOW313_API_URL        — FastAPI event bus (default: http://shadow313-api:8313)
  SHADOW313_AI_BACKEND     — ollama | openai | gateway | disabled
  SHADOW313_AI_ENDPOINT    — Optional custom OpenAI-compatible endpoint
  SHADOW313_AI_MODEL       — Model name for the selected backend
  TELEGRAM_MIN_SEVERITY   — Minimum severity: LOW|MEDIUM|HIGH|CRITICAL (default: HIGH)
  TELEGRAM_POLL_INTERVAL  — Seconds between polls (default: 2)

Quick start:
  1. Message @BotFather → /newbot → copy token
  2. Add bot to your channel, get chat ID via @userinfobot
  3. Set TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, and SHADOW313_API_KEY in .env
  4. docker compose up -d
  5. docker compose --profile telegram up -d telegram-bot
  6. The bot polls authenticated ShiatoAli SOC alerts; event ingestion must be active.
"""

from __future__ import annotations

import asyncio
import datetime
import html
import json
import logging
import os
import time
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("shadow313.telegram")

BOT_TOKEN       = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID         = os.getenv("TELEGRAM_CHAT_ID", "")
API_URL         = os.getenv("SHADOW313_API_URL", "http://shadow313-api:8313")
OLLAMA_URL      = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "matarmohamad313/shadow313-nexus")
AI_BACKEND      = os.getenv("SHADOW313_AI_BACKEND", "ollama")
AI_ENDPOINT     = os.getenv("SHADOW313_AI_ENDPOINT", OLLAMA_URL)
AI_MODEL        = os.getenv("SHADOW313_AI_MODEL", OLLAMA_MODEL)
PROCESSED_ALERT_IDS: set[str] = set()
PROCESSED_ALERT_TIMESTAMPS: dict[str, float] = {}
STATE_PATH = Path(
    os.getenv(
        "TELEGRAM_STATE_PATH",
        "/home/shadow313/.shadow313/telegram-state.json",
    )
).expanduser()
try:
    INITIAL_LOOKBACK_SECONDS = max(
        0, int(os.getenv("TELEGRAM_INITIAL_LOOKBACK_SECONDS", "900"))
    )
except ValueError:
    INITIAL_LOOKBACK_SECONDS = 900
EVENT_PROVIDER_WARNED = False
MIN_SEVERITY    = os.getenv("TELEGRAM_MIN_SEVERITY", "HIGH").upper()
POLL_INTERVAL   = int(os.getenv("TELEGRAM_POLL_INTERVAL", "2"))

SEVERITY_ORDER  = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_EMOJI  = {"LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
TELEGRAM_API    = f"https://api.telegram.org/bot{BOT_TOKEN}"


def _tg_request(method: str, payload: dict) -> dict | None:
    if not BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not set")
        return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310  # nosec B310
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        logger.error("Telegram API %s: %s", e.code, e.read().decode())
        return None
    except Exception as e:
        logger.error("Telegram request failed: %s", e)
        return None


def _ai_engine():
    """Build the same configured AI engine used by the main Python API."""
    from shadow313.core.ai_engine import AIEngine

    return AIEngine({
        "backend": AI_BACKEND,
        "model": AI_MODEL,
        "endpoint": AI_ENDPOINT,
        "timeout": 120,
    })


def _ai_generate(prompt: str) -> str:
    engine = _ai_engine()
    if not engine.is_available():
        raise RuntimeError(f"{engine.backend} is unavailable or missing provider credentials")
    answer = engine.chat(
        prompt,
        system_prompt=(
            "You are SATExpert, a defensive satellite and VSAT security assistant. "
            "Give concise, evidence-based guidance and flag uncertainty."
        ),
    )
    if answer.startswith("[AI error"):
        raise RuntimeError("Configured AI provider request failed")
    return answer


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
        _send_command_reply(
            chat_id,
            "<b>SATExpert commands</b>\n/help — show commands\n"
            "/status — check configured AI backend\n"
            "/ask &lt;question&gt; — ask the configured model",
        )
    elif text == "/status":
        try:
            engine = _ai_engine()
            if not engine.is_available():
                raise RuntimeError("backend is unavailable or provider credentials are missing")
            if engine.backend == "ollama":
                models = ", ".join(engine.list_models()) or "none"
                detail = f"Ollama online. Models: {html.escape(models)}"
            else:
                detail = (
                    f"{html.escape(engine.backend)} credentials configured. "
                    "Provider connectivity is checked when a request is sent."
                )
            _send_command_reply(chat_id, f"AI backend: <code>{detail}</code>")
        except Exception as exc:
            _send_command_reply(
                chat_id,
                f"AI backend unavailable: <code>{html.escape(str(exc))}</code>",
            )
    elif text.startswith("/ask "):
        question = text[5:].strip()
        if not question:
            _send_command_reply(chat_id, "Usage: /ask &lt;question&gt;")
            return
        try:
            answer = _ai_generate(
                "You are SATExpert, a defensive satellite and VSAT security assistant. "
                "Give concise, evidence-based guidance and flag uncertainty.\n\n" + question
            )
            _send_command_reply(chat_id, html.escape(answer[:3900]))
        except Exception as exc:
            _send_command_reply(
                chat_id,
                f"SATExpert request failed: <code>{html.escape(str(exc))}</code>",
            )
    elif text.startswith("/"):
        _send_command_reply(chat_id, "Unknown command. Use /help.")


def _fetch_updates(offset: int) -> list[dict]:
    result = _tg_request(
        "getUpdates",
        {"offset": offset, "timeout": 1, "allowed_updates": ["message"]},
    )
    return result.get("result", []) if result and result.get("ok") else []
def send_message(
    text: str, parse_mode: str = "HTML", chat_id: object = None
) -> dict | None:
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


def send_alert(event: dict) -> bool:
    severity  = str(event.get("severity", "UNKNOWN")).upper()
    emoji     = SEVERITY_EMOJI.get(severity, "⚪")
    source    = event.get("source", event.get("module", "NEXUS"))
    message   = event.get("message", event.get("msg", str(event)))
    ts        = event.get("timestamp", datetime.datetime.now(datetime.UTC).isoformat())
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
        return True
    logger.warning("Failed to send alert: %s", str(message)[:60])
    return False


def _fetch_events(since_ts: float) -> list[dict]:
    """Fetch all new ShiatoAli alerts across API pages, oldest first."""
    global EVENT_PROVIDER_WARNED
    if not API_URL:
        return []
    parsed_api_url = urllib.parse.urlsplit(API_URL)
    if parsed_api_url.scheme not in {"http", "https"} or not parsed_api_url.hostname:
        logger.warning("Alert polling disabled: SHADOW313_API_URL must be an HTTP(S) URL")
        return []
    key = os.environ.get("SHADOW313_API_KEY", "")
    if not key:
        if not EVENT_PROVIDER_WARNED:
            logger.warning("Alert polling disabled: configure SHADOW313_API_KEY")
            EVENT_PROVIDER_WARNED = True
        return []

    items: list[dict] = []
    page_size = 500
    max_pages = 20
    try:
        for page in range(max_pages):
            cursor = datetime.datetime.fromtimestamp(since_ts, datetime.UTC).isoformat()
            query = urllib.parse.urlencode({
                "limit": page_size,
                "offset": page * page_size,
                "since": cursor,
                "order": "asc",
            })
            url = f"{API_URL.rstrip('/')}/api/shiatoali/alerts?{query}"
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "X-API-Key": key},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:  # noqa: S310  # nosec B310
                data = json.loads(resp.read())
            if isinstance(data, dict) and data.get("status") == "unavailable":
                if not EVENT_PROVIDER_WARNED:
                    logger.warning("ShiatoAli alert provider is unavailable")
                    EVENT_PROVIDER_WARNED = True
                return []
            page_items = data.get("items", []) if isinstance(data, dict) else []
            if not isinstance(page_items, list):
                logger.warning("ShiatoAli alert API returned an invalid items payload")
                return []
            items.extend(item for item in page_items if isinstance(item, dict))
            if len(page_items) < page_size:
                break
        else:
            logger.warning(
                "ShiatoAli alert backlog exceeded %s pages; "
                "remaining alerts will be polled next cycle",
                max_pages,
            )

        events = []
        for alert in items:
            alert_id = str(alert.get("alert_id", ""))
            created_at = str(alert.get("created_at", ""))
            try:
                created = datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=datetime.UTC)
                created_unix = created.timestamp()
            except ValueError:
                logger.warning("Skipping ShiatoAli alert with invalid timestamp: %s", alert_id)
                continue
            if created_unix < since_ts or (alert_id and alert_id in PROCESSED_ALERT_IDS):
                continue
            host = str(alert.get("host") or "unknown host")
            title = str(alert.get("title") or "Security alert")
            events.append({
                "id": alert_id,
                "alert_id": alert_id,
                "severity": str(alert.get("severity", "LOW")).upper(),
                "source": "ShiatoAli SOC",
                "message": f"{title} on {host} (risk {alert.get('risk_score', 'n/a')})",
                "timestamp": created_at,
                "timestamp_unix": created_unix,
                "technique": alert.get("technique", ""),
                "host": host,
            })
        events.sort(key=lambda event: (event["timestamp_unix"], event["alert_id"]))
        return events
    except Exception as exc:
        logger.debug("ShiatoAli alert poll failed (API may be starting): %s", exc)
        return []



def _advance_alert_cursor(since_ts: float) -> float:
    """Advance only after successful delivery, retaining IDs tied to the cursor."""
    global PROCESSED_ALERT_IDS, PROCESSED_ALERT_TIMESTAMPS
    if not PROCESSED_ALERT_TIMESTAMPS:
        return since_ts
    latest = max(PROCESSED_ALERT_TIMESTAMPS.values())
    if latest <= since_ts:
        return since_ts
    PROCESSED_ALERT_TIMESTAMPS = {
        alert_id: timestamp
        for alert_id, timestamp in PROCESSED_ALERT_TIMESTAMPS.items()
        if timestamp == latest
    }
    PROCESSED_ALERT_IDS = set(PROCESSED_ALERT_TIMESTAMPS)
    return latest



def _load_delivery_state() -> tuple[float, set[str], dict[str, float]]:
    """Restore the delivery cursor so bot restarts do not skip SOC alerts."""
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        since_ts = float(state["since_ts"])
        timestamps = {
            str(alert_id): float(timestamp)
            for alert_id, timestamp in state.get("processed_alert_timestamps", {}).items()
        }
        processed_ids = {
            str(alert_id)
            for alert_id in state.get("processed_alert_ids", [])
            if alert_id
        }
        processed_ids.update(timestamps)
        return since_ts, processed_ids, timestamps
    except FileNotFoundError:
        return time.time() - INITIAL_LOOKBACK_SECONDS, set(), {}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        logger.warning("Could not restore Telegram delivery state: %s", exc)
        return time.time() - INITIAL_LOOKBACK_SECONDS, set(), {}


def _save_delivery_state(since_ts: float) -> None:
    """Atomically persist the cursor and IDs already delivered in its batch."""
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "since_ts": since_ts,
        "processed_alert_ids": sorted(PROCESSED_ALERT_IDS),
        "processed_alert_timestamps": PROCESSED_ALERT_TIMESTAMPS,
    }
    temporary_path = STATE_PATH.with_suffix(STATE_PATH.suffix + ".tmp")
    temporary_path.write_text(json.dumps(state), encoding="utf-8")
    os.replace(temporary_path, STATE_PATH)


def _severity_passes(event: dict) -> bool:
    sev = str(event.get("severity", "LOW")).upper()
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(MIN_SEVERITY, 2)


def send_startup_message() -> None:
    text = (
        "⬡ <b>Shadow313 NEXUS Bot Online</b>\n"
        f"<code>{datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}</code>\n\n"
        f"Monitoring: <code>{html.escape(API_URL)}</code>\n"
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
    since_ts, saved_ids, saved_timestamps = _load_delivery_state()
    PROCESSED_ALERT_IDS.update(saved_ids)
    PROCESSED_ALERT_TIMESTAMPS.update(saved_timestamps)
    logger.info(
        "Restored Telegram alert cursor; pending IDs at cursor: %s",
        len(PROCESSED_ALERT_IDS),
    )
    update_offset = 0

    while True:
        try:
            for update in _fetch_updates(update_offset):
                update_offset = max(update_offset, int(update.get("update_id", 0)) + 1)
                _handle_update(update)
            events = _fetch_events(since_ts) if API_URL else []
            batch_failed = False
            for event in events:
                alert_id = str(event.get("alert_id") or event.get("id") or "")
                if alert_id and alert_id in PROCESSED_ALERT_IDS:
                    continue
                delivered = not _severity_passes(event) or send_alert(event)
                if delivered and alert_id:
                    PROCESSED_ALERT_IDS.add(alert_id)
                    event_ts = event.get("timestamp_unix")
                    if isinstance(event_ts, (int, float)):
                        PROCESSED_ALERT_TIMESTAMPS[alert_id] = float(event_ts)
                elif not delivered:
                    batch_failed = True
            if events:
                if not batch_failed:
                    since_ts = _advance_alert_cursor(since_ts)
                try:
                    _save_delivery_state(since_ts)
                except OSError as state_error:
                    logger.error("Could not persist Telegram delivery state: %s", state_error)
        except Exception as e:
            logger.error("Polling loop error: %s", e)
        await asyncio.sleep(POLL_INTERVAL)


def main() -> None:
    asyncio.run(run_bot())


if __name__ == "__main__":
    main()
