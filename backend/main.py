"""
SHADOW313 — Local Backend API
Proxies chat requests from the web dashboard to a local Ollama instance.
Eliminates CORS issues and provides a single endpoint for the front-end.
"""

import httpx
import os
import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="SHADOW313 Backend",
    description="Local proxy API for Ollama AI and future CLI tool integration",
    version="1.0.0",
)

# Restrict browser access to a small allowlist and avoid credentialed cross-site requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
CHAT_RATE_LIMIT_MAX = int(os.getenv("CHAT_RATE_LIMIT_MAX", "30"))
RATE_LIMIT_STATE: dict[str, list[float]] = {}

SYSTEM_PROMPT = (
    "You are SHADOW313 QTE (Quantum Thought Engine), an advanced quantum-computing "
    "and cybersecurity assistant. You are concise, technical, and accurate. "
    "Label simulations clearly and never claim real quantum hardware execution "
    "unless the user provides external results."
)


class ChatMessage(BaseModel):
    role: str = "user"
    content: str


class ChatRequest(BaseModel):
    message: str | None = None
    messages: list[ChatMessage] | None = None


def get_client_ip(request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def is_rate_limited(key: str, limit: int) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    hits = [timestamp for timestamp in RATE_LIMIT_STATE.get(key, []) if timestamp > window_start]
    if len(hits) >= limit:
        RATE_LIMIT_STATE[key] = hits
        return True
    hits.append(now)
    RATE_LIMIT_STATE[key] = hits
    return False


@app.middleware("http")
async def rate_limit_chat_requests(request, call_next):
    if request.url.path == "/api/chat":
        key = f"chat:{get_client_ip(request)}"
        if is_rate_limited(key, CHAT_RATE_LIMIT_MAX):
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
                content={"detail": "Too many requests. Please retry shortly."},
            )
    return await call_next(request)


@app.get("/health")
async def health():
    """Health check — also verifies Ollama connectivity."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                return {
                    "status": "ok",
                    "ollama": "connected",
                    "models": model_names,
                    "active_model": OLLAMA_MODEL,
                }
            return {
                "status": "degraded",
                "ollama": "error",
                "error": f"Ollama returned status {resp.status_code}",
            }
    except Exception as exc:
        return {
            "status": "degraded",
            "ollama": "unreachable",
            "error": str(exc),
        }


@app.post("/api/chat")
async def chat(request: ChatRequest):
    """
    Forward a chat request to the local Ollama instance.
    Accepts either:
      { "message": "Hello" }
    or:
      { "messages": [{"role": "user", "content": "Hello"}] }
    """
    # Normalize messages
    if request.messages:
        if len(request.messages) > 50:
            raise HTTPException(status_code=400, detail="Too many messages; limit is 50")
        messages = [{"role": m.role, "content": m.content} for m in request.messages]
    elif request.message:
        messages = [{"role": "user", "content": request.message}]
    else:
        raise HTTPException(status_code=400, detail="A message is required")

    messages = [
        {
            "role": m["role"] if m["role"] in {"assistant", "system"} else "user",
            "content": str(m["content"])[:4000],
        }
        for m in messages
        if str(m["content"]).strip()
    ]
    if not messages:
        raise HTTPException(status_code=400, detail="A message is required")

    # Prepend system prompt
    full_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages

    # Call Ollama
    async with httpx.AsyncClient(timeout=60) as client:
        try:
            resp = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": full_messages,
                    "stream": False,
                },
            )
        except httpx.ConnectError:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Cannot connect to Ollama. "
                    "Make sure 'ollama serve' is running on your machine."
                ),
            )
        except httpx.ReadTimeout:
            raise HTTPException(
                status_code=504,
                detail="Ollama took too long to respond. Try a shorter message.",
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=str(exc))

    if resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code,
            detail=f"Ollama error: {resp.text[:500]}",
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Ollama returned invalid JSON: {exc}",
        )
    reply = data.get("message", {}).get("content", "").strip()

    if not reply:
        raise HTTPException(
            status_code=502,
            detail="Ollama returned an empty response.",
        )

    return {"reply": reply}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
