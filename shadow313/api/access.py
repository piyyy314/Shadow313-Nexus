"""Authentication and bounded request handling for local APIs."""

import secrets
from collections import deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse


def authorize(request: Request, expected: str | None) -> None:
    provided = request.headers.get("x-api-key", "")
    bearer = request.headers.get("authorization", "")
    if not provided and bearer.startswith("Bearer "):
        provided = bearer[7:]
    if len(provided) > 256:
        raise HTTPException(400, "API key too long")
    if expected:
        if not secrets.compare_digest(provided.encode(), expected.encode()):
            raise HTTPException(401, "API key required or invalid")
    elif not request.client or request.client.host not in {"127.0.0.1", "::1", "localhost"}:
        raise HTTPException(503, "Configure an API key before remote access")


def install_limits(app, max_bytes: int = 1_048_576, per_minute: int = 1000) -> None:
    """Per-process global quota and streaming body cap; not distributed limits."""
    lock = Lock()
    calls = deque()

    @app.middleware("http")
    async def limits(request, call_next):
        now = monotonic()
        with lock:
            while calls and calls[0] <= now - 60:
                calls.popleft()
            if len(calls) >= per_minute:
                return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
            calls.append(now)
        size = 0
        body = []
        async for chunk in request.stream():
            size += len(chunk)
            if size > max_bytes:
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
            body.append(chunk)
        request._body = b"".join(body)
        return await call_next(request)
