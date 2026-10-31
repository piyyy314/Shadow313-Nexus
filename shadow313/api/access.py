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


class _RequestLimits:
    """ASGI body replay works with both old and current Starlette versions."""

    def __init__(self, app, max_bytes: int, per_minute: int):
        self.app = app
        self.max_bytes = max_bytes
        self.per_minute = per_minute
        self.lock = Lock()
        self.calls = deque()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        now = monotonic()
        with self.lock:
            while self.calls and self.calls[0] <= now - 60:
                self.calls.popleft()
            limited = len(self.calls) >= self.per_minute
            if not limited:
                self.calls.append(now)
        if limited:
            return await JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)(
                scope, receive, send
            )
        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.max_bytes:
                return await JSONResponse({"detail": "Request body too large"}, status_code=413)(
                    scope, receive, send
                )
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


def install_limits(app, max_bytes: int = 1_048_576, per_minute: int = 1000) -> None:
    """Per-process global quota and streaming body cap; not distributed limits."""
    app.add_middleware(_RequestLimits, max_bytes=max_bytes, per_minute=per_minute)
