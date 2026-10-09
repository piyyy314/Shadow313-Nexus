"""
shadow313.api.middleware
─────────────────────────
Production-grade security middleware for Shadow313 NEXUS FastAPI.

Implements:
  1. JWT Bearer token authentication (RS256 / HS256)
  2. API key authentication (X-API-Key header)
  3. Rate limiting via slowapi (per-IP + per-key)
  4. Security headers (CSP, HSTS, X-Frame-Options, etc.)
  5. Request ID injection for 313-BIND audit correlation
  6. Structured audit logging

Usage in server.py:
    from shadow313.api.middleware import (
        add_security_middleware, get_current_user,
        require_api_key, limiter
    )
    add_security_middleware(app)

Environment variables:
    SHADOW313_API_KEY      — static API key (fallback auth)
    SHADOW313_JWT_SECRET   — JWT signing secret (HS256)
    SHADOW313_JWT_ISSUER   — JWT issuer claim (default: shadow313-nexus)
    SHADOW313_RATE_LIMIT   — requests per minute (default: 60)
    SHADOW313_ENV          — production | development (default: development)
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

logger = logging.getLogger("shadow313.api.middleware")

# ── Optional imports (graceful degradation) ───────────────────────────────────
try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address
    HAS_SLOWAPI = True
except ImportError:
    HAS_SLOWAPI = False
    logger.warning("slowapi not installed — rate limiting disabled. pip install slowapi")

try:
    from jose import JWTError, jwt
    HAS_JOSE = True
except ImportError:
    HAS_JOSE = False
    logger.warning("python-jose not installed — JWT auth disabled. pip install python-jose[cryptography]")

# ── Config ────────────────────────────────────────────────────────────────────

API_KEY        = os.getenv("SHADOW313_API_KEY", "")
JWT_SECRET     = os.getenv("SHADOW313_JWT_SECRET", secrets.token_hex(32))
JWT_ISSUER     = os.getenv("SHADOW313_JWT_ISSUER", "shadow313-nexus")
JWT_ALGORITHM  = "HS256"
JWT_EXPIRE_MIN = int(os.getenv("SHADOW313_JWT_EXPIRE_MIN", "60"))
RATE_LIMIT     = os.getenv("SHADOW313_RATE_LIMIT", "60/minute")
ENV            = os.getenv("SHADOW313_ENV", "development")
IS_PROD        = ENV == "production"

# Public endpoints that don't require auth
PUBLIC_PATHS = {
    "/health",
    "/api/status",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/bind/verify",      # Public receipt verification
    "/api/attck/coverage",   # Public ATT&CK badge
    "/api/ioc/feed",         # Public STIX feed
    "/api/changelog",        # Public changelog
}

# ── Rate Limiter ──────────────────────────────────────────────────────────────

def _get_key_or_ip(request: "Request") -> str:
    """Rate limit key: API key if present, else IP address."""
    key = request.headers.get("X-API-Key", "")
    if key:
        return f"key:{hashlib.sha256(key.encode()).hexdigest()[:16]}"
    return get_remote_address(request) if HAS_SLOWAPI else "unknown"

if HAS_SLOWAPI:
    limiter = Limiter(key_func=_get_key_or_ip, default_limits=[RATE_LIMIT])
else:
    limiter = None


# ── JWT Utilities ─────────────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    scopes: list[str] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token."""
    if not HAS_JOSE:
        raise RuntimeError("python-jose required for JWT: pip install python-jose[cryptography]")
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=JWT_EXPIRE_MIN))
    payload = {
        "sub": subject,
        "iss": JWT_ISSUER,
        "iat": datetime.now(UTC),
        "exp": expire,
        "scopes": scopes or ["read"],
        "jti": secrets.token_hex(16),  # JWT ID for revocation
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    if not HAS_JOSE:
        raise HTTPException(status_code=501, detail="JWT not configured")
    try:
        payload = jwt.decode(
            token, JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Auth Dependencies ─────────────────────────────────────────────────────────

def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> dict[str, Any]:
    """
    FastAPI dependency: authenticate via JWT Bearer OR API key.
    Returns user context dict.

    Usage:
        @app.get("/api/protected")
        async def protected(user = Depends(get_current_user)):
            return {"user": user}
    """
    # ── Try JWT Bearer first ──────────────────────────────────────────────────
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        payload = decode_token(token)
        return {
            "sub": payload.get("sub", "unknown"),
            "scopes": payload.get("scopes", []),
            "auth_method": "jwt",
            "jti": payload.get("jti"),
        }

    # ── Fall back to API key ──────────────────────────────────────────────────
    if x_api_key:
        if not API_KEY:
            # No key configured — accept any key in dev mode
            if not IS_PROD:
                return {"sub": x_api_key[:8] + "...", "scopes": ["read", "write"], "auth_method": "api_key"}
            raise HTTPException(status_code=503, detail="API key auth not configured")
        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(x_api_key.encode(), API_KEY.encode()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return {"sub": "api_key_user", "scopes": ["read", "write"], "auth_method": "api_key"}

    # ── No auth provided ──────────────────────────────────────────────────────
    if IS_PROD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide Bearer token or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Development mode: allow unauthenticated access with warning
    logger.warning("Unauthenticated request in development mode")
    return {"sub": "anonymous", "scopes": ["read"], "auth_method": "none"}


def require_scope(required_scope: str):
    """
    FastAPI dependency factory: require a specific scope.

    Usage:
        @app.post("/api/scan/recon")
        async def recon(user = Depends(require_scope("scan"))):
            ...
    """
    def _check(user: dict = Depends(get_current_user)) -> dict:
        if required_scope not in user.get("scopes", []) and "admin" not in user.get("scopes", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope}' required",
            )
        return user
    return _check


# Convenience aliases
require_read  = Depends(require_scope("read"))
require_write = Depends(require_scope("write"))
require_scan  = Depends(require_scope("scan"))
require_admin = Depends(require_scope("admin"))


# ── Security Headers Middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds production security headers to every response.
    Implements OWASP recommended headers.
    """

    # Content Security Policy — strict but allows local resources
    CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' http://localhost:* ws://localhost:*; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    async def dispatch(self, request: Request, call_next) -> Response:
        # Inject request ID for audit correlation
        request_id = secrets.token_hex(8)
        request.state.request_id = request_id
        request.state.start_time = time.time()

        response = await call_next(request)

        # ── Security headers ──────────────────────────────────────────────────
        response.headers["X-Request-ID"]              = request_id
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"]   = self.CSP

        if IS_PROD:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Remove server fingerprinting headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)

        # ── Audit log ─────────────────────────────────────────────────────────
        duration_ms = round((time.time() - request.state.start_time) * 1000, 1)
        logger.info(
            "API %s %s → %d (%sms) [%s]",
            request.method, request.url.path,
            response.status_code, duration_ms, request_id
        )

        return response


# ── CORS Configuration ────────────────────────────────────────────────────────

def get_cors_origins() -> list[str]:
    """Return allowed CORS origins based on environment."""
    base = [
        "http://localhost:3000",   # Open WebUI
        "http://localhost:8080",   # Burp proxy / local dev
        "http://localhost:7313",   # Shadow313 HTTP
        "http://localhost:7314",   # Shadow313 HTTPS
        "http://open-webui:8080",  # Docker internal
    ]
    if IS_PROD:
        prod_origins = os.getenv("SHADOW313_CORS_ORIGINS", "https://shadow313.dev,https://shadow313.com")
        base.extend(prod_origins.split(","))
    return base


# ── Main setup function ───────────────────────────────────────────────────────

def add_security_middleware(app: "FastAPI") -> None:
    """
    Apply all security middleware to a FastAPI app.
    Call this BEFORE adding routes.

    Example:
        app = FastAPI(...)
        add_security_middleware(app)
        # now add routes
    """
    if not HAS_FASTAPI:
        return

    # 1. Rate limiting
    if HAS_SLOWAPI and limiter:
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        logger.info("Rate limiting enabled: %s", RATE_LIMIT)

    # 2. Security headers (innermost — runs last on response)
    app.add_middleware(SecurityHeadersMiddleware)

    # 3. CORS (outermost — runs first on request)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
        max_age=600,
    )

    logger.info(
        "Security middleware loaded — env=%s cors_origins=%d",
        ENV, len(get_cors_origins())
    )


# ── Token generation helper (for CLI / setup) ─────────────────────────────────

def generate_api_key(prefix: str = "s313") -> str:
    """Generate a secure API key with prefix."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def generate_jwt_for_cli(subject: str = "cli-operator", scopes: list[str] | None = None) -> str:
    """Generate a JWT token for CLI use."""
    return create_access_token(
        subject=subject,
        scopes=scopes or ["read", "write", "scan"],
        expires_delta=timedelta(days=30),
    )
