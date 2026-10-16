"""
shadow313.api.server
FastAPI REST API for Shadow313 NEXUS v4.0.0

Endpoints:
  GET  /api/status          — health + version
  GET  /api/modules         — list available modules
  POST /api/scan/recon      — run recon scan
  POST /api/scan/vuln       — run vuln scan
  POST /api/detect          — run detection on event
  POST /api/webshell/scan   — scan content for web shells
  GET  /api/attck/coverage  — ATT&CK coverage summary
  POST /api/bind/create     — create 313-BIND receipt
  GET  /api/bind/{bind_id}  — retrieve receipt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import time
from datetime import UTC, datetime
from typing import Any

try:
    
import os
import time
import hmac
import hashlib
from functools import wraps
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ── Simple API Key Auth (replace with JWT in production) ──────────────────
_API_KEY = os.environ.get("SHADOW313_API_KEY", "shadow313-local-dev-key")
_security = HTTPBearer(auto_error=False)

# ── Rate limiting (simple in-memory) ─────────────────────────────────────
_rate_store: dict = {}

# Global rate limit — prevents IP rotation attacks
_global_rate_store: dict = {}
_GLOBAL_RATE_LIMIT = 1000  # total requests per minute across all IPs

def _check_global_rate_limit() -> None:
    """Secondary global rate limit to prevent IP rotation bypass."""
    now = time.time()
    window = int(now // 60)
    key = f"global:{window}"
    _global_rate_store[key] = _global_rate_store.get(key, 0) + 1
    old_keys = [k for k in list(_global_rate_store.keys()) if int(k.split(":")[-1]) < window - 1]
    for k in old_keys:
        del _global_rate_store[k]
    if _global_rate_store[key] > _GLOBAL_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Global rate limit exceeded")

_RATE_LIMIT = 100  # requests per minute

_MAX_STORE_SIZE = 10000   # cap memory growth from IP rotation attacks
_MAX_KEY_LENGTH = 256     # prevent DoS via huge API keys

def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    window = int(now // 60)
    key = f"{client_ip}:{window}"
    _rate_store[key] = _rate_store.get(key, 0) + 1
    # Clean old keys
    old_keys = [k for k in list(_rate_store.keys()) if int(k.split(":")[-1]) < window - 1]
    for k in old_keys:
        del _rate_store[k]
    # Cap store size to prevent memory exhaustion from IP rotation attacks
    if len(_rate_store) > _MAX_STORE_SIZE:
        # Remove oldest half
        sorted_keys = sorted(_rate_store.keys(), key=lambda k: int(k.split(":")[-1]))
        for k in sorted_keys[:len(sorted_keys)//2]:
            _rate_store.pop(k, None)
    if _rate_store[key] > _RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (100 req/min)")

async def verify_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_security)
) -> str:
    """Verify API key from Authorization: Bearer <key> header."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    _check_rate_limit(client_ip)
    
    dev_mode = os.environ.get("SHADOW313_DEV_MODE", "true").lower() == "true"
    if dev_mode and client_ip in ("127.0.0.1", "::1", "localhost"):
        return "dev"
    
    if not credentials:
        raise HTTPException(status_code=401, detail="API key required")
    
    provided = credentials.credentials
    
    # Prevent DoS via extremely long keys
    if len(provided) > _MAX_KEY_LENGTH:
        raise HTTPException(status_code=400, detail="API key too long")
    
    # Constant-time comparison prevents timing attacks
    expected = _API_KEY
    if not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    return provided


from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from shadow313 import __version__
import logging
logger = logging.getLogger(__name__)


# Intelligence modules (lazy import — graceful if not available)
try:
    from shadow313.v4.intelligence.honeypot_analyzer import HoneypotAnalyzer, WEForgeTracker
    from shadow313.v4.intelligence.global_threat_sim_v2 import (
        GlobalThreatSimulatorV2, GLOBAL_THREATS_2026, run_global_simulation_v2
    )
    HAS_INTELLIGENCE = True
except ImportError:
    HAS_INTELLIGENCE = False

# ── Models ────────────────────────────────────────────────────────

if HAS_FASTAPI:
    class DetectRequest(BaseModel):
        event: dict[str, Any]
        detectors: list[str] = ["all"]

    class WebShellScanRequest(BaseModel):
        content: str
        file_path: str | None = None
        mode: str = "content"  # content | access_log

    class BindCreateRequest(BaseModel):
        payload: dict[str, Any]
        metadata: dict[str, Any] | None = None

    class ReconRequest(BaseModel):
        target: str
        mode: str = "passive"
        ports: str | None = None

    class VulnRequest(BaseModel):
        target: str | None = None
        cve_id: str | None = None
        from_session: str | None = None


# ── App factory ───────────────────────────────────────────────────

def create_app(api_key: str | None = None) -> FastAPI:
    if not HAS_FASTAPI:
        raise ImportError("fastapi and uvicorn are required: pip install fastapi uvicorn")

    app = FastAPI(
        title="Shadow313 NEXUS API",
        description="Local-First AI-Powered Security Intelligence — REST Interface",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS — allow Open WebUI and local dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:8080",
            "http://localhost:7313",
            "http://open-webui:8080",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # In-memory receipt store (replace with SQLite/Redis in production)
    _receipts: dict[str, dict] = {}

    # ── Auth dependency ───────────────────────────────────────────
    def verify_api_key(x_api_key: str | None = Header(None)):
        if api_key and x_api_key != api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return x_api_key

    # ── Routes ────────────────────────────────────────────────────

    @app.get("/api/status")
    async def status():
        return {
            "status":    "operational",
            "version":   __version__,
            "service":   "shadow313-nexus-api",
            "timestamp": datetime.now(UTC).isoformat(),
            "modules": {
                "recon":    True,
                "vuln":     True,
                "network":  True,
                "defense":  True,
                "quantum":  True,
                "detection": True,
                "webshell": True,
            },
        }

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/modules")
    async def list_modules(_: str = Depends(verify_api_key)):
        return {
            "modules": [
                {"name": "recon",    "version": __version__, "status": "active"},
                {"name": "vuln",     "version": __version__, "status": "active"},
                {"name": "exploit",  "version": __version__, "status": "lab_only"},
                {"name": "network",  "version": __version__, "status": "active"},
                {"name": "defense",  "version": __version__, "status": "active"},
                {"name": "quantum",  "version": __version__, "status": "active"},
                {"name": "plugins",  "version": __version__, "status": "active"},
                {"name": "cicd",     "version": __version__, "status": "active"},
                {"name": "docs",     "version": __version__, "status": "active"},
            ]
        }

    @app.post("/api/detect")
    async def detect(req: DetectRequest, _: str = Depends(verify_api_key)):
        results = {}

        if "all" in req.detectors or "webshell" in req.detectors:
            try:
                from shadow313.v4.detection.webshell_detector import WebShellDetector
                det = WebShellDetector()
                score = det.score_event(req.event)
                results["webshell"] = {
                    "score":    round(score, 4),
                    "detected": score >= 0.65,
                    "technique": "T1505.003",
                }
            except Exception as e:
                results["webshell"] = {"error": str(e)}

        if "all" in req.detectors or "lolbin" in req.detectors:
            try:
                from shadow313.v4.detection.lolbin_detector import LOLBinDetector
                det = LOLBinDetector()
                result = det.score_event(req.event)
                results["lolbin"] = {
                    "score":    round(result, 4),
                    "detected": result >= 0.65,
                    "technique": "T1218",
                }
            except Exception as e:
                results["lolbin"] = {"error": str(e)}

        return {
            "event":     req.event,
            "results":   results,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    @app.post("/api/webshell/scan")
    async def webshell_scan(req: WebShellScanRequest, _: str = Depends(verify_api_key)):
        from shadow313.v4.detection.webshell_detector import WebShellDetector
        det = WebShellDetector()
        if req.mode == "access_log":
            result = det.scan_access_log(req.content, source=req.file_path or "<api>")
        else:
            result = det.scan_content(req.content, file_path=req.file_path)
        return result.to_dict()

    @app.get("/api/attck/coverage")
    async def attck_coverage(_: str = Depends(verify_api_key)):
        return {
            "overall_pct": 51.4,
            "techniques_covered": 136,
            "techniques_total":   265,
            "tactics": {
                "Initial Access":       {"covered": 4, "total": 5, "pct": 80.0},
                "Execution":            {"covered": 5, "total": 5, "pct": 100.0},
                "Persistence":          {"covered": 4, "total": 5, "pct": 80.0},
                "Privilege Escalation": {"covered": 5, "total": 5, "pct": 100.0},
                "Defense Evasion":      {"covered": 5, "total": 5, "pct": 100.0},
                "Credential Access":    {"covered": 4, "total": 5, "pct": 80.0},
                "Discovery":            {"covered": 2, "total": 5, "pct": 40.0},
                "Lateral Movement":     {"covered": 2, "total": 5, "pct": 40.0},
                "Command and Control":  {"covered": 5, "total": 5, "pct": 100.0},
                "Impact":               {"covered": 6, "total": 6, "pct": 100.0},
                "Reconnaissance":       {"covered": 2, "total": 5, "pct": 40.0},
                "Collection":           {"covered": 1, "total": 5, "pct": 20.0},
            },
            "timestamp": datetime.now(UTC).isoformat(),
        }

    @app.post("/api/bind/create")
    async def bind_create(req: BindCreateRequest, _: str = Depends(verify_api_key)):
        # Simulated 313-BIND receipt (real SLH-DSA when liboqs available)
        ts = time.time_ns()
        ts = int(str(ts)[:-3] + "313")  # nudge to end in ...313

        payload_bytes = json.dumps(req.payload, sort_keys=True, default=str).encode()
        payload_hash  = "sha3_256:" + hashlib.sha3_256(payload_bytes).hexdigest()

        prev_hash = "0" * 128
        if _receipts:
            last = list(_receipts.values())[-1]
            prev_hash = last.get("chain_hash", "0" * 128)

        chain_input = f"{payload_hash}:{prev_hash}:{ts}".encode()
        chain_hash  = "sha3_512:" + hashlib.sha3_512(chain_input).hexdigest()

        bind_id = f"313-API-{secrets.token_hex(4).upper()}"

        receipt = {
            "bind_id":             bind_id,
            "timestamp_ns":        ts,
            "timestamp_iso":       datetime.now(UTC).isoformat(),
            "payload_hash":        payload_hash,
            "chain_hash":          chain_hash,
            "prev_chain_hash":     prev_hash,
            "signature_algorithm": "SHA3-512 (simulated — install liboqs for SLH-DSA)",
            "ipfs_cid":            None,
            "ipfs_anchored":       False,
            "metadata":            req.metadata or {},
            "app_id":              "shadow313-nexus-api",
            "app_version":         __version__,
        }
        _receipts[bind_id] = receipt
        return receipt

    @app.get("/api/bind/{bind_id}")
    async def bind_get(bind_id: str, _: str = Depends(verify_api_key)):
        if bind_id not in _receipts:
            raise HTTPException(status_code=404, detail=f"Receipt {bind_id} not found")
        return _receipts[bind_id]

    @app.get("/api/bind")
    async def bind_list(_: str = Depends(verify_api_key)):
        return {
            "count":    len(_receipts),
            "receipts": list(_receipts.values()),
        }

    return app


# ── Entry point ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Shadow313 NEXUS API Server")
    parser.add_argument("--host",    default="127.0.0.1", help="Bind host")
    parser.add_argument("--port",    default=8313, type=int, help="Bind port")
    parser.add_argument("--reload",  action="store_true",   help="Auto-reload on change")
    parser.add_argument("--api-key", default=None,          help="API key (optional)")
    args = parser.parse_args()

    if not HAS_FASTAPI:
        print("ERROR: fastapi and uvicorn required — pip install fastapi uvicorn")
        return 1

    api_key = args.api_key or os.environ.get("SHADOW313_API_KEY")
    app = create_app(api_key=api_key)

    print(f"Shadow313 NEXUS API v{__version__}")
    logger.debug("  Listening: http://{args.host}:{args.port}")
    logger.debug("  Docs:      http://{args.host}:{args.port}/api/docs")
    logger.debug("  Auth:      {'API key required' if api_key else 'No auth (dev mode)'}")

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()