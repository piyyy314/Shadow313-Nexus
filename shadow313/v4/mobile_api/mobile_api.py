"""
shadow313.v4.mobile_api.mobile_api  — v4
REST API for iOS/Android companion app.
Push alerts for critical findings, session management, dashboard data.
"""
from __future__ import annotations
import hmac
import json
from datetime import datetime, timezone
from typing import Any


class MobileAPIModule:
    """shadow313.v4.mobile_api — Mobile companion API. Registered: mobile_api"""

    def __init__(self, kernel) -> None:
        self.kernel = kernel
        self.out    = kernel.out

    def register(self, kernel) -> None:
        kernel.register("mobile_api", self.run)

    def run(self, port: int = 7314, host: str = "127.0.0.1", token: str = "") -> dict:
        self.out.section("MOBILE API SERVER")
        try:
            self._start(host, port, token)
        except ImportError:
            self.out.warn("FastAPI not installed — pip install shadow313[dashboard]")
        return {"host": host, "port": port}

    def _start(self, host: str, port: int, token: str) -> None:
        from fastapi import FastAPI, HTTPException, Depends
        from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
        import uvicorn

        app    = FastAPI(title="Shadow313 Mobile API", version="4.0.0")
        kernel = self.kernel
        bearer = HTTPBearer(auto_error=False)

        async def verify_token(
            creds: HTTPAuthorizationCredentials = Depends(bearer),
        ) -> None:
            if token and (not creds or not hmac.compare_digest(
                creds.credentials.encode() if isinstance(creds.credentials, str) else creds.credentials,
                token.encode() if isinstance(token, str) else token,
            )):
                raise HTTPException(status_code=401, detail="Unauthorized")


        @app.get("/api/v1/status")
        async def status():
            return {"status": "ok", "version": "4.0.0-NEXUS",
                    "session": kernel.session.id,
                    "timestamp": datetime.now(timezone.utc).isoformat()}

        @app.get("/api/v1/findings")
        async def findings(severity: str = "", limit: int = 20):
            data = (kernel.session.read("findings.json") or {}).get("findings", [])
            if severity:
                data = [f for f in data if f.get("severity","").upper() == severity.upper()]
            return {"findings": data[:limit], "total": len(data)}

        @app.get("/api/v1/alerts")
        async def alerts():
            data = kernel.session.read("alerts.json") or []
            critical = [a for a in (data if isinstance(data, list) else [])
                        if a.get("severity","").upper() in ("CRITICAL","HIGH")]
            return {"alerts": critical[:10], "total": len(critical)}

        @app.get("/api/v1/sessions")
        async def sessions():
            from shadow313.core.session import Session
            sessions_dir = kernel.config.get("storage","sessions_dir",
                                             default="~/.shadow313/sessions")
            return {"sessions": Session.list_sessions(sessions_dir)[:20]}

        @app.post("/api/v1/ask")
        async def ask(body: dict):
            question = body.get("question", "")
            if not question:
                return {"error": "No question"}
            answer = kernel.ai.chat(question)
            return {"answer": answer}

        @app.get("/api/v1/receipts")
        async def receipts():
            temporal = kernel.get_module("temporal")
            if not temporal:
                return {"receipts": []}
            return {"receipts": temporal.engine.list_receipts(limit=10)}

        self.out.success(f"Mobile API at http://{host}:{port}")
        uvicorn.run(app, host=host, port=port, log_level="warning")