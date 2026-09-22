"""
shadow313.v3.siem.siem  — v4
SIEM integration: Splunk HEC · Elasticsearch · Wazuh.
Forwards Shadow313 findings and alerts to SIEM platforms.

BUG FIXES:
  - Splunk HEC sender didn't set Content-Type header — Splunk rejected events.
  - Elasticsearch bulk indexer used wrong newline format (missing trailing \n).
  - _format_event() crashed on non-serializable datetime objects — added
    default=str to json.dumps.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any
from urllib import request as urlreq


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_event(source: str, event_type: str, data: dict) -> dict:
    """FIX: use default=str to handle non-serializable objects."""
    return {
        "timestamp":  _now_iso(),
        "source":     "shadow313",
        "source_type":source,
        "event_type": event_type,
        "data":       json.loads(json.dumps(data, default=str)),
    }


# ── Splunk HEC ────────────────────────────────────────────────────────────────

class SplunkHECSender:
    """Sends events to Splunk HTTP Event Collector."""

    def __init__(self, hec_url: str, token: str, index: str = "shadow313") -> None:
        self._url   = hec_url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._index = index

    def send(self, events: list[dict]) -> dict:
        if not events:
            return {"sent": 0}
        # FIX: set Content-Type header — Splunk requires it
        payload = "\n".join(
            json.dumps({"event": e, "index": self._index, "sourcetype": "shadow313"}, default=str)
            for e in events
        )
        req = urlreq.Request(
            self._url,
            data=payload.encode(),
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type":  "application/json",  # FIX
            },
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read())
                return {"sent": len(events), "response": body}
        except Exception as exc:
            return {"sent": 0, "error": str(exc)}


# ── Elasticsearch ─────────────────────────────────────────────────────────────

class ElasticsearchSender:
    """Sends events to Elasticsearch via bulk API."""

    def __init__(self, url: str, index: str = "shadow313", api_key: str = "") -> None:
        self._url     = url.rstrip("/")
        self._index   = index
        self._api_key = api_key

    def send(self, events: list[dict]) -> dict:
        if not events:
            return {"sent": 0}
        # FIX: bulk format requires action line + doc line + trailing newline
        lines = []
        for event in events:
            action = json.dumps({"index": {"_index": self._index}})
            doc    = json.dumps(event, default=str)
            lines.append(action)
            lines.append(doc)
        # FIX: trailing newline required by Elasticsearch bulk API
        payload = "\n".join(lines) + "\n"

        headers = {"Content-Type": "application/x-ndjson"}
        if self._api_key:
            headers["Authorization"] = f"ApiKey {self._api_key}"

        req = urlreq.Request(
            f"{self._url}/_bulk",
            data=payload.encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read())
                errors = body.get("errors", False)
                return {"sent": len(events), "errors": errors}
        except Exception as exc:
            return {"sent": 0, "error": str(exc)}


# ── Wazuh ─────────────────────────────────────────────────────────────────────

class WazuhSender:
    """Sends events to Wazuh via REST API."""

    def __init__(self, url: str, username: str = "wazuh", password: str = "") -> None:
        self._url      = url.rstrip("/")
        self._username = username
        self._password = password
        self._token    = ""

    def _authenticate(self) -> bool:
        import base64
        creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        req   = urlreq.Request(
            f"{self._url}/security/user/authenticate",
            headers={"Authorization": f"Basic {creds}"},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                self._token = data.get("data", {}).get("token", "")
                return bool(self._token)
        except Exception:
            return False

    def send(self, events: list[dict]) -> dict:
        if not self._token and not self._authenticate():
            return {"sent": 0, "error": "Authentication failed"}
        sent = 0
        for event in events:
            payload = json.dumps(event, default=str).encode()
            req = urlreq.Request(
                f"{self._url}/events",
                data=payload,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type":  "application/json",
                },
                method="POST",
            )
            try:
                with urlreq.urlopen(req, timeout=10):
                    sent += 1
            except Exception:
                pass
        return {"sent": sent, "total": len(events)}


# ── SIEM Router ───────────────────────────────────────────────────────────────

class SIEMRouter:
    """Routes events to configured SIEM backends."""

    def __init__(self, config: dict) -> None:
        self._backends: list[Any] = []
        backend = config.get("backend", "disabled")

        if backend == "splunk":
            self._backends.append(SplunkHECSender(
                config.get("splunk_hec_url", ""),
                config.get("splunk_token", ""),
            ))
        elif backend == "elasticsearch":
            self._backends.append(ElasticsearchSender(
                config.get("elastic_url", ""),
                api_key=config.get("elastic_api_key", ""),
            ))
        elif backend == "wazuh":
            self._backends.append(WazuhSender(
                config.get("wazuh_url", ""),
                password=config.get("wazuh_password", ""),
            ))
        elif backend == "all":
            if config.get("splunk_hec_url"):
                self._backends.append(SplunkHECSender(
                    config["splunk_hec_url"], config.get("splunk_token", "")
                ))
            if config.get("elastic_url"):
                self._backends.append(ElasticsearchSender(config["elastic_url"]))
            if config.get("wazuh_url"):
                self._backends.append(WazuhSender(config["wazuh_url"]))

    def forward(self, events: list[dict]) -> dict:
        if not self._backends:
            return {"status": "disabled", "sent": 0}
        results = {}
        for backend in self._backends:
            name = type(backend).__name__
            results[name] = backend.send(events)
        return results

    @property
    def configured(self) -> bool:
        return bool(self._backends)


# ── SIEMModule ────────────────────────────────────────────────────────────────

class SIEMModule:
    """shadow313.v3.siem — SIEM integration. Registered: siem"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        cfg          = kernel.config.get("siem", default={})
        self.router  = SIEMRouter(cfg)

    def register(self, kernel) -> None:
        kernel.register("siem", self.run)

    def run(
        self,
        forward_session: str = "",
        forward_findings: bool = False,
        test: bool = False,
    ) -> dict:
        self.out.section("SIEM INTEGRATION")

        if not self.router.configured:
            self.out.warn("No SIEM backend configured. Set siem.backend in config.yaml")
            return {"status": "disabled"}

        events: list[dict] = []

        if test:
            events.append(_format_event("test", "connectivity_test", {
                "message": "Shadow313 SIEM connectivity test",
                "version": "4.0.0",
            }))

        if forward_findings or forward_session:
            session_id = forward_session or self.session.id
            from shadow313.core.session import Session
            s = Session.resume(session_id) if forward_session else self.session
            findings = (s.read("findings.json") or {}).get("findings", [])
            for f in findings:
                events.append(_format_event("vuln", "finding", f))

            alerts = s.read("alerts.json") or []
            for a in (alerts if isinstance(alerts, list) else []):
                events.append(_format_event("network", "alert", a))

        if not events:
            self.out.warn("No events to forward.")
            return {}

        self.out.info(f"Forwarding {len(events)} events to SIEM …")
        result = self.router.forward(events)
        self.out.result(result, "SIEM Forward Results")
        return result