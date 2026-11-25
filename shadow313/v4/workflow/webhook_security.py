"""SSRF-resistant HTTP webhook delivery for NEXUS workflows."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
from datetime import UTC, datetime
from http.client import HTTPSConnection
from urllib.parse import urlsplit, urlunsplit
from typing import Any


class _PinnedHTTPSConnection(HTTPSConnection):
    """HTTPS connection that connects to a validated IP while preserving TLS SNI."""

    def __init__(
        self,
        host: str,
        port: int,
        pinned_ip: str,
        **kwargs: Any,
    ) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(host, port=port, **kwargs)

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(
            raw_socket,
            server_hostname=self.host,
        )


class HTTPWebhookDelivery:
    """Deliver signed webhooks only to explicitly allowlisted public HTTPS hosts."""

    ALLOWED_METHODS = {"POST", "PUT", "PATCH"}
    RESERVED_HEADERS = {
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-nexus-signature",
        "x-nexus-timestamp",
    }

    def __init__(
        self,
        hmac_secret: bytes | str | None = None,
        allowed_hosts: set[str] | None = None,
    ) -> None:
        configured_secret = hmac_secret or os.environ.get(
            "SHADOW313_WEBHOOK_HMAC_SECRET"
        )
        if isinstance(configured_secret, str):
            configured_secret = configured_secret.encode("utf-8")
        if configured_secret is not None and len(configured_secret) < 32:
            raise ValueError("Webhook HMAC secret must be at least 32 bytes")
        self._secret = configured_secret

        configured_hosts = allowed_hosts
        if configured_hosts is None:
            raw_hosts = os.environ.get("SHADOW313_WEBHOOK_ALLOWED_HOSTS", "")
            configured_hosts = {
                item.strip().lower()
                for item in raw_hosts.replace(";", ",").split(",")
                if item.strip()
            }
        self._allowed_hosts = {
            host.rstrip(".").encode("idna").decode("ascii").lower()
            for host in configured_hosts
        }

    def _validate_target(self, target: str) -> tuple[str, int, str, str]:
        parts = urlsplit(target)
        if parts.scheme.lower() != "https" or not parts.hostname:
            raise ValueError("Webhook targets must use HTTPS and include a hostname")
        if parts.username or parts.password or parts.fragment:
            raise ValueError(
                "Webhook target credentials and fragments are not permitted"
            )
        if parts.port not in (None, 443):
            raise ValueError("Webhook targets are restricted to TCP port 443")

        host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if host not in self._allowed_hosts:
            raise ValueError(
                "Webhook hostname is not in SHADOW313_WEBHOOK_ALLOWED_HOSTS"
            )

        try:
            literal_ip = ipaddress.ip_address(host)
            addresses = [literal_ip]
        except ValueError:
            try:
                records = socket.getaddrinfo(
                    host,
                    443,
                    type=socket.SOCK_STREAM,
                )
            except OSError as exc:
                raise ValueError(f"Webhook hostname resolution failed: {exc}") from exc
            addresses = sorted(
                {
                    ipaddress.ip_address(record[4][0])
                    for record in records
                },
                key=lambda address: (address.version, int(address)),
            )

        if not addresses:
            raise ValueError("Webhook hostname resolved to no addresses")
        if any(not address.is_global for address in addresses):
            raise ValueError("Webhook hostname resolves to a non-public IP address")

        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        return host, 443, str(addresses[0]), path

    def deliver(
        self,
        target: str,
        payload: dict,
        execution_id: str,
        method: str = "POST",
        headers: dict | None = None,
        timeout_ms: int = 5000,
    ) -> dict:
        if not self._secret:
            return {
                "status_code": 0,
                "success": False,
                "status": "not_configured",
                "error": "SHADOW313_WEBHOOK_HMAC_SECRET is not configured",
            }
        if not self._allowed_hosts:
            return {
                "status_code": 0,
                "success": False,
                "status": "not_configured",
                "error": "SHADOW313_WEBHOOK_ALLOWED_HOSTS is not configured",
            }

        method = method.upper()
        if method not in self.ALLOWED_METHODS:
            return {
                "status_code": 0,
                "success": False,
                "status": "rejected",
                "error": "Webhook method is not permitted",
            }

        try:
            host, port, pinned_ip, path = self._validate_target(target)
            payload_bytes = json.dumps(payload, default=str).encode("utf-8")
            payload_hash = hashlib.sha3_256(payload_bytes).hexdigest()
            signature = hmac.new(
                self._secret,
                payload_bytes,
                hashlib.sha256,
            ).hexdigest()

            request_headers = {
                "Content-Type": "application/json",
                "Connection": "close",
                "X-Nexus-Execution-Id": execution_id,
                "X-Nexus-Signature": f"sha256={signature}",
                "X-Nexus-Timestamp": datetime.now(UTC).isoformat(),
            }
            for name, value in (headers or {}).items():
                if name.lower() in self.RESERVED_HEADERS:
                    raise ValueError(f"Webhook header {name!r} is reserved")
                if not isinstance(value, str) or "\r" in value or "\n" in value:
                    raise ValueError(f"Webhook header {name!r} has an invalid value")
                request_headers[name] = value

            timeout = max(0.1, min(timeout_ms / 1000, 30.0))
            connection = _PinnedHTTPSConnection(
                host,
                port,
                pinned_ip,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
            try:
                connection.request(
                    method,
                    path,
                    body=payload_bytes,
                    headers=request_headers,
                )
                response = connection.getresponse()
                status_code = response.status
            finally:
                connection.close()

            success = 200 <= status_code < 300
            return {
                "status_code": status_code,
                "success": success,
                "status": "completed" if success else "failed",
                "payload_hash": payload_hash,
                "error": (
                    "Redirect responses are not followed"
                    if 300 <= status_code < 400
                    else None
                ),
            }
        except (OSError, ValueError, http.client.HTTPException, ssl.SSLError) as exc:
            return {
                "status_code": 0,
                "success": False,
                "status": "rejected" if isinstance(exc, ValueError) else "failed",
                "error": f"{type(exc).__name__}: {exc}",
            }
