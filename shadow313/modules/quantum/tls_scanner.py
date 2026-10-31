"""shadow313.modules.quantum.tls_scanner — TLS endpoint quantum vulnerability scanner."""
from __future__ import annotations
import re
import socket
import ssl
from typing import Any

from .quantum_data import QUANTUM_VULN_TABLE, TLS_CIPHER_PATTERNS, classify_algorithm


class TLSScanner:
    def __init__(self, host: str, port: int = 443, timeout: int = 10) -> None:
        """Select a TLS endpoint and connection timeout in seconds."""
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def scan(self) -> dict:
        """Connect to the endpoint and return TLS, certificate, and cipher findings.

        Disable hostname checks while retaining certificate-chain verification.
        Connection, TLS, and analysis errors are captured in the result's error field.
        """
        result: dict[str, Any] = {
            "host": self.host, "port": self.port,
            "tls_version": "", "cipher_suite": "", "cert_info": {}, "findings": [],
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_OPTIONAL
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    result["tls_version"]    = ssock.version() or ""
                    cipher                   = ssock.cipher()
                    if cipher:
                        result["cipher_suite"]    = cipher[0]
                        result["cipher_protocol"] = cipher[1]
                        result["cipher_bits"]     = cipher[2]
                    cert = ssock.getpeercert()
                    result["cert_info"] = self._parse_cert(cert)
                    result["findings"]  = self._analyse_cipher(
                        result["cipher_suite"], result["tls_version"]
                    )
        except ssl.SSLError as exc:
            result["error"] = f"SSL error: {exc}"
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            result["error"] = f"Connection error: {exc}"
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def _parse_cert(self, cert: dict | None) -> dict:
        """Summarize peer certificate names, expiry, and up to ten SAN entries.

        Return {} for an absent certificate. days_left is whole days until
        expiry, or -1 when the expiry cannot be parsed.
        """
        if not cert:
            return {}
        subject  = dict(x[0] for x in cert.get("subject", []))
        issuer   = dict(x[0] for x in cert.get("issuer", []))
        san      = [v for _, v in cert.get("subjectAltName", [])]
        not_after = cert.get("notAfter", "")
        days_left = -1
        try:
            from datetime import datetime as dt
            expires   = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expires - dt.utcnow()).days
        except Exception:
            pass
        return {
            "subject":   subject.get("commonName", ""),
            "issuer":    issuer.get("organizationName", ""),
            "san":       san[:10],
            "not_after": not_after,
            "days_left": days_left,
        }

    def _analyse_cipher(self, cipher: str, tls_ver: str) -> list[dict]:
        """Return findings for deprecated TLS versions and cipher patterns not classified SAFE."""
        findings = []
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append({
                "type": "DEPRECATED_TLS", "severity": "CRITICAL",
                "detail": f"TLS version {tls_ver} is deprecated",
                "quantum": "VULNERABLE", "replace": "TLS 1.3",
            })
        for pattern, description in TLS_CIPHER_PATTERNS.items():
            if re.search(pattern, cipher, re.IGNORECASE):
                info = classify_algorithm(description)
                if info["vuln"] != "SAFE":
                    findings.append({
                        "type":     "CIPHER_SUITE",
                        "severity": "HIGH" if info["vuln"] == "VULNERABLE" else "MEDIUM",
                        "detail":   f"Cipher uses {description} — {info['reason']}",
                        "quantum":  info["vuln"],
                        "replace":  info.get("replace", ""),
                        "cipher":   cipher,
                    })
        return findings