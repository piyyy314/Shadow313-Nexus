"""shadow313.modules.recon.whois_lookup — WHOIS lookup with python-whois + raw fallback."""
from __future__ import annotations
import socket


class WHOISLookup:
    WHOIS_SERVER = ("whois.iana.org", 43)

    def __init__(self, target: str) -> None:
        """Select a target for WHOIS lookup."""
        self.target = target

    def lookup(self) -> dict:
        """Return parsed WHOIS data, using a raw IANA query if python-whois is unavailable.

        Lookup failures return an error mapping.
        """
        try:
            import whois as python_whois
            w = python_whois.whois(self.target)
            return {
                "domain":       self.target,
                "registrar":    str(w.registrar or ""),
                "created":      str(w.creation_date or ""),
                "expires":      str(w.expiration_date or ""),
                "updated":      str(w.updated_date or ""),
                "name_servers": w.name_servers or [],
                "status":       w.status or [],
                "emails":       w.emails or [],
                "org":          str(w.org or ""),
            }
        except ImportError:
            return self._raw_whois()
        except Exception as exc:
            return {"domain": self.target, "error": str(exc)}

    def _raw_whois(self) -> dict:
        """Return up to 3,000 characters from an IANA WHOIS response, or an error mapping."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(self.WHOIS_SERVER)
                s.send(f"{self.target}\r\n".encode())
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            return {"domain": self.target, "raw": raw.decode("utf-8", errors="replace")[:3000]}
        except Exception as exc:
            return {"domain": self.target, "error": str(exc)}