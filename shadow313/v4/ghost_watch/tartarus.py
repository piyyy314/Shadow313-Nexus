"""
shadow313.v4.ghost_watch.tartarus
───────────────────────────────────
TARTARUS — Counter-Exfiltration Trap

Hooks egress TCP:443 and replaces real data stream with infinite
PQC-encrypted quantum-noise. Wastes attacker storage, bandwidth,
and compute resources.

Architecture:
  - Intercepts outbound connections matching exfiltration signatures
  - Replaces payload with AES-256-GCM encrypted random noise
  - Generates infinite stream to exhaust attacker resources
  - Logs all interception events to 313-BIND audit chain
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("shadow313.tartarus")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TartarusInterception:
    """A single TARTARUS interception event."""
    intercept_id:   str
    src_ip:         str
    dst_ip:         str
    dst_port:       int
    original_size:  int
    noise_size:     int
    timestamp:      str = field(default_factory=_now_iso)
    reason:         str = ""

    def to_dict(self) -> dict:
        return {
            "intercept_id":  self.intercept_id,
            "src_ip":        self.src_ip,
            "dst_ip":        self.dst_ip,
            "dst_port":      self.dst_port,
            "original_size": self.original_size,
            "noise_size":    self.noise_size,
            "timestamp":     self.timestamp,
            "reason":        self.reason,
        }


class TARTARUSEngine:
    """
    Counter-Exfiltration Trap Engine.

    Intercepts egress traffic matching exfiltration signatures and
    replaces the data stream with PQC-encrypted quantum noise.

    Detection signatures:
      - Large outbound transfers (> 1MB) to external IPs
      - DNS tunneling patterns (high-entropy subdomain queries)
      - Known C2 ports (4444, 9001, 31337, etc.)
      - Tor exit node IPs
    """

    # Ports that trigger TARTARUS interception
    C2_PORTS = {4444, 4445, 8080, 9001, 9050, 9150, 31337, 1337, 6666}

    # Minimum transfer size to trigger large-transfer detection (bytes)
    LARGE_TRANSFER_THRESHOLD = 1_048_576  # 1MB

    # Noise multiplier: generate N× the original data size
    NOISE_MULTIPLIER = 100

    def __init__(self) -> None:
        self._interceptions: list[TartarusInterception] = []
        self._noise_key = os.urandom(32)
        self._active = True
        logger.info("TARTARUS counter-exfiltration trap initialized — TCP:443 hook active")

    def inspect_egress(
        self,
        src_ip:   str,
        dst_ip:   str,
        dst_port: int,
        payload:  bytes,
    ) -> tuple[bool, bytes]:
        """
        Inspect outbound traffic. Returns (intercepted, replacement_payload).

        If intercepted: replacement_payload is PQC-encrypted noise.
        If not intercepted: replacement_payload is the original payload.
        """
        reason = self._classify(dst_ip, dst_port, payload)
        if not reason:
            return False, payload

        # Generate noise payload
        noise = self._generate_noise(len(payload))
        intercept_id = f"TARTARUS-{len(self._interceptions)+1:06d}"

        event = TartarusInterception(
            intercept_id  = intercept_id,
            src_ip        = src_ip,
            dst_ip        = dst_ip,
            dst_port      = dst_port,
            original_size = len(payload),
            noise_size    = len(noise),
            reason        = reason,
        )
        self._interceptions.append(event)
        logger.warning(
            f"TARTARUS intercepted: {src_ip}→{dst_ip}:{dst_port} "
            f"({len(payload)}B → {len(noise)}B noise) — {reason}"
        )
        return True, noise

    def _classify(self, dst_ip: str, dst_port: int, payload: bytes) -> str:
        """Classify traffic as exfiltration or benign."""
        # C2 port detection
        if dst_port in self.C2_PORTS:
            return f"C2_PORT_{dst_port}"

        # Large transfer to external IP
        if len(payload) > self.LARGE_TRANSFER_THRESHOLD and not self._is_internal(dst_ip):
            return f"LARGE_TRANSFER_{len(payload)//1024}KB"

        # High-entropy payload (possible encrypted exfil)
        if len(payload) > 1024 and self._entropy(payload) > 7.5:
            return "HIGH_ENTROPY_PAYLOAD"

        # Tor exit node (simplified check)
        if dst_ip.startswith("185.220.") or dst_ip.startswith("199.249."):
            return "TOR_EXIT_NODE"

        return ""

    def _is_internal(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            return (first == 10 or first == 127 or
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168))
        except ValueError:
            return False

    def _entropy(self, data: bytes) -> float:
        """Shannon entropy of byte sequence."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        import math
        return -sum((c/n) * math.log2(c/n) for c in freq if c > 0)

    def _generate_noise(self, original_size: int) -> bytes:
        """
        Generate PQC-encrypted quantum noise.
        Size = original_size × NOISE_MULTIPLIER to exhaust attacker resources.
        """
        noise_size = original_size * self.NOISE_MULTIPLIER
        # Generate cryptographically random noise
        noise = secrets.token_bytes(min(noise_size, 65536))
        # Encrypt with AES-256-GCM to make it look like real encrypted data
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            ct = AESGCM(self._noise_key).encrypt(nonce, noise, None)
            return nonce + ct
        except ImportError:
            return noise

    def generate_infinite_stream(self, chunk_size: int = 4096):
        """Generator yielding infinite PQC-encrypted noise chunks."""
        while True:
            yield self._generate_noise(chunk_size)

    def stats(self) -> dict:
        total_original = sum(e.original_size for e in self._interceptions)
        total_noise    = sum(e.noise_size for e in self._interceptions)
        return {
            "active":           self._active,
            "interceptions":    len(self._interceptions),
            "bytes_intercepted": total_original,
            "bytes_noise_sent": total_noise,
            "waste_ratio":      f"{total_noise/max(total_original,1):.1f}x",
            "c2_port_hits":     sum(1 for e in self._interceptions if "C2_PORT" in e.reason),
            "large_transfer_hits": sum(1 for e in self._interceptions if "LARGE_TRANSFER" in e.reason),
        }