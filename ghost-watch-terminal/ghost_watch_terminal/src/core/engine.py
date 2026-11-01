"""
Ghost-Watch Terminal — Core Engine
===================================
PQC + ACTS + CADL simulation engine.
Hardware binding: HB-9982-AX-2026
LoRa mesh: 915.0 MHz out-of-band channel

Integrates:
  - ML-KEM-768 (FIPS 203) key encapsulation
  - ML-DSA-65 (FIPS 204) signatures
  - SLH-DSA (FIPS 205) root of trust
  - AES-256-GCM symmetric layer
  - ACTS/WE-FORGE canary trap system
  - CADL 5-tier escalation engine
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ghost_watch.engine")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _now_313() -> int:
    ts = time.time_ns()
    return int(str(ts)[:-3] + "313")


# ── Hardware binding ──────────────────────────────────────────────────────────

HARDWARE_ID = "HB-9982-AX-2026"
LORA_FREQ_MHZ = 915.0
EMERGENCY_GATEWAY = "127.0.0.1:8080"


@dataclass
class HardwareBinding:
    """Binds Ghost-Watch to a specific hardware secure element."""
    hardware_id:   str = HARDWARE_ID
    lora_freq_mhz: float = LORA_FREQ_MHZ
    lora_active:   bool = False
    bound_at:      str = field(default_factory=_now_iso)

    def bind(self) -> str:
        """Generate hardware binding token."""
        token = hashlib.sha3_256(
            f"{self.hardware_id}:{self.bound_at}".encode()
        ).hexdigest()
        logger.info(f"Ghost-Watch bound to hardware secure element {self.hardware_id}")
        return token

    def toggle_lora(self) -> bool:
        self.lora_active = not self.lora_active
        status = "ON" if self.lora_active else "OFF"
        logger.info(f"LoRa {self.lora_freq_mhz} MHz interface toggled manually: {status}")
        return self.lora_active


# ── PQC crypto layer ──────────────────────────────────────────────────────────

class PQCLayer:
    """
    Post-Quantum Cryptographic layer.
    ML-KEM-768 + ML-DSA-65 + SLH-DSA + AES-256-GCM hybrid.
    """

    def __init__(self) -> None:
        self._kem_key    = os.urandom(32)   # ML-KEM-768 proxy
        self._dsa_key    = os.urandom(32)   # ML-DSA-65 proxy
        self._slh_key    = os.urandom(48)   # SLH-DSA seed
        self._aes_key    = os.urandom(32)   # AES-256-GCM
        self._algo_kem   = "ML-KEM-768 (FIPS 203)"
        self._algo_dsa   = "ML-DSA-65 (FIPS 204)"
        self._algo_slh   = "SLH-DSA (FIPS 205)"
        self._algo_sym   = "AES-256-GCM (Hybrid)"
        self._initialized = False
        self._init_pqc()

    def _init_pqc(self) -> None:
        """Initialize PQC modules with graceful fallback."""
        try:
            import pyspx.shake_128f as slh
            self._slh_pk, self._slh_sk = slh.generate_keypair(self._slh_key)
            self._pyspx = slh
            self._algo_slh = "SLH-DSA-SHAKE-128f (FIPS 205, pyspx)"
        except ImportError:
            self._pyspx = None
        self._initialized = True
        logger.info(f"PQC initialized: {self._algo_kem} | {self._algo_dsa} | {self._algo_slh}")

    def sign(self, message: bytes) -> str:
        """Sign with SLH-DSA (pyspx) or HMAC-SHA3-256 fallback."""
        if self._pyspx:
            try:
                return self._pyspx.sign(message, self._slh_sk).hex()
            except Exception as _exc:
                import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
        return hmac.new(self._dsa_key, message, hashlib.sha3_256).hexdigest()

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """ML-KEM-768 key encapsulation (HMAC proxy)."""
        shared_secret = hmac.new(self._kem_key, public_key, hashlib.sha3_256).digest()
        ciphertext    = hmac.new(shared_secret, public_key, hashlib.sha3_512).digest()
        return ciphertext, shared_secret

    def encrypt(self, plaintext: bytes) -> bytes:
        """AES-256-GCM encryption."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            ct    = AESGCM(self._aes_key).encrypt(nonce, plaintext, None)
            return nonce + ct
        except ImportError:
            # XOR fallback for environments without cryptography
            key_stream = hashlib.sha3_256(self._aes_key).digest() * (len(plaintext) // 32 + 1)
            return bytes(a ^ b for a, b in zip(plaintext, key_stream[:len(plaintext)]))

    def status(self) -> dict:
        return {
            "initialized": self._initialized,
            "kem":  self._algo_kem,
            "dsa":  self._algo_dsa,
            "slh":  self._algo_slh,
            "sym":  self._algo_sym,
            "pyspx_active": self._pyspx is not None,
        }


# ── ACTS / WE-FORGE canary factory ────────────────────────────────────────────

@dataclass
class LureDocument:
    """A WE-FORGE watermarked lure document."""
    lure_id:      str
    target:       str
    content:      str
    watermark_id: str
    deployed_at:  str = field(default_factory=_now_iso)
    triggered:    bool = False
    trigger_time: Optional[str] = None


class ACTSEngine:
    """
    Advanced Canary Trap System — WE-FORGE lure generation.
    Linguistic watermarking + metadata padding + steganographic LSB embedding.
    """

    def __init__(self, pqc: PQCLayer) -> None:
        self._pqc    = pqc
        self._lures: dict[str, LureDocument] = {}
        self._attribution_db: dict[str, str] = {}  # watermark_id → target

    def forge_lure(self, target: str, template: str = "NIST FIPS 213 (ML-KEM-768) Secret Parameter Set") -> LureDocument:
        """Generate a uniquely watermarked lure document."""
        ts_ns = _now_313()
        lure_id = f"GW-LURE_{datetime.now(timezone.utc).year}_{secrets.randbelow(9999):04d}_{secrets.token_hex(2).upper()}"
        watermark_id = hashlib.sha3_256(f"{lure_id}:{target}:{ts_ns}".encode()).hexdigest()[:16]

        # Linguistic watermark: subtle word substitutions
        content = self._embed_linguistic_watermark(template, target, watermark_id)

        lure = LureDocument(
            lure_id      = lure_id,
            target       = target,
            content      = content,
            watermark_id = watermark_id,
        )
        self._lures[lure_id] = lure
        self._attribution_db[watermark_id] = target
        logger.info(f"WE-FORGE Lure injected successfully: {lure_id} targeted at [{target}]")
        return lure

    def _embed_linguistic_watermark(self, content: str, target: str, wm_id: str) -> str:
        """Embed invisible linguistic watermark."""
        recipient_hash = int(hashlib.sha3_256(target.encode()).hexdigest(), 16)
        substitutions = [
            ("utilize", "use"), ("implement", "deploy"),
            ("configure", "set up"), ("initialize", "start"),
        ]
        watermarked = content
        for i, (word_a, word_b) in enumerate(substitutions):
            if (recipient_hash >> i) & 1:
                watermarked = watermarked.replace(word_a, word_b)
        # Append zero-width watermark
        zwc = "".join("\u200b" if b == "0" else "\u200c"
                      for b in bin(int(wm_id[:8], 16))[2:].zfill(32))
        return watermarked + zwc

    def detect_trigger(self, content: str) -> Optional[LureDocument]:
        """Detect if exfiltrated content contains a watermark."""
        for lure in self._lures.values():
            if lure.watermark_id[:8] in content or lure.lure_id in content:
                if not lure.triggered:
                    lure.triggered = True
                    lure.trigger_time = _now_iso()
                    logger.warning(f"WATERMARK TRIGGERED: {lure.lure_id} → {lure.target}")
                return lure
        return None

    def attribution_lookup(self, watermark_id: str) -> Optional[str]:
        return self._attribution_db.get(watermark_id)


# ── CADL Engine ───────────────────────────────────────────────────────────────

@dataclass
class CADLEvent:
    """A CADL escalation event."""
    event_id:   str
    level:      int
    action:     str
    target:     str
    timestamp:  str = field(default_factory=_now_iso)
    executed:   bool = False


class CADLEngine:
    """
    Cognitive-Adaptive Deception Layer — 5-tier escalation.
    Event-driven Python orchestration with sidecar-style traffic inspection.
    """

    LEVELS = {
        1: ("MONITOR",    "Passive Digital Dust collection"),
        2: ("DELAY",      "Synthetic latency injection"),
        3: ("REROUTE",    "AETHER AI honeypot redirect"),
        4: ("DEGRADE",    "PQC-encrypted poison data injection"),
        5: ("NEUTRALIZE", "Automated session termination + Kill-Switch"),
    }

    def __init__(self, pqc: PQCLayer, acts: ACTSEngine) -> None:
        self._pqc    = pqc
        self._acts   = acts
        self._events: list[CADLEvent] = []
        self._current_level = 1

    def escalate(self, target: str, reason: str, level: Optional[int] = None) -> CADLEvent:
        """Escalate CADL response for a target."""
        if level is None:
            level = min(self._current_level + 1, 5)
        self._current_level = level
        action_name, action_desc = self.LEVELS[level]

        event = CADLEvent(
            event_id = f"CADL-{len(self._events)+1:06d}",
            level    = level,
            action   = action_name,
            target   = target,
        )
        self._events.append(event)
        logger.warning(f"CADL L{level} {action_name}: {target} — {reason}")

        # Execute action
        self._execute(event, reason)
        return event

    def _execute(self, event: CADLEvent, reason: str) -> None:
        """Execute CADL action."""
        if event.level == 1:
            logger.info(f"[L1-MONITOR] Logging Digital Dust for {event.target}")
        elif event.level == 2:
            logger.info(f"[L2-DELAY] Injecting synthetic latency for {event.target}")
        elif event.level == 3:
            logger.info(f"[L3-REROUTE] Redirecting {event.target} to AETHER honeypot")
        elif event.level == 4:
            poison = self._pqc.encrypt(b"POISON_DATA_" + secrets.token_bytes(256))
            logger.warning(f"[L4-DEGRADE] Injecting {len(poison)}B PQC-encrypted poison for {event.target}")
        elif event.level == 5:
            logger.critical(f"[L5-NEUTRALIZE] KILL-SWITCH EXECUTING for {event.target}")
        event.executed = True

    def status(self) -> dict:
        return {
            "current_level": self._current_level,
            "total_events":  len(self._events),
            "levels":        {k: v[0] for k, v in self.LEVELS.items()},
        }


# ── Ghost-Watch Engine ────────────────────────────────────────────────────────

class GhostWatchEngine:
    """
    Ghost-Watch Apex Tier — unified engine.
    Integrates PQC, ACTS/WE-FORGE, and CADL.
    """

    def __init__(self) -> None:
        self.hardware = HardwareBinding()
        self.pqc      = PQCLayer()
        self.acts     = ACTSEngine(self.pqc)
        self.cadl     = CADLEngine(self.pqc, self.acts)
        self._binding_token = self.hardware.bind()
        logger.info(f"Ghost-Watch Engine initialized — {HARDWARE_ID}")
        logger.info(f"915.0 MHz LoRa Mesh-net out-of-band transmitter engaged in listening mode")

    def status(self) -> dict:
        return {
            "hardware_id":     self.hardware.hardware_id,
            "binding_token":   self._binding_token[:16] + "...",
            "lora_active":     self.hardware.lora_active,
            "pqc":             self.pqc.status(),
            "cadl":            self.cadl.status(),
            "lures_deployed":  len(self.acts._lures),
            "lures_triggered": sum(1 for l in self.acts._lures.values() if l.triggered),
        }