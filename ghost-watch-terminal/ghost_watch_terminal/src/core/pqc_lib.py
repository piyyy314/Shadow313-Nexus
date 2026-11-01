"""
Ghost-Watch Terminal — PQC Library
====================================
Unified post-quantum cryptography interface.
FIPS 203 (ML-KEM-768) + FIPS 204 (ML-DSA-65) + FIPS 205 (SLH-DSA) + AES-256-GCM hybrid.
"""
from __future__ import annotations
import hashlib, hmac, os
from .engine import PQCLayer

# Re-export for convenience
__all__ = ["PQCLayer", "pqc_sign", "pqc_verify", "pqc_encrypt", "pqc_decrypt"]

_default_layer = None

def get_default() -> PQCLayer:
    global _default_layer
    if _default_layer is None:
        _default_layer = PQCLayer()
    return _default_layer

def pqc_sign(message: bytes) -> str:
    return get_default().sign(message)

def pqc_encrypt(plaintext: bytes) -> bytes:
    return get_default().encrypt(plaintext)