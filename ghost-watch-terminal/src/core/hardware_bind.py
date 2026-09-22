"""
Ghost-Watch Terminal — Hardware Binding
=========================================
Binds Ghost-Watch to hardware secure element HB-9982-AX-2026.
Provides TPM-style attestation and LoRa mesh control.
"""
from __future__ import annotations
from .engine import HardwareBinding, HARDWARE_ID, LORA_FREQ_MHZ

__all__ = ["HardwareBinding", "HARDWARE_ID", "LORA_FREQ_MHZ", "get_binding"]

_binding = None

def get_binding() -> HardwareBinding:
    global _binding
    if _binding is None:
        _binding = HardwareBinding()
        _binding.bind()
    return _binding