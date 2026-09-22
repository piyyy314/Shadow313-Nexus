"""
shadow313.quantum_middleware — v1 compatibility shim
Redirects to shadow313.v4.quantum_nexus.quantum_nexus
"""
from shadow313.v4.quantum_nexus.quantum_nexus import (
    QuantumNEXUSModule as QuantumMiddleware,
    QKDMonitor,
    HNDLAnalyzer,
)
__all__ = ["QuantumMiddleware", "QKDMonitor", "HNDLAnalyzer"]
