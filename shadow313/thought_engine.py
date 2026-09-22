"""
shadow313.thought_engine — v1 compatibility shim
Redirects to shadow313.v4.agent.orchestrator
"""
from shadow313.v4.agent.orchestrator import AgentOrchestrator as QuantumThoughtEngine
__all__ = ["QuantumThoughtEngine"]
