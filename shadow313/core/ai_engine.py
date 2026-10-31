"""Compatibility shim; the implementation lives in ai_engine/__init__.py.

Python imports the package for shadow313.core.ai_engine. Direct file loaders
receive the same implementation rather than a second divergent backend.
"""
from shadow313.core.ai_engine import AIEngine

__all__ = ["AIEngine"]
