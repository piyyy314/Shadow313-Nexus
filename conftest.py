"""
Root conftest.py — ensures all local packages are importable in CI.
Adds workspace root to sys.path so shadow313_platform, nexus_toolkit, etc.
are always discoverable without needing a separate pip install.
"""
import sys
import os

# Add workspace root to path (handles CI environments where local packages
# like shadow313_platform and nexus_toolkit aren't installed as editable packages)
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
