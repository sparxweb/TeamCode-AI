"""
conftest.py — pytest configuration for the backend package.

This file is auto-discovered by pytest. It inserts `backend/` into sys.path
so that `import app.*` works without any manual sys.path hacks in test files.
"""
import sys
from pathlib import Path

# Ensure the backend package root is on sys.path so `app.*` resolves correctly
backend_root = Path(__file__).resolve().parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))
