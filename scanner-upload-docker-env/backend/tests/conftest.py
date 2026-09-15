"""Makes `backend/` importable as a plain module root (e.g. `import
scanners.utils`, `from ai_analysis import ...`) regardless of the directory
pytest is invoked from. The app's modules use flat imports that assume
backend/ itself is on sys.path (see scanner.py's `from ai_analysis import
...`), so tests need the same thing without relying on cwd."""
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
