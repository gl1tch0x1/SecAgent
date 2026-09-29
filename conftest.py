from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for candidate in (ROOT, ROOT / "python-agents"):
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
