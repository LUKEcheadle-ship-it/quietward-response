#!/usr/bin/env python3
"""Stable root launcher for the Response sensitive-persistence audit."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
for value in (str(BACKEND), str(ROOT)):
    if value not in sys.path:
        sys.path.insert(0, value)

from scripts.audit_sensitive_persistence import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
