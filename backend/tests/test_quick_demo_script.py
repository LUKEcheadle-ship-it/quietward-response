from __future__ import annotations

import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "quick_demo.py"
SPEC = importlib.util.spec_from_file_location("qwr_quick_demo", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


def test_quick_demo_enables_only_existing_synthetic_seed_flag(monkeypatch) -> None:
    monkeypatch.delenv("QWR_SEED_DEMO", raising=False)
    DEMO.prepare_demo_environment()
    assert os.environ["QWR_SEED_DEMO"] == "true"
