#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import bootstrap_local


def prepare_demo_environment() -> None:
    """Enable only the existing synthetic demo seed path."""
    os.environ["QWR_SEED_DEMO"] = "true"


def main() -> int:
    prepare_demo_environment()
    print("QuietWard Response quick demo")
    print("============================= ")
    print("Starting the normal local bootstrap and adding only synthetic demo investigation data.")
    print("No destructive endpoint action is enabled by this helper.\n")
    return bootstrap_local.main()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Demo startup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
