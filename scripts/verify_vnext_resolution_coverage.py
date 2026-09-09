#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.resolution_coverage import public_resolution_coverage, unresolved_categories


def main() -> int:
    unresolved = unresolved_categories()
    coverage = public_resolution_coverage()
    print("QuietWard -> Response resolution coverage")
    for item in coverage:
        status = "READY" if item["release_ready"] else "BLOCKED"
        print(
            f"- {item['category']}: {status} | {item['resolution_mode']} | "
            f"{item['primary_outcome']}"
        )
    if unresolved:
        print("\nGUIDED INCIDENT RESPONSE VNEXT RELEASE GATE: BLOCKED")
        print("Unresolved QuietWard categories: " + ", ".join(unresolved))
        print(
            "The combined QuietWard + Response update must remain draft/unreleased until "
            "every category has a tested resolution path."
        )
        return 1
    print("\nGUIDED INCIDENT RESPONSE VNEXT RELEASE GATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
