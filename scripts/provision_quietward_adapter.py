#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from quietward_adapter_credentials import AdapterCredentialError, provision_from_agent_config


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Derive a private event-ingestion-only QuietWard adapter credential from "
            "the current Response endpoint credential. The endpoint secret is not copied."
        )
    )
    parser.add_argument("--agent-config", type=Path, required=True)
    parser.add_argument(
        "--adapter-config",
        type=Path,
        default=Path("~/.config/quietward-response/adapter.json"),
    )
    parser.add_argument("--force", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        output = provision_from_agent_config(
            args.agent_config.expanduser(),
            args.adapter_config.expanduser(),
            force=args.force,
        )
    except AdapterCredentialError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"QuietWard adapter event-only credential written: {output}")
    print("The endpoint action credential was not copied into adapter.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
