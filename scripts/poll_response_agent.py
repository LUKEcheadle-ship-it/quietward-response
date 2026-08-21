#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from response_agent import AgentConfig, ResponseAgent
from response_agent_capabilities import sync_capabilities


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sync signed Response-agent capabilities, then poll once for approved actions."
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Private Response-agent JSON configuration.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    config = AgentConfig.from_file(args.config.expanduser())
    agent = ResponseAgent(config)
    capability_state = sync_capabilities(agent)
    completed = agent.poll_once()
    print(
        json.dumps(
            {
                "capabilities_updated": True,
                "enabled_actions": capability_state.get("enabled_actions", []),
                "actions_completed": completed,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
