#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from response_agent_v12 import AgentConfig, ResponseAgent, ResponseAgentError
from response_agent_capabilities import sync_capabilities


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the capability-aware QuietWard Response v1.2 agent."
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Private Response-agent JSON configuration.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Sync capabilities and poll once, then exit. Normal operation is continuous.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=5.0,
        help="Successful poll interval. Default: 5 seconds.",
    )
    parser.add_argument(
        "--max-backoff-seconds",
        type=float,
        default=60.0,
        help="Maximum retry backoff after API/network errors. Default: 60 seconds.",
    )
    return parser


def _cycle(agent: ResponseAgent) -> dict[str, object]:
    capability_state = sync_capabilities(agent)
    completed = agent.poll_once()
    return {
        "capabilities_updated": True,
        "enabled_actions": capability_state.get("enabled_actions", []),
        "actions_completed": completed,
    }


def main() -> int:
    args = _parser().parse_args()
    if args.interval_seconds < 1 or args.interval_seconds > 300:
        raise SystemExit("--interval-seconds must be between 1 and 300")
    if args.max_backoff_seconds < args.interval_seconds or args.max_backoff_seconds > 900:
        raise SystemExit(
            "--max-backoff-seconds must be at least the poll interval and no more than 900"
        )

    config = AgentConfig.from_file(args.config.expanduser())
    agent = ResponseAgent(config)

    if args.once:
        print(json.dumps(_cycle(agent), sort_keys=True))
        return 0

    stop = threading.Event()

    def request_stop(*_args) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    backoff = float(args.interval_seconds)
    while not stop.is_set():
        try:
            state = _cycle(agent)
            if int(state.get("actions_completed") or 0) > 0:
                print(json.dumps(state, sort_keys=True), flush=True)
            backoff = float(args.interval_seconds)
            stop.wait(float(args.interval_seconds))
        except ResponseAgentError as exc:
            detail = " ".join(str(exc).replace("\x00", "").split())[:1000]
            print(
                json.dumps(
                    {
                        "status": "degraded",
                        "error": detail,
                        "retry_in_seconds": backoff,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
            stop.wait(backoff)
            backoff = min(float(args.max_backoff_seconds), max(backoff * 2, args.interval_seconds))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
