#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from forward_quietward_events import QuietWardEventAdapter
from response_agent_v12 import AgentConfig, ResponseAgent, ResponseAgentError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the read-only QuietWard to QuietWard Response adapter."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--quietward-db", type=Path, required=True)
    parser.add_argument("--state-file", type=Path)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--max-backoff-seconds", type=float, default=60.0)
    parser.add_argument("--from-beginning", action="store_true")
    parser.add_argument("--once", action="store_true")
    return parser


def _adapter(args) -> QuietWardEventAdapter:
    config = AgentConfig.from_file(args.config.expanduser())
    agent = ResponseAgent(config)
    return QuietWardEventAdapter(
        agent=agent,
        database_path=args.quietward_db.expanduser(),
        state_path=args.state_file.expanduser() if args.state_file else None,
        batch_size=args.batch_size,
        from_beginning=args.from_beginning,
    )


def _cycle(args) -> int:
    # Agent config is intentionally reloaded on every cycle. A successful key
    # rotation atomically replaces the config, so the long-running adapter adopts
    # the promoted HMAC credential without a privileged restart mechanism.
    return _adapter(args).forward_once()


def main() -> int:
    args = _parser().parse_args()
    if args.interval_seconds < 1 or args.interval_seconds > 300:
        raise SystemExit("--interval-seconds must be between 1 and 300")
    if args.max_backoff_seconds < args.interval_seconds or args.max_backoff_seconds > 900:
        raise SystemExit("--max-backoff-seconds is invalid")

    if args.once:
        print(json.dumps({"events_forwarded": _cycle(args)}, sort_keys=True))
        return 0

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    backoff = float(args.interval_seconds)
    while not stop.is_set():
        try:
            forwarded = _cycle(args)
            if forwarded:
                print(json.dumps({"events_forwarded": forwarded}, sort_keys=True), flush=True)
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
