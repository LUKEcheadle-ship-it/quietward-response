#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll a QuietWard agent with QuietWard Response")
    parser.add_argument("--api-url", default="http://127.0.0.1:8002")
    parser.add_argument("--token", required=True, help="QWR_ENROLLMENT_TOKEN value")
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--display-name")
    parser.add_argument("--agent-version", default="0.4.0a2")
    args = parser.parse_args()

    payload = json.dumps(
        {
            "host_id": args.host_id,
            "display_name": args.display_name or f"QuietWard on {args.host_id}",
            "agent_version": args.agent_version,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        args.api_url.rstrip("/") + "/api/v1/agents/enroll",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-QWR-Enrollment-Token": args.token,
        },
    )
    try:
        with urlopen(request, timeout=10) as response:
            enrolled = json.loads(response.read())
    except HTTPError as exc:
        print(exc.read().decode("utf-8", errors="replace"))
        return 1
    except (URLError, OSError) as exc:
        print(f"Enrollment failed: {exc}")
        return 1

    print("Enrollment succeeded. Store the returned secret securely; it is shown only now.\n")
    print("Set these environment variables on the QuietWard endpoint:")
    print("QUIETWARD_RESPONSE_ENABLED=true")
    print(f"QUIETWARD_RESPONSE_URL={args.api_url.rstrip('/')}")
    print(f"QUIETWARD_RESPONSE_AGENT_ID={enrolled['agent_id']}")
    print(f"QUIETWARD_RESPONSE_KEY_ID={enrolled['key_id']}")
    print(f"QUIETWARD_RESPONSE_SECRET={enrolled['secret']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
