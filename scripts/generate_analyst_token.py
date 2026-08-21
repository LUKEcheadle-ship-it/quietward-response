#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import secrets


ROLES = ("viewer", "responder", "admin")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a one-time QuietWard Response analyst bearer token and its SHA-256 credential entry."
    )
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--role", choices=ROLES, required=True)
    args = parser.parse_args()

    actor_id = args.actor_id.strip()
    if not actor_id or len(actor_id) > 128 or "|" in actor_id:
        raise SystemExit("--actor-id must be 1-128 characters and cannot contain '|'")

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    entry = f"{actor_id}|{args.role}|{digest}"

    print("Analyst bearer token (shown once):")
    print(token)
    print("\nHashed QWR_ANALYST_CREDENTIALS entry:")
    print(entry)
    print("\nStore the bearer token in a secret manager. Response stores/configures only the SHA-256 hash entry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
