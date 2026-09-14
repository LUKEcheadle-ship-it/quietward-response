"""Print a hash-only analyst setting; never print or write the credential."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="Analyst name (letters, digits, dot, dash, underscore)")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", args.name):
        parser.error("name must contain 1–64 letters, digits, dots, dashes or underscores")
    token = getpass.getpass("Paste a password-manager-generated random credential (32–512 characters): ")
    if not 32 <= len(token) <= 512:
        parser.error("credential must contain 32–512 characters")
    if token != getpass.getpass("Repeat credential: "):
        parser.error("credentials do not match")
    print("QWR_ANALYST_TOKEN_HASHES=" + json.dumps({args.name: hashlib.sha256(token.encode()).hexdigest()}))


if __name__ == "__main__":
    main()
