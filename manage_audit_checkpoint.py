"""Compatibility import for Response audit-checkpoint tooling.

The executable implementation lives in scripts/manage_audit_checkpoint.py. Keeping
this thin shim lets both `python scripts/...` execution and package-style test imports
resolve the same implementation without duplicating logic.
"""

from scripts.manage_audit_checkpoint import *  # noqa: F401,F403
