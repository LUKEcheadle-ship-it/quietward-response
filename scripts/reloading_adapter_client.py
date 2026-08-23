from __future__ import annotations

from pathlib import Path
from typing import Any

from quietward_adapter_credentials import AdapterCredential, EventOnlyClient


class ReloadingEventOnlyClient:
    """Reload adapter.json before each event request.

    This keeps a long-running bridge synchronized with endpoint-key rotation without
    granting it access to agent.json or requiring platform-specific service restarts.
    """

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path.expanduser()
        self.config = AdapterCredential.from_file(self.config_path)

    def _request(self, method: str, target: str, payload: dict[str, Any]) -> Any:
        refreshed = AdapterCredential.from_file(self.config_path)
        self.config = refreshed
        return EventOnlyClient(refreshed)._request(method, target, payload)
