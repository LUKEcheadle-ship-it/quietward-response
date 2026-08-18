from typing import Any

from app.integrations.base import EventAdapter


class QuietWardV1Adapter(EventAdapter):
    """Identity adapter for agents that already emit protocol v1."""

    def normalize(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {**payload, "source": payload.get("source", "quietward"), "schema_version": "1.0"}
