from __future__ import annotations

from typing import Any

from app.integrations.base import EventIntegration
from app.schemas.event import EventCreate


class QuietWardV1Integration(EventIntegration):
    protocol_version = "1.0"

    def parse(self, payload: dict[str, Any]) -> EventCreate:
        return EventCreate.model_validate(payload)
