from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.schemas.event import EventCreate


class EventIntegration(ABC):
    """Trust-boundary adapter for a versioned external event source."""

    @abstractmethod
    def parse(self, payload: dict[str, Any]) -> EventCreate:
        raise NotImplementedError
