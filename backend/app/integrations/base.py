from abc import ABC, abstractmethod
from typing import Any


class EventAdapter(ABC):
    @abstractmethod
    def normalize(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Convert a source payload into the current event envelope."""
