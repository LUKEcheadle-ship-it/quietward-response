from datetime import datetime

from pydantic import BaseModel


class HostRead(BaseModel):
    host_id: str
    hostname: str
    operating_system: str | None
    agent: str
    agent_version: str | None
    first_seen: datetime
    last_seen: datetime
    status: str
    event_count: int = 0
    incident_count: int = 0
