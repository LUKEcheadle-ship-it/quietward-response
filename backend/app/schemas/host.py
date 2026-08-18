from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HostResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    host_id: str
    hostname: str
    operating_system: str | None
    agent: str
    agent_version: str | None
    first_seen: datetime
    last_seen: datetime
    status: str
