from pydantic import BaseModel, Field


class TelemetryEvent(BaseModel):
    timestamp: str
    event_type: str
    payload: dict = Field(default_factory=dict)


class TelemetryResponse(BaseModel):
    count: int
    items: list[TelemetryEvent] = Field(default_factory=list)
