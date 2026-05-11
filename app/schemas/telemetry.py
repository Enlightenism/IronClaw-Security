from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TelemetryEvent(BaseModel):
    timestamp: str
    event_type: str
    payload: dict = Field(default_factory=dict)


class TelemetryResponse(BaseModel):
    count: int
    items: list[TelemetryEvent] = Field(default_factory=list)


class TelemetryAccessCountsSchema(BaseModel):
    totalevents: int = 0
    allowedreads: int = 0
    flaggedreads: int = 0
    deniedreads: int = 0
    sensitiveexports: int = 0
    latesteventat: str = "Not yet recorded"


class TelemetryAccessControlsSchema(BaseModel):
    retentiontracked: bool = False
    actorattributionrequired: bool = False
    sessioncorrelationenabled: bool = False
    requestcorrelationenabled: bool = False
    redactionguardavailable: bool = False


class TelemetryAccessSummaryResponse(BaseModel):
    pageid: str
    title: str
    path: str
    summary: str
    generatedat: str
    accessavailable: bool = False
    auditvisibilityenabled: bool = False
    recenteventsready: bool = False
    exportcontrolled: bool = False
    counts: TelemetryAccessCountsSchema = Field(default_factory=TelemetryAccessCountsSchema)
    controls: TelemetryAccessControlsSchema = Field(default_factory=TelemetryAccessControlsSchema)
    recentevents: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)