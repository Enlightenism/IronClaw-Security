from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from schemas.release_policy import ReleaseChannel


class ReleasePolicyDecision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    decision_id: str = Field(min_length=8, max_length=128)
    channel: ReleaseChannel
    allowed: bool
    requested_version: str = Field(min_length=1, max_length=64)
    minimum_upgrade_from: str = Field(min_length=1, max_length=64)
    decision_reason: str = Field(min_length=1, max_length=512)
    actor: str = Field(min_length=1, max_length=128)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)