from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReleasePolicyDecisionLatestView(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    title: str = Field(default="Latest Release Policy Decision", min_length=1, max_length=128)
    channel: str = Field(min_length=1, max_length=32)
    decision_id: str = Field(min_length=8, max_length=128)
    allowed: bool
    requested_version: str = Field(min_length=1, max_length=64)
    minimum_upgrade_from: str = Field(min_length=1, max_length=64)
    decision_reason: str = Field(min_length=1, max_length=512)
    actor: str = Field(min_length=1, max_length=128)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status_label: str = Field(min_length=1, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)