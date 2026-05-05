from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ReleaseChannel = Literal["dev", "staging", "production"]
ReleasePolicyStatus = Literal["active", "draft", "deprecated"]
ReleaseRolloutStrategy = Literal["manual", "canary", "blue-green", "in-place"]


class ReleasePolicySummary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    policy_id: str = Field(min_length=3, max_length=64)
    version: str = Field(min_length=1, max_length=32)
    channel: ReleaseChannel
    status: ReleasePolicyStatus
    minimum_upgrade_from: str = Field(min_length=1, max_length=32)
    backup_required: bool
    migration_required: bool
    rollout_strategy: ReleaseRolloutStrategy


class ReleasePolicyDetail(ReleasePolicySummary):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    checksum: str = Field(min_length=64, max_length=64)
    compatibility_notes: list[str] = Field(default_factory=list)
    required_env: list[str] = Field(default_factory=list)
    preflight_checks: list[str] = Field(default_factory=list)
    upgrade_steps: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)


class ReleasePolicyListResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    items: list[ReleasePolicySummary] = Field(default_factory=list)
    count: int = Field(ge=0)


class ReleasePolicyResolveResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    policy: ReleasePolicyDetail
    resolved_channel: ReleaseChannel