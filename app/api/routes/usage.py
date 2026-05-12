from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.auth import require_api_key

router = APIRouter(
    prefix="/usage",
    tags=["usage"],
    dependencies=[Depends(require_api_key)],
)


class UsageSample(BaseModel):
    timestamp: str
    units_consumed: int
    source: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageSummaryView(BaseModel):
    owner_key: str
    total_units_consumed: int
    window_start: str
    window_end: str
    samples: list[UsageSample] = Field(default_factory=list)


class UsageSummaryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    summary: UsageSummaryView


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


# In-memory usage registry for API-key scoped metering.
# This is intentionally simple for Gen1; persistence can be added behind the same interface later.
class UsageRegistry:
    def __init__(self) -> None:
        self._by_owner: dict[str, list[UsageSample]] = {}

    def record_usage(
        self,
        owner_key: str,
        units_consumed: int,
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        normalized_owner = owner_key.strip().lower()
        sample = UsageSample(
            timestamp=_utc_now_iso(),
            units_consumed=max(0, int(units_consumed)),
            source=source,
            metadata=metadata or {},
        )
        self._by_owner.setdefault(normalized_owner, []).append(sample)

    def summarize_owner(
        self,
        owner_key: str,
    ) -> UsageSummaryView:
        normalized_owner = owner_key.strip().lower()
        samples = self._by_owner.get(normalized_owner, [])

        if not samples:
            now = _utc_now_iso()
            return UsageSummaryView(
                owner_key=normalized_owner,
                total_units_consumed=0,
                window_start=now,
                window_end=now,
                samples=[],
            )

        total = sum(s.units_consumed for s in samples)
        window_start = samples[0].timestamp
        window_end = samples[-1].timestamp

        return UsageSummaryView(
            owner_key=normalized_owner,
            total_units_consumed=total,
            window_start=window_start,
            window_end=window_end,
            samples=samples[-250:],  # cap for response size
        )


_usage_registry = UsageRegistry()


def get_usage_registry() -> UsageRegistry:
    return _usage_registry


@router.get(
    "/owner/{owner_key}",
    response_model=UsageSummaryResponse,
)
def get_owner_usage(owner_key: str) -> UsageSummaryResponse:
    """
    Return a metered view of IronClaw-Security protection usage for this owner key.

    In Gen1 this is backed by an in-memory registry. In a production deployment
    the same shape can be hydrated from logs or a billing database.
    """
    summary = _usage_registry.summarize_owner(owner_key=owner_key)

    return UsageSummaryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summary=summary,
    )