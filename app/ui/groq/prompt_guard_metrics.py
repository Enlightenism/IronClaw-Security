from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_allowlist import _ALLOWLIST
from app.ui.groq.prompt_guard_audit_trail import _AUDIT_TRAIL
from app.ui.groq.prompt_guard_review_queue import _REVIEW_QUEUE


router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-metrics"],
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class PromptGuardKpi:
    name: str
    value: int
    delta: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "delta": self.delta,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardMetricsView:
    title: str
    generated_at: str
    kpis: list[PromptGuardKpi]
    breakdowns: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "kpis": [kpi.to_dict() for kpi in self.kpis],
            "breakdowns": dict(self.breakdowns),
            "metadata": dict(self.metadata),
        }


class PromptGuardKpiView(BaseModel):
    name: str
    value: int
    delta: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardMetricsResponse(BaseModel):
    title: str
    generated_at: str
    kpis: list[PromptGuardKpiView]
    breakdowns: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _count_review_statuses() -> dict[str, int]:
    breakdown = {
        "pending": 0,
        "approved": 0,
        "rejected": 0,
    }
    for item in _REVIEW_QUEUE:
        breakdown[item.status] = breakdown.get(item.status, 0) + 1
    return breakdown


def _count_allowlist_statuses() -> dict[str, int]:
    breakdown = {
        "active": 0,
        "disabled": 0,
    }
    for entry in _ALLOWLIST:
        breakdown[entry.status] = breakdown.get(entry.status, 0) + 1
    return breakdown


def _count_audit_event_types() -> dict[str, int]:
    breakdown: dict[str, int] = {}
    for event in _AUDIT_TRAIL:
        breakdown[event.event_type] = breakdown.get(event.event_type, 0) + 1
    return breakdown


def build_prompt_guard_metrics_view() -> PromptGuardMetricsView:
    review_statuses = _count_review_statuses()
    allowlist_statuses = _count_allowlist_statuses()
    audit_event_types = _count_audit_event_types()

    total_reviews = len(_REVIEW_QUEUE)
    total_allowlist_entries = len(_ALLOWLIST)
    total_audit_events = len(_AUDIT_TRAIL)

    pending_reviews = review_statuses.get("pending", 0)
    active_allowlist_entries = allowlist_statuses.get("active", 0)
    simulation_events = audit_event_types.get("simulation", 0)

    kpis = [
        PromptGuardKpi(
            name="total_reviews",
            value=total_reviews,
            delta=pending_reviews,
            metadata={"delta_label": "pending"},
        ),
        PromptGuardKpi(
            name="total_allowlist_entries",
            value=total_allowlist_entries,
            delta=active_allowlist_entries,
            metadata={"delta_label": "active"},
        ),
        PromptGuardKpi(
            name="total_audit_events",
            value=total_audit_events,
            delta=simulation_events,
            metadata={"delta_label": "simulation"},
        ),
    ]

    return PromptGuardMetricsView(
        title="Groq Prompt Guard Metrics",
        generated_at=_utc_now(),
        kpis=kpis,
        breakdowns={
            "review_statuses": review_statuses,
            "allowlist_statuses": allowlist_statuses,
            "audit_event_types": audit_event_types,
        },
        metadata={
            "source_modules": [
                "prompt_guard_review_queue",
                "prompt_guard_allowlist",
                "prompt_guard_audit_trail",
            ],
        },
    )


@router.get("/prompt-guard/metrics", response_model=PromptGuardMetricsResponse)
def get_prompt_guard_metrics() -> PromptGuardMetricsResponse:
    view = build_prompt_guard_metrics_view()
    data = view.to_dict()

    return PromptGuardMetricsResponse(
        title=data["title"],
        generated_at=data["generated_at"],
        kpis=[PromptGuardKpiView(**kpi) for kpi in data["kpis"]],
        breakdowns=data["breakdowns"],
        metadata=data["metadata"],
    )