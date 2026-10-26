from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.guard.prompt_guard_activity_feed import build_prompt_guard_activity_feed
from app.ui.guard.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.guard.prompt_guard_alerts_timeline_summary import (
    build_prompt_guard_alerts_timeline_summary,
)
from app.ui.guard.prompt_guard_coverage_summary import build_prompt_guard_coverage_summary
from app.ui.guard.prompt_guard_executive_summary import build_prompt_guard_executive_summary
from app.ui.guard.prompt_guard_health_snapshot import build_prompt_guard_health_snapshot
from app.ui.guard.prompt_guard_kpi_summary import build_prompt_guard_kpi_summary
from app.ui.guard.prompt_guard_ops_dashboard import build_prompt_guard_ops_dashboard
from app.ui.guard.prompt_guard_performance_snapshot import build_prompt_guard_performance_snapshot
from app.ui.guard.prompt_guard_review_queue_summary import build_prompt_guard_review_queue_summary
from app.ui.guard.prompt_guard_risk_posture_summary import build_prompt_guard_risk_posture_summary
from app.ui.guard.prompt_guard_signals_summary import build_prompt_guard_signals_summary
from app.ui.guard.prompt_guard_status_board_summary import build_prompt_guard_status_board_summary
from app.ui.guard.prompt_guard_timeline_summary import build_prompt_guard_timeline_summary
from app.ui.guard.prompt_guard_trends_summary import build_prompt_guard_trends_summary

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-prompt-guard-dashboard-index"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardDashboardIndexEntry:
    key: str
    title: str
    route: str
    source_module: str
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "route": self.route,
            "source_module": self.source_module,
            "summary": dict(self.summary),
        }


@dataclass(slots=True)
class PromptGuardDashboardIndex:
    generated_at: str
    dashboard: dict[str, Any]
    sections: list[PromptGuardDashboardIndexEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "dashboard": dict(self.dashboard),
            "sections": [section.to_dict() for section in self.sections],
            "metadata": dict(self.metadata),
        }


class PromptGuardDashboardIndexEntryResponse(BaseModel):
    key: str
    title: str
    route: str
    source_module: str
    summary: dict[str, Any] = Field(default_factory=dict)


class PromptGuardDashboardIndexResponse(BaseModel):
    generated_at: str
    dashboard: dict[str, Any] = Field(default_factory=dict)
    sections: list[PromptGuardDashboardIndexEntryResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def build_prompt_guard_dashboard_index() -> PromptGuardDashboardIndex:
    generated_at = _utc_now()

    ops_dashboard = build_prompt_guard_ops_dashboard()
    health = build_prompt_guard_health_snapshot()
    alerts = build_prompt_guard_alerts_overview()
    performance = build_prompt_guard_performance_snapshot()
    risk = build_prompt_guard_risk_posture_summary()
    queue = build_prompt_guard_review_queue_summary()
    signals = build_prompt_guard_signals_summary()
    status_board = build_prompt_guard_status_board_summary()
    executive = build_prompt_guard_executive_summary()
    kpis = build_prompt_guard_kpi_summary()
    timeline = build_prompt_guard_timeline_summary()
    coverage = build_prompt_guard_coverage_summary()
    trends = build_prompt_guard_trends_summary()
    alerts_timeline = build_prompt_guard_alerts_timeline_summary()
    activity = build_prompt_guard_activity_feed()

    sections = [
        PromptGuardDashboardIndexEntry(
            key="ops-dashboard",
            title="Operations dashboard",
            route="/ui/guard/prompt-guard/ops-dashboard",
            source_module="prompt_guard_ops_dashboard",
            summary={
                "generated_at": ops_dashboard.generated_at,
                "recommendation_count": len(ops_dashboard.recommendations),
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="health-snapshot",
            title="Health snapshot",
            route="/ui/guard/prompt-guard/health-snapshot",
            source_module="prompt_guard_health_snapshot",
            summary={
                "overall_status": health.overall_status,
                "trend_status": health.trend_status,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="alerts-overview",
            title="Alerts overview",
            route="/ui/guard/prompt-guard/alerts-overview",
            source_module="prompt_guard_alerts_overview",
            summary={
                "open_alerts": alerts.open_alerts,
                "critical_alerts": alerts.critical_alerts,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="performance-snapshot",
            title="Performance snapshot",
            route="/ui/guard/prompt-guard/performance-snapshot",
            source_module="prompt_guard_performance_snapshot",
            summary={
                "request_volume": performance.request_volume,
                "error_pressure": performance.error_pressure,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="risk-posture-summary",
            title="Risk posture summary",
            route="/ui/guard/prompt-guard/risk-posture-summary",
            source_module="prompt_guard_risk_posture_summary",
            summary={
                "overall_risk_level": risk.overall_risk_level,
                "critical_alerts": risk.critical_alerts,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="review-queue-summary",
            title="Review queue summary",
            route="/ui/guard/prompt-guard/review-queue-summary",
            source_module="prompt_guard_review_queue_summary",
            summary={
                "queue_status": queue.queue_status,
                "review_queue_total": queue.review_queue_total,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="signals-summary",
            title="Signals summary",
            route="/ui/guard/prompt-guard/signals-summary",
            source_module="prompt_guard_signals_summary",
            summary={
                "total_signals": signals.total_signals,
                "signal_pressure": signals.signal_pressure,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="status-board-summary",
            title="Status board summary",
            route="/ui/guard/prompt-guard/status-board-summary",
            source_module="prompt_guard_status_board_summary",
            summary={
                "overall_status": status_board.overall_status,
                "card_count": len(status_board.board_cards),
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="executive-summary",
            title="Executive summary",
            route="/ui/guard/prompt-guard/executive-summary",
            source_module="prompt_guard_executive_summary",
            summary={
                "overall_tone": executive.overall_tone,
                "headline": executive.headline,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="kpi-summary",
            title="KPI summary",
            route="/ui/guard/prompt-guard/kpi-summary",
            source_module="prompt_guard_kpi_summary",
            summary={
                "card_count": len(kpis.cards),
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="timeline-summary",
            title="Timeline summary",
            route="/ui/guard/prompt-guard/timeline-summary",
            source_module="prompt_guard_timeline_summary",
            summary={
                "total_entries": timeline.total_entries,
                "lookback_hours": timeline.lookback_hours,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="coverage-summary",
            title="Coverage summary",
            route="/ui/guard/prompt-guard/coverage-summary",
            source_module="prompt_guard_coverage_summary",
            summary={
                "coverage_status": coverage.coverage_status,
                "incident_coverage_ratio": coverage.incident_coverage_ratio,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="trends-summary",
            title="Trends summary",
            route="/ui/guard/prompt-guard/trends-summary",
            source_module="prompt_guard_trends_summary",
            summary={
                "trend_status": trends.trend_status,
                "point_count": trends.point_count,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="alerts-timeline-summary",
            title="Alerts timeline summary",
            route="/ui/guard/prompt-guard/alerts-timeline-summary",
            source_module="prompt_guard_alerts_timeline_summary",
            summary={
                "total_alerts": alerts_timeline.total_alerts,
                "critical_alerts": alerts_timeline.critical_alerts,
            },
        ),
        PromptGuardDashboardIndexEntry(
            key="activity-feed",
            title="Activity feed",
            route="/ui/guard/prompt-guard/activity-feed",
            source_module="prompt_guard_activity_feed",
            summary={
                "total_items": activity.total_items,
            },
        ),
    ]

    return PromptGuardDashboardIndex(
        generated_at=generated_at,
        dashboard={
            "title": "Prompt Guard Dashboard Index",
            "root_route": "/ui/guard/prompt-guard/dashboard-index",
            "section_count": len(sections),
        },
        sections=sections,
        metadata={
            "source_modules": [
                "prompt_guard_ops_dashboard",
                "prompt_guard_health_snapshot",
                "prompt_guard_alerts_overview",
                "prompt_guard_performance_snapshot",
                "prompt_guard_risk_posture_summary",
                "prompt_guard_review_queue_summary",
                "prompt_guard_signals_summary",
                "prompt_guard_status_board_summary",
                "prompt_guard_executive_summary",
                "prompt_guard_kpi_summary",
                "prompt_guard_timeline_summary",
                "prompt_guard_coverage_summary",
                "prompt_guard_trends_summary",
                "prompt_guard_alerts_timeline_summary",
                "prompt_guard_activity_feed",
            ],
        },
    )


@router.get(
    "/prompt-guard/dashboard-index",
    response_model=PromptGuardDashboardIndexResponse,
)
def get_prompt_guard_dashboard_index() -> PromptGuardDashboardIndexResponse:
    index = build_prompt_guard_dashboard_index()
    data = index.to_dict()

    return PromptGuardDashboardIndexResponse(
        generated_at=data["generated_at"],
        dashboard=data["dashboard"],
        sections=[PromptGuardDashboardIndexEntryResponse(**section) for section in data["sections"]],
        metadata=data["metadata"],
    )
