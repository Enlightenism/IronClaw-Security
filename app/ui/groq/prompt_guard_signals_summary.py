from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_activity_feed import build_prompt_guard_activity_feed
from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_performance_snapshot import build_prompt_guard_performance_snapshot
from app.ui.groq.prompt_guard_risk_posture_summary import build_prompt_guard_risk_posture_summary
from app.ui.groq.prompt_guard_trends import build_prompt_guard_trend_series

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-signals-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


SignalSeverity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(slots=True)
class PromptGuardSignalItem:
    id: str
    title: str
    severity: SignalSeverity
    status: str | None
    timestamp: str
    source_module: str
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "timestamp": self.timestamp,
            "source_module": self.source_module,
            "details": dict(self.details),
            "tags": list(self.tags),
        }


@dataclass(slots=True)
class PromptGuardSignalsSummary:
    generated_at: str
    total_signals: int
    critical_signals: int
    high_signals: int
    medium_signals: int
    low_signals: int
    signal_pressure: float
    latest_signals: list[PromptGuardSignalItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_signals": self.total_signals,
            "critical_signals": self.critical_signals,
            "high_signals": self.high_signals,
            "medium_signals": self.medium_signals,
            "low_signals": self.low_signals,
            "signal_pressure": self.signal_pressure,
            "latest_signals": [item.to_dict() for item in self.latest_signals],
            "metadata": dict(self.metadata),
        }


class PromptGuardSignalItemResponse(BaseModel):
    id: str
    title: str
    severity: SignalSeverity
    status: str | None = None
    timestamp: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class PromptGuardSignalsSummaryResponse(BaseModel):
    generated_at: str
    total_signals: int
    critical_signals: int
    high_signals: int
    medium_signals: int
    low_signals: int
    signal_pressure: float
    latest_signals: list[PromptGuardSignalItemResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_severity(value: str | None) -> SignalSeverity:
    normalized = (value or "info").strip().lower()
    mapping: dict[str, SignalSeverity] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(normalized, "info")


def _severity_rank(value: SignalSeverity) -> int:
    rank: dict[SignalSeverity, int] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return rank[value]


def _compute_signal_pressure(
    total_signals: int,
    request_volume: int,
) -> float:
    if request_volume <= 0:
        return float(total_signals)

    return round(total_signals / request_volume, 4)


def build_prompt_guard_signals_summary() -> PromptGuardSignalsSummary:
    generated_at = _utc_now()

    alerts = build_prompt_guard_alerts_overview()
    activity_feed = build_prompt_guard_activity_feed()
    performance = build_prompt_guard_performance_snapshot()
    risk_posture = build_prompt_guard_risk_posture_summary()
    trends = build_prompt_guard_trend_series()

    signals: list[PromptGuardSignalItem] = []

    for alert in alerts.latest_alerts:
        signals.append(
            PromptGuardSignalItem(
                id=f"signal:alert:{alert.id}",
                title=alert.title,
                severity=_normalize_severity(alert.severity),
                status=alert.status,
                timestamp=alert.timestamp,
                source_module=alert.source_module,
                details=alert.details,
                tags=list(alert.tags),
            ),
        )

    for item in activity_feed.items:
        if item.type not in {"incident_status_changed", "recommendation_created", "trend_snapshot"}:
            continue
        signals.append(
            PromptGuardSignalItem(
                id=f"signal:activity:{item.id}",
                title=item.title,
                severity=_normalize_severity(item.severity),
                status=item.status,
                timestamp=item.timestamp,
                source_module=item.source_module,
                details=item.details,
                tags=list(item.tags),
            ),
        )

    latest_point: dict[str, Any] | None = None
    if trends.points:
        latest_point = trends.points[-1].to_dict()
        blocked = int(latest_point.get("blocked_requests", 0) or 0)
        flagged = int(latest_point.get("flagged_requests", 0) or 0)

        if blocked > 0 or flagged > 0:
            severity: SignalSeverity = "critical" if blocked >= 10 else "high" if blocked > 0 else "medium"
            signals.append(
                PromptGuardSignalItem(
                    id=f"signal:trend:{latest_point.get('bucket_start', generated_at)}",
                    title="Prompt guard trend bucket reported active detections",
                    severity=severity,
                    status="open",
                    timestamp=trends.generated_at,
                    source_module="prompt_guard_trends",
                    details={
                        "blocked_requests": blocked,
                        "flagged_requests": flagged,
                        "total_requests": int(latest_point.get("total_requests", 0) or 0),
                        "bucket_start": latest_point.get("bucket_start"),
                    },
                    tags=["trend", "detections"],
                ),
            )

    signals.sort(key=lambda item: (_severity_rank(item.severity), item.timestamp))
    latest_signals = signals[:12]

    critical_signals = sum(1 for item in latest_signals if item.severity == "critical")
    high_signals = sum(1 for item in latest_signals if item.severity == "high")
    medium_signals = sum(1 for item in latest_signals if item.severity == "medium")
    low_signals = sum(1 for item in latest_signals if item.severity == "low")

    total_signals = len(latest_signals)
    signal_pressure = _compute_signal_pressure(
        total_signals=total_signals,
        request_volume=performance.request_volume,
    )

    return PromptGuardSignalsSummary(
        generated_at=generated_at,
        total_signals=total_signals,
        critical_signals=critical_signals,
        high_signals=high_signals,
        medium_signals=medium_signals,
        low_signals=low_signals,
        signal_pressure=signal_pressure,
        latest_signals=latest_signals,
        metadata={
            "source_modules": [
                "prompt_guard_alerts_overview",
                "prompt_guard_activity_feed",
                "prompt_guard_performance_snapshot",
                "prompt_guard_risk_posture_summary",
                "prompt_guard_trends",
            ],
            "request_volume": performance.request_volume,
            "risk_level": risk_posture.overall_risk_level,
            "latest_trend_point": latest_point,
            "signal_limit": 12,
        },
    )


@router.get(
    "/prompt-guard/signals-summary",
    response_model=PromptGuardSignalsSummaryResponse,
)
def get_prompt_guard_signals_summary() -> PromptGuardSignalsSummaryResponse:
    summary = build_prompt_guard_signals_summary()
    data = summary.to_dict()

    return PromptGuardSignalsSummaryResponse(
        generated_at=data["generated_at"],
        total_signals=data["total_signals"],
        critical_signals=data["critical_signals"],
        high_signals=data["high_signals"],
        medium_signals=data["medium_signals"],
        low_signals=data["low_signals"],
        signal_pressure=data["signal_pressure"],
        latest_signals=[PromptGuardSignalItemResponse(**item) for item in data["latest_signals"]],
        metadata=data["metadata"],
    )
