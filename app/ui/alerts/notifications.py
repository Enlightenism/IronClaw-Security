from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/alerts",
    tags=["alerts-notifications"],
)


class AlertNotificationItem(BaseModel):
    alertid: str
    timestamp: str
    severity: str
    category: str
    title: str
    message: str
    executionid: str | None = None
    reviewitemid: str | None = None
    clientid: str | None = None
    sessionid: str | None = None
    acknowledged: bool = False


class AlertNotificationResponse(BaseModel):
    generatedat: str
    items: list[AlertNotificationItem] = Field(default_factory=list)
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _build_placeholder_items() -> list[AlertNotificationItem]:
    return [
        AlertNotificationItem(
            alertid="alert-001",
            timestamp=_utc_iso(2026, 4, 18, 9, 5),
            severity="critical",
            category="boundary-block",
            title="High-risk shell request blocked",
            message="The runtime boundary blocked a high-risk shell tool call before execution.",
            executionid="exec-202",
            reviewitemid="review-202",
            clientid="client-alpha",
            sessionid="sess-alpha-001",
            acknowledged=False,
        ),
        AlertNotificationItem(
            alertid="alert-002",
            timestamp=_utc_iso(2026, 4, 18, 10, 10),
            severity="high",
            category="review-queue",
            title="Manual review required",
            message="A mid-risk guarded execution was queued for analyst review.",
            executionid="exec-203",
            reviewitemid="review-203",
            clientid="client-beta",
            sessionid="sess-beta-001",
            acknowledged=False,
        ),
        AlertNotificationItem(
            alertid="alert-003",
            timestamp=_utc_iso(2026, 4, 18, 11, 30),
            severity="medium",
            category="review-resolution",
            title="Review item approved",
            message="A queued review item was approved and execution completed.",
            executionid="exec-203",
            reviewitemid="review-203",
            clientid="client-beta",
            sessionid="sess-beta-001",
            acknowledged=True,
        ),
    ]


@router.get("/notifications", response_model=AlertNotificationResponse)
def get_alert_notifications() -> AlertNotificationResponse:
    items = _build_placeholder_items()

    return AlertNotificationResponse(
        generatedat=datetime.now(UTC).isoformat(),
        items=items,
        total=len(items),
        critical=sum(1 for item in items if item.severity == "critical"),
        high=sum(1 for item in items if item.severity == "high"),
        medium=sum(1 for item in items if item.severity == "medium"),
        low=sum(1 for item in items if item.severity == "low"),
    )
