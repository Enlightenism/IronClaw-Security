from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

DEFAULT_REVIEW_STATUS = "pending"
DEFAULT_REVIEW_PRIORITY = "normal"
ESCALATED_REVIEW_PRIORITY = "high"


@dataclass(slots=True)
class ReviewQueueItem:
    review_item_id: str
    created_at: str
    updated_at: str
    review_status: str
    priority: str
    risk_score: int
    client_id: str
    session_id: str
    source: str
    summary: str
    reason: str
    payload: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_review_item_id(source: str, session_id: str, created_at: str) -> str:
    normalized_source = (source or "review").replace(" ", "_").lower()
    normalized_session = (session_id or "unknown").replace(" ", "_").lower()
    compact_time = created_at.replace(":", "").replace("-", "").replace(".", "")
    return f"{normalized_source}-{normalized_session}-{compact_time}"


def _derive_priority(risk_score: int) -> str:
    if risk_score >= 80:
        return ESCALATED_REVIEW_PRIORITY
    return DEFAULT_REVIEW_PRIORITY


def create_review_queue_item(payload: dict[str, Any]) -> ReviewQueueItem:
    created_at = _utc_now()
    updated_at = created_at

    risk_score = _safe_int(payload.get("risk_score"), 0)
    source = str(payload.get("source") or "runtime_guard")
    session_id = str(payload.get("session_id") or "")
    client_id = str(payload.get("client_id") or "")
    summary = str(payload.get("summary") or payload.get("reason") or "Review required")
    reason = str(payload.get("reason") or "Review required due to guarded security decision")
    review_item_id = str(payload.get("review_item_id") or _build_review_item_id(source, session_id, created_at))

    raw_tags = payload.get("tags") or []
    tags = [str(tag) for tag in raw_tags] if isinstance(raw_tags, list) else [str(raw_tags)]

    return ReviewQueueItem(
        review_item_id=review_item_id,
        created_at=created_at,
        updated_at=updated_at,
        review_status=str(payload.get("review_status") or DEFAULT_REVIEW_STATUS),
        priority=str(payload.get("priority") or _derive_priority(risk_score)),
        risk_score=risk_score,
        client_id=client_id,
        session_id=session_id,
        source=source,
        summary=summary,
        reason=reason,
        payload=dict(payload),
        tags=tags,
        metadata={"service": "review_queue_service"},
    )


def summarize_review_queue_item(payload: dict[str, Any]) -> dict[str, Any]:
    return create_review_queue_item(payload).to_dict()


__all__ = [
    "DEFAULT_REVIEW_PRIORITY",
    "DEFAULT_REVIEW_STATUS",
    "ESCALATED_REVIEW_PRIORITY",
    "ReviewQueueItem",
    "create_review_queue_item",
    "summarize_review_queue_item",
]
