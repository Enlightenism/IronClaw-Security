from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    if isinstance(value, int | float):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        candidate = candidate.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return default
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return default


def _coerce_list_of_str(value: Any) -> tuple[str, ...]:
    if isinstance(value, list | tuple | set):
        normalized = []
        for item in value:
            text = _coerce_str(item)
            if text:
                normalized.append(text)
        return tuple(normalized)
    if isinstance(value, str):
        text = value.strip()
        return (text,) if text else ()
    return ()


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    code: str
    title: str
    severity: str
    confidence: str
    status: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class ReviewEvidence:
    kind: str
    label: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class ReviewTimelineEvent:
    at: datetime
    stage: str
    actor: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": _isoformat(self.at),
            "stage": self.stage,
            "actor": self.actor,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ReviewDetail:
    review_id: str
    title: str
    category: str
    severity: str
    verdict: str
    status: str
    source: str
    assignee: str = ""
    summary: str = ""
    rationale: str = ""
    requested_by: str = ""
    escalation_reason: str = ""
    requires_human: bool = True
    policy_refs: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    findings: tuple[ReviewFinding, ...] = ()
    evidence: tuple[ReviewEvidence, ...] = ()
    timeline: tuple[ReviewTimelineEvent, ...] = ()
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    due_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "verdict": self.verdict,
            "status": self.status,
            "source": self.source,
            "assignee": self.assignee,
            "summary": self.summary,
            "rationale": self.rationale,
            "requested_by": self.requested_by,
            "escalation_reason": self.escalation_reason,
            "requires_human": self.requires_human,
            "policy_refs": list(self.policy_refs),
            "tags": list(self.tags),
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "timeline": [item.to_dict() for item in self.timeline],
            "created_at": _isoformat(self.created_at),
            "updated_at": _isoformat(self.updated_at),
            "due_at": _isoformat(self.due_at),
        }


def _normalize_finding(value: Any) -> ReviewFinding | None:
    if not isinstance(value, dict):
        return None

    code = _coerce_str(value.get("code"))
    title = _coerce_str(value.get("title"))
    if not code and not title:
        return None

    return ReviewFinding(
        code=code or "finding",
        title=title or "Review finding",
        severity=_coerce_str(value.get("severity"), "medium") or "medium",
        confidence=_coerce_str(value.get("confidence"), "medium") or "medium",
        status=_coerce_str(value.get("status"), "open") or "open",
        summary=_coerce_str(value.get("summary"), "No finding summary provided.") or "No finding summary provided.",
    )


def _normalize_evidence(value: Any) -> ReviewEvidence | None:
    if not isinstance(value, dict):
        return None

    label = _coerce_str(value.get("label"))
    item_value = _coerce_str(value.get("value"))
    if not label and not item_value:
        return None

    return ReviewEvidence(
        kind=_coerce_str(value.get("kind"), "artifact") or "artifact",
        label=label or "Evidence",
        value=item_value or "",
    )


def _normalize_timeline_event(value: Any) -> ReviewTimelineEvent | None:
    if not isinstance(value, dict):
        return None

    stage = _coerce_str(value.get("stage"))
    actor = _coerce_str(value.get("actor"))
    detail = _coerce_str(value.get("detail"))
    if not stage and not detail:
        return None

    return ReviewTimelineEvent(
        at=_coerce_datetime(value.get("at"), _utc_now()) or _utc_now(),
        stage=stage or "queued",
        actor=actor or "system",
        detail=detail or "Review event recorded.",
    )


def default_review_detail(review_id: str = "") -> ReviewDetail:
    normalized_review_id = _coerce_str(review_id)
    return ReviewDetail(
        review_id=normalized_review_id,
        title="Review detail",
        category="general",
        severity="medium",
        verdict="block",
        status="pending",
        source="runtime",
        summary="No review detail is available.",
        rationale="No rationale has been recorded.",
    )


def build_review_detail(
    data: dict[str, Any] | None = None,
    *,
    review_id: str = "",
    baseline: ReviewDetail | None = None,
) -> ReviewDetail:
    source = data or {}
    current = baseline or default_review_detail(review_id=review_id)

    raw_findings = source.get("findings")
    if isinstance(raw_findings, list):
        findings = tuple(item for entry in raw_findings if (item := _normalize_finding(entry)) is not None)
    else:
        findings = current.findings

    raw_evidence = source.get("evidence")
    if isinstance(raw_evidence, list):
        evidence = tuple(item for entry in raw_evidence if (item := _normalize_evidence(entry)) is not None)
    else:
        evidence = current.evidence

    raw_timeline = source.get("timeline")
    if isinstance(raw_timeline, list):
        timeline = tuple(item for entry in raw_timeline if (item := _normalize_timeline_event(entry)) is not None)
    else:
        timeline = current.timeline

    detail = ReviewDetail(
        review_id=_coerce_str(source.get("review_id"), current.review_id or review_id),
        title=_coerce_str(source.get("title"), current.title) or current.title,
        category=_coerce_str(source.get("category"), current.category) or current.category,
        severity=_coerce_str(source.get("severity"), current.severity) or current.severity,
        verdict=_coerce_str(source.get("verdict"), current.verdict) or current.verdict,
        status=_coerce_str(source.get("status"), current.status) or current.status,
        source=_coerce_str(source.get("source"), current.source) or current.source,
        assignee=_coerce_str(source.get("assignee"), current.assignee),
        summary=_coerce_str(source.get("summary"), current.summary) or current.summary,
        rationale=_coerce_str(source.get("rationale"), current.rationale) or current.rationale,
        requested_by=_coerce_str(source.get("requested_by"), current.requested_by),
        escalation_reason=_coerce_str(source.get("escalation_reason"), current.escalation_reason),
        requires_human=_coerce_bool(source.get("requires_human"), current.requires_human),
        policy_refs=_coerce_list_of_str(source.get("policy_refs")) or current.policy_refs,
        tags=_coerce_list_of_str(source.get("tags")) or current.tags,
        findings=findings,
        evidence=evidence,
        timeline=timeline,
        created_at=_coerce_datetime(source.get("created_at"), current.created_at) or current.created_at,
        updated_at=_coerce_datetime(source.get("updated_at"), _utc_now()) or _utc_now(),
        due_at=_coerce_datetime(source.get("due_at"), current.due_at),
    )

    if not detail.review_id:
        return ReviewDetail(
            **{
                **detail.__dict__,
                "review_id": _coerce_str(review_id),
            },
        )

    return detail


def review_detail_summary(detail: ReviewDetail) -> dict[str, Any]:
    open_findings = sum(1 for item in detail.findings if item.status.lower() not in {"resolved", "closed"})
    critical_findings = sum(1 for item in detail.findings if item.severity.lower() == "critical")
    high_findings = sum(1 for item in detail.findings if item.severity.lower() == "high")

    return {
        "review_id": detail.review_id,
        "title": detail.title,
        "category": detail.category,
        "severity": detail.severity,
        "verdict": detail.verdict,
        "status": detail.status,
        "source": detail.source,
        "assignee": detail.assignee,
        "requested_by": detail.requested_by,
        "requires_human": detail.requires_human,
        "summary": detail.summary,
        "rationale": detail.rationale,
        "escalation_reason": detail.escalation_reason,
        "policy_refs": list(detail.policy_refs),
        "tags": list(detail.tags),
        "counts": {
            "findings_total": len(detail.findings),
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "evidence_total": len(detail.evidence),
            "timeline_events_total": len(detail.timeline),
        },
        "findings": [item.to_dict() for item in detail.findings],
        "evidence": [item.to_dict() for item in detail.evidence],
        "timeline": [item.to_dict() for item in detail.timeline],
        "created_at": _isoformat(detail.created_at),
        "updated_at": _isoformat(detail.updated_at),
        "due_at": _isoformat(detail.due_at),
    }
