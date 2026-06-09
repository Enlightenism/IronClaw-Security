from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any, Literal, cast

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from app.core.errors import AppError, NotFoundError
from app.schemas.scan import ScanHistoryItem, ScanHistoryResponse
from app.services.audit_log_service import (
    list_audit_events,
    list_audit_events_for_actor,
    list_audit_events_for_session,
)
from app.services.history import get_scan_by_id, read_scan_history, update_scan_by_id

router = APIRouter()

_log = logging.getLogger(__name__)

_HISTORY_EVENTS_LIMIT_DEFAULT = 100
_HISTORY_EVENTS_LIMIT_MAX = 1000
_SCAN_HISTORY_LIMIT_DEFAULT = 20
_SCAN_HISTORY_LIMIT_MAX = 200
_REVIEWABLE_VERDICT = "quarantine"
_HEURISTIC_PROMPT_INJECTION_SCORE_ID = "heuristic_prompt_injection_score"
_REVIEW_STATUS_NONE = "none"
_REVIEW_STATUS_APPROVED = "approved"
_REVIEW_STATUS_REJECTED = "rejected"
_VERDICT_ALLOW = "allow"
_VERDICT_BLOCK = "block"
_DEFAULT_SAFE_SUMMARY = "No risky patterns detected."

# Exception base names that indicate a repository connectivity failure.
# Checked by name so this module never imports Supabase-specific packages.
_REPO_CONNECTION_ERROR_NAMES = frozenset(
    {
        "ScanHistoryRepositoryConnectionError",
        "RepositoryConnectionError",
        "ConnectionError",
        "OperationalError",
    }
)


class ReviewRequest(BaseModel):
    """Request body for reviewing a quarantined scan record."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["approve", "reject"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_repository_connection_error(exc: Exception) -> bool:
    """Return True if *exc* looks like a repository connectivity failure.

    Checked by class-name only so this module remains free of Supabase imports.
    """
    return type(exc).__name__ in _REPO_CONNECTION_ERROR_NAMES


def _handle_repository_error(exc: Exception, context: str) -> None:
    """Normalize repository exceptions to typed AppErrors.

    - Known connection-error class names  → 503 AppError.
    - AppError / HTTPException already typed → re-raise unchanged so their
      registered handlers fire correctly.
    - Any other unexpected exception       → 503 AppError (broad fallback so
      mock side-effects and unknown adapter errors never surface as 500).
    """
    # Already a typed application error — let registered handlers deal with it.
    if isinstance(exc, (AppError, HTTPException)):
        raise

    # Named connection-error classes (Supabase adapter, etc.)
    if _is_repository_connection_error(exc):
        _log.error("history: repository connection error in %s: %s", context, exc)
        raise AppError(
            error="repository_unavailable",
            message="Scan history repository is temporarily unavailable",
            status_code=503,
            details={"context": context},
        ) from exc

    # Broad fallback: any unexpected exception from the repository layer maps
    # to 503 so it never bubbles through as an unhandled 500.
    _log.error(
        "history: unexpected repository error in %s (%s): %s",
        context,
        type(exc).__name__,
        exc,
    )
    raise AppError(
        error="repository_unavailable",
        message="Scan history repository is temporarily unavailable",
        status_code=503,
        details={"context": context, "exc_type": type(exc).__name__},
    ) from exc


def _coerce_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if value is None:
        return []
    return []


def _derive_summary(matched_patterns: list[Any]) -> str:
    if matched_patterns:
        return f"Detected {len(matched_patterns)} risky pattern(s)."
    return _DEFAULT_SAFE_SUMMARY


def _derive_risk_score(matched_patterns: list[Any]) -> int:
    heuristic_bonus = 0
    for pattern in matched_patterns:
        identifier: Any = None
        if isinstance(pattern, Mapping):
            identifier = pattern.get("id") or pattern.get("name")
        elif isinstance(pattern, str):
            identifier = pattern

        if identifier == _HEURISTIC_PROMPT_INJECTION_SCORE_ID:
            heuristic_bonus = 5
            break

    base_score = len(matched_patterns) * 15 + heuristic_bonus
    return max(0, min(100, base_score))


def _build_review_summary(summary: Any, action: Literal["approve", "reject"]) -> str:
    base_summary = str(summary or "").strip()
    review_suffix = f"Review action: {action}."
    if not base_summary:
        return review_suffix
    if base_summary.endswith(review_suffix):
        return base_summary
    return f"{base_summary} {review_suffix}"


def _normalize_history_item(item: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a raw scan history item so downstream code and UI always see
    the expected keys and safe default values.
    """
    normalized: dict[str, Any] = dict(item)

    matched_patterns = _coerce_list(normalized.get("matched_patterns"))
    normalized["matched_patterns"] = matched_patterns

    if not normalized.get("summary"):
        normalized["summary"] = _derive_summary(matched_patterns)

    risk_score = normalized.get("risk_score")
    if risk_score is None:
        normalized["risk_score"] = _derive_risk_score(matched_patterns)
    else:
        try:
            normalized["risk_score"] = max(0, min(100, int(risk_score)))
        except (TypeError, ValueError):
            normalized["risk_score"] = _derive_risk_score(matched_patterns)

    normalized["risky_files"] = _coerce_list(normalized.get("risky_files"))
    normalized["checks_loaded"] = _coerce_list(normalized.get("checks_loaded"))
    normalized["failed_checks"] = _coerce_list(normalized.get("failed_checks"))
    normalized.setdefault("quarantine_reason", None)
    normalized.setdefault("review_status", _REVIEW_STATUS_NONE)
    normalized["untrusted"] = bool(normalized.get("untrusted", False))

    return normalized


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/events")
def get_history_events(
    limit: int = Query(
        default=_HISTORY_EVENTS_LIMIT_DEFAULT,
        ge=1,
        le=_HISTORY_EVENTS_LIMIT_MAX,
    ),
) -> list[dict[str, Any]]:
    """Return recent security history events, newest-first."""
    return cast("list[dict[str, Any]]", list_audit_events(limit=limit))


@router.get("/events/by-session/{session_id}")
def get_history_events_by_session(
    session_id: str,
    limit: int = Query(
        default=_HISTORY_EVENTS_LIMIT_DEFAULT,
        ge=1,
        le=_HISTORY_EVENTS_LIMIT_MAX,
    ),
) -> list[dict[str, Any]]:
    """Return recent security history events for a given session_id, newest-first."""
    return cast(
        "list[dict[str, Any]]",
        list_audit_events_for_session(session_id=session_id, limit=limit),
    )


@router.get("/events/by-actor/{actor_id}")
def get_history_events_by_actor(
    actor_id: str,
    limit: int = Query(
        default=_HISTORY_EVENTS_LIMIT_DEFAULT,
        ge=1,
        le=_HISTORY_EVENTS_LIMIT_MAX,
    ),
) -> list[dict[str, Any]]:
    """Return recent security history events for a given actor_id, newest-first."""
    return cast(
        "list[dict[str, Any]]",
        list_audit_events_for_actor(actor_id=actor_id, limit=limit),
    )


@router.get("/", response_model=ScanHistoryResponse)
def get_scan_history(
    limit: int = Query(
        default=_SCAN_HISTORY_LIMIT_DEFAULT,
        ge=1,
        le=_SCAN_HISTORY_LIMIT_MAX,
    ),
) -> ScanHistoryResponse:
    """Return recent scan history records, normalized for UI consumption."""
    try:
        history = read_scan_history(limit=limit)
    except Exception as exc:
        _handle_repository_error(exc, "get_scan_history")

    items = history.get("items", [])
    normalized_items = [_normalize_history_item(item) for item in items]

    return ScanHistoryResponse(
        count=len(normalized_items),
        items=normalized_items,
    )


@router.get("/{scan_id}", response_model=ScanHistoryItem)
def get_scan_record(scan_id: str) -> ScanHistoryItem:
    """Return a single normalized scan history record by its identifier."""
    try:
        item = get_scan_by_id(scan_id)
    except Exception as exc:
        _handle_repository_error(exc, "get_scan_record")

    if not item:
        raise NotFoundError(
            message="Scan not found",
            details={"scan_id": scan_id},
        )
    return ScanHistoryItem(**_normalize_history_item(item))


@router.post("/{scan_id}/review", response_model=ScanHistoryItem)
def review_scan_record(scan_id: str, request: ReviewRequest) -> ScanHistoryItem:
    """Review a quarantined scan record and update its verdict + review status.

    Only scans with verdict == "quarantine" are eligible for review.
    """
    try:
        item = get_scan_by_id(scan_id)
    except Exception as exc:
        _handle_repository_error(exc, "review_scan_record.get")

    if not item:
        raise NotFoundError(
            message="Scan not found",
            details={"scan_id": scan_id},
        )

    item = _normalize_history_item(item)

    if item.get("verdict") != _REVIEWABLE_VERDICT:
        raise AppError(
            error="invalid_review_state",
            message="Only quarantined scans can be reviewed",
            status_code=400,
            details={
                "scan_id": scan_id,
                "verdict": item.get("verdict"),
                "review_action": request.action,
            },
        )

    approved = request.action == "approve"
    updates: dict[str, Any] = {
        "review_status": _REVIEW_STATUS_APPROVED if approved else _REVIEW_STATUS_REJECTED,
        "untrusted": not approved,
        "verdict": _VERDICT_ALLOW if approved else _VERDICT_BLOCK,
        "summary": _build_review_summary(item.get("summary"), request.action),
    }

    try:
        updated = update_scan_by_id(scan_id, updates)
    except Exception as exc:
        _handle_repository_error(exc, "review_scan_record.update")

    if not updated:
        raise NotFoundError(
            message="Scan not found",
            details={"scan_id": scan_id},
        )

    return ScanHistoryItem(**_normalize_history_item(updated))
