from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import logging
from typing import Any, Generic, Literal, TypeVar
import uuid

import httpx

from app.core.settings import get_settings

_log = logging.getLogger(__name__)

# ── Verdict / status literals mirroring backend contracts ────────────────────
Verdict = Literal["allow", "block", "quarantine", "warn"]
ReviewStatus = Literal["not_required", "pending", "approved", "rejected"]
DecisionStatus = Literal["allowed", "blocked", "quarantined", "warned", "error"]

# ── Timeout configuration ─────────────────────────────────────────────────────
_DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_STREAM_TIMEOUT = httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=5.0)

# ── Generic typed paged result ────────────────────────────────────────────────
T = TypeVar("T")


# ── Response dataclasses ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class HealthStatus:
    status: str
    version: str
    environment: str
    uptime_seconds: float | None = None
    checks: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanResult:
    scan_id: str
    verdict: Verdict
    risk_score: int
    threat_types: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    review_status: ReviewStatus = "not_required"
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GuardDecision:
    decision_id: str
    status: DecisionStatus
    verdict: Verdict
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)
    review_required: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ActionDecision:
    action_id: str
    allowed: bool
    verdict: Verdict
    policy_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReviewItem:
    review_id: str
    scan_id: str
    status: ReviewStatus
    risk_score: int
    verdict: Verdict
    created_at: str | None = None
    updated_at: str | None = None
    reviewed_by: str | None = None
    notes: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuditEntry:
    audit_id: str
    event_type: str
    actor: str
    timestamp: str
    resource_id: str | None = None
    resource_type: str | None = None
    outcome: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PolicyRecord:
    policy_id: str
    name: str
    enabled: bool
    rules: list[dict[str, Any]] = field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    incident_id: str
    title: str
    severity: str
    status: str
    created_at: str | None = None
    updated_at: str | None = None
    affected_resources: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ThreatAlert:
    alert_id: str
    threat_type: str
    severity: str
    message: str
    timestamp: str | None = None
    source: str | None = None
    indicators: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TelemetrySummary:
    total_scans: int
    blocked: int
    allowed: int
    quarantined: int
    warned: int
    avg_risk_score: float
    period: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DeleteResult:
    success: bool
    resource_id: str | None = None
    message: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PagedResult(Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    has_more: bool
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ApiError:
    error: str
    message: str
    status_code: int
    request_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


# ── Client error ─────────────────────────────────────────────────────────────


class IronClawApiError(Exception):
    def __init__(self, api_error: ApiError) -> None:
        super().__init__(api_error.message)
        self.api_error = api_error

    @property
    def status_code(self) -> int:
        return self.api_error.status_code

    @property
    def error_code(self) -> str:
        return self.api_error.error


# ── Auth header resolution ────────────────────────────────────────────────────


def _resolve_auth_header() -> dict[str, str]:
    try:
        s = get_settings()
        key = s.effective_platform_api_key
    except Exception as exc:
        _log.warning("frontend.api_client: could not resolve API key from settings — %s", exc)
        key = None
    if key:
        return {"X-API-Key": key}
    return {}


def _resolve_base_url() -> str:
    try:
        s = get_settings()
        return s.effective_base_url
    except Exception as exc:
        _log.warning("frontend.api_client: could not resolve base URL from settings — %s", exc)
        return "http://127.0.0.1:8000"


# ── httpx client factory ─────────────────────────────────────────────────────


def _build_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    request_id = str(uuid.uuid4())
    headers: dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "IronClaw-Frontend/1.0",
        "X-Request-ID": request_id,
    }
    headers.update(_resolve_auth_header())
    if extra:
        headers.update(extra)
    return headers


@asynccontextmanager
async def _client(
    *,
    timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
    extra_headers: dict[str, str] | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        base_url=_resolve_base_url(),
        headers=_build_headers(extra_headers),
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        yield client


# ── Error normalization ───────────────────────────────────────────────────────


def _normalize_error(response: httpx.Response) -> ApiError:
    request_id: str | None = response.headers.get("X-Request-ID")
    try:
        body = response.json()
    except Exception:
        body = {}

    if isinstance(body, dict):
        error_code = str(body.get("error") or "api_error")
        message = str(body.get("message") or response.reason_phrase or "Request failed")
        details = dict(body.get("details") or {})
        request_id = request_id or body.get("request_id")
    else:
        error_code = "api_error"
        message = str(response.reason_phrase or "Request failed")
        details = {}

    return ApiError(
        error=error_code,
        message=message,
        status_code=response.status_code,
        request_id=str(request_id) if request_id else None,
        details=details,
    )


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code >= 400:
        err = _normalize_error(response)
        _log.warning(
            "frontend.api_client: backend error — status=%s error=%s message=%s",
            err.status_code,
            err.error,
            err.message,
        )
        raise IronClawApiError(err)


def _wrap_transport_error(exc: httpx.TransportError, *, url: str) -> IronClawApiError:
    _log.warning("frontend.api_client: transport error — url=%s exc=%s", url, exc)
    return IronClawApiError(
        ApiError(
            error="transport_error",
            message=f"Network error contacting IronClaw backend: {exc}",
            status_code=0,
            details={"url": url, "exc_type": type(exc).__name__},
        )
    )


# ── Typed paged parser ────────────────────────────────────────────────────────


def _parse_paged_typed(
    d: dict[str, Any],
    parser: Callable[[dict[str, Any]], T],
) -> PagedResult[T]:
    raw_items = d.get("items") or d.get("results") or d.get("data") or []
    parsed: list[T] = []
    for item in raw_items:
        if isinstance(item, dict):
            parsed.append(parser(item))
    total = int(d.get("total") or len(parsed))
    page = int(d.get("page") or 1)
    page_size = int(d.get("page_size") or len(parsed))
    has_more = bool(d.get("has_more") if d.get("has_more") is not None else (page * page_size < total))
    return PagedResult(
        items=parsed,
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more,
        raw=d,
    )


def _parse_paged_raw(d: dict[str, Any]) -> PagedResult[dict[str, Any]]:
    """Fallback for endpoints that return heterogeneous items."""
    raw_items = list(d.get("items") or d.get("results") or d.get("data") or [])
    total = int(d.get("total") or len(raw_items))
    page = int(d.get("page") or 1)
    page_size = int(d.get("page_size") or len(raw_items))
    has_more = bool(d.get("has_more") if d.get("has_more") is not None else (page * page_size < total))
    return PagedResult(
        items=raw_items,
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more,
        raw=d,
    )


# ── Health ────────────────────────────────────────────────────────────────────


async def get_health() -> HealthStatus:
    try:
        async with _client() as c:
            r = await c.get("/health")
            _raise_for_status(r)
            d = r.json()
            return HealthStatus(
                status=str(d.get("status", "unknown")),
                version=str(d.get("version", "")),
                environment=str(d.get("environment", "")),
                uptime_seconds=d.get("uptime_seconds"),
                checks=dict(d.get("checks") or {}),
                raw=d,
            )
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/health") from exc


# ── Scan ──────────────────────────────────────────────────────────────────────


async def submit_scan(
    *,
    target_type: str,
    content: str,
    org_id: str | None = None,
    context: dict[str, Any] | None = None,
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ScanResult:
    payload: dict[str, Any] = {
        "target_type": target_type,
        "content": content,
    }
    if org_id:
        payload["org_id"] = org_id
    if context:
        payload["context"] = context
    if session_id:
        payload["session_id"] = session_id
    if metadata:
        payload["metadata"] = metadata

    try:
        async with _client() as c:
            r = await c.post("/api/v1/scan", json=payload)
            _raise_for_status(r)
            return _parse_scan_result(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/scan") from exc


async def get_scan_result(scan_id: str) -> ScanResult:
    try:
        async with _client() as c:
            r = await c.get(f"/api/v1/scan/{scan_id}")
            _raise_for_status(r)
            return _parse_scan_result(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/scan/{scan_id}") from exc


async def list_scan_history(
    *,
    page: int = 1,
    page_size: int = 25,
    verdict: str | None = None,
    org_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> PagedResult[ScanResult]:
    params: dict[str, Any] = {"page": page, "page_size": page_size}
    if verdict:
        params["verdict"] = verdict
    if org_id:
        params["org_id"] = org_id
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    try:
        async with _client() as c:
            r = await c.get("/api/v1/history", params=params)
            _raise_for_status(r)
            return _parse_paged_typed(r.json(), _parse_scan_result)
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/history") from exc


def _parse_scan_result(d: dict[str, Any]) -> ScanResult:
    return ScanResult(
        scan_id=str(d.get("scan_id") or d.get("id") or ""),
        verdict=str(d.get("verdict") or "allow"),
        risk_score=int(d.get("risk_score") or 0),
        threat_types=list(d.get("threat_types") or []),
        reasons=list(d.get("reasons") or []),
        review_status=str(d.get("review_status") or "not_required"),
        metadata=dict(d.get("metadata") or {}),
        raw=d,
    )


# ── Guard ─────────────────────────────────────────────────────────────────────


async def submit_guard_check(
    *,
    agent_id: str,
    prompt: str,
    tool_calls: list[dict[str, Any]] | None = None,
    context: dict[str, Any] | None = None,
) -> GuardDecision:
    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "prompt": prompt,
    }
    if tool_calls:
        payload["tool_calls"] = tool_calls
    if context:
        payload["context"] = context

    try:
        async with _client() as c:
            r = await c.post("/api/v1/guard", json=payload)
            _raise_for_status(r)
            d = r.json()
            return GuardDecision(
                decision_id=str(d.get("decision_id") or d.get("id") or ""),
                status=str(d.get("status") or "allowed"),
                verdict=str(d.get("verdict") or "allow"),
                risk_score=int(d.get("risk_score") or 0),
                reasons=list(d.get("reasons") or []),
                blocked_actions=list(d.get("blocked_actions") or []),
                review_required=bool(d.get("review_required") or False),
                metadata=dict(d.get("metadata") or {}),
                raw=d,
            )
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/guard") from exc


# ── Action guard ──────────────────────────────────────────────────────────────


async def evaluate_action(
    *,
    action_type: str,
    agent_id: str,
    parameters: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> ActionDecision:
    payload: dict[str, Any] = {
        "action_type": action_type,
        "agent_id": agent_id,
    }
    if parameters:
        payload["parameters"] = parameters
    if context:
        payload["context"] = context

    try:
        async with _client() as c:
            r = await c.post("/api/v1/action/guard", json=payload)
            _raise_for_status(r)
            d = r.json()
            return ActionDecision(
                action_id=str(d.get("action_id") or d.get("id") or ""),
                allowed=bool(d.get("allowed") if d.get("allowed") is not None else True),
                verdict=str(d.get("verdict") or "allow"),
                policy_id=d.get("policy_id"),
                reasons=list(d.get("reasons") or []),
                metadata=dict(d.get("metadata") or {}),
                raw=d,
            )
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/action/guard") from exc


# ── Review queue ──────────────────────────────────────────────────────────────


async def list_review_queue(
    *,
    status: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> PagedResult[ReviewItem]:
    params: dict[str, Any] = {"page": page, "page_size": page_size}
    if status:
        params["status"] = status
    try:
        async with _client() as c:
            r = await c.get("/api/v1/review", params=params)
            _raise_for_status(r)
            return _parse_paged_typed(r.json(), _parse_review_item)
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/review") from exc


async def get_review_item(review_id: str) -> ReviewItem:
    try:
        async with _client() as c:
            r = await c.get(f"/api/v1/review/{review_id}")
            _raise_for_status(r)
            return _parse_review_item(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/review/{review_id}") from exc


async def submit_review_decision(
    review_id: str,
    *,
    decision: Literal["approved", "rejected"],
    notes: str | None = None,
    reviewer: str | None = None,
) -> ReviewItem:
    payload: dict[str, Any] = {"decision": decision}
    if notes:
        payload["notes"] = notes
    if reviewer:
        payload["reviewer"] = reviewer
    try:
        async with _client() as c:
            r = await c.post(f"/api/v1/review/{review_id}/decide", json=payload)
            _raise_for_status(r)
            return _parse_review_item(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/review/{review_id}/decide") from exc


def _parse_review_item(d: dict[str, Any]) -> ReviewItem:
    return ReviewItem(
        review_id=str(d.get("review_id") or d.get("id") or ""),
        scan_id=str(d.get("scan_id") or ""),
        status=str(d.get("status") or "pending"),
        risk_score=int(d.get("risk_score") or 0),
        verdict=str(d.get("verdict") or "quarantine"),
        created_at=d.get("created_at"),
        updated_at=d.get("updated_at"),
        reviewed_by=d.get("reviewed_by"),
        notes=d.get("notes"),
        metadata=dict(d.get("metadata") or {}),
        raw=d,
    )


# ── Audit log ─────────────────────────────────────────────────────────────────


async def list_audit_log(
    *,
    page: int = 1,
    page_size: int = 50,
    event_type: str | None = None,
    actor: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> PagedResult[AuditEntry]:
    params: dict[str, Any] = {"page": page, "page_size": page_size}
    if event_type:
        params["event_type"] = event_type
    if actor:
        params["actor"] = actor
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    try:
        async with _client() as c:
            r = await c.get("/api/v1/audit", params=params)
            _raise_for_status(r)
            return _parse_paged_typed(r.json(), _parse_audit_entry)
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/audit") from exc


def _parse_audit_entry(d: dict[str, Any]) -> AuditEntry:
    return AuditEntry(
        audit_id=str(d.get("audit_id") or d.get("id") or ""),
        event_type=str(d.get("event_type") or ""),
        actor=str(d.get("actor") or ""),
        timestamp=str(d.get("timestamp") or ""),
        resource_id=d.get("resource_id"),
        resource_type=d.get("resource_type"),
        outcome=d.get("outcome"),
        details=dict(d.get("details") or {}),
        raw=d,
    )


# ── Policy ────────────────────────────────────────────────────────────────────


async def list_policies(
    *,
    page: int = 1,
    page_size: int = 25,
    enabled: bool | None = None,
) -> PagedResult[PolicyRecord]:
    params: dict[str, Any] = {"page": page, "page_size": page_size}
    if enabled is not None:
        params["enabled"] = str(enabled).lower()
    try:
        async with _client() as c:
            r = await c.get("/api/v1/policy", params=params)
            _raise_for_status(r)
            return _parse_paged_typed(r.json(), _parse_policy)
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/policy") from exc


async def get_policy(policy_id: str) -> PolicyRecord:
    try:
        async with _client() as c:
            r = await c.get(f"/api/v1/policy/{policy_id}")
            _raise_for_status(r)
            return _parse_policy(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/policy/{policy_id}") from exc


async def create_policy(payload: dict[str, Any]) -> PolicyRecord:
    try:
        async with _client() as c:
            r = await c.post("/api/v1/policy", json=payload)
            _raise_for_status(r)
            return _parse_policy(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/policy") from exc


async def update_policy(policy_id: str, payload: dict[str, Any]) -> PolicyRecord:
    try:
        async with _client() as c:
            r = await c.patch(f"/api/v1/policy/{policy_id}", json=payload)
            _raise_for_status(r)
            return _parse_policy(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/policy/{policy_id}") from exc


async def delete_policy(policy_id: str) -> DeleteResult:
    try:
        async with _client() as c:
            r = await c.delete(f"/api/v1/policy/{policy_id}")
            _raise_for_status(r)
            d: dict[str, Any] = r.json() if r.content else {}
            return DeleteResult(
                success=True,
                resource_id=policy_id,
                message=str(d.get("message") or "Policy deleted"),
                raw=d,
            )
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/policy/{policy_id}") from exc


def _parse_policy(d: dict[str, Any]) -> PolicyRecord:
    return PolicyRecord(
        policy_id=str(d.get("policy_id") or d.get("id") or ""),
        name=str(d.get("name") or ""),
        enabled=bool(d.get("enabled") if d.get("enabled") is not None else True),
        rules=list(d.get("rules") or []),
        created_at=d.get("created_at"),
        updated_at=d.get("updated_at"),
        metadata=dict(d.get("metadata") or {}),
        raw=d,
    )


# ── Incidents ─────────────────────────────────────────────────────────────────


async def list_incidents(
    *,
    page: int = 1,
    page_size: int = 25,
    severity: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> PagedResult[IncidentRecord]:
    params: dict[str, Any] = {"page": page, "page_size": page_size}
    if severity:
        params["severity"] = severity
    if status:
        params["status"] = status
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    try:
        async with _client() as c:
            r = await c.get("/api/v1/incidents", params=params)
            _raise_for_status(r)
            return _parse_paged_typed(r.json(), _parse_incident)
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/incidents") from exc


async def get_incident(incident_id: str) -> IncidentRecord:
    try:
        async with _client() as c:
            r = await c.get(f"/api/v1/incidents/{incident_id}")
            _raise_for_status(r)
            return _parse_incident(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/incidents/{incident_id}") from exc


def _parse_incident(d: dict[str, Any]) -> IncidentRecord:
    return IncidentRecord(
        incident_id=str(d.get("incident_id") or d.get("id") or ""),
        title=str(d.get("title") or ""),
        severity=str(d.get("severity") or ""),
        status=str(d.get("status") or ""),
        created_at=d.get("created_at"),
        updated_at=d.get("updated_at"),
        affected_resources=list(d.get("affected_resources") or []),
        metadata=dict(d.get("metadata") or {}),
        raw=d,
    )


# ── Threat alerts ─────────────────────────────────────────────────────────────


async def list_threat_alerts(
    *,
    page: int = 1,
    page_size: int = 25,
    severity: str | None = None,
    threat_type: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> PagedResult[ThreatAlert]:
    params: dict[str, Any] = {"page": page, "page_size": page_size}
    if severity:
        params["severity"] = severity
    if threat_type:
        params["threat_type"] = threat_type
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    try:
        async with _client() as c:
            r = await c.get("/api/v1/threats", params=params)
            _raise_for_status(r)
            return _parse_paged_typed(r.json(), _parse_threat_alert)
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/threats") from exc


async def get_threat_alert(alert_id: str) -> ThreatAlert:
    try:
        async with _client() as c:
            r = await c.get(f"/api/v1/threats/{alert_id}")
            _raise_for_status(r)
            return _parse_threat_alert(r.json())
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url=f"/api/v1/threats/{alert_id}") from exc


def _parse_threat_alert(d: dict[str, Any]) -> ThreatAlert:
    return ThreatAlert(
        alert_id=str(d.get("alert_id") or d.get("id") or ""),
        threat_type=str(d.get("threat_type") or ""),
        severity=str(d.get("severity") or ""),
        message=str(d.get("message") or ""),
        timestamp=d.get("timestamp"),
        source=d.get("source"),
        indicators=list(d.get("indicators") or []),
        metadata=dict(d.get("metadata") or {}),
        raw=d,
    )


# ── Telemetry ─────────────────────────────────────────────────────────────────


async def get_telemetry_summary(
    *,
    period: str | None = None,
    org_id: str | None = None,
) -> TelemetrySummary:
    params: dict[str, Any] = {}
    if period:
        params["period"] = period
    if org_id:
        params["org_id"] = org_id
    try:
        async with _client() as c:
            r = await c.get("/api/v1/telemetry/summary", params=params)
            _raise_for_status(r)
            d = r.json()
            return TelemetrySummary(
                total_scans=int(d.get("total_scans") or 0),
                blocked=int(d.get("blocked") or 0),
                allowed=int(d.get("allowed") or 0),
                quarantined=int(d.get("quarantined") or 0),
                warned=int(d.get("warned") or 0),
                avg_risk_score=float(d.get("avg_risk_score") or 0.0),
                period=d.get("period"),
                metadata=dict(d.get("metadata") or {}),
                raw=d,
            )
    except IronClawApiError:
        raise
    except httpx.TransportError as exc:
        raise _wrap_transport_error(exc, url="/api/v1/telemetry/summary") from exc
