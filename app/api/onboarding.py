from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
import threading
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.auth import AuthContext, get_auth_context

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OnboardingStepKey(StrEnum):
    ACCOUNT_CREATED = "account_created"
    ORG_CONFIGURED = "org_configured"
    POLICY_CREATED = "policy_created"
    FIRST_SCAN = "first_scan"
    WEBHOOK_REGISTERED = "webhook_registered"
    REVIEW_QUEUE_ENABLED = "review_queue_enabled"
    AUDIT_LOG_VERIFIED = "audit_log_verified"
    INTEGRATION_CONNECTED = "integration_connected"
    COMPLETED = "completed"


class OnboardingStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"


class OnboardingSessionStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class OnboardingStep(BaseModel):
    key: OnboardingStepKey
    title: str
    description: str
    status: OnboardingStatus = OnboardingStatus.PENDING
    required: bool = True
    completed_at: str | None = None
    skipped_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class OnboardingSession(BaseModel):
    session_id: str
    org_id: str | None
    principal_id: str
    status: OnboardingSessionStatus
    steps: list[OnboardingStep]
    current_step: OnboardingStepKey | None
    progress_pct: int
    created_at: str
    updated_at: str
    completed_at: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)


class OnboardingStartRequest(BaseModel):
    org_id: str | None = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)


class OnboardingStepCompleteRequest(BaseModel):
    key: OnboardingStepKey
    metadata: dict[str, Any] = Field(default_factory=dict)


class OnboardingStepSkipRequest(BaseModel):
    key: OnboardingStepKey
    reason: str | None = Field(default=None, max_length=512)


class OnboardingChecklistResponse(BaseModel):
    session_id: str
    org_id: str | None
    status: OnboardingSessionStatus
    progress_pct: int
    steps: list[OnboardingStep]
    current_step: OnboardingStepKey | None
    completed_at: str | None


class OnboardingProgressResponse(BaseModel):
    session_id: str
    org_id: str | None
    status: OnboardingSessionStatus
    progress_pct: int
    total_steps: int
    completed_steps: int
    skipped_steps: int
    pending_steps: int
    current_step: OnboardingStepKey | None
    completed_at: str | None


class OnboardingResetResponse(BaseModel):
    session_id: str
    org_id: str | None
    reset_at: str
    message: str


# ---------------------------------------------------------------------------
# Default step definitions
# ---------------------------------------------------------------------------

_DEFAULT_STEPS: list[dict[str, Any]] = [
    {
        "key": OnboardingStepKey.ACCOUNT_CREATED,
        "title": "Account Created",
        "description": "Your IronClaw account has been created and authenticated.",
        "required": True,
    },
    {
        "key": OnboardingStepKey.ORG_CONFIGURED,
        "title": "Organization Configured",
        "description": "Set your organization ID and basic configuration.",
        "required": True,
    },
    {
        "key": OnboardingStepKey.POLICY_CREATED,
        "title": "Security Policy Created",
        "description": "Define at least one guard policy for your organization.",
        "required": True,
    },
    {
        "key": OnboardingStepKey.FIRST_SCAN,
        "title": "First Scan Completed",
        "description": "Run your first prompt inspection scan.",
        "required": True,
    },
    {
        "key": OnboardingStepKey.WEBHOOK_REGISTERED,
        "title": "Webhook Registered",
        "description": "Register a webhook endpoint to receive security event notifications.",
        "required": False,
    },
    {
        "key": OnboardingStepKey.REVIEW_QUEUE_ENABLED,
        "title": "Review Queue Enabled",
        "description": "Enable the human review queue for flagged requests.",
        "required": False,
    },
    {
        "key": OnboardingStepKey.AUDIT_LOG_VERIFIED,
        "title": "Audit Log Verified",
        "description": "Confirm audit log collection is active.",
        "required": False,
    },
    {
        "key": OnboardingStepKey.INTEGRATION_CONNECTED,
        "title": "Integration Connected",
        "description": "Connect an external integration (SIEM, alerting, or logging platform).",
        "required": False,
    },
]


# ---------------------------------------------------------------------------
# In-memory store (same pattern as webhook_dispatcher)
# ---------------------------------------------------------------------------


class _OnboardingRecord(BaseModel):
    session_id: str
    org_id: str | None
    principal_id: str
    status: OnboardingSessionStatus
    steps: list[OnboardingStep]
    current_step: OnboardingStepKey | None
    created_at: str
    updated_at: str
    completed_at: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)


class OnboardingService:
    def __init__(self) -> None:
        self._sessions: dict[str, _OnboardingRecord] = {}
        # index: (org_id, principal_id) -> session_id
        self._index: dict[tuple[str | None, str], str] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _utcnow() -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _build_steps() -> list[OnboardingStep]:
        return [OnboardingStep(**s) for s in _DEFAULT_STEPS]

    @staticmethod
    def _compute_progress(steps: list[OnboardingStep]) -> int:
        total = len(steps)
        if total == 0:
            return 0
        done = sum(1 for s in steps if s.status in (OnboardingStatus.COMPLETED, OnboardingStatus.SKIPPED))
        return round((done / total) * 100)

    @staticmethod
    def _next_pending(steps: list[OnboardingStep]) -> OnboardingStepKey | None:
        for s in steps:
            if s.status == OnboardingStatus.PENDING:
                return s.key
        return None

    def _to_session(self, record: _OnboardingRecord) -> OnboardingSession:
        return OnboardingSession(
            session_id=record.session_id,
            org_id=record.org_id,
            principal_id=record.principal_id,
            status=record.status,
            steps=record.steps,
            current_step=record.current_step,
            progress_pct=self._compute_progress(record.steps),
            created_at=record.created_at,
            updated_at=record.updated_at,
            completed_at=record.completed_at,
            metadata=record.metadata,
        )

    # ------------------------------------------------------------------
    # Public service methods
    # ------------------------------------------------------------------

    def start(
        self,
        principal_id: str,
        org_id: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> OnboardingSession:
        with self._lock:
            idx_key = (org_id, principal_id)
            existing_id = self._index.get(idx_key)
            if existing_id and existing_id in self._sessions:
                existing = self._sessions[existing_id]
                if existing.status != OnboardingSessionStatus.ABANDONED:
                    return self._to_session(existing)

            now = self._utcnow()
            steps = self._build_steps()
            # Mark account_created as completed immediately (caller is authenticated)
            for s in steps:
                if s.key == OnboardingStepKey.ACCOUNT_CREATED:
                    s.status = OnboardingStatus.COMPLETED
                    s.completed_at = now
                    break

            session_id = f"obs-{uuid4().hex[:20]}"
            record = _OnboardingRecord(
                session_id=session_id,
                org_id=org_id,
                principal_id=principal_id,
                status=OnboardingSessionStatus.ACTIVE,
                steps=steps,
                current_step=self._next_pending(steps),
                created_at=now,
                updated_at=now,
                completed_at=None,
                metadata=metadata or {},
            )
            self._sessions[session_id] = record
            self._index[idx_key] = session_id
            return self._to_session(record)

    def get(self, session_id: str) -> OnboardingSession | None:
        with self._lock:
            record = self._sessions.get(session_id)
            return self._to_session(record) if record else None

    def get_by_principal(self, principal_id: str, org_id: str | None) -> OnboardingSession | None:
        with self._lock:
            session_id = self._index.get((org_id, principal_id))
            if session_id is None:
                return None
            record = self._sessions.get(session_id)
            return self._to_session(record) if record else None

    def complete_step(
        self,
        session_id: str,
        key: OnboardingStepKey,
        metadata: dict[str, Any] | None = None,
    ) -> OnboardingSession | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            if record.status == OnboardingSessionStatus.COMPLETED:
                return self._to_session(record)

            now = self._utcnow()
            found = False
            for s in record.steps:
                if s.key == key:
                    s.status = OnboardingStatus.COMPLETED
                    s.completed_at = now
                    if metadata:
                        s.metadata.update(metadata)
                    found = True
                    break

            if not found:
                return self._to_session(record)

            record.current_step = self._next_pending(record.steps)
            record.updated_at = now

            all_done = all(s.status in (OnboardingStatus.COMPLETED, OnboardingStatus.SKIPPED) for s in record.steps)
            if all_done:
                record.status = OnboardingSessionStatus.COMPLETED
                record.completed_at = now

            return self._to_session(record)

    def skip_step(
        self,
        session_id: str,
        key: OnboardingStepKey,
        reason: str | None = None,
    ) -> OnboardingSession | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None

            now = self._utcnow()
            for s in record.steps:
                if s.key == key:
                    if s.required:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=f"Step '{key}' is required and cannot be skipped.",
                        )
                    s.status = OnboardingStatus.SKIPPED
                    s.skipped_at = now
                    if reason:
                        s.metadata["skip_reason"] = reason
                    break

            record.current_step = self._next_pending(record.steps)
            record.updated_at = now

            all_done = all(s.status in (OnboardingStatus.COMPLETED, OnboardingStatus.SKIPPED) for s in record.steps)
            if all_done:
                record.status = OnboardingSessionStatus.COMPLETED
                record.completed_at = now

            return self._to_session(record)

    def abandon(self, session_id: str) -> OnboardingSession | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.status = OnboardingSessionStatus.ABANDONED
            record.updated_at = self._utcnow()
            return self._to_session(record)

    def reset(
        self,
        session_id: str,
        principal_id: str,
        org_id: str | None,
    ) -> OnboardingResetResponse | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None

            now = self._utcnow()
            steps = self._build_steps()
            for s in steps:
                if s.key == OnboardingStepKey.ACCOUNT_CREATED:
                    s.status = OnboardingStatus.COMPLETED
                    s.completed_at = now
                    break

            record.steps = steps
            record.status = OnboardingSessionStatus.ACTIVE
            record.current_step = self._next_pending(steps)
            record.completed_at = None
            record.updated_at = now

            return OnboardingResetResponse(
                session_id=session_id,
                org_id=org_id,
                reset_at=now,
                message="Onboarding session reset. All steps returned to pending.",
            )

    def checklist(self, session_id: str) -> OnboardingChecklistResponse | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            return OnboardingChecklistResponse(
                session_id=record.session_id,
                org_id=record.org_id,
                status=record.status,
                progress_pct=self._compute_progress(record.steps),
                steps=record.steps,
                current_step=record.current_step,
                completed_at=record.completed_at,
            )

    def progress(self, session_id: str) -> OnboardingProgressResponse | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            completed = sum(1 for s in record.steps if s.status == OnboardingStatus.COMPLETED)
            skipped = sum(1 for s in record.steps if s.status == OnboardingStatus.SKIPPED)
            pending = sum(1 for s in record.steps if s.status == OnboardingStatus.PENDING)
            return OnboardingProgressResponse(
                session_id=record.session_id,
                org_id=record.org_id,
                status=record.status,
                progress_pct=self._compute_progress(record.steps),
                total_steps=len(record.steps),
                completed_steps=completed,
                skipped_steps=skipped,
                pending_steps=pending,
                current_step=record.current_step,
                completed_at=record.completed_at,
            )

    def full_reset_for_tests(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._index.clear()


# ---------------------------------------------------------------------------
# Singleton accessor (mirrors get_webhook_dispatcher pattern)
# ---------------------------------------------------------------------------

_service_instance: OnboardingService | None = None
_service_lock = threading.Lock()


def get_onboarding_service() -> OnboardingService:
    global _service_instance
    if _service_instance is None:
        with _service_lock:
            if _service_instance is None:
                _service_instance = OnboardingService()
    return _service_instance


def reset_onboarding_service() -> None:
    global _service_instance
    with _service_lock:
        _service_instance = None


# ---------------------------------------------------------------------------
# Route-level dependencies
# ---------------------------------------------------------------------------


def _service() -> OnboardingService:
    return get_onboarding_service()


def _auth_context(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
    """Dependency that ensures authentication is required for onboarding endpoints."""
    if not ctx.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return ctx


def _org_id(request: Request, ctx: AuthContext = Depends(_auth_context)) -> str | None:
    if ctx.org_id:
        return ctx.org_id
    return request.headers.get("X-Organization-Id") or None


def _principal_id(request: Request, ctx: AuthContext = Depends(_auth_context)) -> str:
    # Prefer explicit principal_id from the auth context (registry key path).
    if ctx.principal_id:
        return ctx.principal_id
    # Configured-key path: registry record is None so principal_id is None.
    # Fall back to the raw API key value as the stable principal identity.
    if ctx.api_key:
        return ctx.api_key
    # Anonymous / auth-disabled: derive a deterministic identity from the
    # request to avoid passing None into _OnboardingRecord.
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return f"anon:{forwarded_for.split(',')[0].strip()}"
    client_host = getattr(request.client, "host", None)
    if client_host:
        return f"anon:{client_host}"
    return "anon:unknown"


# ---------------------------------------------------------------------------
# Routes — static paths BEFORE dynamic /{session_id} paths
# ---------------------------------------------------------------------------


@router.post(
    "/start",
    response_model=OnboardingSession,
    status_code=status.HTTP_201_CREATED,
    summary="Start or resume an onboarding session",
)
def start_onboarding(
    body: OnboardingStartRequest = Body(default_factory=OnboardingStartRequest),
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingSession:
    resolved_org = body.org_id or org_id
    return svc.start(
        principal_id=principal_id,
        org_id=resolved_org,
        metadata=body.metadata,
    )


@router.get(
    "/me",
    response_model=OnboardingSession,
    status_code=status.HTTP_200_OK,
    summary="Get the current principal's onboarding session",
)
def get_my_onboarding(
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingSession:
    session = svc.get_by_principal(principal_id=principal_id, org_id=org_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active onboarding session found. POST /onboarding/start to begin.",
        )
    return session


@router.get(
    "/steps",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List all available onboarding step definitions",
)
def list_step_definitions(
    ctx: AuthContext = Depends(_auth_context),
) -> list[dict[str, Any]]:
    return [
        {
            "key": s["key"].value,
            "title": s["title"],
            "description": s["description"],
            "required": s["required"],
        }
        for s in _DEFAULT_STEPS
    ]


# ---------------------------------------------------------------------------
# Per-session routes — dynamic /{session_id}
# ---------------------------------------------------------------------------


@router.get(
    "/{session_id}",
    response_model=OnboardingSession,
    status_code=status.HTTP_200_OK,
    summary="Get an onboarding session by ID",
)
def get_onboarding_session(
    session_id: str,
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingSession:
    session = svc.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    _assert_session_ownership(session, principal_id, org_id, session_id)
    return session


@router.get(
    "/{session_id}/checklist",
    response_model=OnboardingChecklistResponse,
    status_code=status.HTTP_200_OK,
    summary="Get the step checklist for a session",
)
def get_checklist(
    session_id: str,
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingChecklistResponse:
    session = svc.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    _assert_session_ownership(session, principal_id, org_id, session_id)
    result = svc.checklist(session_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    return result


@router.get(
    "/{session_id}/progress",
    response_model=OnboardingProgressResponse,
    status_code=status.HTTP_200_OK,
    summary="Get progress metrics for a session",
)
def get_progress(
    session_id: str,
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingProgressResponse:
    session = svc.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    _assert_session_ownership(session, principal_id, org_id, session_id)
    result = svc.progress(session_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    return result


@router.post(
    "/{session_id}/complete-step",
    response_model=OnboardingSession,
    status_code=status.HTTP_200_OK,
    summary="Mark an onboarding step as completed",
)
def complete_step(
    session_id: str,
    body: OnboardingStepCompleteRequest,
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingSession:
    session = svc.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    _assert_session_ownership(session, principal_id, org_id, session_id)
    result = svc.complete_step(session_id, body.key, metadata=body.metadata)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    return result


@router.post(
    "/{session_id}/skip-step",
    response_model=OnboardingSession,
    status_code=status.HTTP_200_OK,
    summary="Skip a non-required onboarding step",
)
def skip_step(
    session_id: str,
    body: OnboardingStepSkipRequest,
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingSession:
    session = svc.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    _assert_session_ownership(session, principal_id, org_id, session_id)
    result = svc.skip_step(session_id, body.key, reason=body.reason)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    return result


@router.post(
    "/{session_id}/abandon",
    response_model=OnboardingSession,
    status_code=status.HTTP_200_OK,
    summary="Abandon an onboarding session",
)
def abandon_session(
    session_id: str,
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingSession:
    session = svc.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    _assert_session_ownership(session, principal_id, org_id, session_id)
    result = svc.abandon(session_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    return result


@router.post(
    "/{session_id}/reset",
    response_model=OnboardingResetResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset an onboarding session to its initial state",
)
def reset_session(
    session_id: str,
    org_id: str | None = Depends(_org_id),
    principal_id: str = Depends(_principal_id),
    svc: OnboardingService = Depends(_service),
) -> OnboardingResetResponse:
    session = svc.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    _assert_session_ownership(session, principal_id, org_id, session_id)
    result = svc.reset(session_id, principal_id=principal_id, org_id=org_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Onboarding session '{session_id}' not found.",
        )
    return result


# ---------------------------------------------------------------------------
# Internal ownership guard
# ---------------------------------------------------------------------------


def _assert_session_ownership(
    session: OnboardingSession,
    principal_id: str,
    org_id: str | None,
    session_id: str,
) -> None:
    if session.principal_id != principal_id:
        if org_id and session.org_id and session.org_id == org_id:
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Onboarding session '{session_id}' does not belong to your principal.",
        )
