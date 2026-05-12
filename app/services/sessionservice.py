from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.principals import Principal
from app.core.session_security import SessionPolicy, SessionRecord, SessionValidationResult
from app.services.authservice import AuthResult, AuthService, build_auth_service


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}


@dataclass(frozen=True, slots=True)
class SessionServiceResult:
    ok: bool
    reason: str
    session: SessionRecord | None = None
    validation: SessionValidationResult | None = None
    auth: AuthResult | None = None
    secret: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "session": self.session.to_dict() if self.session else None,
            "validation": self.validation.to_dict() if self.validation else None,
            "auth": self.auth.to_dict() if self.auth else None,
            "secret": self.secret,
            "metadata": dict(self.metadata),
        }


class SessionService:
    def __init__(
        self,
        *,
        auth_service: AuthService | None = None,
        session_policy: SessionPolicy | None = None,
    ) -> None:
        self._auth_service = auth_service or build_auth_service(
            session_policy=session_policy,
        )

    @property
    def auth_service(self) -> AuthService:
        return self._auth_service

    @property
    def session_policy(self) -> SessionPolicy:
        return self._auth_service.session_policy

    def create_session(
        self,
        *,
        principal: Principal,
        secret: str | None = None,
        session_id: str | None = None,
        now: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> SessionServiceResult:
        session, issued_secret = self._auth_service.issue_session(
            principal=principal,
            secret=secret,
            session_id=session_id,
            now=now,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata,
        )
        return SessionServiceResult(
            ok=True,
            reason="session_created",
            session=session,
            secret=issued_secret,
            metadata=_stringify_metadata(metadata),
        )

    def validate_session(
        self,
        *,
        principal: Principal,
        session: SessionRecord,
        presented_secret: str,
        now: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> SessionServiceResult:
        auth_result = self._auth_service.authenticate_session(
            principal=principal,
            session=session,
            presented_secret=presented_secret,
            now=now,
            ip_address=ip_address,
            user_agent=user_agent,
            auth_method="session",
            metadata=metadata,
        )
        return SessionServiceResult(
            ok=auth_result.authenticated,
            reason=auth_result.reason,
            session=session,
            validation=auth_result.validation,
            auth=auth_result,
            metadata=_stringify_metadata(metadata),
        )

    def refresh_session(
        self,
        *,
        session: SessionRecord,
        now: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> SessionServiceResult:
        refreshed = self._auth_service.refresh_session(
            session,
            now=now,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return SessionServiceResult(
            ok=True,
            reason="session_refreshed",
            session=refreshed,
            metadata=_stringify_metadata(metadata),
        )

    def rotate_session(
        self,
        *,
        session: SessionRecord,
        new_secret: str | None = None,
        now: datetime | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> SessionServiceResult:
        rotated, issued_secret = self._auth_service.rotate_session(
            session,
            new_secret=new_secret,
            now=now,
        )
        return SessionServiceResult(
            ok=True,
            reason="session_rotated",
            session=rotated,
            secret=issued_secret,
            metadata=_stringify_metadata(metadata),
        )

    def revoke_session(
        self,
        *,
        session: SessionRecord,
        reason: str = "revoked",
        now: datetime | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> SessionServiceResult:
        revoked = self._auth_service.revoke_session(
            session,
            reason=reason,
            now=now,
        )
        return SessionServiceResult(
            ok=True,
            reason="session_revoked",
            session=revoked,
            metadata=_stringify_metadata(metadata),
        )


def build_session_service(
    *,
    auth_service: AuthService | None = None,
    session_policy: SessionPolicy | None = None,
) -> SessionService:
    return SessionService(
        auth_service=auth_service,
        session_policy=session_policy,
    )