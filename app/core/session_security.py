from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Mapping


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_lower(value: object) -> str:
    return _clean(value).lower()


def _ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_session_id(prefix: str = "sess") -> str:
    normalized_prefix = _clean_lower(prefix) or "sess"
    return f"{normalized_prefix}_{secrets.token_urlsafe(24)}"


def generate_session_secret(length: int = 48) -> str:
    size = max(32, int(length))
    return secrets.token_urlsafe(size)


def fingerprint_session_secret(secret: str) -> str:
    normalized_secret = _clean(secret)
    if not normalized_secret:
        return ""
    return _sha256(normalized_secret)


def constant_time_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(_clean(left), _clean(right))


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    idle_timeout_seconds: int = 1800
    absolute_timeout_seconds: int = 43200
    renewal_window_seconds: int = 300
    require_ip_binding: bool = False
    require_user_agent_binding: bool = True
    enforce_secret_rotation: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "absolute_timeout_seconds": self.absolute_timeout_seconds,
            "renewal_window_seconds": self.renewal_window_seconds,
            "require_ip_binding": self.require_ip_binding,
            "require_user_agent_binding": self.require_user_agent_binding,
            "enforce_secret_rotation": self.enforce_secret_rotation,
        }


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    principal_id: str
    principal_type: str
    org_id: str | None = None
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "org_id": self.org_id,
            "roles": list(self.roles),
            "permissions": list(self.permissions),
        }


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: str
    principal: SessionPrincipal
    secret_fingerprint: str
    issued_at: datetime
    expires_at: datetime
    idle_expires_at: datetime
    last_seen_at: datetime
    created_ip: str | None = None
    last_ip: str | None = None
    user_agent: str | None = None
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "principal": self.principal.to_dict(),
            "secret_fingerprint": self.secret_fingerprint,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "idle_expires_at": self.idle_expires_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
            "created_ip": self.created_ip,
            "last_ip": self.last_ip,
            "user_agent": self.user_agent,
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
            "active": self.active,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class SessionValidationResult:
    valid: bool
    reason: str
    session_id: str | None
    principal_id: str | None
    org_id: str | None
    should_rotate: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "session_id": self.session_id,
            "principal_id": self.principal_id,
            "org_id": self.org_id,
            "should_rotate": self.should_rotate,
            "metadata": dict(self.metadata),
        }


def build_session_principal(
    *,
    principal_id: str,
    principal_type: str,
    org_id: str | None = None,
    roles: tuple[str, ...] | list[str] | set[str] | None = None,
    permissions: tuple[str, ...] | list[str] | set[str] | None = None,
) -> SessionPrincipal:
    return SessionPrincipal(
        principal_id=_clean(principal_id),
        principal_type=_clean_lower(principal_type) or "unknown",
        org_id=_clean(org_id) or None,
        roles=_normalize_string_values(roles),
        permissions=_normalize_string_values(permissions),
    )


def create_session_record(
    *,
    principal: SessionPrincipal,
    secret: str | None = None,
    session_id: str | None = None,
    policy: SessionPolicy | None = None,
    now: datetime | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> tuple[SessionRecord, str]:
    active_policy = policy or SessionPolicy()
    issued_at = _ensure_utc(now) or utc_now()
    raw_secret = _clean(secret) or generate_session_secret()
    resolved_session_id = _clean(session_id) or generate_session_id()

    record = SessionRecord(
        session_id=resolved_session_id,
        principal=principal,
        secret_fingerprint=fingerprint_session_secret(raw_secret),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=active_policy.absolute_timeout_seconds),
        idle_expires_at=issued_at + timedelta(seconds=active_policy.idle_timeout_seconds),
        last_seen_at=issued_at,
        created_ip=_clean(ip_address) or None,
        last_ip=_clean(ip_address) or None,
        user_agent=_clean(user_agent) or None,
        rotated_at=None,
        revoked_at=None,
        revocation_reason=None,
        metadata=_stringify_metadata(metadata),
    )
    return record, raw_secret


def validate_session_record(
    record: SessionRecord,
    *,
    presented_secret: str,
    policy: SessionPolicy | None = None,
    now: datetime | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> SessionValidationResult:
    active_policy = policy or SessionPolicy()
    current_time = _ensure_utc(now) or utc_now()
    metadata: dict[str, str] = {}

    if record.revoked_at is not None:
        return SessionValidationResult(
            valid=False,
            reason="session_revoked",
            session_id=record.session_id,
            principal_id=record.principal.principal_id,
            org_id=record.principal.org_id,
            metadata=metadata,
        )

    if current_time >= record.expires_at:
        return SessionValidationResult(
            valid=False,
            reason="session_expired",
            session_id=record.session_id,
            principal_id=record.principal.principal_id,
            org_id=record.principal.org_id,
            metadata=metadata,
        )

    if current_time >= record.idle_expires_at:
        return SessionValidationResult(
            valid=False,
            reason="session_idle_timeout",
            session_id=record.session_id,
            principal_id=record.principal.principal_id,
            org_id=record.principal.org_id,
            metadata=metadata,
        )

    if not constant_time_equals(
        record.secret_fingerprint,
        fingerprint_session_secret(presented_secret),
    ):
        return SessionValidationResult(
            valid=False,
            reason="invalid_session_secret",
            session_id=record.session_id,
            principal_id=record.principal.principal_id,
            org_id=record.principal.org_id,
            metadata=metadata,
        )

    normalized_ip = _clean(ip_address) or None
    if active_policy.require_ip_binding and record.last_ip and normalized_ip != record.last_ip:
        metadata["expected_ip"] = record.last_ip
        metadata["presented_ip"] = normalized_ip or ""
        return SessionValidationResult(
            valid=False,
            reason="ip_binding_mismatch",
            session_id=record.session_id,
            principal_id=record.principal.principal_id,
            org_id=record.principal.org_id,
            metadata=metadata,
        )

    normalized_user_agent = _clean(user_agent) or None
    if (
        active_policy.require_user_agent_binding
        and record.user_agent
        and normalized_user_agent != record.user_agent
    ):
        metadata["expected_user_agent"] = record.user_agent
        metadata["presented_user_agent"] = normalized_user_agent or ""
        return SessionValidationResult(
            valid=False,
            reason="user_agent_mismatch",
            session_id=record.session_id,
            principal_id=record.principal.principal_id,
            org_id=record.principal.org_id,
            metadata=metadata,
        )

    should_rotate = False
    if active_policy.enforce_secret_rotation:
        renewal_start = record.expires_at - timedelta(seconds=active_policy.renewal_window_seconds)
        should_rotate = current_time >= renewal_start

    return SessionValidationResult(
        valid=True,
        reason="valid",
        session_id=record.session_id,
        principal_id=record.principal.principal_id,
        org_id=record.principal.org_id,
        should_rotate=should_rotate,
        metadata=metadata,
    )


def touch_session_record(
    record: SessionRecord,
    *,
    policy: SessionPolicy | None = None,
    now: datetime | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> SessionRecord:
    active_policy = policy or SessionPolicy()
    current_time = _ensure_utc(now) or utc_now()

    return SessionRecord(
        session_id=record.session_id,
        principal=record.principal,
        secret_fingerprint=record.secret_fingerprint,
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        idle_expires_at=current_time + timedelta(seconds=active_policy.idle_timeout_seconds),
        last_seen_at=current_time,
        created_ip=record.created_ip,
        last_ip=_clean(ip_address) or record.last_ip,
        user_agent=_clean(user_agent) or record.user_agent,
        rotated_at=record.rotated_at,
        revoked_at=record.revoked_at,
        revocation_reason=record.revocation_reason,
        metadata=dict(record.metadata),
    )


def rotate_session_secret(
    record: SessionRecord,
    *,
    new_secret: str | None = None,
    now: datetime | None = None,
    policy: SessionPolicy | None = None,
) -> tuple[SessionRecord, str]:
    active_policy = policy or SessionPolicy()
    current_time = _ensure_utc(now) or utc_now()
    raw_secret = _clean(new_secret) or generate_session_secret()

    rotated = SessionRecord(
        session_id=record.session_id,
        principal=record.principal,
        secret_fingerprint=fingerprint_session_secret(raw_secret),
        issued_at=record.issued_at,
        expires_at=current_time + timedelta(seconds=active_policy.absolute_timeout_seconds),
        idle_expires_at=current_time + timedelta(seconds=active_policy.idle_timeout_seconds),
        last_seen_at=current_time,
        created_ip=record.created_ip,
        last_ip=record.last_ip,
        user_agent=record.user_agent,
        rotated_at=current_time,
        revoked_at=record.revoked_at,
        revocation_reason=record.revocation_reason,
        metadata=dict(record.metadata),
    )
    return rotated, raw_secret


def revoke_session_record(
    record: SessionRecord,
    *,
    reason: str = "revoked",
    now: datetime | None = None,
) -> SessionRecord:
    current_time = _ensure_utc(now) or utc_now()
    return SessionRecord(
        session_id=record.session_id,
        principal=record.principal,
        secret_fingerprint=record.secret_fingerprint,
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        idle_expires_at=record.idle_expires_at,
        last_seen_at=record.last_seen_at,
        created_ip=record.created_ip,
        last_ip=record.last_ip,
        user_agent=record.user_agent,
        rotated_at=record.rotated_at,
        revoked_at=current_time,
        revocation_reason=_clean(reason) or "revoked",
        metadata=dict(record.metadata),
    )


def session_is_active(record: SessionRecord, *, now: datetime | None = None) -> bool:
    current_time = _ensure_utc(now) or utc_now()
    return (
        record.revoked_at is None
        and current_time < record.expires_at
        and current_time < record.idle_expires_at
    )


def _normalize_string_values(
    values: tuple[str, ...] | list[str] | set[str] | None,
) -> tuple[str, ...]:
    if values is None:
        return ()

    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = _clean_lower(value)
        if not cleaned or cleaned in seen:
            continue
        normalized.append(cleaned)
        seen.add(cleaned)

    return tuple(normalized)


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(value) for key, value in metadata.items()}