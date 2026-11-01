from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.core.apikeys import (
    APIKeyRecord,
    fingerprint_api_key,
    get_api_key_registry,
    is_api_key_expired,
)
from app.core.auth import AuthContext
from app.core.org_isolation import evaluate_org_isolation
from app.core.permissions import evaluate_permission
from app.core.principals import Principal, build_principal
from app.core.session_security import (
    SessionPolicy,
    SessionRecord,
    SessionValidationResult,
    build_session_principal,
    create_session_record,
    revoke_session_record,
    rotate_session_secret,
    touch_session_record,
    validate_session_record,
)


def _clean(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _clean_lower(value: object) -> str:
    return _clean(value).lower()


def _stringify_metadata(metadata: Mapping[str, object] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    return {str(key): str(item) for key, item in metadata.items()}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _getattr_safe(obj: object, attr: str) -> object:
    try:
        return getattr(obj, attr, None)
    except Exception:
        return None


@dataclass(frozen=True, slots=True)
class AuthResult:
    authenticated: bool
    context: AuthContext
    principal: Principal | None = None
    session: SessionRecord | None = None
    validation: SessionValidationResult | None = None
    reason: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "context": {
                "authenticated": self.context.authenticated,
                "principal_id": self.context.principal_id,
                "principal_type": self.context.principal_type,
                "org_id": self.context.org_id,
                "roles": list(self.context.roles),
                "permissions": list(self.context.permissions),
                "session_id": self.context.session_id,
                "auth_method": self.context.auth_method,
                "metadata": dict(self.context.metadata),
            },
            "principal": self.principal.to_dict() if self.principal else None,
            "session": self.session.to_dict() if self.session else None,
            "validation": self.validation.to_dict() if self.validation else None,
            "reason": self.reason,
        }


class AuthService:
    def __init__(self, *, session_policy: SessionPolicy | None = None) -> None:
        self._session_policy = session_policy or SessionPolicy()

    @property
    def session_policy(self) -> SessionPolicy:
        return self._session_policy

    # ------------------------------------------------------------------
    # API Key authentication — O(1) SHA-256 fingerprint lookup
    # ------------------------------------------------------------------

    def authenticate_api_key(
        self,
        raw_key: str,
        *,
        now: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuthResult:
        """
        Authenticate a raw API key against the registry using O(1) SHA-256
        fingerprint lookup via registry.get_by_fingerprint().

        Guard chain (fail-closed):
          1. Compute SHA-256 fingerprint via fingerprint_api_key().
          2. Look up record by fingerprint — O(1), no plaintext stored in lookup path.
          3. Reject if record not found.
          4. Reject if active is False  (revoked = FALSE guard).
          5. Reject if revoked_at is not None (belt-and-suspenders).
          6. Reject if expires_at is present and <= now (expires_at > NOW() guard).
          7. Write last_used_at via record.touch() + registry.upsert_record().
          8. Return AuthResult authenticated=True, auth_method="api_key".
        """
        effective_now = now or _utc_now()
        fingerprint = fingerprint_api_key(raw_key)

        registry = get_api_key_registry()
        record: APIKeyRecord | None = None

        get_by_fp = getattr(registry, "get_by_fingerprint", None)
        if callable(get_by_fp):
            try:
                record = get_by_fp(fingerprint)
            except Exception:
                record = None
        else:
            # Hard fallback: registry does not yet expose get_by_fingerprint.
            # Scan list_keys() by fingerprint — slower but safe.
            list_keys = getattr(registry, "list_keys", None)
            if callable(list_keys):
                try:
                    for candidate in list_keys():
                        if getattr(candidate, "fingerprint", None) == fingerprint:
                            record = candidate
                            break
                except Exception:
                    record = None

        if record is None:
            return self._denied_api_key_result("key_not_found", metadata)

        # Guard: active flag (revoked = FALSE)
        if not getattr(record, "active", True):
            return self._denied_api_key_result("key_revoked", metadata)

        # Guard: explicit revoked_at timestamp
        if getattr(record, "revoked_at", None) is not None:
            return self._denied_api_key_result("key_revoked", metadata)

        # Guard: expires_at > NOW()
        expires_at = getattr(record, "expires_at", None)
        if is_api_key_expired(expires_at, now=effective_now):
            return self._denied_api_key_result("key_expired", metadata)

        # Write last_used_at on successful auth
        touch = getattr(record, "touch", None)
        if callable(touch):
            try:
                touched = touch()
                upsert = getattr(registry, "upsert_record", None)
                if callable(upsert):
                    try:
                        upsert(touched)
                        record = touched
                    except Exception:
                        pass
            except Exception:
                pass

        principal_id: str | None = None
        for attr in ("key_id", "id", "client_id", "owner_id", "principal_id"):
            val = _clean(_getattr_safe(record, attr))
            if val:
                principal_id = val
                break

        org_id: str | None = None
        for attr in ("org_id", "organization_id", "tenant_id"):
            val = _clean(_getattr_safe(record, attr))
            if val:
                org_id = val
                break

        permissions: tuple[str, ...] = ()
        for attr in ("permissions", "scopes", "allowed_actions"):
            val = getattr(record, attr, None)
            if isinstance(val, list | tuple | set):
                permissions = tuple(str(s).strip() for s in val if str(s).strip())
                break

        roles: tuple[str, ...] = ()
        for attr in ("roles", "role_names", "grants"):
            val = getattr(record, attr, None)
            if isinstance(val, list | tuple | set):
                roles = tuple(str(s).strip() for s in val if str(s).strip())
                break

        extra_meta = _stringify_metadata(metadata)
        extra_meta["fingerprint"] = fingerprint
        if ip_address:
            extra_meta["ip_address"] = ip_address
        if user_agent:
            extra_meta["user_agent"] = user_agent

        context = AuthContext(
            api_key=_clean(_getattr_safe(record, "masked_key")) or None,
            principal_type="api_key",
            principal_id=principal_id,
            session_id=None,
            org_id=org_id,
            permissions=permissions,
            roles=roles,
            authenticated=True,
            auth_source="registry",
            auth_method="api_key",
            metadata=extra_meta,
        )

        return AuthResult(
            authenticated=True,
            context=context,
            principal=None,
            session=None,
            validation=None,
            reason="ok",
        )

    def _denied_api_key_result(
        self,
        reason: str,
        metadata: Mapping[str, object] | None,
    ) -> AuthResult:
        context = AuthContext(
            api_key=None,
            principal_type="anonymous",
            principal_id=None,
            session_id=None,
            org_id=None,
            permissions=(),
            roles=(),
            authenticated=False,
            auth_source="registry",
            auth_method="api_key",
            metadata=_stringify_metadata(metadata),
        )
        return AuthResult(
            authenticated=False,
            context=context,
            principal=None,
            session=None,
            validation=None,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Principal construction
    # ------------------------------------------------------------------

    def build_principal(
        self,
        *,
        principal_id: str,
        principal_type: str,
        org_id: str | None = None,
        email: str | None = None,
        display_name: str | None = None,
        roles: tuple[str, ...] | list[str] | set[str] | None = None,
        permissions: tuple[str, ...] | list[str] | set[str] | None = None,
        active: bool = True,
        service_name: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Principal:
        return build_principal(
            principal_id=principal_id,
            principal_type=principal_type,
            org_id=org_id,
            email=email,
            display_name=display_name,
            roles=roles,
            permissions=permissions,
            active=active,
            service_name=service_name,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def issue_session(
        self,
        *,
        principal: Principal,
        secret: str | None = None,
        session_id: str | None = None,
        now: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> tuple[SessionRecord, str]:
        session_principal = build_session_principal(
            principal_id=principal.principal_id,
            principal_type=principal.principal_type,
            org_id=principal.org_id,
            roles=principal.roles,
            permissions=principal.permissions,
        )
        return create_session_record(
            principal=session_principal,
            secret=secret,
            session_id=session_id,
            policy=self._session_policy,
            now=now,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata,
        )

    def authenticate_session(
        self,
        *,
        principal: Principal,
        session: SessionRecord,
        presented_secret: str,
        now: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        auth_method: str = "session",
        metadata: Mapping[str, object] | None = None,
    ) -> AuthResult:
        validation = validate_session_record(
            session,
            presented_secret=presented_secret,
            policy=self._session_policy,
            now=now,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        context = self._build_auth_context(
            principal=principal,
            session=session,
            authenticated=validation.valid and principal.active,
            auth_method=auth_method,
            metadata=metadata,
        )

        reason = validation.reason
        if validation.valid and not principal.active:
            reason = "principal_inactive"

        return AuthResult(
            authenticated=validation.valid and principal.active,
            context=context,
            principal=principal,
            session=session,
            validation=validation,
            reason=reason,
        )

    def refresh_session(
        self,
        session: SessionRecord,
        *,
        now: datetime | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SessionRecord:
        return touch_session_record(
            session,
            policy=self._session_policy,
            now=now,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def rotate_session(
        self,
        session: SessionRecord,
        *,
        new_secret: str | None = None,
        now: datetime | None = None,
    ) -> tuple[SessionRecord, str]:
        return rotate_session_secret(
            session,
            new_secret=new_secret,
            now=now,
            policy=self._session_policy,
        )

    def revoke_session(
        self,
        session: SessionRecord,
        *,
        reason: str = "revoked",
        now: datetime | None = None,
    ) -> SessionRecord:
        return revoke_session_record(
            session,
            reason=reason,
            now=now,
        )

    # ------------------------------------------------------------------
    # Authorization helpers
    # ------------------------------------------------------------------

    def check_permission(
        self,
        context: AuthContext,
        permission: str,
        *,
        resource_org_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> bool:
        decision = evaluate_permission(
            context,
            permission,
            resource_org_id=resource_org_id,
            metadata=metadata,
        )
        return decision.allowed

    def check_org_access(
        self,
        context: AuthContext,
        *,
        target_org_id: str | None,
        metadata: Mapping[str, object] | None = None,
    ) -> bool:
        decision = evaluate_org_isolation(
            context,
            target_org_id=target_org_id,
            metadata=metadata,
        )
        return decision.allowed

    def build_anonymous_context(
        self,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> AuthContext:
        return AuthContext(
            api_key=None,
            authenticated=False,
            principal_id=None,
            principal_type="anonymous",
            org_id=None,
            roles=(),
            permissions=(),
            session_id=None,
            auth_method=None,
            auth_source="none",
            metadata=_stringify_metadata(metadata),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_auth_context(
        self,
        *,
        principal: Principal,
        session: SessionRecord | None,
        authenticated: bool,
        auth_method: str | None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuthContext:
        combined_metadata = dict(principal.metadata)
        combined_metadata.update(_stringify_metadata(metadata))

        return AuthContext(
            api_key=None,
            authenticated=authenticated,
            principal_id=principal.principal_id,
            principal_type=_clean_lower(principal.principal_type) or "unknown",
            org_id=_clean(principal.org_id) or None,
            roles=principal.roles,
            permissions=principal.permissions,
            session_id=session.session_id if session else None,
            auth_method=_clean_lower(auth_method) or None,
            auth_source="session",
            metadata=combined_metadata,
        )


def build_auth_service(
    *,
    session_policy: SessionPolicy | None = None,
) -> AuthService:
    return AuthService(session_policy=session_policy)
