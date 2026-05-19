from __future__ import annotations

import logging
from typing import Annotated

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.apikeys import APIKeyRecord, authenticate_api_key
from app.core.settings import get_settings

logger = logging.getLogger(__name__)

_API_KEY_HEADER_SCHEME = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description=(
        "IronClaw-Security API key. "
        "Pass a valid `ic_…` key issued by the key-management endpoint. "
        "When AUTH_REQUIRED is enabled, platform keys configured via environment "
        "variables are also accepted. "
        "Keys are validated via constant-time comparison against the in-memory "
        "registry and must be active (not revoked)."
    ),
)


def _resolve_settings_key(raw_key: str) -> APIKeyRecord | None:
    settings = get_settings()

    candidates: list[tuple[str, str, tuple[str, ...]]] = []
    if settings.internal_platform_api_key:
        candidates.append(
            (
                settings.internal_platform_api_key,
                "internal-platform",
                ("system", "admin", "internal"),
            ),
        )
    if settings.platform_api_key:
        candidates.append(
            (settings.platform_api_key, "platform", ("system", "admin")),
        )
    if settings.admin_api_key:
        candidates.append(
            (settings.admin_api_key, "admin", ("system", "admin")),
        )
    if settings.api_key:
        candidates.append(
            (settings.api_key, "default", ("system",)),
        )

    import hmac

    for expected_key, label, scopes in candidates:
        if hmac.compare_digest(raw_key, expected_key):
            from app.core.apikeys import fingerprint_api_key, mask_api_key

            return APIKeyRecord(
                key_id=f"settings-{label}",
                api_key=raw_key,
                masked_key=mask_api_key(raw_key),
                fingerprint=fingerprint_api_key(raw_key),
                display_name=f"Settings/{label.capitalize()} Key",
                owner_key="ironclaw-system",
                scopes=scopes,
                active=True,
                created_by="settings",
                rate_plan="internal",
                metadata={"source": "settings", "label": label},
            )

    return None


def _make_synthetic_record(
    key_id: str,
    raw_key: str,
    display_name: str,
    scopes: tuple[str, ...],
    source: str,
) -> APIKeyRecord:
    from app.core.apikeys import fingerprint_api_key, mask_api_key

    return APIKeyRecord(
        key_id=key_id,
        api_key=raw_key,
        masked_key=mask_api_key(raw_key),
        fingerprint=fingerprint_api_key(raw_key),
        display_name=display_name,
        owner_key="ironclaw-system",
        scopes=scopes,
        active=True,
        created_by="system",
        rate_plan="internal",
        metadata={"source": source},
    )


async def api_key_header_auth(
    raw_key: Annotated[str | None, Security(_API_KEY_HEADER_SCHEME)],
) -> APIKeyRecord:
    settings = get_settings()

    # ---- No key provided ----
    if not raw_key:
        if not settings.auth_required:
            return _make_synthetic_record(
                key_id="noauth",
                raw_key="ic_noauth",
                display_name="Unauthenticated Request",
                scopes=("system",),
                source="noauth",
            )

        logger.warning("api_key_header_auth: missing X-API-Key header (auth_required=True)")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "missing_api_key",
                "message": "X-API-Key header is required.",
            },
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # ---- Registry lookup (ic_… keys) ----
    record = authenticate_api_key(raw_key, touch=True)

    if record is not None:
        if not record.active:
            logger.warning(
                "api_key_header_auth: revoked registry key key_id=%s owner=%s",
                record.key_id,
                record.owner_key,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "revoked_api_key",
                    "message": "This API key has been revoked and is no longer valid.",
                    "key_id": record.key_id,
                },
            )
        logger.debug(
            "api_key_header_auth: registry auth ok key_id=%s owner=%s scopes=%s",
            record.key_id,
            record.owner_key,
            record.scopes,
        )
        return record

    # ---- Settings-level fallback (platform / admin / api_key env vars) ----
    settings_record = _resolve_settings_key(raw_key)
    if settings_record is not None:
        logger.debug(
            "api_key_header_auth: settings-level auth ok key_id=%s",
            settings_record.key_id,
        )
        return settings_record

    # ---- Test environment fallback — only when auth is NOT required ----
    # When auth_required=True, an unrecognised key must be rejected even in
    # test mode. The passthrough is exclusively for test suites that run with
    # auth_required=False and no seeded registry/env-var keys.
    if settings.is_test and not settings.auth_required:
        logger.debug(
            "api_key_header_auth: test-env passthrough (auth_required=False) key prefix=%s",
            raw_key[:6] if len(raw_key) >= 6 else "???",
        )
        return _make_synthetic_record(
            key_id="test-passthrough",
            raw_key=raw_key,
            display_name="Test Passthrough Key",
            scopes=("system", "admin"),
            source="test",
        )

    # ---- Not found anywhere ----
    logger.warning(
        "api_key_header_auth: invalid key prefix=%s",
        raw_key[:6] if len(raw_key) >= 6 else "???",
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "invalid_api_key",
            "message": "The provided API key is invalid or does not exist.",
        },
        headers={"WWW-Authenticate": "ApiKey"},
    )


def require_scopes(*required: str):
    """Returns a FastAPI dependency that validates the API key AND asserts
    the resolved record holds all ``required`` scopes.

    Usage::

        @router.delete("/keys/{key_id}")
        async def revoke(
            api_key: Annotated[APIKeyRecord, Security(require_scopes("admin"))],
            key_id: str,
        ) -> ...:
            ...
    """

    async def _dependency(
        record: Annotated[APIKeyRecord, Security(api_key_header_auth)],
    ) -> APIKeyRecord:
        missing = [s for s in required if s not in record.scopes]
        if missing:
            logger.warning(
                "require_scopes: key_id=%s owner=%s missing_scopes=%s",
                record.key_id,
                record.owner_key,
                missing,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_scopes",
                    "message": "The API key does not have the required permission scopes.",
                    "required_scopes": list(required),
                    "missing_scopes": missing,
                },
            )
        return record

    return _dependency
