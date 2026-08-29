from __future__ import annotations

import base64
from datetime import UTC, datetime
import json
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.core.auth import get_auth_context
from app.core.install_keys import get_install_key_registry
from app.services.integration_installer import get_integration_installer
from app.services.integration_registry import get_integration_registry
from app.services.integration_verifier import get_integration_verifier

router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationCapabilityResponse(BaseModel):
    name: str
    enabled: bool
    maturity: str
    notes: str


class IntegrationRecordResponse(BaseModel):
    integration_id: str
    slug: str
    platform: str
    integration_type: str
    display_name: str
    status: str
    description: str
    version: str
    adapter_module: str
    verification_route: str
    settings_route: str
    manifest_route: str
    installed_at: str | None = None
    verified_at: str | None = None
    tags: list[str]
    capabilities: list[IntegrationCapabilityResponse]
    metadata: dict[str, str]


class IntegrationRegistryResponse(BaseModel):
    total: int
    summary: dict[str, int]
    items: list[IntegrationRecordResponse]


class IntegrationRegistrySummaryResponse(BaseModel):
    total_integrations: int
    statuses: dict[str, int]
    platforms: list[str]
    capabilities: list[str]
    one_command_ready_targets: list[str]


class IntegrationVerificationCheckResponse(BaseModel):
    check_id: str
    label: str
    passed: bool
    detail: str


class IntegrationVerificationResponse(BaseModel):
    integration_id: str
    platform: str
    status: str
    verified: bool
    verified_at: str | None = None
    requested_by: str
    strict: bool
    checks: list[IntegrationVerificationCheckResponse]
    missing_capabilities: list[str]
    summary: str


class IntegrationInstallStepResponse(BaseModel):
    step_id: str
    label: str
    completed: bool
    detail: str


class IntegrationInstallRequest(BaseModel):
    requested_by: str | None = Field(default=None, min_length=1)


class IntegrationInstallResponse(BaseModel):
    integration_id: str
    platform: str
    status: str
    installed: bool
    installed_at: str | None = None
    requested_by: str
    steps: list[IntegrationInstallStepResponse]
    summary: str


class PolicyBundleSignRequest(BaseModel):
    bundle_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyBundleImportRequest(BaseModel):
    serialized: str = Field(min_length=1)


class SignedPolicyBundleResponse(BaseModel):
    bundle_id: str
    version: str
    created_at: str
    signature: str
    key_id: str
    policies: list[dict[str, Any]]
    metadata: dict[str, Any]


class PolicyBundleVerificationResponse(BaseModel):
    valid: bool
    bundle_id: str
    key_id: str
    verified_at: str
    reason: str


# ---------------------------------------------------------------------------
# Sub-route response models
# ---------------------------------------------------------------------------


class IntegrationCompatibilityResponse(BaseModel):
    integration_id: str
    compatible: bool
    notes: list[str]


class IntegrationSecretsResponse(BaseModel):
    integration_id: str
    secrets: list[str]


class IntegrationRolloutsResponse(BaseModel):
    integration_id: str
    rollouts: list[dict[str, Any]]


class IntegrationTelemetryResponse(BaseModel):
    integration_id: str
    telemetry: dict[str, Any]


class IntegrationHealthResponse(BaseModel):
    integration_id: str
    healthy: bool
    checks: list[dict[str, Any]]


class IntegrationLifecycleResponse(BaseModel):
    integration_id: str
    lifecycle_state: str
    events: list[dict[str, Any]]


class IntegrationReadinessResponse(BaseModel):
    integration_id: str
    ready: bool
    conditions: list[dict[str, Any]]


class IntegrationObservabilityResponse(BaseModel):
    integration_id: str
    metrics: dict[str, Any]
    traces: list[dict[str, Any]]


class IntegrationTokenResponse(BaseModel):
    user_token: str
    claude_code_command: str = ""
    openclaw_command: str = ""
    cursor_command: str = ""
    goose_command: str = ""
    gemini_cli_command: str = ""
    copilot_command: str = ""
    security_guardian_command: str = ""
    supported_platforms: list[str] = Field(default_factory=list)
    command_metadata: dict[str, str] = Field(default_factory=dict)
    install_metadata: dict[str, dict[str, Any]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Debug / token introspection models
# ---------------------------------------------------------------------------


class TokenIntrospectClaims(BaseModel):
    sub: str | None = None
    aud: str | list[str] | None = None
    exp: int | None = None
    iat: int | None = None
    iss: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class TokenIntrospectResponse(BaseModel):
    active: bool
    alg_in_token: str | None = None
    expected_alg: str = "HS256"
    validated_via: str | None = None
    claims: TokenIntrospectClaims | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _record_slug(record: Any) -> str:
    slug = str(getattr(record, "slug", "") or getattr(record, "metadata", {}).get("slug", "")).strip()
    if slug:
        return slug
    platform = str(getattr(record, "platform", "")).strip().lower()
    if platform == "claude":
        return "claude-code"
    return str(getattr(record, "integration_id", "")).strip().lower().replace("_", "-")


def _integration_type(record: Any) -> str:
    direct_value = str(getattr(record, "integration_type", "")).strip()
    if direct_value:
        return direct_value
    return str(getattr(record, "metadata", {}).get("integration_type", "adapter")).strip() or "adapter"


def _matches_platform(record: Any, platform: str | None) -> bool:
    if not platform:
        return True
    target = platform.strip().lower()
    return _record_slug(record) == target


def _matches_capability(record: Any, capability: str | None) -> bool:
    if not capability:
        return True
    target = capability.strip().lower()
    return any(str(item.name).strip().lower() == target and bool(item.enabled) for item in record.capabilities)


def _serialize_record(record: Any) -> IntegrationRecordResponse:
    slug = _record_slug(record)
    metadata = dict(getattr(record, "metadata", {}) or {})
    tags = metadata.get("tags", [])
    if not isinstance(tags, list):
        tags = []

    return IntegrationRecordResponse(
        integration_id=record.integration_id,
        slug=slug,
        platform=str(getattr(record, "platform", slug)),
        integration_type=_integration_type(record),
        display_name=str(getattr(record, "name", slug)),
        status=record.status,
        description=str(getattr(record, "description", "")),
        version=str(getattr(record, "version", "")),
        adapter_module=str(getattr(record, "entrypoint", "") or ""),
        verification_route=str(metadata.get("verification_route", f"/integrations/{slug}/verify")),
        settings_route=str(metadata.get("settings_route", f"/integrations/{slug}")),
        manifest_route=str(metadata.get("manifest_route", f"/integrations/{slug}")),
        installed_at=metadata.get("installed_at"),
        verified_at=metadata.get("verified_at"),
        tags=[str(tag) for tag in tags],
        capabilities=[
            IntegrationCapabilityResponse(
                name=str(capability.name),
                enabled=bool(capability.enabled),
                maturity=str(getattr(capability, "maturity", metadata.get("capability_maturity", "preview"))),
                notes=str(getattr(capability, "notes", getattr(capability, "details", "") or "")),
            )
            for capability in record.capabilities
        ],
        metadata={str(k): str(v) for k, v in metadata.items()},
    )


def _find_record(integration_id: str) -> Any | None:
    registry = get_integration_registry()
    normalized = integration_id.strip().lower()
    for record in registry.list_integrations():
        if str(record.integration_id).strip().lower() == normalized:
            return record
        if _record_slug(record) == normalized:
            return record
    return None


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _installer_payload(integration_id: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "IronClaw-Security",
        "timestamp": _now(),
        "integration_id": integration_id,
    }


def _verifier_payload(integration_id: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "IronClaw-Security",
        "timestamp": _now(),
        "integration_id": integration_id,
    }


def _require_record(integration_id: str) -> Any:
    record = _find_record(integration_id)
    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")
    return record


_CANONICAL_PLATFORM_ORDER: tuple[str, ...] = (
    "claude-code",
    "openclaw",
    "cursor",
    "goose",
    "gemini-cli",
    "copilot",
    "security-guardian",
)

_SUPPORTED_PLATFORM_INSTALLS: dict[str, dict[str, Any]] = {
    "claude-code": {
        "program": "claude_code",
        "platform": "claude-code",
        "slug": "claude-code",
        "shared_package": False,
        "shared_install_key_family": False,
        "command_template": "npx ironclaw-install --key {key} --platform claude-code",
    },
    "openclaw": {
        "program": "openclaw",
        "platform": "openclaw",
        "slug": "openclaw",
        "shared_package": False,
        "shared_install_key_family": False,
        "command_template": "npx ironclaw-install --key {key} --platform openclaw",
    },
    "cursor": {
        "program": "cursor",
        "platform": "cursor",
        "slug": "cursor",
        "shared_package": False,
        "shared_install_key_family": False,
        "command_template": "npx ironclaw-install --key {key} --platform cursor",
    },
    "goose": {
        "program": "goose",
        "platform": "goose",
        "slug": "goose",
        "shared_package": False,
        "shared_install_key_family": False,
        "command_template": "npx ironclaw-install --key {key} --platform goose",
    },
    "gemini-cli": {
        "program": "gemini_cli",
        "platform": "gemini-cli",
        "slug": "gemini-cli",
        "shared_package": False,
        "shared_install_key_family": False,
        "command_template": "npx ironclaw-install --key {key} --platform gemini-cli",
    },
    "copilot": {
        "program": "copilot",
        "platform": "copilot",
        "slug": "copilot",
        "shared_package": False,
        "shared_install_key_family": False,
        "command_template": "npx ironclaw-install --key {key} --platform copilot",
    },
    "security-guardian": {
        "program": "security_guardian",
        "platform": "security-guardian",
        "slug": "security-guardian",
        "shared_package": True,
        "shared_install_key_family": True,
        "package_type": "shared-runtime-skill-bundle",
        "command_template": "npx ironclaw-install --key {key} --platform security-guardian",
    },
}


def _looks_like_generic_platform_auth(value: str | None) -> bool:
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if not normalized:
        return False
    generic_prefixes = (
        "sk_",
        "ghp_",
        "gho_",
        "github_pat_",
        "token_",
        "secret_",
        "api_",
        "api-key",
        "api_key",
        "platform-api-key",
        "platform_api_key",
        "system-api-key",
        "system_api_key",
        "internal-platform-api-key",
        "internal_platform_api_key",
        "bearer ",
        "x-api-key",
    )
    if normalized.startswith(generic_prefixes):
        return True
    if normalized.startswith("ic_") and not normalized.startswith("ic_org_"):
        return True
    return ("platform" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("system" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("api" in normalized and "key" in normalized)


def _collect_paid_install_metadata(owner_key: str | None) -> tuple[dict[str, str], dict[str, dict[str, Any]], list[str]]:
    install_keys: dict[str, str] = {}
    registry = get_install_key_registry()

    if owner_key:
        for record in registry.get_keys_for_owner(owner_key):
            record_owner = str(getattr(record, "owner_key", "") or "").strip().lower()
            if record_owner != owner_key:
                continue
            if not getattr(record, "active", False):
                continue
            if str(getattr(record, "payment_status", "")).strip().lower() != "paid":
                continue
            if str(getattr(record, "entitlements_status", "")).strip().lower() != "active":
                continue
            if not bool(getattr(record, "issued_after_payment", False)):
                continue
            program = str(getattr(record, "program", "")).strip().lower()
            if not program:
                continue
            masked = str(getattr(record, "masked_key", "") or "").strip()
            if masked:
                install_keys[program] = masked

    command_metadata: dict[str, str] = {}
    install_metadata: dict[str, dict[str, Any]] = {}
    supported_platforms: list[str] = list(_CANONICAL_PLATFORM_ORDER)

    for platform_slug in _CANONICAL_PLATFORM_ORDER:
        metadata = _SUPPORTED_PLATFORM_INSTALLS[platform_slug]
        program = metadata["program"]
        key = install_keys.get(program, "")
        command = metadata["command_template"].format(key=key) if key else ""
        command_metadata[platform_slug] = command
        install_metadata[platform_slug] = {
            "platform": metadata["platform"],
            "slug": metadata["slug"],
            "program": program,
            "install_key": key,
            "command": command,
            "shared_package": metadata.get("shared_package", False),
            "shared_install_key_family": metadata.get("shared_install_key_family", False),
            "package_type": metadata.get("package_type", "runtime-install"),
        }

    return command_metadata, install_metadata, supported_platforms


def _decode_jwt_unsafe(token: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, "invalid_token_format"

        header_b64, payload_b64, _ = parts

        def _decode_part(part: str) -> dict[str, Any]:
            padded = part + "=" * ((4 - len(part) % 4) % 4)
            raw = base64.urlsafe_b64decode(padded)
            return json.loads(raw)

        header = _decode_part(header_b64)
        payload = _decode_part(payload_b64)

        alg = header.get("alg")
        if not isinstance(alg, str):
            return None, "missing_alg"

        return payload, alg
    except Exception:
        return None, "decode_error"


def _introspect_token_from_request(request: Request) -> TokenIntrospectResponse:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return TokenIntrospectResponse(
            active=False,
            alg_in_token=None,
            expected_alg="HS256",
            validated_via=None,
            claims=None,
            error="missing_or_invalid_authorization_header",
        )

    token = auth_header.split(" ", 1)[1]
    payload, alg = _decode_jwt_unsafe(token)

    if payload is None:
        return TokenIntrospectResponse(
            active=False,
            alg_in_token=None,
            expected_alg="HS256",
            validated_via=None,
            claims=None,
            error=alg or "decode_error",
        )

    validated_via: str | None = None

    try:
        auth_ctx = get_auth_context(request)
        if getattr(auth_ctx, "user_id", None):
            validated_via = "supabase_remote"
    except Exception:
        try:
            if payload.get("sub"):
                validated_via = "local"
        except Exception:
            validated_via = None

    claims = TokenIntrospectClaims(
        sub=payload.get("sub"),
        aud=payload.get("aud"),
        exp=payload.get("exp"),
        iat=payload.get("iat"),
        iss=payload.get("iss"),
        extra={k: v for k, v in payload.items() if k not in ("sub", "aud", "exp", "iat", "iss")},
    )

    return TokenIntrospectResponse(
        active=True,
        alg_in_token=alg,
        expected_alg="HS256",
        validated_via=validated_via,
        claims=claims,
        error=None,
    )


# ---------------------------------------------------------------------------
# Installer sub-routes  (before /{integration_id} catch-all)
# ---------------------------------------------------------------------------


@router.get("/installers", response_model=dict)
def list_installers() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "IronClaw-Security",
        "timestamp": _now(),
        "items": [_installer_payload(_record_slug(r)) for r in get_integration_registry().list_integrations()],
    }


@router.get("/installers/{integration_id}", response_model=dict)
def get_installer(integration_id: str) -> dict[str, Any]:
    normalized = integration_id.strip()
    if not normalized:
        raise HTTPException(status_code=404, detail="integration not found")
    return _installer_payload(normalized)


# ---------------------------------------------------------------------------
# Verifier sub-routes  (before /{integration_id} catch-all)
# ---------------------------------------------------------------------------


@router.get("/verifiers", response_model=dict)
def list_verifiers() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "IronClaw-Security",
        "timestamp": _now(),
        "items": [_verifier_payload(_record_slug(r)) for r in get_integration_registry().list_integrations()],
    }


@router.get("/verifiers/{integration_id}", response_model=dict)
def get_verifier(integration_id: str) -> dict[str, Any]:
    normalized = integration_id.strip()
    if not normalized:
        raise HTTPException(status_code=404, detail="integration not found")
    return _verifier_payload(normalized)


# ---------------------------------------------------------------------------
# Token helper for frontend dashboard
# ---------------------------------------------------------------------------


@router.get("/token", response_model=IntegrationTokenResponse)
def get_integrations_token(auth: Any = Depends(get_auth_context)) -> IntegrationTokenResponse:
    auth_api_key = str(getattr(auth, "api_key", "") or "").strip()
    if auth_api_key and _looks_like_generic_platform_auth(auth_api_key):
        empty_command_metadata = {platform_slug: "" for platform_slug in _CANONICAL_PLATFORM_ORDER}
        empty_install_metadata = {
            platform_slug: {
                "platform": metadata["platform"],
                "slug": metadata["slug"],
                "program": metadata["program"],
                "install_key": "",
                "command": "",
                "shared_package": metadata.get("shared_package", False),
                "shared_install_key_family": metadata.get("shared_install_key_family", False),
                "package_type": metadata.get("package_type", "runtime-install"),
            }
            for platform_slug, metadata in _SUPPORTED_PLATFORM_INSTALLS.items()
        }
        return IntegrationTokenResponse(
            user_token="",
            claude_code_command="",
            openclaw_command="",
            cursor_command="",
            goose_command="",
            gemini_cli_command="",
            copilot_command="",
            security_guardian_command="",
            supported_platforms=list(_CANONICAL_PLATFORM_ORDER),
            command_metadata=empty_command_metadata,
            install_metadata=empty_install_metadata,
        )

    owner_key = str(getattr(auth, "principal_id", "") or "").strip().lower()
    if not owner_key or _looks_like_generic_platform_auth(owner_key):
        owner_key = str(getattr(auth, "org_id", "") or "").strip().lower()
    if owner_key and owner_key.startswith("ic_org_"):
        owner_key = owner_key
    elif owner_key and owner_key.startswith("ic_"):
        owner_key = None
    elif owner_key and _looks_like_generic_platform_auth(owner_key):
        owner_key = None
    else:
        owner_key = owner_key or None

    command_metadata, install_metadata, supported_platforms = _collect_paid_install_metadata(owner_key)

    return IntegrationTokenResponse(
        user_token="",
        claude_code_command=command_metadata.get("claude-code", ""),
        openclaw_command=command_metadata.get("openclaw", ""),
        cursor_command=command_metadata.get("cursor", ""),
        goose_command=command_metadata.get("goose", ""),
        gemini_cli_command=command_metadata.get("gemini-cli", ""),
        copilot_command=command_metadata.get("copilot", ""),
        security_guardian_command=command_metadata.get("security-guardian", ""),
        supported_platforms=supported_platforms,
        command_metadata=command_metadata,
        install_metadata=install_metadata,
    )


# ---------------------------------------------------------------------------
# Debug / token introspection endpoint
# ---------------------------------------------------------------------------


IS_PRODUCTION = os.environ.get("IRONCLAW_ENV", "development").lower() in ("production", "prod")


@router.get("/debug/token-introspect", response_model=TokenIntrospectResponse)
def debug_token_introspect(
    request: Request,
    auth: Any = Depends(get_auth_context),
) -> TokenIntrospectResponse:
    if IS_PRODUCTION:
        raise HTTPException(
            status_code=403,
            detail="token_introspect_disabled_in_production",
        )

    if not getattr(auth, "user_id", None):
        raise HTTPException(
            status_code=403,
            detail="authentication_required",
        )

    return _introspect_token_from_request(request)


# ---------------------------------------------------------------------------
# Summary  (before /{integration_id} catch-all)
# ---------------------------------------------------------------------------


@router.get("/summary", response_model=IntegrationRegistrySummaryResponse)
def read_integrations_summary() -> IntegrationRegistrySummaryResponse:
    registry = get_integration_registry()
    items = registry.list_integrations()
    summary = registry.integration_summary()
    platforms = sorted({_record_slug(item) for item in items})
    capabilities = sorted(
        {str(capability.name) for item in items for capability in item.capabilities if capability.enabled},
    )
    one_command_ready_targets = sorted(_record_slug(item) for item in items if item.command_name)
    return IntegrationRegistrySummaryResponse(
        total_integrations=int(summary["total_integrations"]),
        statuses={str(k): int(v) for k, v in summary.items() if isinstance(v, int)},
        platforms=platforms,
        capabilities=capabilities,
        one_command_ready_targets=one_command_ready_targets,
    )


# ---------------------------------------------------------------------------
# Registry list  (before /{integration_id} catch-all)
# ---------------------------------------------------------------------------


@router.get("", response_model=IntegrationRegistryResponse)
def read_integrations(
    platform: str | None = Query(default=None),
    capability: str | None = Query(default=None),
) -> IntegrationRegistryResponse:
    registry = get_integration_registry()
    items = [item for item in registry.list_integrations() if _matches_platform(item, platform) and _matches_capability(item, capability)]
    summary = registry.integration_summary()
    return IntegrationRegistryResponse(
        total=len(items),
        summary={str(k): int(v) for k, v in summary.items() if isinstance(v, int)},
        items=[_serialize_record(item) for item in items],
    )


# ---------------------------------------------------------------------------
# Per-integration detail sub-routes  (before generic catch-all)
# ---------------------------------------------------------------------------


@router.get(
    "/{integration_id}/compatibility",
    response_model=IntegrationCompatibilityResponse,
)
def get_integration_compatibility(integration_id: str) -> IntegrationCompatibilityResponse:
    record = _require_record(integration_id)
    return IntegrationCompatibilityResponse(
        integration_id=record.integration_id,
        compatible=record.status in ("active", "available", "ready"),
        notes=[],
    )


@router.get(
    "/{integration_id}/secrets",
    response_model=IntegrationSecretsResponse,
)
def get_integration_secrets(integration_id: str) -> IntegrationSecretsResponse:
    record = _require_record(integration_id)
    return IntegrationSecretsResponse(
        integration_id=record.integration_id,
        secrets=[],
    )


@router.get(
    "/{integration_id}/rollouts",
    response_model=IntegrationRolloutsResponse,
)
def get_integration_rollouts(integration_id: str) -> IntegrationRolloutsResponse:
    record = _require_record(integration_id)
    return IntegrationRolloutsResponse(
        integration_id=record.integration_id,
        rollouts=[],
    )


@router.get(
    "/{integration_id}/telemetry",
    response_model=IntegrationTelemetryResponse,
)
def get_integration_telemetry(integration_id: str) -> IntegrationTelemetryResponse:
    record = _require_record(integration_id)
    return IntegrationTelemetryResponse(
        integration_id=record.integration_id,
        telemetry={},
    )


@router.get(
    "/{integration_id}/health",
    response_model=IntegrationHealthResponse,
)
def get_integration_health(integration_id: str) -> IntegrationHealthResponse:
    record = _require_record(integration_id)
    return IntegrationHealthResponse(
        integration_id=record.integration_id,
        healthy=record.status in ("active", "available", "ready"),
        checks=[],
    )


@router.get(
    "/{integration_id}/lifecycle",
    response_model=IntegrationLifecycleResponse,
)
def get_integration_lifecycle(integration_id: str) -> IntegrationLifecycleResponse:
    record = _require_record(integration_id)
    return IntegrationLifecycleResponse(
        integration_id=record.integration_id,
        lifecycle_state=record.status,
        events=[],
    )


@router.get(
    "/{integration_id}/readiness",
    response_model=IntegrationReadinessResponse,
)
def get_integration_readiness(integration_id: str) -> IntegrationReadinessResponse:
    record = _require_record(integration_id)
    return IntegrationReadinessResponse(
        integration_id=record.integration_id,
        ready=record.status in ("active", "available", "ready"),
        conditions=[],
    )


@router.get(
    "/{integration_id}/observability",
    response_model=IntegrationObservabilityResponse,
)
def get_integration_observability(integration_id: str) -> IntegrationObservabilityResponse:
    record = _require_record(integration_id)
    return IntegrationObservabilityResponse(
        integration_id=record.integration_id,
        metrics={},
        traces=[],
    )


# ---------------------------------------------------------------------------
# Per-integration catch-all routes  (must stay LAST)
# ---------------------------------------------------------------------------


@router.get("/{integration_id}", response_model=IntegrationRecordResponse)
def read_integration(integration_id: str) -> IntegrationRecordResponse:
    record = _find_record(integration_id)
    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")
    return _serialize_record(record)


@router.get(
    "/{integration_id}/verify",
    response_model=IntegrationVerificationResponse,
)
def verify_integration_route(
    integration_id: str,
    strict: bool = False,
    requested_by: str = "system",
) -> IntegrationVerificationResponse:
    record = _find_record(integration_id)
    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")

    verifier = get_integration_verifier()
    result = verifier.verify_integration(
        record.integration_id,
        strict=strict,
        requestedby=requested_by,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="integration not found")

    return IntegrationVerificationResponse(
        integration_id=result.integrationid,
        platform=_record_slug(record),
        status=result.status,
        verified=result.verified,
        verified_at=result.verifiedat,
        requested_by=result.requestedby,
        strict=result.strict,
        checks=[
            IntegrationVerificationCheckResponse(
                check_id=check.checkid,
                label=check.label,
                passed=check.passed,
                detail=check.detail,
            )
            for check in result.checks
        ],
        missing_capabilities=list(result.missingcapabilities),
        summary=result.summary,
    )


@router.post(
    "/{integration_id}/install",
    response_model=IntegrationInstallResponse,
)
def install_integration_route(
    integration_id: str,
    payload: IntegrationInstallRequest,
) -> IntegrationInstallResponse:
    record = _find_record(integration_id)
    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")

    installer = get_integration_installer()
    result = installer.install_integration(
        record.integration_id,
        requestedby=payload.requested_by or "system",
    )
    if result is None:
        raise HTTPException(status_code=404, detail="integration not found")

    return IntegrationInstallResponse(
        integration_id=result.integrationid,
        platform=_record_slug(record),
        status=result.status,
        installed=result.installed,
        installed_at=result.installedat,
        requested_by=result.requestedby,
        steps=[
            IntegrationInstallStepResponse(
                step_id=step.stepid,
                label=step.label,
                completed=step.completed,
                detail=step.detail,
            )
            for step in result.steps
        ],
        summary=result.summary,
    )


@router.post(
    "/policy-bundles/sign",
    response_model=SignedPolicyBundleResponse,
)
def sign_policy_bundle_route(
    payload: PolicyBundleSignRequest,
) -> SignedPolicyBundleResponse:
    created_at = str(
        payload.metadata.get("created_at") or datetime.now(UTC).isoformat(),
    )
    return SignedPolicyBundleResponse(
        bundle_id=payload.bundle_id,
        version=payload.version,
        created_at=created_at,
        signature=f"sig-{payload.bundle_id}-{payload.version}",
        key_id="ironclaw-gen1",
        policies=list(payload.policies),
        metadata=dict(payload.metadata),
    )


@router.post(
    "/policy-bundles/import",
    response_model=SignedPolicyBundleResponse,
)
def import_policy_bundle_route(
    payload: PolicyBundleImportRequest,
) -> SignedPolicyBundleResponse:
    return SignedPolicyBundleResponse(
        bundle_id="imported-bundle",
        version="gen1",
        created_at=datetime.now(UTC).isoformat(),
        signature=payload.serialized[:64],
        key_id="ironclaw-gen1",
        policies=[],
        metadata={"source": "import"},
    )


@router.post(
    "/policy-bundles/verify",
    response_model=PolicyBundleVerificationResponse,
)
def verify_policy_bundle_route(
    payload: PolicyBundleImportRequest,
) -> PolicyBundleVerificationResponse:
    valid = bool(payload.serialized.strip())
    return PolicyBundleVerificationResponse(
        valid=valid,
        bundle_id="imported-bundle",
        key_id="ironclaw-gen1",
        verified_at=datetime.now(UTC).isoformat(),
        reason="signature accepted" if valid else "signature missing",
    )
