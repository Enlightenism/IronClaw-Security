from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.core.auth import get_auth_context
from app.core.billing import resolve_authenticated_billing_owner
from app.core.install_key_formats import RUNTIME_INSTALL_KEY_PROGRAMS, InstallKeyFormatRegistry
from app.core.install_keys import get_install_key_registry
from app.services.install_key_handoff import (
    InstallKeyHandoffError,
    InstallKeySecretUnavailableError,
    InvalidInstallKeyClaimError,
    get_install_key_handoff_service,
)

router = APIRouter(tags=["integration-routes"])

_PAID_PAYMENT_STATUSES = {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}
_ACTIVE_ENTITLEMENT_STATUSES = {"active", "paid", "enabled", "granted"}
_RUNTIME_PROGRAMS: frozenset[str] = frozenset(RUNTIME_INSTALL_KEY_PROGRAMS)
_SUPPORTED_PLATFORM_INSTALLS: dict[str, dict[str, Any]] = {}
for _program in RUNTIME_INSTALL_KEY_PROGRAMS:
    _spec = InstallKeyFormatRegistry.get_spec(_program)
    _SUPPORTED_PLATFORM_INSTALLS[_spec.canonical_slug] = {
        "program": _spec.program,
        "platform": _spec.canonical_slug,
        "slug": _spec.canonical_slug,
        "shared_package": False,
        "shared_install_key_family": False,
        "command_template": _spec.command_template,
    }

_CANONICAL_PLATFORM_ORDER: tuple[str, ...] = tuple(_SUPPORTED_PLATFORM_INSTALLS)


class InstallKeyClaimRedeemRequest(BaseModel):
    claim_token: str = Field(min_length=10, max_length=256, repr=False)


def _resolve_install_owner(auth: Any) -> str | None:
    return resolve_authenticated_billing_owner(auth)


def _is_valid_install_key_record(record: Any, *, owner_key: str, program: str) -> bool:
    if record is None:
        return False

    record_owner = str(getattr(record, "owner_key", "") or "").strip().lower()
    if record_owner != owner_key:
        return False

    canonical_program = InstallKeyFormatRegistry.normalize_program(str(getattr(record, "program", "") or "").strip())
    if canonical_program is None or canonical_program not in _RUNTIME_PROGRAMS:
        return False

    expected_program = InstallKeyFormatRegistry.normalize_program(program)
    if expected_program is None or expected_program != canonical_program:
        return False

    if not bool(getattr(record, "active", False)):
        return False

    payment_status = str(getattr(record, "payment_status", "") or "").strip().lower()
    if payment_status not in _PAID_PAYMENT_STATUSES:
        return False

    entitlements_status = str(getattr(record, "entitlements_status", "") or "").strip().lower()
    if entitlements_status not in _ACTIVE_ENTITLEMENT_STATUSES:
        return False

    if not bool(getattr(record, "issued_after_payment", False)):
        return False

    if not str(getattr(record, "key_id", "") or "").strip():
        return False

    masked_key = str(getattr(record, "masked_key", "") or "").strip()
    if not masked_key:
        return False
    if not masked_key.startswith("ic_install_"):
        return False

    return True


def _select_paid_install_key_records(owner_key: str) -> dict[str, Any]:
    registry = get_install_key_registry()
    try:
        records = registry.get_keys_for_owner(owner_key)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Install-key records are temporarily unavailable.",
        ) from exc
    if not isinstance(records, (list, tuple)):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Install-key records returned an invalid response.",
        )

    selected: dict[str, Any] = {}
    for record in records:
        canonical_program = InstallKeyFormatRegistry.normalize_program(str(getattr(record, "program", "") or ""))
        if canonical_program is None or canonical_program not in _RUNTIME_PROGRAMS:
            continue
        if canonical_program in selected or not _is_valid_install_key_record(
            record,
            owner_key=owner_key,
            program=canonical_program,
        ):
            continue
        selected[canonical_program] = record
    return selected


@router.get("/integrations/installers")
def list_integration_installers() -> dict[str, object]:
    return {
        "items": [
            {
                "integration_id": platform_slug,
                "status": "ready",
                "program": metadata["program"],
                "shared_package": metadata.get("shared_package", False),
                "shared_install_key_family": metadata.get("shared_install_key_family", False),
            }
            for platform_slug, metadata in _SUPPORTED_PLATFORM_INSTALLS.items()
        ],
    }


@router.get("/integrations/installers/{integration_id}")
def get_integration_installer(integration_id: str) -> dict[str, str]:
    return {
        "integration_id": integration_id,
        "kind": "installer",
        "status": "ready",
    }


@router.get("/integrations/verifiers")
def list_integration_verifiers() -> dict[str, object]:
    return {
        "items": [
            {
                "integration_id": platform_slug,
                "status": "ready",
                "program": metadata["program"],
                "shared_package": metadata.get("shared_package", False),
                "shared_install_key_family": metadata.get("shared_install_key_family", False),
            }
            for platform_slug, metadata in _SUPPORTED_PLATFORM_INSTALLS.items()
        ],
    }


@router.get("/integrations/verifiers/{integration_id}")
def get_integration_verifier(integration_id: str) -> dict[str, str]:
    return {
        "integration_id": integration_id,
        "kind": "verifier",
        "status": "ready",
    }


@router.get("/integrations/{integration_id}/compatibility")
def get_integration_compatibility(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "compatible": True,
        "status": "ready",
    }


@router.get("/integrations/{integration_id}/secrets")
def get_integration_secrets(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "status": "configured",
        "secrets": [],
    }


@router.get("/integrations/{integration_id}/rollouts")
def get_integration_rollouts(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "status": "ready",
        "rollouts": [],
    }


@router.get("/integrations/{integration_id}/telemetry")
def get_integration_telemetry(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "status": "active",
        "events": [],
    }


@router.get("/integrations/{integration_id}/health")
def get_integration_health(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "status": "healthy",
    }


@router.get("/integrations/{integration_id}/lifecycle")
def get_integration_lifecycle(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "status": "managed",
    }


@router.get("/integrations/{integration_id}/readiness")
def get_integration_readiness(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "ready": True,
        "status": "ready",
    }


@router.get("/integrations/{integration_id}/observability")
def get_integration_observability(integration_id: str) -> dict[str, object]:
    return {
        "integration_id": integration_id,
        "status": "available",
        "signals": [],
    }


@router.get("/integrations/token")
async def get_integrations_token(auth: Any = Depends(get_auth_context)) -> dict[str, Any]:
    owner_key = _resolve_install_owner(auth)
    install_keys = _select_paid_install_key_records(owner_key) if owner_key else {}

    payload: dict[str, Any] = {
        "status": "locked",
        "user_token": "",
        "claude_code_command": "",
        "openclaw_command": "",
        "cursor_command": "",
        "goose_command": "",
        "gemini_cli_command": "",
        "copilot_command": "",
        "hermes_command": "",
        "security_guardian_command": "",
        "supported_platforms": list(_CANONICAL_PLATFORM_ORDER),
        "command_metadata": {},
        "install_metadata": {},
    }

    for platform_slug, metadata in _SUPPORTED_PLATFORM_INSTALLS.items():
        program = metadata["program"]
        record = install_keys.get(program)
        payload["install_metadata"][platform_slug] = {
            "platform": metadata["platform"],
            "slug": metadata["slug"],
            "program": program,
            "key_id": str(getattr(record, "key_id", "") or ""),
            "available": record is not None,
            "shared_package": metadata.get("shared_package", False),
            "shared_install_key_family": metadata.get("shared_install_key_family", False),
            "package_type": metadata.get("package_type", "runtime-install"),
        }
        payload["command_metadata"][platform_slug] = ""
        if record is not None:
            payload["status"] = "ok"

    return payload


@router.post("/integrations/installers/{integration_id}/claim", status_code=status.HTTP_201_CREATED)
def create_integration_install_claim(
    integration_id: str,
    response: Response,
    auth: Any = Depends(get_auth_context),
) -> dict[str, Any]:
    if auth is None or getattr(auth, "authenticated", False) is not True:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication is required.")

    owner_key = _resolve_install_owner(auth)
    if not owner_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="A verified customer identity is required.")

    try:
        spec = InstallKeyFormatRegistry.get_spec(integration_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unsupported integration runtime.") from exc
    if spec.program not in _RUNTIME_PROGRAMS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unsupported integration runtime.")

    record = _select_paid_install_key_records(owner_key).get(spec.program)
    if record is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No active paid install key is available.")

    try:
        claim = get_install_key_handoff_service().issue_claim(
            key_id=record.key_id,
            owner_key=owner_key,
            program=spec.program,
        )
    except InstallKeySecretUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except InstallKeyHandoffError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure install handoff is temporarily unavailable.",
        ) from exc

    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return {
        "integration_id": spec.canonical_slug,
        "program": spec.program,
        "key_id": record.key_id,
        "claim_token": claim.claim_token,
        "expires_at": claim.expires_at.isoformat(),
        "command": spec.format_command(claim.claim_token),
    }


@router.post("/integrations/install-claims/redeem")
def redeem_install_key_claim(
    payload: InstallKeyClaimRedeemRequest,
    response: Response,
) -> dict[str, str]:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    try:
        redemption = get_install_key_handoff_service().redeem_claim(payload.claim_token)
    except InvalidInstallKeyClaimError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Install claim is invalid, expired, or already redeemed.",
        ) from exc
    except InstallKeyHandoffError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure install handoff is temporarily unavailable.",
        ) from exc

    return {
        "key_id": redemption.key_id,
        "program": redemption.program,
        "install_key": redemption.install_key,
    }
