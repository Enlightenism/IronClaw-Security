from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.core.auth import get_auth_context
from app.core.install_keys import get_install_key_registry

router = APIRouter(tags=["integration-routes"])

_PAID_PAYMENT_STATUSES = {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}
_ACTIVE_ENTITLEMENT_STATUSES = {"active", "paid", "enabled", "granted"}


def _resolve_install_owner(auth: Any) -> str | None:
    if auth is None:
        return None

    org_id = str(getattr(auth, "org_id", "") or "").strip()
    if org_id:
        owner_key = f"ic_org_{org_id.lower()}"
        if not owner_key.startswith("ic_"):
            return None
        return owner_key

    principal_id = str(getattr(auth, "principal_id", "") or "").strip()
    if principal_id:
        if principal_id.startswith("ic_"):
            return None
        return principal_id.lower()

    buyer_email = str(getattr(auth, "email", "") or "").strip()
    if buyer_email:
        if buyer_email.startswith("ic_"):
            return None
        return buyer_email.lower()

    return None


def _is_valid_install_key_record(record: Any, *, owner_key: str, program: str) -> bool:
    if record is None:
        return False

    record_owner = str(getattr(record, "owner_key", "") or "").strip().lower()
    if record_owner != owner_key:
        return False

    if str(getattr(record, "program", "")).strip().lower() != program:
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

    masked_key = str(getattr(record, "masked_key", "") or "").strip()
    if not masked_key:
        return False
    if not masked_key.startswith("ic_install_"):
        return False

    return True


def _select_paid_install_key(owner_key: str | None, program: str) -> str:
    if not owner_key:
        return ""

    registry = get_install_key_registry()
    try:
        records = registry.get_keys_for_owner(owner_key)
    except Exception:
        return ""

    for record in records:
        if not _is_valid_install_key_record(record, owner_key=owner_key, program=program):
            continue
        value = str(getattr(record, "masked_key", "") or "").strip()
        if value and value.startswith("ic_install_"):
            return value

    return ""


@router.get("/integrations/installers")
def list_integration_installers() -> dict[str, object]:
    return {
        "items": [
            {"integration_id": "claude-code", "status": "ready"},
            {"integration_id": "openclaw", "status": "ready"},
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
            {"integration_id": "claude-code", "status": "ready"},
            {"integration_id": "openclaw", "status": "ready"},
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
async def get_integrations_token(auth: Any = Depends(get_auth_context)) -> dict[str, str]:
    owner_key = _resolve_install_owner(auth)
    claude_key = _select_paid_install_key(owner_key, "claude_code")
    openclaw_key = _select_paid_install_key(owner_key, "openclaw")

    payload: dict[str, str] = {
        "status": "locked",
        "user_token": "",
        "claude_code_command": "",
        "openclaw_command": "",
    }

    if claude_key:
        payload["status"] = "ok"
        payload["claude_code_command"] = f"npx ironclaw-install --key {claude_key} --platform claude-code"

    if openclaw_key:
        payload["status"] = "ok"
        payload["openclaw_command"] = f"npx ironclaw-install --key {openclaw_key} --platform openclaw"

    return payload
