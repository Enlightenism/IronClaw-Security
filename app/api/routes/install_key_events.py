from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.auth import require_api_key
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import InstallKeyRegistry, get_install_key_registry
from app.core.unit_wallet import (
    InstallKeyUsageSource,
    RegistryUnitLedgerEntry,
    UnitWalletRegistry,
    get_unit_wallet_registry,
)

router = APIRouter(
    prefix="/install-key-events",
    tags=["install-key-events"],
    dependencies=[Depends(require_api_key)],
)

InstallKeyEventType = Literal[
    "action_blocked",
    "prompt_injection_detected",
    "quarantine_detected",
    "quarantine_event",
    "usage_units_debited",
    "install_key_usage_recorded",
    "install_key_activated",
    "install_key_revoked",
    "install_key_reported",
]


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _coerce_iso(value: str | None, *, default: str) -> str:
    candidate = (value or default).strip()
    if not candidate:
        return default
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("occurred_at must be ISO-8601") from exc
    return candidate.replace("+00:00", "Z")


def _parse_datetime(value: str | None) -> datetime:
    candidate = (value or _utc_now_iso()).strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    return datetime.fromisoformat(candidate)


def _normalize_owner(owner_key: str | None) -> str | None:
    if owner_key is None:
        return None
    normalized = str(owner_key).strip().lower()
    return normalized or None


def _normalize_program(program: str | None) -> str | None:
    if program is None:
        return None
    normalized = str(program).strip().lower()
    if not normalized:
        return None
    canonical = InstallKeyFormatRegistry.normalize_program(normalized)
    if canonical is not None:
        return canonical
    normalized = normalized.replace(" ", "_").replace("-", "_").replace("__", "_").strip("_")
    return normalized if normalized in set(InstallKeyFormatRegistry.list_programs()) else None


def _looks_like_generic_platform_auth(value: str | None) -> bool:
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if not normalized:
        return False
    if normalized.startswith("ic_org_"):
        return False
    if normalized.startswith("ic_install_") or normalized.startswith("ic_"):
        return True

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
    if normalized.startswith(("owner_", "customer_", "user_", "org_", "acct_")):
        return False
    if "@" in normalized:
        return False
    return ("platform" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("system" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("api" in normalized and "key" in normalized)


class InstallKeyEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True, str_strip_whitespace=True)

    event_id: str = Field(..., min_length=1, max_length=128)
    event_type: InstallKeyEventType
    key_id: str | None = Field(default=None, min_length=1, max_length=128)
    owner_key: str | None = Field(default=None, min_length=1, max_length=512)
    program: str | None = Field(default=None, min_length=1, max_length=32)
    action_type: str | None = Field(default=None, min_length=1, max_length=128)
    units: int | None = Field(default=None, ge=0)
    blocked_attack_count: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    occurred_at: str | None = None

    @field_validator("program", mode="before")
    @classmethod
    def _validate_program(cls, value: Any) -> Any:
        if value is None:
            return None
        normalized = _normalize_program(value)
        if normalized is None:
            raise ValueError("program must be one of: openclaw, claude_code, cursor, goose, gemini_cli, copilot, hermes")
        return normalized

    @field_validator("occurred_at", mode="before")
    @classmethod
    def _validate_occurred_at(cls, value: Any) -> str | None:
        if value is None:
            return None
        candidate = str(value).strip()
        if not candidate:
            return None
        _coerce_iso(candidate, default=_utc_now_iso())
        return candidate.replace("+00:00", "Z")


class InstallKeyEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    status: Literal["ok"] = "ok"
    service: str = "IronClaw-Security"
    event_id: str
    event_type: InstallKeyEventType
    key_id: str | None = None
    owner_key: str | None = None
    program: str | None = None
    processed: bool = True
    wallet_updated: bool = False
    dashboard_synced: bool = True
    recorded_at: str = Field(default_factory=_utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


_processed_event_ids: set[str] = set()


def _event_store_record(event_id: str) -> None:
    _processed_event_ids.add(event_id)


def _ensure_key_context(
    *,
    payload: InstallKeyEventRequest,
    install_key_registry: InstallKeyRegistry,
) -> tuple[str | None, str | None]:
    owner_key = _normalize_owner(payload.owner_key)
    program = _normalize_program(payload.program)

    if payload.key_id:
        record = install_key_registry.get_key_by_id(payload.key_id)
        if record is not None:
            if owner_key is None:
                owner_key = _normalize_owner(record.owner_key)
            if program is None:
                program = _normalize_program(record.program)

    if owner_key is None and payload.key_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="owner_key or key_id is required for install-key telemetry events.",
        )

    if owner_key is not None and _looks_like_generic_platform_auth(owner_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Install-key lifecycle events must resolve to the canonical install-key owner, not the generic platform auth credential.",
        )

    return owner_key, program


def _require_key_record(
    *,
    payload: InstallKeyEventRequest,
    install_key_registry: InstallKeyRegistry,
    owner_key: str | None,
    op: str,
) -> Any:
    if payload.key_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{op} requires key_id.",
        )

    record = install_key_registry.get_key_by_id(payload.key_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Install key not found: {payload.key_id!r}",
        )

    if owner_key is not None and _normalize_owner(record.owner_key) != owner_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Install key does not belong to the supplied owner_key.",
        )

    return record


def _sync_wallet_event(
    *,
    wallet_registry: UnitWalletRegistry,
    owner_key: str,
    key_id: str | None,
    program: str | None,
    event_type: str,
    units: int,
    blocked_attack_count: int,
    action_type: str | None,
    occurred_at: str,
    metadata: dict[str, Any],
) -> bool:
    wallet = wallet_registry.get_or_create_wallet(owner_key)
    effective_program = program or "openclaw"
    timestamp = _parse_datetime(occurred_at)

    if key_id:
        usage = wallet.install_key_usage.setdefault(
            key_id,
            InstallKeyUsageSource(
                key_id=key_id,
                owner_key=wallet.owner_key,
                program=effective_program,
            ),
        )
        usage.program = effective_program
        usage.balance_units = max(wallet.balance_units, 0)
        usage.last_action_at = timestamp
        usage.metadata.update(
            {
                "owner_key": owner_key,
                "key_id": key_id,
                "program": effective_program,
                "last_event_type": event_type,
                "last_event_at": occurred_at,
                "action_type": action_type or usage.metadata.get("action_type") or "telemetry",
            }
        )
        if blocked_attack_count > 0 and event_type not in {"usage_units_debited"}:
            usage.total_blocked_attacks += int(blocked_attack_count)
            wallet.total_blocked_attacks += int(blocked_attack_count)
            if event_type in {"prompt_injection_detected", "quarantine_detected", "quarantine_event"}:
                usage.total_quarantined_actions += int(blocked_attack_count)
        if units > 0 and event_type not in {"usage_units_debited"}:
            usage.total_consumed_units += int(units)
        wallet.install_key_usage[key_id] = usage

    wallet.updated_at = timestamp
    wallet.metadata.setdefault("dashboard_sync", {})
    wallet.metadata["dashboard_sync"][event_type] = {
        "occurred_at": occurred_at,
        "key_id": key_id,
        "owner_key": owner_key,
        "program": effective_program,
        "units": units,
        "blocked_attack_count": blocked_attack_count,
        "metadata": dict(metadata),
    }
    wallet_registry._repo.upsert_wallet(wallet)

    if key_id:
        ledger_entry = RegistryUnitLedgerEntry(
            entry_id=f"ledger_{event_type}_{key_id}_{int(timestamp.timestamp() * 1000)}",
            wallet_id=wallet.wallet_id,
            owner_key=wallet.owner_key,
            entry_type="install_key_event",
            units=units,
            balance_after=wallet.balance_units,
            created_at=timestamp,
            metadata={
                "event_type": event_type,
                "key_id": key_id,
                "program": effective_program,
                "owner_key": owner_key,
                "action_type": action_type,
                "blocked_attack_count": blocked_attack_count,
                **dict(metadata),
            },
        )
        try:
            wallet_registry._repo.append_ledger_entry(ledger_entry)
        except AttributeError:
            pass
    return True


def _apply_event(
    *,
    payload: InstallKeyEventRequest,
    install_key_registry: InstallKeyRegistry,
    wallet_registry: UnitWalletRegistry,
) -> tuple[bool, dict[str, Any]]:
    owner_key, program = _ensure_key_context(payload=payload, install_key_registry=install_key_registry)
    if owner_key is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="owner_key could not be resolved for this install-key event.",
        )

    event_name = payload.event_type
    if event_name in {"install_key_issued", "install_key_provisioned"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Install-key generation events are reserved for provisioning; this telemetry route only accepts usage, activation, revocation, and runtime security-sync events.",
        )

    occurred_at = _coerce_iso(payload.occurred_at, default=_utc_now_iso())
    metadata = dict(payload.metadata or {})
    metadata.setdefault("source", "install-key-events")

    if event_name in {"usage_units_debited", "install_key_usage_recorded"}:
        if payload.key_id is None or payload.units is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="usage_units_debited requires key_id and units.",
            )
        record = install_key_registry.get_key_by_id(payload.key_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Install key not found: {payload.key_id!r}",
            )
        if record.owner_key != owner_key:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Install key does not belong to the supplied owner_key.",
            )

        wallet_registry.debit_units_for_install_key(
            owner_key=owner_key,
            key_id=payload.key_id,
            program=program or record.program,
            units=payload.units,
            action_type=payload.action_type or "telemetry",
            blocked_attack_count=payload.blocked_attack_count,
            metadata={**metadata, "event_type": event_name},
        )
        install_key_registry.record_key_usage(payload.key_id, units=payload.units)
        _sync_wallet_event(
            wallet_registry=wallet_registry,
            owner_key=owner_key,
            key_id=payload.key_id,
            program=program or record.program,
            event_type=event_name,
            units=int(payload.units),
            blocked_attack_count=int(payload.blocked_attack_count),
            action_type=payload.action_type or "telemetry",
            occurred_at=occurred_at,
            metadata={**metadata, "event_type": event_name},
        )
        return True, {"event_type": event_name, "balance_update": "debit"}

    if event_name == "install_key_reported":
        if payload.key_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="install_key_reported requires key_id.",
            )
        record = _require_key_record(
            payload=payload,
            install_key_registry=install_key_registry,
            owner_key=owner_key,
            op="install_key_reported",
        )
        _sync_wallet_event(
            wallet_registry=wallet_registry,
            owner_key=owner_key,
            key_id=payload.key_id,
            program=program or record.program,
            event_type=event_name,
            units=0,
            blocked_attack_count=int(payload.blocked_attack_count or 0),
            action_type=payload.action_type or "reporting",
            occurred_at=occurred_at,
            metadata={**metadata, "event_type": event_name},
        )
        return True, {"event_type": event_name, "status": "reported"}

    if event_name in {"action_blocked", "prompt_injection_detected", "quarantine_detected", "quarantine_event"}:
        if payload.key_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{event_name} requires key_id.",
            )
        record = _require_key_record(
            payload=payload,
            install_key_registry=install_key_registry,
            owner_key=owner_key,
            op=event_name,
        )
        blocked_count = max(1, int(payload.blocked_attack_count or 1))
        _sync_wallet_event(
            wallet_registry=wallet_registry,
            owner_key=owner_key,
            key_id=payload.key_id,
            program=program or record.program,
            event_type=event_name,
            units=0,
            blocked_attack_count=blocked_count,
            action_type=payload.action_type or ("quarantine" if event_name in {"quarantine_detected", "quarantine_event"} else event_name),
            occurred_at=occurred_at,
            metadata={**metadata, "event_type": event_name},
        )
        return True, {"event_type": event_name, "blocked_attack_count": blocked_count}

    if event_name == "install_key_activated":
        _require_key_record(
            payload=payload,
            install_key_registry=install_key_registry,
            owner_key=owner_key,
            op="install_key_activated",
        )
        _sync_wallet_event(
            wallet_registry=wallet_registry,
            owner_key=owner_key,
            key_id=payload.key_id,
            program=program,
            event_type=event_name,
            units=0,
            blocked_attack_count=0,
            action_type=payload.action_type or "activation",
            occurred_at=occurred_at,
            metadata={**metadata, "event_type": event_name},
        )
        return True, {"event_type": event_name, "status": "activated"}

    if event_name == "install_key_revoked":
        _require_key_record(
            payload=payload,
            install_key_registry=install_key_registry,
            owner_key=owner_key,
            op="install_key_revoked",
        )
        try:
            install_key_registry.revoke_key(payload.key_id)
        except Exception as exc:  # pragma: no cover - defensive; re-raise as HTTP 404/409 style
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        _sync_wallet_event(
            wallet_registry=wallet_registry,
            owner_key=owner_key,
            key_id=payload.key_id,
            program=program,
            event_type=event_name,
            units=0,
            blocked_attack_count=0,
            action_type=payload.action_type or "revocation",
            occurred_at=occurred_at,
            metadata={**metadata, "event_type": event_name},
        )
        return True, {"event_type": event_name, "status": "revoked"}

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=f"Unsupported install-key event_type: {event_name!r}",
    )


@router.post(
    "/ingest",
    response_model=InstallKeyEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest install-key telemetry for dashboard and wallet sync",
    description=("Receives runtime telemetry for install-key activity and mirrors it into the canonical install key registry and wallet ledger without generating install keys for customers. This route is reserved for dashboard sync, runtime security events, and usage accounting."),
)
def ingest_install_key_event(
    payload: InstallKeyEventRequest,
    install_key_registry: InstallKeyRegistry = Depends(get_install_key_registry),
    wallet_registry: UnitWalletRegistry = Depends(get_unit_wallet_registry),
) -> InstallKeyEventResponse:
    if payload.event_id in _processed_event_ids:
        return InstallKeyEventResponse(
            event_id=payload.event_id,
            event_type=payload.event_type,
            key_id=payload.key_id,
            owner_key=_normalize_owner(payload.owner_key),
            program=_normalize_program(payload.program),
            processed=True,
            wallet_updated=False,
            dashboard_synced=True,
            recorded_at=_coerce_iso(payload.occurred_at, default=_utc_now_iso()),
            metadata={"status": "duplicate", "source": "install-key-events"},
        )

    _, _ = _apply_event(
        payload=payload,
        install_key_registry=install_key_registry,
        wallet_registry=wallet_registry,
    )
    _event_store_record(payload.event_id)

    owner_key, program = _ensure_key_context(payload=payload, install_key_registry=install_key_registry)
    return InstallKeyEventResponse(
        event_id=payload.event_id,
        event_type=payload.event_type,
        key_id=payload.key_id,
        owner_key=owner_key,
        program=program,
        processed=True,
        wallet_updated=True,
        dashboard_synced=True,
        recorded_at=_coerce_iso(payload.occurred_at, default=_utc_now_iso()),
        metadata={"source": "install-key-events", "status": "applied"},
    )


__all__ = [
    "InstallKeyEventType",
    "InstallKeyEventRequest",
    "InstallKeyEventResponse",
    "router",
    "ingest_install_key_event",
]
