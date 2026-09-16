from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Path, status
from pydantic import BaseModel, Field

from app.core.install_key_formats import get_install_key_format_registry
from app.core.install_keys import get_install_key_registry
from app.services.integrationinstaller import get_integration_installer
from app.services.platform_install_key_router import get_platform_install_key_router

router = APIRouter(prefix="/integrations", tags=["integration-installer"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _datetime_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    text = str(value).strip()
    return text or None


def _normalize_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return [str(value)]


def _coerce_mapping(record: Any) -> dict[str, Any]:
    if record is None:
        return {}
    if hasattr(record, "model_dump"):
        return record.model_dump()
    if isinstance(record, dict):
        return dict(record)
    data: dict[str, Any] = {}
    for name in dir(record):
        if name.startswith("_"):
            continue
        try:
            value = getattr(record, name)
        except Exception:
            continue
        if callable(value):
            continue
        data[name] = value
    return data


def _extract_value(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data.get(key) is not None:
            return data.get(key)
    return None


def _normalize_step_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"ok", "pass", "passed", "complete", "completed", "success", "installed"}:
        return "completed"
    if normalized in {"fail", "failed", "error", "blocked"}:
        return "failed"
    if normalized in {"running", "installing", "pending", "queued", "in_progress"}:
        return "in_progress"
    if normalized in {"warn", "warning"}:
        return "warning"
    return normalized or "in_progress"


class InstallationStepView(BaseModel):
    step_id: str
    title: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InstallationSummaryView(BaseModel):
    state: str
    installed: bool
    steps_total: int
    steps_completed: int
    steps_failed: int
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationInstallRequest(BaseModel):
    platform: str | None = Field(default=None, min_length=1, max_length=120)
    adapter_version: str | None = Field(default=None, min_length=1, max_length=120)
    initiated_by: str | None = Field(default=None, min_length=1, max_length=120)
    install_key: str | None = Field(default=None, min_length=1, max_length=1024)
    owner_key: str | None = Field(default=None, min_length=1, max_length=512)
    dry_run: bool = False
    force: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class IntegrationInstallResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    integration_id: str
    platform: str | None = None
    adapter_version: str | None = None
    installation: InstallationSummaryView
    steps: list[InstallationStepView] = Field(default_factory=list)


def _build_step_view(record: Any, fallback_index: int) -> InstallationStepView:
    data = _coerce_mapping(record)
    step_id = str(
        _extract_value(data, "step_id", "stepid", "id", "name", "key") or f"step-{fallback_index}",
    )
    title = str(
        _extract_value(data, "title", "label", "name", "summary") or step_id.replace("-", " ").replace("_", " ").title(),
    )
    detail = str(
        _extract_value(data, "detail", "details", "message", "summary", "description") or "",
    )
    status_value = _normalize_step_status(
        _extract_value(data, "status", "state", "result"),
    )
    metadata = _normalize_dict(data.get("metadata"))
    for key in ("component", "phase", "duration_ms", "started_at", "completed_at"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)
    return InstallationStepView(
        step_id=step_id,
        title=title,
        status=status_value,
        detail=detail,
        metadata=metadata,
    )


def _canonicalize_platform_name(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if not normalized:
        return None

    for prefix in ("integration-", "integration_", "platform-"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break

    registry = get_install_key_format_registry()
    program = registry.normalize_program(normalized)
    if program is not None:
        return program

    normalized = normalized.replace("_", "-")
    return registry.normalize_program(normalized)


def _infer_expected_program(integration_id: str | None, *, platform: str | None = None) -> str | None:
    registry = get_install_key_format_registry()
    candidates = [platform, integration_id]
    for candidate in candidates:
        normalized = _canonicalize_platform_name(candidate)
        if normalized is not None:
            return normalized
        if candidate is not None:
            canonical = registry.normalize_program(str(candidate).strip().lower().replace("_", "-"))
            if canonical is not None:
                return canonical
    return None


def _platform_install_command(program: str | None, install_key: str) -> str:
    registry = get_install_key_format_registry()
    program_name = (program or "").strip()
    if not program_name:
        return ""

    try:
        spec = registry.get_spec(program_name)
    except ValueError:
        return ""

    command_map = {
        "claude_code": "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key {key}",
        "openclaw": "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user --key {key}",
        "cursor": "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user --key {key}",
        "goose": "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user --key {key}",
        "gemini_cli": "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user --key {key}",
        "copilot": "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user --key {key}",
        "hermes": "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key {key}",
    }
    command = command_map.get(spec.program)
    if command is not None:
        return command.format(key=install_key) if install_key else ""
    return f"npx ironclaw-install --key {install_key} --platform {spec.program}"


def _reject_non_production_install_key(candidate: str, *, expected_program: str | None = None) -> bool:
    normalized = str(candidate).strip().lower()
    if not normalized:
        return True

    rejected_markers = (
        "...",
        "placeholder",
        "demo",
        "example",
        "fake",
        "staging",
        "test_key",
        "testkey",
        "redacted",
        "masked",
        "replaceme",
        "sample",
        "dummy",
        "not-a-real-key",
        "invalid-key",
        "token",
        "secret",
        "api_key",
        "api-key",
        "auth_token",
        "bearer ",
    )
    if any(marker in normalized for marker in rejected_markers):
        return True

    if expected_program is not None:
        candidate_program = _canonicalize_platform_name(expected_program)
        if candidate_program and f"ic_install_{candidate_program}_" in normalized:
            suffix = normalized.split(f"ic_install_{candidate_program}_", 1)[1]
            if not suffix or any(token in suffix for token in ("demo", "placeholder", "fake", "test", "sample", "example", "redacted", "masked")):
                return True

    return False


def _require_paid_install_key(
    install_key: str | None,
    owner_key: str | None,
    *,
    integration_id: str | None = None,
    platform: str | None = None,
) -> None:
    if not install_key or not str(install_key).strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid paid install key is required; install key unavailable until payment is complete",
        )

    if not owner_key or not str(owner_key).strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid paid install key is required; install key unavailable until payment is complete",
        )

    candidate = str(install_key).strip()
    expected_program = _infer_expected_program(integration_id, platform=platform)
    normalized_owner = str(owner_key).strip().lower()
    standardized_platform = platform or integration_id or ""

    if standardized_platform:
        try:
            router = get_platform_install_key_router()
            route = router.validate_platform_key(standardized_platform, candidate)
            expected_program = route.program if expected_program is None else expected_program
            if route.program != expected_program and expected_program is not None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="A valid paid install key is required; install key unavailable until payment is complete",
                )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="A valid paid install key is required; install key unavailable until payment is complete",
            ) from exc

    registry = get_install_key_format_registry()
    valid_prefixes = tuple(spec.prefix for spec in registry.list_specs()) if expected_program is None else (registry.get_spec(expected_program).prefix,)

    if (
        candidate.startswith("ic_org_")
        or candidate.startswith("sk_")
        or candidate.startswith("ghp_")
        or candidate.startswith("gho_")
        or candidate.startswith("github_pat_")
        or candidate.startswith("token_")
        or candidate.startswith("secret_")
        or candidate.startswith("api_")
        or (candidate.startswith("ic_") and not candidate.startswith(valid_prefixes))
        or not candidate.startswith(valid_prefixes)
        or _reject_non_production_install_key(candidate, expected_program=expected_program)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid paid install key is required; install key unavailable until payment is complete",
        )

    key_registry = get_install_key_registry()
    record = key_registry.authenticate_install_key(candidate)

    if record is None or not getattr(record, "active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid paid install key is required; install key unavailable until payment is complete",
        )

    if record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid paid install key is required; install key unavailable until payment is complete",
        )

    if expected_program and record.program != expected_program:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid paid install key is required; install key unavailable until payment is complete",
        )

    if record.owner_key != normalized_owner:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A valid paid install key is required; install key unavailable until payment is complete",
        )


def _build_install_response(integration_id: str, result: Any) -> IntegrationInstallResponse:
    data = _coerce_mapping(result)
    raw_steps = _extract_value(data, "steps", "items", "phases") or []
    steps = [_build_step_view(item, index + 1) for index, item in enumerate(raw_steps)]
    steps_completed = sum(1 for item in steps if item.status == "completed")
    steps_failed = sum(1 for item in steps if item.status == "failed")
    installed_value = _extract_value(data, "installed", "success")
    installed = bool(installed_value) if installed_value is not None else steps_failed == 0 and len(steps) > 0
    state = (
        str(
            _extract_value(data, "state", "installation_state", "overall_status", "status") or ("failed" if steps_failed else "completed" if installed else "pending"),
        )
        .strip()
        .lower()
    )
    platform = _extract_value(data, "platform")
    adapter_version = _extract_value(data, "adapter_version", "version")
    blockers = _normalize_list(_extract_value(data, "blockers", "errors"))
    warnings = _normalize_list(_extract_value(data, "warnings"))
    metadata = _normalize_dict(data.get("metadata"))
    for key in ("provider", "adapter_name", "initiated_by", "dry_run", "force"):
        if key in data and key not in metadata and data.get(key) is not None:
            metadata[key] = data.get(key)
    return IntegrationInstallResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        integration_id=integration_id,
        platform=str(platform) if platform is not None else None,
        adapter_version=str(adapter_version) if adapter_version is not None else None,
        installation=InstallationSummaryView(
            state=state,
            installed=installed,
            steps_total=len(steps),
            steps_completed=steps_completed,
            steps_failed=steps_failed,
            blockers=blockers,
            warnings=warnings,
            metadata=metadata,
        ),
        steps=steps,
    )


@router.post(
    "/{integration_id}/install",
    response_model=IntegrationInstallResponse,
    summary="Install or provision an integration",
)
def install_integration(
    integration_id: str = Path(..., min_length=1, max_length=255),
    request: IntegrationInstallRequest | None = None,
) -> IntegrationInstallResponse:
    normalized_id = integration_id.strip()
    effective_request = request or IntegrationInstallRequest()
    _require_paid_install_key(
        effective_request.install_key,
        effective_request.owner_key,
        integration_id=normalized_id,
        platform=effective_request.platform,
    )

    service = get_integration_installer()
    result = service.install_integration(
        normalized_id,
        requested_by=effective_request.initiated_by or "system",
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"integration '{normalized_id}' not found",
        )

    return _build_install_response(
        integration_id=normalized_id,
        result=result,
    )
