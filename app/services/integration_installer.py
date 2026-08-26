from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.core.install_keys import get_install_key_registry
from app.services.integration_registry import (
    IntegrationRecord,
    IntegrationRegistry,
    get_integration,
    get_integration_registry,
    update_integration_status,
)

_SECURITY_INSTALL_SLUGS: frozenset[str] = frozenset(
    {
        "claude-code",
        "openclaw",
        "generic-agent",
        "llamafirewall",
    }
)

InstallState = Literal["pending", "installed", "skipped", "failed"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class InstallStepResult:
    name: str
    state: InstallState
    message: str
    command: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "message": self.message,
            "command": self.command,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationInstallResult:
    integration_id: str
    slug: str
    status_before: str
    status_after: str
    installed: bool
    command_name: str | None
    install_target: str | None
    started_at: str
    completed_at: str
    steps: list[InstallStepResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "status_before": self.status_before,
            "status_after": self.status_after,
            "installed": self.installed,
            "command_name": self.command_name,
            "install_target": self.install_target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "steps": [step.to_dict() for step in self.steps],
            "metadata": dict(self.metadata),
        }


def _requires_paid_install_key(record: IntegrationRecord) -> bool:
    slug = (record.slug or "").strip().lower()
    if slug in _SECURITY_INSTALL_SLUGS:
        return True
    if bool(record.metadata.get("requires_paid_install_key")):
        return True
    platform = (record.platform or "").strip().lower()
    description = (record.description or "").lower()
    return platform in {"openclaw", "claude-code", "generic"} and "security" in description


def _extract_install_key(extra_metadata: dict[str, Any] | None, *, explicit_install_key: str | None = None) -> str | None:
    metadata = dict(extra_metadata or {})
    if explicit_install_key is not None:
        return str(explicit_install_key).strip() or None
    for key_name in ("install_key", "install_key_value", "raw_install_key", "security_install_key"):
        value = metadata.get(key_name)
        if value is not None:
            candidate = str(value).strip()
            if candidate:
                return candidate
    return None


def _extract_owner_key(extra_metadata: dict[str, Any] | None, *, explicit_owner_key: str | None = None) -> str | None:
    metadata = dict(extra_metadata or {})
    if explicit_owner_key is not None:
        return str(explicit_owner_key).strip() or None
    for key_name in ("owner_key", "customer_owner_key", "owner", "principal_id"):
        value = metadata.get(key_name)
        if value is not None:
            candidate = str(value).strip()
            if candidate:
                return candidate
    return None


def _infer_expected_program(record: IntegrationRecord) -> str | None:
    slug = (record.slug or "").strip().lower()
    platform = (record.platform or "").strip().lower()
    if slug in {"openclaw", "openclaw-agent"} or platform == "openclaw":
        return "openclaw"
    if slug in {"claude-code", "claude_code", "claude"} or platform in {"claude-code", "claude_code"}:
        return "claude_code"
    return None


def _validate_paid_install_key_for_installation(*, record: IntegrationRecord, install_key: str | None, owner_key: str | None) -> tuple[bool, dict[str, Any], str | None]:
    if not install_key:
        return (
            False,
            {"install_key_required": True, "install_key_valid": False, "reason": "install key unavailable until payment is complete"},
            "install key unavailable until payment is complete",
        )

    candidate = str(install_key).strip()
    if not candidate:
        return (
            False,
            {"install_key_required": True, "install_key_valid": False, "reason": "install key unavailable until payment is complete"},
            "install key unavailable until payment is complete",
        )

    expected_program = _infer_expected_program(record)
    valid_prefixes = ("ic_install_openclaw_", "ic_install_claude_code_")
    if expected_program == "openclaw":
        valid_prefixes = ("ic_install_openclaw_",)
    elif expected_program == "claude_code":
        valid_prefixes = ("ic_install_claude_code_",)

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
    ):
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "key_classification": "system_api_key_or_generic_token",
            },
            "install key unavailable until payment is complete",
        )

    registry = get_install_key_registry()
    validated_record = registry.authenticate_install_key(candidate)
    if validated_record is None:
        return (
            False,
            {"install_key_required": True, "install_key_valid": False, "reason": "install key unavailable until payment is complete", "key_classification": "unrecognized_or_inactive"},
            "install key unavailable until payment is complete",
        )

    if validated_record.payment_status != "paid" or validated_record.entitlements_status != "active" or not validated_record.issued_after_payment:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "payment_status": validated_record.payment_status,
                "entitlements_status": validated_record.entitlements_status,
                "issued_after_payment": validated_record.issued_after_payment,
            },
            "install key unavailable until payment is complete",
        )

    if expected_program and validated_record.program != expected_program:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "expected_program": expected_program,
                "program": validated_record.program,
            },
            "install key unavailable until payment is complete",
        )

    normalized_owner = str(owner_key).strip().lower() if owner_key else None
    if normalized_owner and validated_record.owner_key != normalized_owner:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "owner_key": validated_record.owner_key,
                "supplied_owner_key": normalized_owner,
            },
            "install key unavailable until payment is complete",
        )

    return (
        True,
        {
            "install_key_required": True,
            "install_key_valid": True,
            "key_id": validated_record.key_id,
            "owner_key": validated_record.owner_key,
            "program": validated_record.program,
            "payment_status": validated_record.payment_status,
            "entitlements_status": validated_record.entitlements_status,
            "issued_after_payment": validated_record.issued_after_payment,
        },
        None,
    )


def install_integration(
    registry: IntegrationRegistry,
    integration_id: str,
    *,
    dry_run: bool = False,
    requested_by: str | None = None,
    install_target: str | None = None,
    install_key: str | None = None,
    owner_key: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> IntegrationInstallResult:
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    started_at = _utc_now()
    status_before = record.status
    effective_target = install_target or record.install_target

    steps: list[InstallStepResult] = [
        InstallStepResult(
            name="resolve-integration",
            state="installed",
            message=f"Resolved integration '{record.slug}'.",
            metadata={"platform": record.platform},
        ),
        InstallStepResult(
            name="validate-command",
            state="installed" if record.command_name else "skipped",
            message=("Install command available." if record.command_name else "No install command registered yet."),
            command=record.command_name,
        ),
        InstallStepResult(
            name="prepare-target",
            state="installed" if effective_target else "skipped",
            message=(f"Prepared install target '{effective_target}'." if effective_target else "No install target declared."),
            metadata={"install_target": effective_target},
        ),
    ]

    metadata = dict(extra_metadata or {})
    if requested_by:
        metadata["requested_by"] = requested_by
    if dry_run:
        metadata["dry_run"] = True

    effective_install_key = _extract_install_key(metadata, explicit_install_key=install_key)
    effective_owner_key = _extract_owner_key(metadata, explicit_owner_key=owner_key)

    status_after = status_before
    installed = False

    if _requires_paid_install_key(record):
        valid_key, key_metadata, key_error = _validate_paid_install_key_for_installation(
            record=record,
            install_key=effective_install_key,
            owner_key=effective_owner_key,
        )
        if not valid_key:
            steps.append(
                InstallStepResult(
                    name="validate-paid-install-key",
                    state="failed",
                    message=key_error or "Paid install key validation failed.",
                    metadata=key_metadata,
                ),
            )
            return IntegrationInstallResult(
                integration_id=record.integration_id,
                slug=record.slug,
                status_before=status_before,
                status_after="blocked",
                installed=False,
                command_name=record.command_name,
                install_target=effective_target,
                started_at=started_at,
                completed_at=_utc_now(),
                steps=steps,
                metadata={**metadata, "install_key_required": True, "install_key_valid": False},
            )

        metadata.update({"install_key_required": True, "install_key_valid": True, **key_metadata})
        steps.append(
            InstallStepResult(
                name="validate-paid-install-key",
                state="installed",
                message="Validated a paid install key against the canonical install-key registry.",
                metadata=key_metadata,
            ),
        )

    if dry_run:
        steps.append(
            InstallStepResult(
                name="apply-install",
                state="skipped",
                message="Dry run only; no changes applied.",
            ),
        )
    else:
        update_integration_status(registry, integration_id, "active")
        status_after = "active"
        installed = True
        steps.append(
            InstallStepResult(
                name="apply-install",
                state="installed",
                message=f"Integration '{record.slug}' marked active.",
            ),
        )

    completed_at = _utc_now()
    refreshed_record = get_integration(registry, integration_id) or record

    return IntegrationInstallResult(
        integration_id=refreshed_record.integration_id,
        slug=refreshed_record.slug,
        status_before=status_before,
        status_after=status_after,
        installed=installed,
        command_name=refreshed_record.command_name,
        install_target=effective_target,
        started_at=started_at,
        completed_at=completed_at,
        steps=steps,
        metadata=metadata,
    )


def build_install_plan(record: IntegrationRecord) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = [
        {
            "step": "resolve-integration",
            "description": f"Resolve integration metadata for '{record.slug}'.",
        },
        {
            "step": "validate-command",
            "description": "Confirm one-command installer entrypoint exists.",
            "command": record.command_name,
        },
        {
            "step": "prepare-target",
            "description": "Prepare target platform for local IronClaw attachment.",
            "install_target": record.install_target,
        },
    ]

    if _requires_paid_install_key(record):
        steps.append(
            {
                "step": "validate-paid-install-key",
                "description": "Validate a paid install key against the canonical install-key registry before activation.",
                "install_key_required": True,
            },
        )

    steps.append(
        {
            "step": "apply-install",
            "description": "Activate the integration and expose protected runtime hooks.",
        },
    )
    return steps


def summarize_install_result(result: IntegrationInstallResult) -> dict[str, Any]:
    return {
        "integration_id": result.integration_id,
        "slug": result.slug,
        "installed": result.installed,
        "status_before": result.status_before,
        "status_after": result.status_after,
        "step_count": len(result.steps),
        "completed_at": result.completed_at,
        "command_name": result.command_name,
        "install_target": result.install_target,
    }


def get_integration_installer() -> Any:
    registry = get_integration_registry()

    class _IntegrationInstaller:
        def install_integration(
            self,
            integration_id: str,
            *,
            dry_run: bool = False,
            requested_by: str | None = None,
            install_target: str | None = None,
            extra_metadata: dict[str, Any] | None = None,
        ) -> IntegrationInstallResult:
            return install_integration(
                registry,
                integration_id,
                dry_run=dry_run,
                requested_by=requested_by,
                install_target=install_target,
                extra_metadata=extra_metadata,
            )

    return _IntegrationInstaller()
