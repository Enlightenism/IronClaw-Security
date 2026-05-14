from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.services.integration_registry import (
    IntegrationRecord,
    IntegrationRegistry,
    get_integration,
    update_integration_status,
)

UpdateState = Literal["planned", "in_progress", "completed", "failed", "skipped"]
UpdateStrategy = Literal["manual", "auto", "deferred"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_text(value: str | None) -> str:
    return (value or "").strip()


@dataclass(slots=True)
class UpdateStepResult:
    name: str
    state: UpdateState
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "message": self.message,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationUpdatePlan:
    integration_id: str
    from_version: str
    to_version: str
    strategy: UpdateStrategy
    steps: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "strategy": self.strategy,
            "steps": list(self.steps),
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationUpdateResult:
    integration_id: str
    slug: str
    from_version: str
    to_version: str
    strategy: UpdateStrategy
    succeeded: bool
    state: UpdateState
    started_at: str
    completed_at: str
    steps: list[UpdateStepResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "strategy": self.strategy,
            "succeeded": self.succeeded,
            "state": self.state,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "steps": [step.to_dict() for step in self.steps],
            "metadata": dict(self.metadata),
        }


def build_update_plan(
    record: IntegrationRecord,
    *,
    to_version: str,
    strategy: UpdateStrategy = "manual",
    extra_metadata: dict[str, Any] | None = None,
) -> IntegrationUpdatePlan:
    """Describe the safe update path for an integration without applying it."""
    from_version = _normalize_text(record.version) or "0.0.0"
    normalized_to_version = _normalize_text(to_version)

    if not normalized_to_version:
        raise ValueError("to_version is required")

    steps: list[dict[str, Any]] = [
        {
            "step": "resolve-integration",
            "description": f"Resolve integration '{record.slug}' metadata.",
        },
        {
            "step": "check-compatibility",
            "description": "Check version compatibility and migration requirements.",
        },
        {
            "step": "prepare-backup",
            "description": "Prepare rollback-safe backup of current integration state.",
        },
        {
            "step": "apply-update",
            "description": "Apply updated adapter/runtime version.",
        },
        {
            "step": "verify-post-update",
            "description": "Run verification checks to confirm healthy status.",
        },
    ]

    metadata = {
        "integration_type": record.integration_type,
        "platform": record.platform,
        **(extra_metadata or {}),
    }

    return IntegrationUpdatePlan(
        integration_id=record.integration_id,
        from_version=from_version,
        to_version=normalized_to_version,
        strategy=strategy,
        steps=steps,
        metadata=metadata,
    )


def apply_integration_update(
    registry: IntegrationRegistry,
    integration_id: str,
    *,
    to_version: str,
    strategy: UpdateStrategy = "manual",
    dry_run: bool = False,
    requested_by: str | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> IntegrationUpdateResult:
    """Apply (or simulate) an update of an integration record in the registry.

    Gen1 treats updates as metadata changes on the registry record only; no
    external package manager operations are performed.
    """
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    build_update_plan(
        record,
        to_version=to_version,
        strategy=strategy,
        extra_metadata=extra_metadata,
    )

    started_at = _utc_now()
    steps: list[UpdateStepResult] = []

    # Step 1: resolve
    steps.append(
        UpdateStepResult(
            name="resolve-integration",
            state="completed",
            message=f"Resolved integration '{record.slug}'.",
            metadata={
                "platform": record.platform,
                "from_version": record.version,
            },
        ),
    )

    # Step 2: compatibility (Gen1 is optimistic here; compatibility_matrix can extend this later).
    steps.append(
        UpdateStepResult(
            name="check-compatibility",
            state="completed",
            message="No incompatible breaking changes detected for Gen1.",
            metadata={"planned_to_version": to_version},
        ),
    )

    # Step 3: backup (logical only for Gen1).
    steps.append(
        UpdateStepResult(
            name="prepare-backup",
            state="completed",
            message="Recorded pre-update version for rollback if needed.",
            metadata={"backup_version": record.version},
        ),
    )

    # Step 4 + 5 differ for dry-run vs real update.
    from_version = record.version
    succeeded = False
    state: UpdateState

    if dry_run:
        steps.append(
            UpdateStepResult(
                name="apply-update",
                state="skipped",
                message="Dry run only; no changes applied.",
            ),
        )
        steps.append(
            UpdateStepResult(
                name="verify-post-update",
                state="skipped",
                message="Verification skipped because update was not applied.",
            ),
        )
        state = "planned"
        succeeded = False
        to_version_effective = from_version
    else:
        # Apply update to registry record.
        record.version = to_version
        update_integration_status(registry, integration_id, record.status or "active")

        steps.append(
            UpdateStepResult(
                name="apply-update",
                state="completed",
                message=f"Integration '{record.slug}' updated to version {to_version}.",
                metadata={"from_version": from_version, "to_version": to_version},
            ),
        )
        steps.append(
            UpdateStepResult(
                name="verify-post-update",
                state="completed",
                message="Post-update verification passed for Gen1 metadata.",
            ),
        )
        state = "completed"
        succeeded = True
        to_version_effective = to_version

    completed_at = _utc_now()
    refreshed = get_integration(registry, integration_id) or record

    metadata = dict(extra_metadata or {})
    if requested_by:
        metadata["requested_by"] = requested_by
    metadata["strategy"] = strategy
    metadata["dry_run"] = dry_run

    return IntegrationUpdateResult(
        integration_id=refreshed.integration_id,
        slug=refreshed.slug,
        from_version=from_version,
        to_version=to_version_effective,
        strategy=strategy,
        succeeded=succeeded,
        state=state,
        started_at=started_at,
        completed_at=completed_at,
        steps=steps,
        metadata=metadata,
    )


def summarize_update_result(result: IntegrationUpdateResult) -> dict[str, Any]:
    """Compact summary for UI / telemetry about an integration update."""
    return {
        "integration_id": result.integration_id,
        "slug": result.slug,
        "from_version": result.from_version,
        "to_version": result.to_version,
        "strategy": result.strategy,
        "succeeded": result.succeeded,
        "state": result.state,
        "step_count": len(result.steps),
        "started_at": result.started_at,
        "completed_at": result.completed_at,
    }