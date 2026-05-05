from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(prefix="/ui-pages", tags=["ui-pages"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class UIPageDefinition(BaseModel):
    key: str
    section: str
    title: str
    route: str
    method: Literal["GET", "POST"]
    status: Literal["enabled"] = "enabled"
    description: str
    capability: str


class UIPageRegistryResponse(BaseModel):
    title: str = "IronClaw UI Page Registry"
    status: Literal["ok"] = "ok"
    generated_at: str
    pages: list[UIPageDefinition]


BACKUP_RESTORE_PAGES: list[UIPageDefinition] = [
    UIPageDefinition(
        key="backup-control-status",
        section="backup-restore-implementation-targets",
        title="Backup Control Status",
        route="/backup",
        method="GET",
        description="Expose configured backup targets and current control summary.",
        capability="backup-status",
    ),
    UIPageDefinition(
        key="backup-targets",
        section="backup-restore-implementation-targets",
        title="Backup Targets",
        route="/backup/targets",
        method="GET",
        description="Expose configured backup target definitions for UI selection.",
        capability="backup-target-list",
    ),
    UIPageDefinition(
        key="backup-snapshot",
        section="backup-restore-implementation-targets",
        title="Run Snapshot Backup",
        route="/backup/snapshot",
        method="POST",
        description="Trigger on-demand snapshot backup execution for a selected target.",
        capability="backup-snapshot-run",
    ),
    UIPageDefinition(
        key="backup-export",
        section="backup-restore-implementation-targets",
        title="Run Export Backup",
        route="/backup/export",
        method="POST",
        description="Trigger on-demand export backup execution for a selected target.",
        capability="backup-export-run",
    ),
    UIPageDefinition(
        key="backup-rotate",
        section="backup-restore-implementation-targets",
        title="Rotate Backups",
        route="/backup/rotate",
        method="POST",
        description="Apply retention and rotation policy to a selected backup target.",
        capability="backup-rotation-run",
    ),
    UIPageDefinition(
        key="backup-action",
        section="backup-restore-implementation-targets",
        title="Unified Backup Action",
        route="/backup/action",
        method="POST",
        description="Expose a single UI action endpoint for snapshot, export, or rotation.",
        capability="backup-action-dispatch",
    ),
    UIPageDefinition(
        key="restore-control-status",
        section="backup-restore-implementation-targets",
        title="Restore Control Status",
        route="/restore",
        method="GET",
        description="Expose restore control readiness for validation, dry-run, and rollback-safe replay.",
        capability="restore-status",
    ),
    UIPageDefinition(
        key="restore-validate",
        section="backup-restore-implementation-targets",
        title="Validate Restore Manifest",
        route="/restore/validate",
        method="POST",
        description="Validate a restore manifest before any restore execution.",
        capability="restore-validate",
    ),
    UIPageDefinition(
        key="restore-plan",
        section="backup-restore-implementation-targets",
        title="Build Restore Plan",
        route="/restore/plan",
        method="POST",
        description="Generate a dry-run restore plan for operator review.",
        capability="restore-plan",
    ),
    UIPageDefinition(
        key="restore-dry-run",
        section="backup-restore-implementation-targets",
        title="Dry-Run Restore",
        route="/restore/dry-run",
        method="POST",
        description="Execute a non-mutating restore preview with replay details.",
        capability="restore-dry-run",
    ),
    UIPageDefinition(
        key="restore-run",
        section="backup-restore-implementation-targets",
        title="Run Restore",
        route="/restore/run",
        method="POST",
        description="Execute a validated restore with rollback checkpoint protection.",
        capability="restore-run",
    ),
    UIPageDefinition(
        key="restore-replay",
        section="backup-restore-implementation-targets",
        title="Rollback-Safe Replay",
        route="/restore/replay",
        method="POST",
        description="Replay a restore flow with rollback-safe orchestration semantics.",
        capability="restore-replay",
    ),
    UIPageDefinition(
        key="restore-rollback",
        section="backup-restore-implementation-targets",
        title="Rollback Restore",
        route="/restore/rollback",
        method="POST",
        description="Rollback a restore target to a previously captured checkpoint.",
        capability="restore-rollback",
    ),
    UIPageDefinition(
        key="restore-validate-from-backup",
        section="backup-restore-implementation-targets",
        title="Validate Restore From Backup Path",
        route="/restore/validate-from-backup",
        method="POST",
        description="Resolve and validate a manifest sidecar from a backup artifact path.",
        capability="restore-validate-from-backup",
    ),
]


@router.get(
    "",
    response_model=UIPageRegistryResponse,
    summary="Expose completed UI section pages",
)
def get_ui_pages() -> UIPageRegistryResponse:
    return UIPageRegistryResponse(
        generated_at=_utc_now_iso(),
        pages=BACKUP_RESTORE_PAGES,
    )


@router.get(
    "/backup-restore",
    response_model=list[UIPageDefinition],
    summary="Expose backup and restore section pages only",
)
def get_backup_restore_ui_pages() -> list[UIPageDefinition]:
    return BACKUP_RESTORE_PAGES