from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.backupservice import (
    BackupManifest,
    BackupService,
    build_default_backup_service,
)


router = APIRouter(prefix="/backup", tags=["backup"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def get_backup_service() -> BackupService:
    return build_default_backup_service()


def _raise_backup_http_error(exc: Exception) -> None:
    if isinstance(exc, KeyError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if isinstance(exc, FileNotFoundError):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    raise exc


class BackupTargetResponse(BaseModel):
    name: str
    kind: str
    format: str
    base_path: str
    rotation_policy: dict[str, Any]
    encrypt_at_rest: bool
    checksum_required: bool


class BackupManifestResponse(BaseModel):
    target_name: str
    target_kind: str
    backup_format: str
    backup_path: str
    created_at: str
    size_bytes: int
    sha256: str | None
    rotation_tier: str
    encryption_applied: bool
    meta: dict[str, Any]


class BackupStatusResponse(BaseModel):
    title: str = "Backup Control"
    status: Literal["ok"] = "ok"
    generated_at: str
    targets: list[BackupTargetResponse]
    summary: dict[str, Any]


class BackupActionRequest(BaseModel):
    target_name: str = Field(..., min_length=1)
    action: Literal["snapshot", "export", "rotate"] = "snapshot"


class BackupActionResponse(BaseModel):
    title: str = "Backup Action"
    status: Literal["ok"] = "ok"
    generated_at: str
    action: Literal["snapshot", "export", "rotate"]
    target_name: str
    result: dict[str, Any]


def _manifest_to_response(manifest: BackupManifest) -> BackupManifestResponse:
    return BackupManifestResponse(**manifest.to_dict())


@router.get(
    "",
    response_model=BackupStatusResponse,
    summary="Get backup control status",
)
def get_backup_status(
    service: Annotated[BackupService, Depends(get_backup_service)],
) -> BackupStatusResponse:
    targets = service.list_targets()
    typed_targets = [BackupTargetResponse(**target) for target in targets]

    return BackupStatusResponse(
        generated_at=_utc_now_iso(),
        targets=typed_targets,
        summary={
            "target_count": len(typed_targets),
            "snapshot_targets": sum(1 for item in typed_targets if item.kind == "snapshot"),
            "export_targets": sum(1 for item in typed_targets if item.kind == "export"),
            "checksum_enforced_targets": sum(1 for item in typed_targets if item.checksum_required),
            "encrypted_targets": sum(1 for item in typed_targets if item.encrypt_at_rest),
        },
    )


@router.get(
    "/targets",
    response_model=list[BackupTargetResponse],
    summary="List configured backup targets",
)
def list_backup_targets(
    service: Annotated[BackupService, Depends(get_backup_service)],
) -> list[BackupTargetResponse]:
    return [BackupTargetResponse(**target) for target in service.list_targets()]


@router.post(
    "/snapshot",
    response_model=BackupManifestResponse,
    summary="Run an on-demand snapshot backup",
    status_code=status.HTTP_201_CREATED,
)
def run_backup_snapshot(
    target_name: Annotated[str, Query(min_length=1)],
    service: Annotated[BackupService, Depends(get_backup_service)],
) -> BackupManifestResponse:
    try:
        manifest = service.run_snapshot(target_name)
    except (KeyError, FileNotFoundError, ValueError) as exc:
        _raise_backup_http_error(exc)

    return _manifest_to_response(manifest)


@router.post(
    "/export",
    response_model=BackupManifestResponse,
    summary="Run an on-demand export backup",
    status_code=status.HTTP_201_CREATED,
)
def run_backup_export(
    target_name: Annotated[str, Query(min_length=1)],
    service: Annotated[BackupService, Depends(get_backup_service)],
) -> BackupManifestResponse:
    try:
        manifest = service.run_export(target_name)
    except (KeyError, FileNotFoundError, ValueError) as exc:
        _raise_backup_http_error(exc)

    return _manifest_to_response(manifest)


@router.post(
    "/rotate",
    response_model=BackupActionResponse,
    summary="Apply rotation policy to a backup target",
)
def rotate_backups(
    target_name: Annotated[str, Query(min_length=1)],
    service: Annotated[BackupService, Depends(get_backup_service)],
) -> BackupActionResponse:
    try:
        removed = service.rotate(target_name)
    except (KeyError, FileNotFoundError, ValueError) as exc:
        _raise_backup_http_error(exc)

    return BackupActionResponse(
        generated_at=_utc_now_iso(),
        action="rotate",
        target_name=target_name,
        result={
            "removed_count": len(removed),
            "removed_paths": [str(path) for path in removed],
        },
    )


@router.post(
    "/action",
    response_model=BackupActionResponse,
    summary="Run a generic backup control action",
)
def run_backup_action(
    request: BackupActionRequest,
    service: Annotated[BackupService, Depends(get_backup_service)],
) -> BackupActionResponse:
    try:
        if request.action == "snapshot":
            manifest = service.run_snapshot(request.target_name)
            result: dict[str, Any] = _manifest_to_response(manifest).model_dump()
        elif request.action == "export":
            manifest = service.run_export(request.target_name)
            result = _manifest_to_response(manifest).model_dump()
        else:
            removed = service.rotate(request.target_name)
            result = {
                "removed_count": len(removed),
                "removed_paths": [str(path) for path in removed],
            }
    except (KeyError, FileNotFoundError, ValueError) as exc:
        _raise_backup_http_error(exc)

    return BackupActionResponse(
        generated_at=_utc_now_iso(),
        action=request.action,
        target_name=request.target_name,
        result=result,
    )