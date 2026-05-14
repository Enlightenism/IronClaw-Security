from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.services.restoreservice import (
    RestoreManifest,
    RestoreService,
    build_default_restore_service,
)

router = APIRouter(prefix="/restore", tags=["restore"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def get_restore_service() -> RestoreService:
    return build_default_restore_service()


def _raise_restore_http_error(exc: Exception) -> None:
    if isinstance(exc, KeyError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if isinstance(exc, FileNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    raise exc


class RestoreTargetResponse(BaseModel):
    name: str
    kind: str
    source_path: str
    restore_path: str
    checksum_required: bool
    dry_run_supported: bool


class RestoreManifestResponse(BaseModel):
    target_name: str
    target_kind: str
    source_path: str
    restore_path: str
    restored_at: str
    files_restored: int
    bytes_restored: int
    checksum_verified: bool
    dry_run: bool
    meta: dict[str, Any]


class RestoreStatusResponse(BaseModel):
    title: str = "Restore Control"
    status: Literal["ok"] = "ok"
    generated_at: str
    targets: list[RestoreTargetResponse]
    summary: dict[str, Any]


class RestoreActionRequest(BaseModel):
    target_name: str = Field(..., min_length=1)
    action: Literal["restore", "validate"] = "restore"
    dry_run: bool = False


class RestoreActionResponse(BaseModel):
    title: str = "Restore Action"
    status: Literal["ok"] = "ok"
    generated_at: str
    action: Literal["restore", "validate"]
    target_name: str
    dry_run: bool
    result: dict[str, Any]


def _manifest_to_response(manifest: RestoreManifest) -> RestoreManifestResponse:
    return RestoreManifestResponse(**manifest.to_dict())


@router.get(
    "",
    response_model=RestoreStatusResponse,
    summary="Get restore control status",
)
def get_restore_status(
    service: Annotated[RestoreService, Depends(get_restore_service)],
) -> RestoreStatusResponse:
    targets = service.list_targets()
    typed_targets = [RestoreTargetResponse(**target) for target in targets]

    return RestoreStatusResponse(
        generated_at=_utc_now_iso(),
        targets=typed_targets,
        summary={
            "target_count": len(typed_targets),
            "checksum_enforced_targets": sum(1 for item in typed_targets if item.checksum_required),
            "dry_run_supported_targets": sum(1 for item in typed_targets if item.dry_run_supported),
        },
    )


@router.get(
    "/targets",
    response_model=list[RestoreTargetResponse],
    summary="List configured restore targets",
)
def list_restore_targets(
    service: Annotated[RestoreService, Depends(get_restore_service)],
) -> list[RestoreTargetResponse]:
    return [RestoreTargetResponse(**target) for target in service.list_targets()]


@router.post(
    "/validate",
    response_model=RestoreActionResponse,
    summary="Validate a restore target before restore",
)
def validate_restore_target(
    target_name: Annotated[str, Query(min_length=1)],
    service: Annotated[RestoreService, Depends(get_restore_service)],
) -> RestoreActionResponse:
    try:
        result = service.validate(target_name)
    except (KeyError, FileNotFoundError, ValueError) as exc:
        _raise_restore_http_error(exc)

    return RestoreActionResponse(
        generated_at=_utc_now_iso(),
        action="validate",
        target_name=target_name,
        dry_run=True,
        result=result,
    )


@router.post(
    "/run",
    response_model=RestoreManifestResponse,
    summary="Run an on-demand restore",
    status_code=status.HTTP_201_CREATED,
)
def run_restore(
    target_name: Annotated[str, Query(min_length=1)],
    dry_run: Annotated[bool, Query()] = False,
    service: Annotated[RestoreService, Depends(get_restore_service)] = None,
) -> RestoreManifestResponse:
    if service is None:
        service = get_restore_service()

    try:
        manifest = service.run_restore(target_name, dry_run=dry_run)
    except (KeyError, FileNotFoundError, ValueError) as exc:
        _raise_restore_http_error(exc)

    return _manifest_to_response(manifest)


@router.post(
    "/action",
    response_model=RestoreActionResponse,
    summary="Run a generic restore control action",
)
def run_restore_action(
    request: RestoreActionRequest,
    service: Annotated[RestoreService, Depends(get_restore_service)],
) -> RestoreActionResponse:
    try:
        if request.action == "validate":
            result: dict[str, Any] = service.validate(request.target_name)
        else:
            manifest = service.run_restore(request.target_name, dry_run=request.dry_run)
            result = _manifest_to_response(manifest).model_dump()
    except (KeyError, FileNotFoundError, ValueError) as exc:
        _raise_restore_http_error(exc)

    return RestoreActionResponse(
        generated_at=_utc_now_iso(),
        action=request.action,
        target_name=request.target_name,
        dry_run=request.dry_run if request.action == "restore" else True,
        result=result,
    )
