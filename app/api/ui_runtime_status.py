from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.dependencies.auth import require_api_key

router = APIRouter(
    prefix="/ui",
    tags=["runtime-status"],
    dependencies=[Depends(require_api_key)],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class RuntimeDependencyView(BaseModel):
    name: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class UIRuntimeStatusResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    environment: str
    runtime_state: str
    request_guard_enabled: bool
    protected_docs_enabled: bool
    telemetry_enabled: bool
    dependencies: list[RuntimeDependencyView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _build_dependencies() -> list[RuntimeDependencyView]:
    return [
        RuntimeDependencyView(
            name="api-key-auth",
            status="healthy",
            detail="Protected API key dependency is active for guarded routes.",
            metadata={"scope": "request-ingress"},
        ),
        RuntimeDependencyView(
            name="runtime-boundary",
            status="healthy",
            detail="Guarded execution boundary is available for protected actions.",
            metadata={"scope": "execution"},
        ),
        RuntimeDependencyView(
            name="telemetry-pipeline",
            status="healthy",
            detail="Telemetry summary and event collection are enabled for UI monitoring.",
            metadata={"scope": "telemetry"},
        ),
        RuntimeDependencyView(
            name="protected-docs",
            status="healthy",
            detail="Protected OpenAPI and docs endpoints are enabled behind authentication.",
            metadata={"scope": "documentation"},
        ),
    ]


@router.get("/runtime-status", response_model=UIRuntimeStatusResponse)
def get_ui_runtime_status(
    requested_by: str = Query("ui-runtime-status", min_length=1),
) -> UIRuntimeStatusResponse:
    dependencies = _build_dependencies()
    return UIRuntimeStatusResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        environment="local",
        runtime_state="healthy",
        request_guard_enabled=True,
        protected_docs_enabled=True,
        telemetry_enabled=True,
        dependencies=dependencies,
        metadata={
            "requested_by": requested_by,
            "dependency_count": len(dependencies),
        },
    )
