from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/guard-registry", tags=["guard-registry"])


class GuardRegistryEntry(BaseModel):
    name: str
    prefix: str
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class GuardRegistryResponse(BaseModel):
    status: str
    service: str
    provider: str
    timestamp: str
    total_routes: int
    routes: list[GuardRegistryEntry] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _route_name_from_prefix(prefix: str) -> str:
    cleaned = prefix.strip("/")
    if not cleaned:
        return "root"
    return cleaned.replace("/", "-")


@router.get("", response_model=GuardRegistryResponse)
def read_guard_registry() -> GuardRegistryResponse:
    from app.ui.router import get_ui_routers  # local import breaks circular

    ui_routers = get_ui_routers()

    routes = sorted(
        [
            GuardRegistryEntry(
                name=_route_name_from_prefix(str(ui_router.prefix or "")),
                prefix=str(ui_router.prefix or ""),
                tags=[str(tag) for tag in (ui_router.tags or [])],
                enabled=True,
                metadata={"source": "app.ui.router"},
            )
            for ui_router in ui_routers
        ],
        key=lambda r: r.prefix,
    )

    return GuardRegistryResponse(
        status="ok",
        service="IronClaw-Security",
        provider="guard",
        timestamp=_utc_now_iso(),
        total_routes=len(routes),
        routes=routes,
        metadata={
            "ui_router_registry": "app.ui.router",
            "sorted_by": "prefix",
        },
    )
