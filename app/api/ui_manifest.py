from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.router import get_ui_routers

router = APIRouter(prefix="/ui-manifest", tags=["ui-manifest"])



class UIManifestRoute(BaseModel):
    prefix: str
    tags: list[str] = Field(default_factory=list)
    slug: str
    label: str
    category: str
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)



class UIManifestResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total_routes: int
    routes: list[UIManifestRoute] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)



def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")



def _slug_from_prefix(prefix: str) -> str:
    normalized = str(prefix or "").strip("/")
    return normalized.replace("/", "-") or "root"



def _label_from_prefix(prefix: str) -> str:
    normalized = str(prefix or "").strip("/")
    if not normalized:
        return "Root"
    parts = [part.replace("-", " ").strip() for part in normalized.split("/") if part.strip()]
    return " / ".join(part.title() for part in parts)



def _category_from_tags(tags: list[str]) -> str:
    if not tags:
        return "general"


    tag = tags[0].strip().lower()


    if tag in {
        "execution-dashboard",
        "execution-detail",
        "execution-explorer",
        "execution-test-console",
    }:
        return "executions"


    if tag in {"review-queue", "review-detail"}:
        return "reviews"


    if tag in {"policy-insights", "request-context"}:
        return "policy"


    if tag in {"client-session-activity", "client-profile", "session-timeline"}:
        return "activity"


    if tag in {"runtime-status", "system-diagnostics", "alerts-notifications", "incident-triage"}:
        return "operations"


    if tag in {"operator-management", "access-control-roles", "settings-configuration"}:
        return "administration"


    if tag in {"integration-settings"}:
        return "integrations"


    if tag in {"audit-log", "data-retention"}:
        return "governance"


    if tag in {"customer-keys", "customer-key-detail", "usage-reports", "usage-event-detail"}:
        return "customer-access"


    if tag in {"ui-manifest"}:
        return "platform"


    if tag.startswith("groq"):
        return "groq"


    if tag.startswith("billing"):
        return "billing"


    return "general"



def _route_metadata(prefix: str, tags: list[str]) -> dict[str, Any]:
    slug = _slug_from_prefix(prefix)


    return {
        "slug": slug,
        "label": _label_from_prefix(prefix),
        "category": _category_from_tags(tags),
        "has_detail_view": any(token in slug for token in ("detail", "profile", "timeline")),
    }



@router.get("", response_model=UIManifestResponse)
def read_ui_manifest() -> UIManifestResponse:
    ui_routers = get_ui_routers()


    routes = []
    for ui_router in ui_routers:
        prefix = str(ui_router.prefix or "")
        tags = [str(tag) for tag in (ui_router.tags or [])]
        metadata = _route_metadata(prefix, tags)


        routes.append(
            UIManifestRoute(
                prefix=prefix,
                tags=tags,
                slug=str(metadata["slug"]),
                label=str(metadata["label"]),
                category=str(metadata["category"]),
                enabled=True,
                metadata=metadata,
            )
        )


    routes = sorted(routes, key=lambda route: route.prefix)


    categories = sorted({route.category for route in routes})
    tags_index = sorted({tag for route in routes for tag in route.tags})


    return UIManifestResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total_routes=len(routes),
        routes=routes,
        metadata={
            "ui_router_registry": "app.ui.router",
            "sorted_by": "prefix",
            "categories": categories,
            "tags_index": tags_index,
        },
    )