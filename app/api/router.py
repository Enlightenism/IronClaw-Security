from __future__ import annotations

from importlib import import_module
from typing import Final, cast

from fastapi import APIRouter
from fastapi.routing import APIRoute

router = APIRouter(prefix="/api", tags=["api"])
inventory_router = APIRouter(tags=["api-inventory"])

OPTIONAL_API_MODULES: Final[tuple[str, ...]] = (
    "app.api.routes.incidents",
    "app.api.routes.integrations",
    "app.api.routes.reviewqueue",
    "app.api.threat_feed",
)

CORE_API_MODULES: Final[tuple[str, ...]] = (
    "app.api.ui_manifest",
    "app.ui.groq_registry",
    "app.api.routes.unit_wallet",
    "app.api.routes.unit_ledger",
    "app.api.routes.actionhistorytest",
)


def _optional_router(module_path: str) -> APIRouter | None:
    try:
        module = import_module(module_path)
    except ModuleNotFoundError as exc:
        missing_name = getattr(exc, "name", "") or ""
        if missing_name == module_path or module_path.endswith(f".{missing_name}"):
            return None
        raise

    candidate = getattr(module, "router", None)
    return candidate if isinstance(candidate, APIRouter) else None


def _route_signature(route: APIRoute) -> tuple[str, tuple[str, ...], str]:
    methods = tuple(sorted(method for method in (route.methods or set()) if method != "HEAD"))
    return (route.path, methods, route.name)


def _router_label(api_router: APIRouter) -> str:
    prefix = str(getattr(api_router, "prefix", "") or "<no-prefix>")
    return f"{prefix} ({len(api_router.routes)} routes)"


def get_api_routers() -> list[APIRouter]:
    routers: list[APIRouter] = []
    for module_path in CORE_API_MODULES:
        core_router = _optional_router(module_path)
        if core_router is not None:
            routers.append(core_router)
    for module_path in OPTIONAL_API_MODULES:
        optional_router = _optional_router(module_path)
        if optional_router is not None:
            routers.append(optional_router)
    return routers


def validate_api_routers() -> None:
    seen_router_objects: set[int] = set()
    seen_route_signatures: dict[tuple[str, tuple[str, ...], str], str] = {}

    for api_router in get_api_routers():
        router_id = id(api_router)
        label = _router_label(api_router)

        if router_id in seen_router_objects:
            raise ValueError(f"duplicate API router object registration detected: {label}")
        seen_router_objects.add(router_id)

        if not api_router.routes:
            raise ValueError(f"API router has no routes: {label}")

        for route in api_router.routes:
            if not isinstance(route, APIRoute):
                continue

            signature = _route_signature(route)
            path, methods, _ = signature

            if not path:
                raise ValueError(f"API router contains a route with an empty path: {label}")

            if signature in seen_route_signatures:
                raise ValueError(
                    f"duplicate API route registration detected: {path} {methods} already registered under {seen_route_signatures[signature]}",
                )
            seen_route_signatures[signature] = label


# NOTE: /ui-manifest and /groq-registry are intentionally OMITTED here.
# Those paths are already served by app.api.ui_manifest and app.ui.groq_registry
# (loaded via CORE_API_MODULES). Adding them here would cause duplicate route registration.
@inventory_router.get("/incidents", summary="Api Incidents Inventory")
def api_incidents_inventory() -> dict[str, str]:
    return {"resource": "incidents", "path": "/api/incidents"}


@inventory_router.get("/integrations", summary="Api Integrations Inventory")
def api_integrations_inventory() -> dict[str, str]:
    return {"resource": "integrations", "path": "/api/integrations"}


@inventory_router.get("/review-queue", summary="Api Review Queue Inventory")
def api_review_queue_inventory() -> dict[str, str]:
    return {"resource": "review-queue", "path": "/api/review-queue"}


@inventory_router.get("/unit-ledger", summary="Api Unit Ledger Inventory")
def api_unit_ledger_inventory() -> dict[str, str]:
    return {"resource": "unit-ledger", "path": "/api/unit-ledger"}


@inventory_router.get("/unit-wallet", summary="Api Unit Wallet Inventory")
def api_unit_wallet_inventory() -> dict[str, str]:
    return {"resource": "unit-wallet", "path": "/api/unit-wallet"}


@inventory_router.get("/threat/iocs", summary="Api IOC Management Inventory")
def api_ioc_management_inventory() -> dict[str, str]:
    return {"resource": "ioc-management", "path": "/threat/iocs"}


@inventory_router.get("/threat/feeds", summary="Api Threat Feed Management Inventory")
def api_threat_feed_inventory() -> dict[str, str]:
    return {"resource": "threat-feeds", "path": "/threat/feeds"}


def include_api_routers() -> None:
    validate_api_routers()

    existing_route_signatures = {_route_signature(cast("APIRoute", route)) for route in router.routes if isinstance(route, APIRoute)}

    for api_router in get_api_routers():
        router_signatures = {_route_signature(cast("APIRoute", route)) for route in api_router.routes if isinstance(route, APIRoute)}

        if router_signatures and router_signatures.issubset(existing_route_signatures):
            continue

        router.include_router(api_router)
        existing_route_signatures.update(router_signatures)

    inventory_signatures = {_route_signature(cast("APIRoute", route)) for route in inventory_router.routes if isinstance(route, APIRoute)}

    if not inventory_signatures.issubset(existing_route_signatures):
        router.include_router(inventory_router)


include_api_routers()
