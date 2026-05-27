from __future__ import annotations

from collections.abc import Iterable
from importlib import import_module
from typing import Final, cast

from fastapi import APIRouter, FastAPI


def _optional_router(module_path: str) -> APIRouter | None:
    try:
        module = import_module(module_path)
    except ModuleNotFoundError as exc:
        if exc.name != module_path:
            raise
        return None
    router = getattr(module, "router", None)
    if router is None:
        return None
    return cast(APIRouter, router)


router = APIRouter(prefix="/ui", tags=["ui"])

UI_ROUTERS: Final[tuple[APIRouter, ...]] = (
    router,
    *filter(
        None,
        (
            # ── core domain ──────────────────────────────────────────────────
            _optional_router("app.ui.organizations"),
            _optional_router("app.ui.request_context"),
            # ── executions ───────────────────────────────────────────────────
            _optional_router("app.ui.executions.dashboard"),
            _optional_router("app.ui.executions.detail"),
            _optional_router("app.ui.executions.explorer"),
            _optional_router("app.ui.executions.testconsole"),
            # ── reviews ──────────────────────────────────────────────────────
            _optional_router("app.ui.reviews.queue"),
            _optional_router("app.ui.reviews.detail"),
            # ── insights / policy ────────────────────────────────────────────
            _optional_router("app.ui.insights.policy"),
            # ── activity ─────────────────────────────────────────────────────
            _optional_router("app.ui.activity.clientsession"),
            _optional_router("app.ui.activity.clientprofile"),
            _optional_router("app.ui.activity.sessiontimeline"),
            # ── settings / runtime / audit ───────────────────────────────────
            _optional_router("app.ui.settings.configuration"),
            _optional_router("app.ui.runtime.status"),
            _optional_router("app.ui.audit.log"),
            # ── alerts / system / incidents ──────────────────────────────────
            _optional_router("app.ui.alerts.notifications"),
            _optional_router("app.ui.system.diagnostics"),
            _optional_router("app.ui.incidents.triage"),
            # ── integrations ─────────────────────────────────────────────────
            _optional_router("app.ui.integrations.settings"),
            # ── admin ────────────────────────────────────────────────────────
            _optional_router("app.ui.admin.operators"),
            _optional_router("app.ui.admin.roles"),
            # ── groq ─────────────────────────────────────────────────────────
            _optional_router("app.ui.groq"),
            # ── billing ──────────────────────────────────────────────────────
            _optional_router("app.ui.billing_manifest"),
            _optional_router("app.ui.billing_registry"),
            _optional_router("app.ui.billing_index"),
            _optional_router("app.ui.billing_summary"),
            _optional_router("app.ui.billing_wallet"),
            _optional_router("app.ui.billing_purchase"),
            _optional_router("app.ui.billing.invoices"),
            _optional_router("app.ui.billing.invoice_detail"),
            _optional_router("app.ui.billing.payment_methods"),
            _optional_router("app.ui.billing.plan_change"),
            _optional_router("app.ui.billing.package"),
            # ── usage / telemetry / metrics / health ─────────────────────────
            _optional_router("app.ui.usage_reports"),
            _optional_router("app.ui.usage_event_detail"),
            _optional_router("app.ui.telemetry_access_summary"),
            _optional_router("app.ui.metrics_summary"),
            _optional_router("app.ui.health_snapshot"),
            # ── customer keys ─────────────────────────────────────────────────
            _optional_router("app.ui.customer_keys"),
            _optional_router("app.ui.customer_key_detail"),
            # ── docs ──────────────────────────────────────────────────────────
            _optional_router("app.ui.docs.quickstart"),
            _optional_router("app.ui.docs.api_reference"),
            _optional_router("app.ui.docs.authentication"),
            _optional_router("app.ui.docs.policy_guide"),
            _optional_router("app.ui.docs.telemetry_guide"),
            _optional_router("app.ui.docs.webhooks"),
            _optional_router("app.ui.docs.changelog"),
        ),
    ),
)


@router.get("/status", tags=["ui"])
def ui_router_status() -> dict[str, object]:
    return {
        "status": "ok",
        "total_routers": len(UI_ROUTERS),
        "routers": [
            {
                "prefix": ui_router.prefix,
                "tags": list(ui_router.tags or []),
            }
            for ui_router in UI_ROUTERS
        ],
    }


def get_ui_routers() -> tuple[APIRouter, ...]:
    return UI_ROUTERS


def iter_ui_routers() -> Iterable[APIRouter]:
    return iter(UI_ROUTERS)


def _router_label(ui_router: APIRouter) -> str:
    prefix = str(getattr(ui_router, "prefix", "") or "<no-prefix>")
    route_count = len(getattr(ui_router, "routes", ()))
    return f"{prefix} ({route_count} routes)"


def _route_signature(route: object) -> tuple[str, tuple[str, ...], str]:
    path = str(getattr(route, "path", ""))
    methods = tuple(sorted(cast("set[str]", getattr(route, "methods", set()) or set())))
    name = str(getattr(route, "name", ""))
    return (path, methods, name)


def validate_ui_routers() -> None:
    seen_router_objects: set[int] = set()
    seen_route_signatures: dict[tuple[str, tuple[str, ...], str], str] = {}

    for ui_router in UI_ROUTERS:
        router_id = id(ui_router)
        label = _router_label(ui_router)

        if router_id in seen_router_objects:
            raise ValueError(f"duplicate UI router object registration detected: {label}")
        seen_router_objects.add(router_id)

        if not ui_router.routes:
            continue

        for route in ui_router.routes:
            signature = _route_signature(route)
            path, methods, _ = signature

            if not path:
                raise ValueError(f"UI router contains a route with an empty path: {label}")

            if signature in seen_route_signatures:
                raise ValueError(
                    f"duplicate UI route registration detected: {path} {methods} already registered under {seen_route_signatures[signature]}",
                )

            seen_route_signatures[signature] = label


def include_ui_routers(app: FastAPI) -> None:
    validate_ui_routers()

    existing_route_signatures = {_route_signature(route) for route in app.routes if getattr(route, "path", "")}

    for ui_router in UI_ROUTERS:
        router_signatures = {_route_signature(route) for route in ui_router.routes if getattr(route, "path", "")}

        if router_signatures and router_signatures.issubset(existing_route_signatures):
            continue

        app.include_router(ui_router)
        existing_route_signatures.update(router_signatures)


def includeuirouters(app: FastAPI) -> None:
    include_ui_routers(app)


def register_page(path: str, **kwargs: object) -> object:
    """No-op page registration shim — metadata only, no route side-effects."""
    return kwargs
