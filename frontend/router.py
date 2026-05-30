from __future__ import annotations

from importlib import import_module
import logging
from typing import Any

from fastapi import APIRouter

_log = logging.getLogger(__name__)

_DASHBOARD_PREFIX = "/dashboard"


def _optional_page_router(module_path: str) -> Any | None:
    try:
        module = import_module(module_path)
        return getattr(module, "router", None)
    except ModuleNotFoundError as exc:
        if exc.name != module_path:
            raise
        _log.debug("frontend.router: optional page not yet built — %s", module_path)
        return None
    except Exception as exc:  # noqa: BLE001
        _log.warning("frontend.router: failed to load %s — %s", module_path, exc)
        return None


def _build_frontend_router() -> APIRouter:
    root = APIRouter(tags=["frontend"])

    # ── Auth routes (no /dashboard prefix) ─────────────────────────────────
    auth_page_modules: list[tuple[str, dict[str, Any]]] = [
        ("frontend.pages.login", {}),
    ]
    for module_path, kwargs in auth_page_modules:
        page_router = _optional_page_router(module_path)
        if page_router is None:
            continue
        root.include_router(page_router, **kwargs)

    # ── Dashboard-prefixed routes ───────────────────────────────────────────
    dashboard = APIRouter(prefix=_DASHBOARD_PREFIX)

    page_modules: list[tuple[str, dict[str, Any]]] = [
        # ── Phase 3 — Dashboard home ────────────────────────────────────────
        ("frontend.pages.dashboard", {}),
        # ── Phase 4 — Core security pages ───────────────────────────────────
        ("frontend.pages.scan", {}),
        ("frontend.pages.threats", {}),
        ("frontend.pages.threat_alerts", {}),
        ("frontend.pages.threat_feed", {}),
        ("frontend.pages.threat_hunt", {}),
        ("frontend.pages.action_guard", {}),
        ("frontend.pages.action_execute", {}),
        ("frontend.pages.quarantine", {}),
        ("frontend.pages.review_queue", {}),
        # ── Phase 5 — Intelligence pages ────────────────────────────────────
        ("frontend.pages.ioc_management", {}),
        ("frontend.pages.behavioral_baseline", {}),
        ("frontend.pages.history", {}),
        ("frontend.pages.request_context", {}),
        # ── Phase 6 — System / admin pages ──────────────────────────────────
        ("frontend.pages.policies", {}),
        ("frontend.pages.access_control", {}),
        ("frontend.pages.diagnostics", {}),
        ("frontend.pages.telemetry", {}),
        ("frontend.pages.audit", {}),
        # ── Phase 7 — Onboarding flow ────────────────────────────────────────
        ("frontend.pages.onboarding", {}),
    ]

    for module_path, kwargs in page_modules:
        page_router = _optional_page_router(module_path)
        if page_router is None:
            continue
        dashboard.include_router(page_router, **kwargs)

    root.include_router(dashboard)

    return root
